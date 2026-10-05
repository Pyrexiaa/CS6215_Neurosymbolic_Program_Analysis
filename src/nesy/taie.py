"""Running Tai-e and parsing its taint-analysis output (S2 - symbolic propagation).

Tai-e prints detected flows to its log as::

    Detected 2 taint flow(s):
    TaintFlow{<a.B: void m()>[3@L5] %v5 = invokestatic x.Taint.src()/result -> <a.C: void n(java.lang.String)>[9@L17] invokespecial out.<init>(d, n)/1}

and dumps a taint flow graph (application code only) to ``taint-flow-graph.dot``.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .jvm import is_jdk_class, parse_taie_signature

DRIVER_PACKAGE = "nesy."


# ----------------------------------------------------------------- data model

@dataclass(frozen=True)
class TaintPoint:
    method: str            # Tai-e signature of the containing (or source) method
    stmt_index: int        # -1 for parameter sources
    line: int              # -1 when unknown
    stmt: str              # IR statement text ('' for parameter sources)
    index: str             # index reference, e.g. result, base, 0, 1[*]
    raw: str

    @property
    def owner(self) -> str:
        ms = parse_taie_signature(self.method)
        return ms.owner if ms else ""

    @property
    def in_driver(self) -> bool:
        return self.owner.startswith(DRIVER_PACKAGE)


@dataclass(frozen=True)
class TaintFlow:
    source: TaintPoint
    sink: TaintPoint

    @property
    def raw(self) -> str:
        return f"TaintFlow{{{self.source.raw} -> {self.sink.raw}}}"

    @property
    def key(self) -> str:
        """Stable identity used across configurations and runs.

        Driver-generated sources are collapsed into ``DRIVER`` so that flows found with
        different drivers but the same sink site compare equal.
        """
        src = "DRIVER" if self.source.in_driver else f"{self.source.method}@L{self.source.line}/{self.source.index}"
        return f"{src} => {self.sink.method}@L{self.sink.line}/{self.sink.index}"

    @property
    def short_id(self) -> str:
        return hashlib.sha1(self.key.encode()).hexdigest()[:10]

    def to_json(self) -> dict:
        return {"id": self.short_id, "key": self.key, "source": asdict(self.source), "sink": asdict(self.sink)}

    @staticmethod
    def from_json(d: dict) -> "TaintFlow":
        return TaintFlow(TaintPoint(**d["source"]), TaintPoint(**d["sink"]))


_POINT_POS = re.compile(r"^\[(\d+)@L(-?\d+)\]\s*(.*)$")


def _split_method_sig(s: str) -> Tuple[str, str]:
    """Split ``<a.B: void <init>(x)>rest`` into (sig, rest). Signatures end with ')>'."""
    end = s.find(")>")
    if not s.startswith("<") or end < 0:
        raise ValueError(f"not a taint point: {s!r}")
    return s[:end + 2], s[end + 2:]


def parse_point(s: str) -> TaintPoint:
    s = s.strip()
    sig, rest = _split_method_sig(s)
    rest = rest.strip()
    if "/" not in rest:
        raise ValueError(f"no index reference in {s!r}")
    body, index = rest.rsplit("/", 1)
    body = body.strip()
    if not body:
        return TaintPoint(sig, -1, -1, "", index, s)
    m = _POINT_POS.match(body)
    if m:
        return TaintPoint(sig, int(m.group(1)), int(m.group(2)), m.group(3), index, s)
    return TaintPoint(sig, -1, -1, body, index, s)


_FLOW = re.compile(r"TaintFlow\{(.*)\}\s*$")


def parse_flow_line(line: str) -> Optional[TaintFlow]:
    m = _FLOW.search(line)
    if not m:
        return None
    inner = m.group(1)
    # the sink point always starts with a method signature: split on ' -> <'
    pos = inner.find(" -> <")
    while pos >= 0:
        try:
            src = parse_point(inner[:pos])
            snk = parse_point(inner[pos + 4:])
            return TaintFlow(src, snk)
        except ValueError:
            pos = inner.find(" -> <", pos + 1)
    return None


def parse_flows_from_log(text: str) -> Tuple[Optional[int], List[TaintFlow]]:
    detected = None
    flows: List[TaintFlow] = []
    seen: Set[str] = set()
    for line in text.splitlines():
        m = re.search(r"Detected (\d+) taint flow", line)
        if m:
            detected = int(m.group(1))
            continue
        if "TaintFlow{" in line:
            f = parse_flow_line(line)
            if f and f.raw not in seen:
                seen.add(f.raw)
                flows.append(f)
    return detected, flows


# ----------------------------------------------------------------- filtering

def filter_flows(flows: Iterable[TaintFlow], app_classes: Set[str], drop_jdk_internal_sinks: bool = True,
                 app_sinks_only: bool = False, drop_jdk_internal_sources: bool = True) -> List[TaintFlow]:
    """Keep flows whose sink call site is relevant to the subject.

    * ``drop_jdk_internal_sinks``: discard sinks inside the Java library itself (e.g. a
      ``new File`` inside ``java.util.logging``), which are artefacts of whole-program
      analysis and never part of a subject's vulnerability.
    * ``drop_jdk_internal_sources``: same for sources (e.g. ``readLine`` called inside the JDK).
    * ``app_sinks_only``: additionally require the sink call site to be in application code.

    Flows with the same ``key`` (same sink site and index, same non-driver source) are merged:
    they are one alarm for a developer even if several driver calls reach it.
    """
    out = []
    seen_keys: Set[str] = set()
    for f in flows:
        if f.key in seen_keys:      # same alarm reached from several driver call sites
            continue
        owner = f.sink.owner
        if owner.startswith(DRIVER_PACKAGE):
            continue
        if drop_jdk_internal_sinks and is_jdk_class(owner):
            continue
        if drop_jdk_internal_sources and is_jdk_class(f.source.owner):
            continue
        if app_sinks_only and owner not in app_classes:
            continue
        seen_keys.add(f.key)
        out.append(f)
    return out


# ----------------------------------------------------------------- TFG

_EDGE = re.compile(r'^\s*"((?:[^"\\]|\\.)*)"\s*->\s*"((?:[^"\\]|\\.)*)"\s*(\[.*\])?\s*;?\s*$')
_NODE_METHOD = re.compile(r"(?:VarNode|InstanceFieldNode|ArrayIndexNode)\{(<[^{}]*?\)>)")


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\n", "\n")


class TaintFlowGraph:
    """Parsed ``taint-flow-graph.dot``. Nodes are pointer labels; source/sink nodes carry
    their configuration entry and point text separated by a newline."""

    def __init__(self, edges: List[Tuple[str, str, str]]):
        self.succ: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        self.pred: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        for a, b, attr in edges:
            self.succ[a].append((b, attr))
            self.pred[b].append((a, attr))
        self.nodes: Set[str] = set(self.succ) | set(self.pred)

    @staticmethod
    def load(path: Path) -> "TaintFlowGraph":
        edges = []
        p = Path(path)
        if p.exists():
            for line in p.read_text(errors="replace").splitlines():
                m = _EDGE.match(line)
                if m:
                    edges.append((_unescape(m.group(1)), _unescape(m.group(2)), m.group(3) or ""))
        return TaintFlowGraph(edges)

    def _node_for_point(self, point: TaintPoint) -> List[str]:
        # Sort set-derived nodes so evidence order and prompt cache keys do not depend on the hash seed.
        return sorted(n for n in self.nodes if n.endswith("\n" + point.raw) or n.endswith(point.raw))

    def path(self, flow: TaintFlow, max_nodes: int = 60) -> List[str]:
        """Shortest TFG path from the flow's source node to its sink node ([] if none)."""
        starts = self._node_for_point(flow.source)
        goals = set(self._node_for_point(flow.sink))
        if not starts or not goals:
            return []
        prev: Dict[str, Optional[str]] = {s: None for s in starts}
        q = deque(starts)
        while q:
            u = q.popleft()
            if u in goals:
                out = []
                while u is not None:
                    out.append(u)
                    u = prev[u]
                return list(reversed(out))[:max_nodes]
            for v, _ in self.succ.get(u, []):
                if v not in prev:
                    prev[v] = u
                    q.append(v)
        return []

    def methods_between(self, flow: TaintFlow) -> List[str]:
        """App methods on any TFG route source->sink; falls back to nodes reachable from the
        source or reaching the sink when the route leaves application code."""
        starts = self._node_for_point(flow.source)
        goals = self._node_for_point(flow.sink)
        fwd = self._reach(starts, self.succ)
        bwd = self._reach(goals, self.pred)
        nodes = (fwd & bwd) or (fwd | bwd)
        methods = []
        for n in sorted(nodes):
            for m in _NODE_METHOD.findall(n):
                if m not in methods:
                    methods.append(m)
        return methods

    def sink_entries(self, point: TaintPoint) -> List[str]:
        """Method signatures of the taint-config sink entries that produced ``point``. A sink node
        is labelled ``{ method: "<sig>", index: ... }\n<point>``."""
        out: List[str] = []
        for n in self._node_for_point(point):
            first = n.split("\n", 1)[0]
            m = re.search(r'method:\s*"(<[^"]*\)>)"', first)
            if m and m.group(1) not in out:
                out.append(m.group(1))
        return out

    def route_methods(self, flow: TaintFlow) -> List[str]:
        """App methods on a TFG route source->sink (forward-reachable from the source AND
        backward-reachable from the sink). Unlike ``methods_between`` there is no fallback, so
        only complete connecting routes contribute to patch-method matching."""
        starts = self._node_for_point(flow.source)
        goals = self._node_for_point(flow.sink)
        nodes = self._reach(starts, self.succ) & self._reach(goals, self.pred)
        methods: List[str] = []
        for n in sorted(nodes):
            for m in _NODE_METHOD.findall(n):
                if m not in methods:
                    methods.append(m)
        return methods

    @staticmethod
    def _reach(starts: Sequence[str], adj: Dict[str, List[Tuple[str, str]]]) -> Set[str]:
        seen = set(starts)
        q = deque(starts)
        while q:
            u = q.popleft()
            for v, _ in adj.get(u, []):
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        return seen


def node_method(node: str) -> Optional[str]:
    m = _NODE_METHOD.search(node)
    if m:
        return m.group(1)
    # source/sink element: last line is the point text
    last = node.split("\n")[-1]
    try:
        return _split_method_sig(last)[0]
    except ValueError:
        return None


# ----------------------------------------------------------------- runner

@dataclass
class TaieResult:
    ok: bool
    returncode: int
    elapsed_s: float
    timed_out: bool
    out_dir: str
    log_path: str
    detected: Optional[int]
    flows: List[TaintFlow] = field(default_factory=list)
    command: List[str] = field(default_factory=list)
    reachable_methods: Optional[int] = None
    error: str = ""

    def to_json(self) -> dict:
        d = asdict(self)
        d["flows"] = [f.to_json() for f in self.flows]
        return d


@dataclass
class TaieSettings:
    jar: Path
    java_bin: Path                      # java of a JDK 17+ (runs Tai-e)
    jre_version: Optional[int] = 8      # analysed Java library; None = Tai-e's current JRE
    jre_jars: Sequence[Path] = ()       # rt.jar etc. when jre_version is set
    home: Path = Path("work/taie-home") # working dir holding java-benchmarks/JREs/jre1.X
    cs: str = "ci"
    only_app: bool = False
    time_limit_s: int = 1800
    wall_timeout_s: int = 3600
    xmx: str = "6g"
    extra_pta_options: Dict[str, str] = field(default_factory=dict)


def prepare_taie_home(settings: TaieSettings) -> Path:
    """Tai-e loads ``-java 8`` libraries from ``java-benchmarks/JREs/jre1.8`` relative to its
    working directory. We build that layout from an installed JDK 8 instead of cloning the
    (multi-GB) java-benchmarks repository."""
    home = Path(settings.home).resolve()
    if settings.jre_version is None:
        home.mkdir(parents=True, exist_ok=True)
        return home
    jre_dir = home / "java-benchmarks" / "JREs" / f"jre1.{settings.jre_version}"
    jre_dir.mkdir(parents=True, exist_ok=True)
    for jar in settings.jre_jars:
        jar = Path(jar)
        target = jre_dir / jar.name
        if not target.exists():
            try:
                target.symlink_to(jar.resolve())
            except OSError:
                shutil.copy2(jar, target)
    return home


def build_command(settings: TaieSettings, app_cp: Sequence[Path], lib_cp: Sequence[Path], main_class: str,
                  taint_config: Path, out_dir: Path, input_classes: Sequence[str] = ()) -> List[str]:
    opts = {
        "cs": settings.cs,
        "only-app": str(settings.only_app).lower(),
        "taint-config": str(Path(taint_config).resolve()),
        "time-limit": str(settings.time_limit_s),
    }
    opts.update(settings.extra_pta_options or {})
    pta = "pta=" + ";".join(f"{k}:{v}" for k, v in opts.items()) + ";"
    cmd = [str(settings.java_bin), f"-Xmx{settings.xmx}", "-jar", str(Path(settings.jar).resolve())]
    if settings.jre_version is not None:
        cmd += ["-java", str(settings.jre_version)]
    for p in app_cp:
        cmd += ["-acp", str(Path(p).resolve())]
    for p in lib_cp:
        cmd += ["-cp", str(Path(p).resolve())]
    cmd += ["-m", main_class]
    if input_classes:
        cmd += [f"--input-classes={','.join(input_classes)}"]
    cmd += ["--output-dir", str(Path(out_dir).resolve()), "-a", pta]
    return cmd


# An uncaught exception in Tai-e's main thread does not end the JVM: the pointer-analysis
# time-limit timer is a non-daemon thread, so the process idles until `time-limit` expires
# (observed: ClassCastException at 0:05, process exit at 30:00). We watch the log and kill it.
CRASH_MARKERS = ('Exception in thread "main"',)


def run_watched(cmd: Sequence[str], cwd: Path, log_path: Path, env: Optional[dict], wall_timeout_s: float,
                poll_s: float = 1.0, grace_s: float = 3.0,
                crash_markers: Sequence[str] = CRASH_MARKERS) -> Tuple[int, bool, bool]:
    """Run ``cmd`` with stdout+stderr to ``log_path``. Returns (returncode, timed_out, crashed).

    If a crash marker appears in the log, the process gets ``grace_s`` seconds to exit by itself
    (so the stack trace is complete) and is then killed; the return code is forced to 1."""
    t0 = time.time()
    crashed = timed_out = False
    crash_seen_at: Optional[float] = None
    pos, carry = 0, ""
    with open(log_path, "w") as logf:
        proc = subprocess.Popen(list(cmd), cwd=cwd, stdout=logf, stderr=subprocess.STDOUT, env=env)
        try:
            while True:
                try:
                    proc.wait(timeout=poll_s)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if crash_seen_at is None:
                    with open(log_path, "r", errors="replace") as rf:
                        rf.seek(pos)
                        chunk = rf.read()
                        pos = rf.tell()
                    window = carry + chunk
                    if any(m in window for m in crash_markers):
                        crash_seen_at = time.time()
                    carry = window[-200:]
                elif time.time() - crash_seen_at >= grace_s:
                    crashed = True
                    proc.kill()
                    proc.wait()
                    break
                if time.time() - t0 > wall_timeout_s:
                    timed_out = True
                    proc.kill()
                    proc.wait()
                    break
        except BaseException:          # Ctrl-C etc.: never leave a 6 GB JVM behind
            proc.kill()
            proc.wait()
            raise
    rc = proc.returncode
    if timed_out:
        rc = -9
    elif crashed or (crash_seen_at is not None and rc == 0):
        crashed, rc = True, 1
    return rc, timed_out, crashed


def run_taie(settings: TaieSettings, app_cp: Sequence[Path], lib_cp: Sequence[Path], main_class: str,
             taint_config: Path, out_dir: Path, input_classes: Sequence[str] = ()) -> TaieResult:
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    home = prepare_taie_home(settings)
    cmd = build_command(settings, app_cp, lib_cp, main_class, taint_config, out_dir, input_classes)
    log_path = out_dir / "console.log"
    env = dict(os.environ)
    env.pop("JAVA_TOOL_OPTIONS", None)   # avoid proxy agents etc. leaking into the analysis
    t0 = time.time()
    rc, timed_out, crashed = run_watched(cmd, home, log_path, env, settings.wall_timeout_s)
    elapsed = time.time() - t0
    text = log_path.read_text(errors="replace")
    detected, flows = parse_flows_from_log(text)
    m = re.search(r"#reachable methods:\s+(\d[\d,]*)", text)
    reach = int(m.group(1).replace(",", "")) if m else None
    err = ""
    if rc != 0:
        lines = text.splitlines()
        # the fatal line first; "Exception"/"Error" also occur in class names of Tai-e's
        # duplicate-class warnings, which must not be mistaken for the cause
        fatal = [l for l in lines if any(m in l for m in CRASH_MARKERS) or l.startswith("Caused by:")]
        other = [l for l in lines if ("Exception" in l or "Error" in l) and "is founded in" not in l
                 and not l.startswith("[") and l not in fatal]
        err = "\n".join((fatal + other)[:5])[:2000]
        if fatal:
            crashed = True
            err = "CRASH (uncaught exception in Tai-e's main thread)\n" + err
    if "time-limit" in text and "reached" in text.lower():
        timed_out = True
    res = TaieResult(rc == 0 and detected is not None, rc, round(elapsed, 2), timed_out, str(out_dir),
                     str(log_path), detected, flows, cmd, reach, err)
    (out_dir / "result.json").write_text(json.dumps(res.to_json(), indent=2))
    return res
