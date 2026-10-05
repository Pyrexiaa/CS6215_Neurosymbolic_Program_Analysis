"""Entry-point drivers for Tai-e.

* ``template`` driver (symbolic, used by B1/B2/v1): calls the top-ranked entry candidates from S1
  and passes taint-API values for every attacker-controllable parameter type.
* ``llm`` driver (N1, used by v2/v3): the LLM chooses entry points and which parameters are
  attacker controlled; V1 compiles it, feeds errors back for repair, and statically checks
  that the compiled driver really calls application code and the taint API.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .classfile import parse_class
from .facts import EntryCandidate, ProgramFacts
from .jvm import default_value_expr, java_source_type, parse_taie_signature
from .llm import BaseLLM, extract_code_block, extract_json
from .prompts import build_messages, prompt_version

DRIVER_CLASS = "nesy.NesyDriver"

# Bump when the template generator changes to invalidate incompatible cached drivers.
TEMPLATE_VERSION = 2

TAINT_JAVA = """package nesy;

/**
 * Taint API used by generated drivers. Tai-e treats the RESULT of every method below as a
 * taint source (see config/taint/driver-sources.yml), so the bodies are irrelevant.
 */
public final class Taint {
    private Taint() {}
    public static String src() { return new String("nesy-tainted"); }
    public static byte[] srcBytes() { return src().getBytes(); }
    public static java.io.InputStream srcStream() { return new java.io.ByteArrayInputStream(srcBytes()); }
    public static java.io.File srcFile() { return new java.io.File(src()); }
}
"""

TAINT_API_DOC = (
    "nesy.Taint.src() -> String; nesy.Taint.srcBytes() -> byte[]; "
    "nesy.Taint.srcStream() -> java.io.InputStream; nesy.Taint.srcFile() -> java.io.File"
)

DRIVER_SOURCES_YAML = """# Taint sources for generated drivers (nesy.Taint). Always part of every configuration.
sources:
  - { kind: call, method: "<nesy.Taint: java.lang.String src()>", index: result }
  - { kind: call, method: "<nesy.Taint: byte[] srcBytes()>", index: result }
  - { kind: call, method: "<nesy.Taint: java.io.InputStream srcStream()>", index: result }
  - { kind: call, method: "<nesy.Taint: java.io.File srcFile()>", index: result }
"""

TAINTED_EXPR = {
    "java.lang.String": "nesy.Taint.src()",
    "java.lang.CharSequence": "nesy.Taint.src()",
    "java.lang.Object": "nesy.Taint.src()",
    "java.lang.String[]": "new String[]{nesy.Taint.src()}",
    "byte[]": "nesy.Taint.srcBytes()",
    "char[]": "nesy.Taint.src().toCharArray()",
    "java.io.InputStream": "nesy.Taint.srcStream()",
    "java.io.Reader": "new java.io.StringReader(nesy.Taint.src())",
    "java.io.File": "nesy.Taint.srcFile()",
    "java.nio.file.Path": "nesy.Taint.srcFile().toPath()",
    "java.net.URL": "new java.net.URL(nesy.Taint.src())",
    "java.net.URI": "java.net.URI.create(nesy.Taint.src())",
    "java.util.List": "java.util.Collections.singletonList(nesy.Taint.src())",
    "java.util.Collection": "java.util.Collections.singletonList(nesy.Taint.src())",
    "java.util.Map": "java.util.Collections.singletonMap(nesy.Taint.src(), nesy.Taint.src())",
    "java.util.zip.ZipInputStream": "new java.util.zip.ZipInputStream(nesy.Taint.srcStream())",
    "java.util.zip.ZipFile": "new java.util.zip.ZipFile(nesy.Taint.srcFile())",
}


@dataclass
class DriverResult:
    kind: str                       # template | llm | llm-fallback-template
    ok: bool
    classes_dir: str
    source_path: str
    entries: List[str] = field(default_factory=list)
    attempts: int = 0
    errors: List[str] = field(default_factory=list)
    removed_entries: List[str] = field(default_factory=list)
    app_calls: int = 0
    taint_calls: int = 0
    llm_entries: List[dict] = field(default_factory=list)
    prompt_version: str = ""
    entry_mismatches: List[str] = field(default_factory=list)   # V1 entry-call check
    check_version: int = 0          # ENTRY_CHECK_VERSION the driver was validated with (0 = no entry check)

    def save(self, path: Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2))


# ----------------------------------------------------------------- template driver

def _accessible(e: EntryCandidate) -> bool:
    simple = e.owner.rsplit(".", 1)[-1]
    if any(part[:1].isdigit() for part in simple.split("$")[1:]):
        return False  # anonymous / local class
    if not e.is_static and e.name != "<init>" and e.owner_is_abstract:
        return False
    if e.name != "<init>" and not e.is_static and not e.constructors:
        return False
    return True


def _arg_exprs(params: Sequence[str], taint: bool, tainted_idx: Optional[Sequence[int]] = None) -> List[str]:
    out = []
    for i, p in enumerate(params):
        want = taint and (tainted_idx is None or i in tainted_idx)
        if want and p in TAINTED_EXPR:
            out.append(TAINTED_EXPR[p])
        elif p == "java.lang.String":
            out.append('"nesy-benign"')
        else:
            out.append(default_value_expr(p))
    return out


def template_call(e: EntryCandidate) -> Optional[str]:
    owner = java_source_type(e.owner)
    args = ", ".join(_arg_exprs(e.params, taint=True))
    if e.name == "<init>":
        return f"new {owner}({args});"
    if e.is_static:
        return f"{owner}.{e.name}({args});"
    ctor = e.constructors[0] if e.constructors else []
    ctor_args = ", ".join(_arg_exprs(ctor, taint=False))
    return f"{owner} r = new {owner}({ctor_args}); r.{e.name}({args});"


def render_driver(lines_in: List[Tuple[str, str]]) -> str:
    """``lines_in`` = [(tag, Java statement line)] -> Java source. Every line carries ``// ENTRY <tag>``
    so the deterministic repair can drop exactly the lines javac rejects."""
    lines = ["package nesy;", "", "/** Generated by nesy (template driver). */",
             "public class NesyDriver {", "    public static void main(String[] args) {"]
    for tag, stmt in lines_in:
        lines.append(f"        {stmt} // ENTRY {tag}")
    lines += ["    }", "}", ""]
    return "\n".join(lines)


def _try(stmt: str) -> str:
    return f"try {{ {stmt} }} catch (Throwable t) {{}}"


def make_template_driver(facts: ProgramFacts, max_entries: int) -> Tuple[str, List[str]]:
    """Symbolic driver: one shared receiver object per class, configured before use.

    * Constructors that are entry points (e.g. Jenkins @DataBoundConstructor) build the shared
      receiver with tainted arguments; otherwise the smallest public constructor gets benign values.
    * Setters run before the other instance methods on the same object, so state written by one
      entry (e.g. a configured command path) is visible to the next (e.g. a build step).
    * Every attacker-controllable parameter type receives a taint-API value.
    Tai-e's pointer analysis is flow-insensitive, so statement order only matters for readability.
    """
    selected: List[EntryCandidate] = []
    seen = set()
    for e in facts.entries:
        if len(selected) >= max_entries:
            break
        if e.signature in seen or not _accessible(e):
            continue
        seen.add(e.signature)
        selected.append(e)
    ctor_entry: Dict[str, EntryCandidate] = {}
    by_owner: Dict[str, List[EntryCandidate]] = {}
    statics: List[EntryCandidate] = []
    for e in selected:
        if e.name == "<init>":
            ctor_entry.setdefault(e.owner, e)
        elif e.is_static:
            statics.append(e)
        else:
            by_owner.setdefault(e.owner, []).append(e)
    out: List[Tuple[str, str]] = []
    used: List[str] = []
    for n, (owner, ents) in enumerate(by_owner.items()):
        t = java_source_type(owner)
        var = f"o{n}"
        ce = ctor_entry.get(owner)
        if ce is not None:
            cargs, tag = ", ".join(_arg_exprs(ce.params, taint=True)), ce.signature
            used.append(ce.signature)
        else:
            cargs, tag = ", ".join(_arg_exprs(ents[0].constructors[0], taint=False)), f"RECEIVER {owner}"
        out.append((f"RECEIVER {owner}", f"{t} {var} = null;"))
        out.append((tag, _try(f"{var} = new {t}({cargs});")))
        for e in sorted(ents, key=lambda x: (not x.name.startswith("set"), facts.entries.index(x))):
            out.append((e.signature, _try(f"{var}.{e.name}({', '.join(_arg_exprs(e.params, taint=True))});")))
            used.append(e.signature)
    for owner, ce in ctor_entry.items():
        if owner not in by_owner:
            out.append((ce.signature, _try(f"new {java_source_type(owner)}({', '.join(_arg_exprs(ce.params, taint=True))});")))
            used.append(ce.signature)
    for e in statics:
        out.append((e.signature, _try(f"{java_source_type(e.owner)}.{e.name}({', '.join(_arg_exprs(e.params, taint=True))});")))
        used.append(e.signature)
    return render_driver(out), used


# ----------------------------------------------------------------- compilation (V1)

_ERR = re.compile(r"^(.*?NesyDriver\.java):(\d+): error: (.*)$", re.M)


def javac_path(java_home: Optional[Path]) -> str:
    if java_home and (Path(java_home) / "bin" / "javac").exists():
        return str(Path(java_home) / "bin" / "javac")
    return "javac"


def compile_driver(src_dir: Path, out_dir: Path, classpath: Sequence[Path], javac: str,
                   release: int = 8) -> Tuple[bool, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    files = [str(src_dir / "nesy" / "Taint.java"), str(src_dir / "nesy" / "NesyDriver.java")]
    cp = os.pathsep.join(str(Path(p).resolve()) for p in classpath)
    rel = ["--release", str(release)]
    # -proc:none: the driver needs no annotation processing, and processors found on the subject's
    # class path (e.g. an old Lombok in cron-utils) crash on newer javac.
    cmd = [javac, *rel, "-g", "-nowarn", "-proc:none", "-encoding", "UTF-8", "-cp", cp, "-d", str(out_dir), *files]
    env = dict(os.environ)
    env.pop("JAVA_TOOL_OPTIONS", None)
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
    out = (p.stdout + p.stderr).strip()
    if p.returncode != 0 and "invalid flag: --release" in out:   # javac 8
        cmd = [javac, "-source", "1.8", "-target", "1.8", *cmd[3:]]
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
        out = (p.stdout + p.stderr).strip()
    return p.returncode == 0, out


def error_lines(output: str) -> List[int]:
    return sorted({int(m.group(2)) for m in _ERR.finditer(output)})


def static_check(classes_dir: Path, app_classes: set) -> Tuple[int, int]:
    """V1 static check on the compiled driver: (#calls into app classes, #calls to the taint API)."""
    p = Path(classes_dir) / "nesy" / "NesyDriver.class"
    if not p.exists():
        return 0, 0
    ci = parse_class(p.read_bytes(), str(p))
    app_calls = taint_calls = 0
    for m in ci.methods:
        for c in m.calls:
            if c.owner == "nesy.Taint":
                taint_calls += 1
            elif c.owner in app_classes:
                app_calls += 1
    return app_calls, taint_calls


def _declared_in_app(owner: str, subsig: str, app_classes: Dict[str, object]) -> bool:
    """True if ``owner`` or one of its application superclasses declares ``subsig``."""
    seen = set()
    while owner and owner in app_classes and owner not in seen:
        seen.add(owner)
        ci = app_classes[owner]
        for m in ci.methods:
            try:
                if m.sig.subsig == subsig:
                    return True
            except ValueError:
                continue
        owner = ci.super_name
    return False


def entry_call_mismatches(classes_dir: Path, app_classes: Dict[str, object],
                          declared_entries: Sequence[str] = ()) -> List[str]:
    """V1 entry-call check on the *compiled* driver.

    A driver can compile and still call the wrong method: ``w.setUp(null, null, null)`` makes javac
    pick the most specific overload, which may be an inherited library method (e.g. Jenkins'
    deprecated ``BuildWrapper.setUp(Build,...)``) instead of the application's own
    ``setUp(AbstractBuild,...)``. With library bodies not analysed, the entry point is then never
    reached. We flag every call on an application class whose resolved signature is not declared by
    the application although the application declares a method of that name and arity. Entry points the model
    itself listed in its JSON entries but never calls are reported too."""
    p = Path(classes_dir) / "nesy" / "NesyDriver.class"
    if not p.exists():
        return []
    ci = parse_class(p.read_bytes(), str(p))
    out: List[str] = []
    for m in ci.methods:
        for c in m.calls:
            if c.owner not in app_classes or c.name in ("<init>", "<clinit>"):
                continue
            try:
                target = c.sig
            except ValueError:
                continue
            if _declared_in_app(c.owner, target.subsig, app_classes):
                continue
            cands = []
            owner = c.owner
            seen = set()
            while owner and owner in app_classes and owner not in seen:
                seen.add(owner)
                for am in app_classes[owner].methods:
                    try:
                        sig = am.sig
                    except ValueError:
                        continue
                    if am.name == c.name and len(sig.params) == len(target.params) and sig.taie not in cands:
                        cands.append(sig.taie)
                owner = app_classes[owner].super_name
            if not cands:
                continue
            first = parse_taie_signature(cands[0])
            hint = ", ".join(f"({java_source_type(t)}) null" for t in first.params) if first else ""
            out.append(f"line {c.line}: the call `{c.name}(...)` on {c.owner} compiles to the inherited library "
                       f"method <{target.subsig}>, not to the application method {cands[0]}. "
                       f"The entry point is therefore never analysed. Cast every null argument to the exact "
                       f"parameter type so javac selects the intended overload, e.g. {c.name}({hint}).")
    # declared but never called
    called = set()
    for m in ci.methods:
        for c in m.calls:
            try:
                called.add((c.owner, c.sig.subsig))
            except ValueError:
                continue

    def chain(o):
        seen = []
        while o and o in app_classes and o not in seen:
            seen.append(o)
            o = app_classes[o].super_name
        return seen
    flagged = {msg.split("`")[1].split("(")[0] for msg in out if "`" in msg}   # names with a wrong overload
    for e in declared_entries:
        es = e.strip() if e.strip().startswith("<") else f"<{e.strip()}>"
        ms = parse_taie_signature(es)
        if ms is None or ms.owner not in app_classes or not _declared_in_app(ms.owner, ms.subsig, app_classes):
            continue
        if ms.name in flagged:
            continue
        if any(sub == ms.subsig and ms.owner in chain(o) for o, sub in called):
            continue
        hint = ", ".join(f"({java_source_type(t)}) null" for t in ms.params)
        out.append(f"the entry point {ms.taie} listed in your JSON entries is never called. Call it on an "
                   f"object whose fields were set from nesy.Taint sources (pass null for framework objects, "
                   f"cast to the parameter type, e.g. {ms.name}({hint})).")
    return out


ENTRY_CHECK_VERSION = 2   # Cache version for overload, declared-entry and receiver-state checks.

_NEW_VAR = re.compile(r"([A-Za-z_$][\w.$]*)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+([A-Za-z_$][\w.$]*)\s*\(")
_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\(")
_TAINT = re.compile(r"\b(?:nesy\.)?Taint\.src\w*\s*\(")


def _paren_args(code: str, open_pos: int) -> str:
    """Text between the parenthesis at ``open_pos`` and its matching close (strings are skipped)."""
    depth, i, in_str = 0, open_pos, None
    while i < len(code):
        c = code[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == in_str:
                in_str = None
        elif c in "\"'":
            in_str = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return code[open_pos + 1:i]
        i += 1
    return code[open_pos + 1:]


def receiver_state_problems(code: str, declared_entries: Sequence[str], app_classes: Dict[str, object]) -> List[str]:
    """V1 receiver-state check on the driver *source*.

    An instance entry point that receives no tainted argument can only see attacker data through
    the state of its receiver (constructor arguments, setters). If the driver calls it on an object
    that was built with no ``Taint`` value and on which no method was ever called with a ``Taint``
    value, the call can never carry taint, e.g. ``w = new W(null, ...); w.setUp(null, null, null);``
    while the setters were called on *other* ``W`` objects. Such calls are reported."""
    code = re.sub(r"//[^\n]*", "", code)                      # comments mention method names too
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    var_type: Dict[str, str] = {}
    tainted: Dict[str, bool] = {}
    for m in _NEW_VAR.finditer(code):
        v, cls = m.group(2), m.group(3).replace("$", ".")
        var_type[v] = cls
        args = _paren_args(code, m.end() - 1)
        tainted[v] = tainted.get(v, False) or bool(_TAINT.search(args))
    calls = []
    for m in _CALL.finditer(code):
        v, name = m.group(1), m.group(2)
        if v not in var_type:
            continue
        args = _paren_args(code, m.end() - 1)
        has_taint = bool(_TAINT.search(args))
        calls.append((v, name, has_taint))
        if has_taint:
            tainted[v] = True
    # entries: dotted owner (source spelling of inner classes uses '.') -> instance method names
    entries: Dict[str, set] = {}
    setters: Dict[str, List[str]] = {}
    for e in declared_entries:
        es = e.strip() if e.strip().startswith("<") else f"<{e.strip()}>"
        ms = parse_taie_signature(es)
        if ms is None or ms.owner not in app_classes or ms.name in ("<init>", "<clinit>"):
            continue
        mi = next((x for x in app_classes[ms.owner].methods if x.name == ms.name), None)
        if mi is None or mi.is_static:
            continue
        key = ms.owner.replace("$", ".")
        entries.setdefault(key, set()).add(ms.name)
        setters[key] = sorted({x.name for x in app_classes[ms.owner].methods
                               if x.name.startswith("set") and not x.is_static})[:6]
    out: List[str] = []
    reported = set()
    for v, name, has_taint in calls:
        cls = var_type[v]
        if name not in entries.get(cls, ()) or has_taint or tainted.get(v):
            continue
        if any(v2 != v and var_type.get(v2) == cls and n2 == name and tainted.get(v2) for v2, n2, _ in calls):
            continue            # the same entry is also called on a receiver that does carry state
        # Only flag the split-state pattern: attacker data WAS put into other objects of this class,
        # just not into the one the entry runs on. (Calls with null framework arguments, e.g. a servlet
        # filter's doFilter(null, ...), can still reach sources in call-site mode and are not flagged.)
        others = sorted(v2 for v2, c2 in var_type.items() if v2 != v and c2 == cls and tainted.get(v2))
        if not others:
            continue
        if (cls, name) in reported:
            continue
        reported.add((cls, name))
        hint = ", ".join(f"{s}(nesy.Taint.src())" for s in setters.get(cls, [])[:3])
        out.append(f"`{v}.{name}(...)` runs on a {cls.rsplit('.', 1)[-1]} object that never receives attacker "
                   f"data: its constructor got no Taint value and no Taint value was passed to a method of "
                   f"`{v}`. The Taint values went to other objects ({', '.join(others[:4])}), which {name} never "
                   f"sees. Configure the SAME object first"
                   + (f", e.g. {v}.{hint}, then call {v}.{name}(...) in the same try block." if hint else
                      ", e.g. pass nesy.Taint.src() to its constructor, then call the entry on it."))
    return out


def write_sources(src_dir: Path, driver_code: str) -> Path:
    (src_dir / "nesy").mkdir(parents=True, exist_ok=True)
    (src_dir / "nesy" / "Taint.java").write_text(TAINT_JAVA)
    path = src_dir / "nesy" / "NesyDriver.java"
    path.write_text(driver_code)
    return path


def build_template_driver(facts: ProgramFacts, work: Path, classpath: Sequence[Path], javac: str,
                          max_entries: int, release: int = 8, max_rounds: int = 10) -> DriverResult:
    """Template driver with deterministic repair: drop the call blocks javac rejects."""
    code, entries = make_template_driver(facts, max_entries)
    src_dir, out_dir = work / "src", work / "classes"
    removed: List[str] = []
    errors: List[str] = []
    ok = False
    attempts = 0
    for attempts in range(1, max_rounds + 1):
        write_sources(src_dir, code)
        ok, out = compile_driver(src_dir, out_dir, classpath, javac, release)
        if ok:
            break
        errors.append(out[-4000:])
        bad = set(error_lines(out))
        if not bad:
            break
        lines = code.splitlines()
        keep = []
        for i, line in enumerate(lines, start=1):
            if i in bad and "// ENTRY " in line:
                tag = line.split("// ENTRY ", 1)[1]
                if not tag.startswith("RECEIVER "):
                    removed.append(tag)
                continue
            keep.append(line)
        if len(keep) == len(lines):
            break
        code = "\n".join(keep) + "\n"
    entries = [e for e in entries if e not in removed]
    app_calls, taint_calls = static_check(out_dir, set(facts.app_classes)) if ok else (0, 0)
    res = DriverResult("template", ok, str(out_dir), str(src_dir / "nesy" / "NesyDriver.java"), entries,
                       attempts, errors, removed, app_calls, taint_calls)
    res.save(work / "driver.json")
    return res


# ----------------------------------------------------------------- N1: LLM driver

def _candidate_lines(facts: ProgramFacts, limit: int) -> str:
    rows = []
    for e in [e for e in facts.entries if _accessible(e)][:limit]:
        ctors = "; ".join("(" + ", ".join(c) + ")" for c in e.constructors[:3]) or "-"
        tag = "static" if e.is_static else "instance"
        rows.append(f"- {e.signature} | {e.kind}, {tag} | ctors: {ctors}")
    return "\n".join(rows) or "- (none found)"


def _readme(project_dir: Optional[Path], max_lines: int = 60) -> str:
    if not project_dir:
        return "(no README)"
    for name in ("README.md", "README.markdown", "README.adoc", "README.txt", "README"):
        p = Path(project_dir) / name
        if p.exists():
            lines = p.read_text(errors="replace").splitlines()[:max_lines]
            return "\n".join(lines)
    return "(no README)"


def build_llm_driver(facts: ProgramFacts, llm: BaseLLM, work: Path, classpath: Sequence[Path], javac: str,
                     cwe: dict, cwe_id: str, project: str, project_dir: Optional[Path], cfg: dict,
                     release: int = 8) -> DriverResult:
    src_dir, out_dir = work / "src", work / "classes"
    values = {
        "cwe_id": cwe_id, "cwe_name": cwe.get("name", ""), "cwe_description": cwe.get("description", ""),
        "project": project, "readme": _readme(project_dir),
        "candidates": _candidate_lines(facts, int(cfg.get("max_entries_prompt", 60))),
        "taint_api": TAINT_API_DOC, "max_calls": int(cfg.get("max_calls", 40)),
    }
    msgs = build_messages("n1_driver", values)
    offset = int(cfg.get("sample_offset", 0))
    max_tokens = int(cfg.get("max_tokens", 8192))
    resp = llm.chat(msgs, stage="N1-driver", temperature=float(cfg.get("temperature", 0.0)),
                    max_tokens=max_tokens, sample=offset)
    errors: List[str] = []
    if resp.finish_reason == "length" and not extract_code_block(resp.text, "java"):
        # Retry a truncated answer without a Java block with a larger token budget.
        # Ask once more with a larger budget instead of falling back to the template driver.
        # Only cut-off answers are retried, so cached answers of successful runs are unaffected.
        errors.append(f"N1: answer cut off at max_tokens={max_tokens}; retried with {2 * max_tokens}")
        resp = llm.chat(msgs, stage="N1-driver", temperature=float(cfg.get("temperature", 0.0)),
                        max_tokens=2 * max_tokens, sample=offset)
    llm_entries: List[dict] = []
    try:
        j = extract_json(resp.text)
        if isinstance(j, dict):
            llm_entries = [e for e in j.get("entries", []) if isinstance(e, dict)]
    except ValueError:
        errors.append("N1: no JSON entry list in answer")
    code = extract_code_block(resp.text, "java")
    attempts = 0
    ok = False
    entry_mismatches: List[str] = []
    max_repairs = int(cfg.get("max_repairs", 3))
    if code:
        for attempts in range(1, max_repairs + 2):
            code = _normalise_driver_code(code)
            write_sources(src_dir, code)
            ok, out = compile_driver(src_dir, out_dir, classpath, javac, release)
            if ok:
                app_calls, taint_calls = static_check(out_dir, set(facts.app_classes))
                if app_calls > 0 and taint_calls > 0:
                    if not cfg.get("entry_check"):
                        break
                    declared = [str(e.get("signature", "")) for e in llm_entries]
                    mismatches = entry_call_mismatches(out_dir, facts.app_classes, declared) + \
                        receiver_state_problems(code, declared, facts.app_classes)
                    if not mismatches:
                        break
                    if attempts > max_repairs:
                        # keep the compiled driver; the remaining mismatches are recorded (not hidden)
                        entry_mismatches = mismatches
                        break
                    ok = False
                    out = "Entry-call check failed (the code compiles but calls the wrong methods):\n" + \
                        "\n".join(mismatches)
                else:
                    ok = False
                    out = (f"Static check failed: the driver makes {app_calls} calls into application classes "
                           f"and {taint_calls} calls to nesy.Taint; both must be > 0.")
            errors.append(out[-4000:])
            if attempts > max_repairs:
                break
            rmsgs = build_messages("n1_repair", {"errors": out[-6000:], "code": code})
            r2 = llm.chat(rmsgs, stage="N1-repair", temperature=0.0, max_tokens=max_tokens,
                          sample=offset + attempts)
            if r2.finish_reason == "length" and not extract_code_block(r2.text, "java"):
                errors.append(f"N1-repair: answer cut off at max_tokens={max_tokens}; retried with {2 * max_tokens}")
                r2 = llm.chat(rmsgs, stage="N1-repair", temperature=0.0, max_tokens=2 * max_tokens,
                              sample=offset + attempts)
            new_code = extract_code_block(r2.text, "java")
            if not new_code:
                errors.append("repair answer had no java block")
                break
            code = new_code
    else:
        errors.append("N1: no java block in answer")

    if ok:
        app_calls, taint_calls = static_check(out_dir, set(facts.app_classes))
        entries = [e.get("signature", "") for e in llm_entries]
        res = DriverResult("llm", True, str(out_dir), str(src_dir / "nesy" / "NesyDriver.java"), entries,
                           attempts, errors, [], app_calls, taint_calls, llm_entries, prompt_version("n1_driver"),
                           entry_mismatches, ENTRY_CHECK_VERSION if cfg.get("entry_check") else 0)
    else:
        # fall back to the symbolic template so the configuration still runs; recorded in results
        fb = build_template_driver(facts, work / "fallback", classpath, javac,
                                   int(cfg.get("max_entries_template", 300)), release)
        res = DriverResult("llm-fallback-template", fb.ok, fb.classes_dir, fb.source_path, fb.entries,
                           attempts, errors, fb.removed_entries, fb.app_calls, fb.taint_calls, llm_entries,
                           prompt_version("n1_driver"))
    res.save(work / "driver.json")
    return res


def _normalise_driver_code(code: str) -> str:
    """Force the expected package/class names; models sometimes drop the package line."""
    if not re.search(r"^\s*package\s+nesy\s*;", code, re.M):
        code = "package nesy;\n\n" + code
    code = re.sub(r"public\s+class\s+\w+", "public class NesyDriver", code, count=1)
    return code


def entry_signature_ok(sig: str, facts: ProgramFacts) -> bool:
    ms = parse_taie_signature(sig)
    return bool(ms) and ms.taie in facts.method_index()
