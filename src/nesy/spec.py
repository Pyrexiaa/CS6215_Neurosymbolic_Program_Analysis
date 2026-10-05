"""Taint specifications: base config assembly, N2 inference, V2 validation and voting."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml

from .config import REPO_ROOT
from .facts import ExternalApi, ProgramFacts
from .jvm import MethodSig, PRIMITIVE_NAMES, is_jdk_class, normalize_taie_signature, parse_taie_signature
from .llm import BaseLLM, extract_json
from .prompts import build_messages, prompt_version

COMMON_DIR = REPO_ROOT / "config" / "taint" / "commonly-used"
MANUAL_DIR = REPO_ROOT / "config" / "taint" / "manual"
ROLES = ("source", "sink", "transfer", "sanitizer")
# Bump when aggregation semantics change, so stored specs are re-derived from LLM cache.
SPEC_VOTE_VERSION = 2
_INDEX = re.compile(r"^(result|base|\d+)(\[\*\]|\.[A-Za-z_$][\w$]*)?$")


# ----------------------------------------------------------------- base config (B1)

def base_config_files(cwe_cfg: dict, cwe_id: str) -> List[Path]:
    """YAML files of Tai-e's commonly-used config selected for ``cwe_id`` (see config/cwe.yaml)."""
    common = cwe_cfg.get("common", {})
    entry = (cwe_cfg.get("cwes") or {}).get(cwe_id)
    if entry is None:
        raise KeyError(f"{cwe_id} not configured in config/cwe.yaml")
    rels = list(common.get("sources", [])) + list(entry.get("sinks", [])) + list(common.get("transfers", []))
    files: List[Path] = []
    for rel in rels:
        p = COMMON_DIR / rel
        if p.is_dir():
            files += sorted(p.rglob("*.yml"))
        elif p.exists():
            files.append(p)
        else:
            raise FileNotFoundError(f"commonly-used config path not found: {p}")
    return files


def assemble_config(out_dir: Path, layers: Dict[str, Sequence[Path]], extra_yaml: Dict[str, str],
                    exclude_lines: Sequence[str] = ()) -> Path:
    """Write a Tai-e taint-config *directory* (Tai-e loads every YAML file below it).

    Lines containing any string in ``exclude_lines`` are dropped while copying (used to
    remove known-harmful entries from the commonly-used config, see config/cwe.yaml)."""
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    for layer, files in layers.items():
        for i, f in enumerate(files):
            dst = out_dir / layer / f"{i:03d}_{Path(f).name}"
            dst.parent.mkdir(parents=True, exist_ok=True)
            text = Path(f).read_text()
            if exclude_lines:
                text = "\n".join(l for l in text.splitlines() if not any(x in l for x in exclude_lines)) + "\n"
            dst.write_text(text)
    for name, text in extra_yaml.items():
        (out_dir / name).write_text(text)
    return out_dir


def signatures_in_config(files: Iterable[Path]) -> Dict[str, Set[str]]:
    """role -> method signatures present in YAML files (used to skip already-known APIs)."""
    out: Dict[str, Set[str]] = defaultdict(set)
    for f in files:
        try:
            d = yaml.safe_load(Path(f).read_text()) or {}
        except yaml.YAMLError:
            continue
        for key, role in (("sources", "source"), ("source", "source"), ("sinks", "sink"),
                          ("transfers", "transfer"), ("transfer", "transfer"), ("sanitizers", "sanitizer")):
            for e in d.get(key) or []:
                if isinstance(e, dict) and e.get("method"):
                    norm = normalize_taie_signature(str(e["method"]))
                    out[role].add(norm or str(e["method"]))
    return out


def known_entries(files: Iterable[Path]) -> Dict[str, List[str]]:
    """signature -> human-readable roles already configured, e.g. ['sink[0]', 'transfer[0->base]']."""
    out: Dict[str, List[str]] = defaultdict(list)
    for f in files:
        try:
            d = yaml.safe_load(Path(f).read_text()) or {}
        except yaml.YAMLError:
            continue
        for key, role in (("sources", "source"), ("source", "source"), ("sinks", "sink"),
                          ("transfers", "transfer"), ("transfer", "transfer"), ("sanitizers", "sanitizer")):
            for e in d.get(key) or []:
                if isinstance(e, dict) and e.get("method"):
                    sig = normalize_taie_signature(str(e["method"])) or str(e["method"])
                    if role == "transfer":
                        tag = f"transfer[{e.get('from')}->{e.get('to')}]"
                    else:
                        tag = f"{role}[{e.get('index')}]"
                    if tag not in out[sig]:
                        out[sig].append(tag)
    return out


def chain_transfers_yaml(files: Iterable[Path]) -> str:
    """Transfers needed when Tai-e does not analyse library bodies (`only-app`): StringBuilder and
    StringBuffer append/insert return the receiver, so taint must also reach the call's result."""
    sigs = set()
    for f in files:
        for m in re.finditer(r'"(<java\.lang\.(StringBuilder|StringBuffer): java\.lang\.\2 '
                             r'(append|insert|appendCodePoint)\([^)]*\)>)"', Path(f).read_text()):
            sigs.add((m.group(1), m.group(3)))
    lines = ["# Generated for only-app mode: append/insert return `this`.", "transfers:"]
    for sig, name in sorted(sigs):
        arg = 1 if name == "insert" else 0
        lines.append(f'  - {{ method: "{sig}", from: base, to: result }}')
        if not sig.endswith("()>"):
            lines.append(f'  - {{ method: "{sig}", from: {arg}, to: result }}')
    return "\n".join(lines) + "\n"


def manual_config_file(subject_id: str) -> Optional[Path]:
    p = MANUAL_DIR / f"{subject_id}.yml"
    return p if p.exists() else None


# ----------------------------------------------------------------- V2 helpers

class JdkMethodOracle:
    """Answers 'does this JDK method exist?' via the class index (rt.jar) or ``javap`` as fallback."""

    def __init__(self, facts: ProgramFacts, javap: Optional[str] = None):
        self.facts = facts
        self.javap = javap or shutil.which("javap")
        self._javap_cache: Dict[str, Optional[Set[str]]] = {}

    def exists(self, sig: MethodSig) -> Optional[bool]:
        """True/False when known, None when it cannot be decided (class not available)."""
        if sig.owner in self.facts.index:
            return self.facts.index.find_by_signature(sig) is not None
        if is_jdk_class(sig.owner) and self.javap:
            subs = self._javap_subsigs(sig.owner)
            if subs is not None:
                return sig.subsig in subs
        return None

    def _javap_subsigs(self, owner: str) -> Optional[Set[str]]:
        if owner in self._javap_cache:
            return self._javap_cache[owner]
        env = dict(os.environ)
        env.pop("JAVA_TOOL_OPTIONS", None)
        try:
            out = subprocess.run([self.javap, "-p", "-s", owner], capture_output=True, text=True, timeout=60,
                                 env=env).stdout
        except Exception:
            self._javap_cache[owner] = None
            return None
        subs: Set[str] = set()
        lines = out.splitlines()
        for i, line in enumerate(lines):
            m = re.search(r"\s([\w$<>]+)\(", line)
            if m and i + 1 < len(lines) and "descriptor:" in lines[i + 1]:
                desc = lines[i + 1].split("descriptor:", 1)[1].strip()
                name = m.group(1)
                if name == owner.split(".")[-1] or name == owner:
                    name = "<init>"
                try:
                    subs.add(MethodSig.from_descriptor(owner.replace(".", "/"), name, desc).subsig)
                except ValueError:
                    continue
        self._javap_cache[owner] = subs or None
        return self._javap_cache[owner]


def _index_type(sig: MethodSig, index: str, is_static: bool) -> Tuple[Optional[str], str]:
    """Type referred to by an index ref, or (None, reason) if the ref is invalid."""
    m = _INDEX.match(index)
    if not m:
        return None, "bad-index-format"
    base, ref = m.group(1), m.group(2) or ""
    if base == "result":
        if sig.ret == "void":
            return None, "result-of-void"
        t = sig.ret
    elif base == "base":
        if is_static:
            return None, "base-of-static"
        t = sig.owner
    else:
        i = int(base)
        if i >= len(sig.params):
            return None, "arg-out-of-range"
        t = sig.params[i]
    if ref == "[*]":
        if not t.endswith("[]"):
            return None, "array-ref-on-non-array"
        t = t[:-2]
    elif ref.startswith("."):
        t = "java.lang.Object"   # field refs: type not checked
    return t, ""


def validate_label(label: dict, sig: MethodSig, is_static: bool) -> Tuple[Optional[dict], str]:
    """V2 per-label check. Returns (Tai-e YAML entry, '') or (None, rejection reason)."""
    role = str(label.get("role", "")).strip().lower()
    if role == "none":
        return None, "none"
    if role not in ROLES:
        return None, "bad-role"
    if role == "transfer":
        frm, to = str(label.get("from", "")).strip(), str(label.get("to", "")).strip()
        tf, why = _index_type(sig, frm, is_static)
        if tf is None:
            return None, f"from:{why}"
        tt, why = _index_type(sig, to, is_static)
        if tt is None:
            return None, f"to:{why}"
        if frm == to:
            return None, "transfer-to-self"
        if tt in PRIMITIVE_NAMES:
            return None, "transfer-to-primitive"
        return {"method": sig.taie, "from": _yaml_index(frm), "to": _yaml_index(to)}, ""
    index = str(label.get("index", "")).strip()
    t, why = _index_type(sig, index, is_static)
    if t is None:
        return None, why
    if t in PRIMITIVE_NAMES:
        return None, "primitive-type"
    if role == "source":
        if index == "base" and sig.is_constructor:
            pass
        return {"kind": "call", "method": sig.taie, "index": _yaml_index(index)}, ""
    if role == "sink":
        return {"method": sig.taie, "index": _yaml_index(index)}, ""
    # sanitizer: Tai-e supports plain parameter indexes only
    if not index.isdigit():
        return None, "sanitizer-needs-arg-index"
    return {"kind": "param", "method": sig.taie, "index": int(index)}, ""


def _yaml_index(index: str):
    return int(index) if index.isdigit() else index


def unchecked_label(label: dict, sig: MethodSig) -> Optional[dict]:
    """Used when validators are disabled (ablation): only the shape is enforced."""
    role = str(label.get("role", "")).strip().lower()
    if role == "transfer":
        return {"method": sig.taie, "from": _yaml_index(str(label.get("from", "0"))),
                "to": _yaml_index(str(label.get("to", "result")))}
    if role == "source":
        return {"kind": "call", "method": sig.taie, "index": _yaml_index(str(label.get("index", "result")))}
    if role == "sink":
        return {"method": sig.taie, "index": _yaml_index(str(label.get("index", "0")))}
    if role == "sanitizer":
        idx = str(label.get("index", "0"))
        return {"kind": "param", "method": sig.taie, "index": int(idx) if idx.isdigit() else 0}
    return None


# ----------------------------------------------------------------- N2

@dataclass
class SpecResult:
    yaml_text: str
    stats: dict
    accepted: List[dict] = field(default_factory=list)
    rejected: List[dict] = field(default_factory=list)
    votes: Dict[str, List[str]] = field(default_factory=dict)
    prompt_version: str = ""

    def save(self, work: Path) -> None:
        work.mkdir(parents=True, exist_ok=True)
        (work / "inferred.yml").write_text(self.yaml_text)
        (work / "spec.json").write_text(json.dumps(asdict(self), indent=2))


def select_candidates(facts: ProgramFacts, known: Dict[str, Set[str]], include_jdk: bool,
                      reachable_methods: Optional[Set[str]] = None) -> List[ExternalApi]:
    """External APIs to label. APIs already configured as sources/transfers/sanitizers are
    skipped; APIs already configured as sinks are kept (the LLM sees which argument is
    configured and may add others, e.g. the child argument of ``File(File,String)``)."""
    skip = set()
    for role in ("source", "transfer", "sanitizer"):
        skip |= set(known.get(role, set()))
    skip -= set(known.get("sink", set()))
    out = []
    for api in facts.external_apis.values():
        if api.signature in skip:
            continue
        if api.from_jdk and not include_jdk:
            continue
        if api.owner in ("java.lang.Object", "java.lang.Enum", "java.lang.Throwable", "java.lang.Exception",
                         "java.lang.RuntimeException", "java.lang.Integer", "java.lang.Boolean", "java.lang.Long"):
            continue
        if reachable_methods is not None and not any(cs.caller in reachable_methods for cs in api.call_sites):
            continue
        out.append(api)
    out.sort(key=lambda a: (a.from_jdk, a.signature))
    return out


def _api_line(i: int, api: ExternalApi, facts: ProgramFacts, max_sites: int,
              known_tags: Optional[Dict[str, List[str]]] = None) -> str:
    sites = []
    for cs in api.call_sites[:max_sites]:
        caller = parse_taie_signature(cs.caller)
        text = ""
        if caller:
            ci = facts.app_classes.get(caller.owner)
            path = facts.sources.file_for_class(caller.owner, ci.source_file if ci else None)
            if path and cs.line > 0:
                lines = facts.sources.lines(path)
                if cs.line <= len(lines):
                    text = lines[cs.line - 1].strip()[:140]
            where = f"{caller.owner.rsplit('.', 1)[-1]}.{caller.name}:L{cs.line}"   # Outer$Inner.m
        else:
            where = f"?:L{cs.line}"
        sites.append(f"{where} `{text}`" if text else where)
    lib = "JDK" if api.from_jdk else api.origin
    tags = (known_tags or {}).get(api.signature)
    if tags:
        lib += " (already configured: " + ", ".join(tags) + ")"
    return f"{i} | {api.signature} | {_index_slots(api)} | {lib} | " + ("; ".join(sites) or "-")


def _index_slots(api: ExternalApi) -> str:
    """Spell out the index references the model may use for this method:
    arguments are 0-based and exclude the receiver, which is 'base'."""
    short = lambda t: t.rsplit(".", 1)[-1]
    parts = [f"{k}={short(t)}" for k, t in enumerate(api.params)]
    if api.name == "<init>":
        parts.append("base=new object")
    elif not api.is_static:
        parts.append("base=receiver")
    if api.ret not in ("void", "") and api.ret not in PRIMITIVE_NAMES and api.name != "<init>":
        parts.append(f"result={short(api.ret)}")
    return "idx: " + (", ".join(parts) if parts else "-")


def infer_spec(facts: ProgramFacts, llm: BaseLLM, cwe: dict, cwe_id: str, project: str, cfg: dict,
               known: Dict[str, Set[str]], validators: bool = True,
               reachable_methods: Optional[Set[str]] = None, javap: Optional[str] = None,
               known_tags: Optional[Dict[str, List[str]]] = None) -> SpecResult:
    cands = select_candidates(facts, known, bool(cfg.get("include_jdk_apis", True)), reachable_methods)
    batch_size = int(cfg.get("batch_size", 25))
    samples = max(1, int(cfg.get("samples", 3)))
    offset = int(cfg.get("sample_offset", 0))     # run-indexed samples; hosted responses are not guaranteed independent
    t0, t1 = float(cfg.get("temperature", 0.0)), float(cfg.get("sample_temperature", 0.7))
    max_sites = int(cfg.get("max_call_sites_per_api", 2))
    oracle = JdkMethodOracle(facts, javap)

    # Each sample is one replicate across all API batches. A repeated label in one
    # answer, or an extra signature repeated in another batch of the same replicate,
    # must not count as an independent vote. Several distinct labels remain allowed.
    sample_votes: Dict[str, Dict[int, Set[str]]] = defaultdict(lambda: defaultdict(set))
    label_of: Dict[Tuple[str, str], dict] = {}
    statics: Dict[str, bool] = {}
    rejected: List[dict] = []
    parse_failures = 0
    extra_seen: Set[str] = set()

    for b in range(0, len(cands), batch_size):
        batch = cands[b:b + batch_size]
        lines = [_api_line(i, a, facts, max_sites, known_tags) for i, a in enumerate(batch)]
        values = {"cwe_id": cwe_id, "cwe_name": cwe.get("name", ""), "cwe_description": cwe.get("description", ""),
                  "project": project, "apis": "\n".join(lines)}
        msgs = build_messages("n2_spec", values)
        for s in range(samples):
            resp = llm.chat(msgs, stage="N2-spec", temperature=t0 if s == 0 else t1,
                            max_tokens=int(cfg.get("max_tokens", 8192)), sample=offset + s)
            try:
                data = extract_json(resp.text)
            except ValueError:
                data = []
                parse_failures += 1
            if isinstance(data, dict):
                data = data.get("labels") or data.get("entries") or [data]
            for lab in data if isinstance(data, list) else []:
                if not isinstance(lab, dict):
                    continue
                sig, is_static, origin = _resolve_label_target(lab, batch, facts, oracle, validators)
                if sig is None:
                    rejected.append({"label": lab, "reason": origin, "sample": s})
                    continue
                statics[sig.taie] = is_static
                if validators:
                    entry, why = validate_label(lab, sig, is_static)
                else:
                    entry = unchecked_label(lab, sig)
                    # without V2 the only drop is role "none"/unknown; do not count "none" as a rejection
                    is_none = str(lab.get("role", "")).strip().lower() == "none"
                    why = "none" if is_none else ("" if entry is not None else "bad-role")
                if entry is None:
                    if why != "none":
                        rejected.append({"signature": sig.taie, "label": lab, "reason": why, "sample": s})
                    continue
                role = str(lab.get("role")).lower()
                norm = role + ":" + json.dumps(entry, sort_keys=True)
                label_of[(sig.taie, norm)] = {"role": role, "entry": entry, "why": lab.get("why", "")}
                sample_votes[sig.taie][s].add(norm)
                if origin == "extra":
                    extra_seen.add(sig.taie)
            for a in batch:
                sample_votes[a.signature][s]  # retain omitted/invalid labels as no votes

    votes = {sig: [label for s in range(samples)
                   for label in (sorted(by_sample.get(s, set())) or ["none"])]
             for sig, by_sample in sample_votes.items()}
    accepted: List[dict] = []
    agree = []
    for sig, vs in votes.items():
        # one signature may legitimately have several labels (e.g. sink on arg 0 and arg 1):
        # accept every label that appears in a strict majority of samples
        counts = Counter(v for v in vs if v != "none")
        n = samples
        for norm, c in counts.items():
            if c * 2 > n or n == 1:
                lab = label_of[(sig, norm)]
                accepted.append({"signature": sig, **lab, "votes": c, "samples": n})
        top = Counter(vs).most_common(1)[0][1] if vs else 0
        agree.append(top / samples)

    yaml_text = to_taie_yaml(accepted)
    stats = {
        "candidates": len(cands), "batches": (len(cands) + batch_size - 1) // batch_size if cands else 0,
        "samples": samples, "accepted": len(accepted),
        "accepted_by_role": dict(Counter(a["role"] for a in accepted)),
        "rejected": len(rejected), "rejected_by_reason": dict(Counter(r["reason"] for r in rejected)),
        "extra_signatures": len(extra_seen), "parse_failures": parse_failures,
        "mean_vote_agreement": round(sum(agree) / len(agree), 3) if agree else None,
        "validators": validators, "vote_version": SPEC_VOTE_VERSION,
    }
    return SpecResult(yaml_text, stats, accepted, rejected, {k: v for k, v in votes.items()},
                      prompt_version("n2_spec"))


def _resolve_label_target(lab: dict, batch: List[ExternalApi], facts: ProgramFacts, oracle: JdkMethodOracle,
                          validators: bool) -> Tuple[Optional[MethodSig], bool, str]:
    """Map a label to a method: by batch id (grounded), or by an explicit extra signature (checked by V2)."""
    if "id" in lab and str(lab["id"]).strip().lstrip("-").isdigit():
        i = int(lab["id"])
        if 0 <= i < len(batch):
            api = batch[i]
            return MethodSig(api.owner, api.name, tuple(api.params), api.ret), api.is_static, "id"
        return None, False, "unknown-id"
    sig_s = lab.get("signature")
    if not sig_s:
        return None, False, "no-target"
    ms = parse_taie_signature(str(sig_s))
    if ms is None:
        return None, False, "malformed-signature"
    if ms.owner in facts.app_classes:
        return None, False, "application-method"
    if validators:
        ex = oracle.exists(ms)
        if ex is False:
            return None, False, "signature-not-found"
        if ex is None:
            return None, False, "signature-unverifiable"
    mi = facts.index.find_by_signature(ms)
    return ms, bool(mi.is_static) if mi else False, "extra"


def array_element_sinks(accepted: List[dict]) -> List[dict]:
    """Symbolic V2 completion rule: for every accepted sink on an *array*
    argument N, also add a sink on its elements ``N[*]``. Tai-e treats ``index: N`` as the array
    object only, so a command array built as ``{"bash", "-c", tainted}`` never fires."""
    have = {(a["entry"]["method"], str(a["entry"].get("index"))) for a in accepted if a["role"] == "sink"}
    out: List[dict] = []
    for a in accepted:
        if a["role"] != "sink":
            continue
        idx = a["entry"].get("index")
        if not isinstance(idx, int):
            continue
        ms = parse_taie_signature(a["entry"]["method"])
        if ms is None or idx >= len(ms.params) or not ms.params[idx].endswith("[]"):
            continue
        key = (a["entry"]["method"], f"{idx}[*]")
        if key in have:
            continue
        have.add(key)
        out.append({"signature": a["signature"], "role": "sink", "why": "array-element rule",
                    "entry": {"method": a["entry"]["method"], "index": f"{idx}[*]"}})
    return out


def to_taie_yaml(accepted: List[dict]) -> str:
    groups = {"sources": [], "sinks": [], "transfers": [], "sanitizers": []}
    key = {"source": "sources", "sink": "sinks", "transfer": "transfers", "sanitizer": "sanitizers"}
    for a in accepted:
        groups[key[a["role"]]].append(a["entry"])
    lines = ["# Generated by N2 (LLM taint-spec inference) after V2 validation and voting."]
    for g, entries in groups.items():
        if not entries:
            continue
        lines.append(f"{g}:")
        seen = set()
        for e in entries:
            s = _flow_map(e)
            if s not in seen:
                seen.add(s)
                lines.append(f"  - {s}")
    return "\n".join(lines) + "\n"


def _flow_map(e: dict) -> str:
    parts = []
    for k in ("kind", "method", "index", "from", "to"):
        if k in e:
            v = e[k]
            if isinstance(v, int):
                parts.append(f"{k}: {v}")
            else:
                parts.append(f'{k}: "{v}"')
    return "{ " + ", ".join(parts) + " }"


# ----------------------------------------------------------------- B2 manual spec checker

def check_manual_spec(path: Path, facts: ProgramFacts, oracle: Optional[JdkMethodOracle] = None) -> Tuple[int, List[str]]:
    """Syntax check of a hand-written Tai-e taint config (B2). Checks only *form* (YAML keys,
    signature format, method exists, index refs valid for the signature), never whether an
    entry is a good choice. Returns (number of entries, problems)."""
    oracle = oracle or JdkMethodOracle(facts)
    try:
        d = yaml.safe_load(Path(path).read_text()) or {}
    except yaml.YAMLError as e:
        return 0, [f"YAML syntax error: {e}"]
    if not isinstance(d, dict):
        return 0, ["top level must be a mapping with sources/sinks/transfers/sanitizers"]
    problems: List[str] = []
    allowed = {"sources", "sinks", "transfers", "sanitizers", "call-site-mode"}
    for k in d:
        if k not in allowed:
            problems.append(f"unknown top-level key '{k}' (expected one of {sorted(allowed)})")
    n = 0
    for key in ("sources", "sinks", "transfers", "sanitizers"):
        entries = d.get(key) or []
        if not isinstance(entries, list):
            problems.append(f"{key}: must be a list")
            continue
        for i, e in enumerate(entries):
            n += 1
            where = f"{key}[{i}]"
            if not isinstance(e, dict) or not e.get("method"):
                problems.append(f"{where}: needs a 'method' field")
                continue
            sig = parse_taie_signature(str(e["method"]))
            if sig is None:
                problems.append(f"{where}: malformed signature {e['method']!r} "
                                "(format <pkg.Cls: retType name(argType1,argType2)>, no spaces after commas)")
                continue
            if ", " in str(e["method"]) or sig.taie != str(e["method"]).strip():
                problems.append(f"{where}: write the signature exactly as {sig.taie!r} (Tai-e matches it literally)")
            where = f"{where} {sig.taie}"
            exists = oracle.exists(sig)
            if exists is False:
                problems.append(f"{where}: method not found in the program, its libraries or the JDK")
            elif exists is None:
                problems.append(f"{where}: class not on the analysed class path (cannot verify; Tai-e will ignore it)")
            mi = facts.index.find_by_signature(sig) if sig.owner in facts.index else None
            is_static = bool(mi.is_static) if mi else False
            refs = [("from", e.get("from")), ("to", e.get("to"))] if key == "transfers" else [("index", e.get("index"))]
            for name, ref in refs:
                if ref is None:
                    problems.append(f"{where}: missing '{name}'")
                    continue
                t, why = _index_type(sig, str(ref).strip(), is_static)
                if t is None:
                    problems.append(f"{where}: {name}={ref!r} invalid ({why})")
            kind = e.get("kind")
            if key == "sources" and kind not in ("call", "param", "field"):
                problems.append(f"{where}: sources need kind: call | param")
            if key == "sanitizers" and (kind != "param" or not str(e.get("index", "")).isdigit()):
                problems.append(f"{where}: sanitizers need kind: param and a plain argument number")
            if key == "sources" and kind == "param" and not str(e.get("index", "")).isdigit():
                problems.append(f"{where}: param sources need a plain argument number")
            if key in ("sinks", "transfers") and kind is not None:
                problems.append(f"{where}: '{key}' entries take no 'kind'")
    return n, problems


def invalid_spec_entries(path: Path, facts: ProgramFacts) -> List[str]:
    """Entries of a generated taint config whose index refs do not fit the method (what V2 rejects:
    base of a static method, argument out of range, result of void, ...). Used to explain Tai-e
    crashes in the validator-off ablations."""
    _, problems = check_manual_spec(path, facts)
    return [p for p in problems if " invalid (" in p or "malformed" in p]
