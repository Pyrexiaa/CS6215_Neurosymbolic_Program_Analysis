"""N3 - evidence-grounded triage of Tai-e flows, and V3 - shown-evidence check.

The LLM sees the flow, a bounded shortest TFG route when available, and numbered
application-code snippets. When library gaps prevent a complete route, evidence
falls back to methods reachable from the source or reaching the sink; endpoints
and source context can also be shown. V3 requires a removal verdict to cite only
shown lines. This establishes evidence membership, not route feasibility or the
correctness of the removal. A rejected verdict keeps the flow.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .facts import ProgramFacts
from .jvm import normalize_taie_signature, parse_taie_signature
from .llm import BaseLLM, extract_json
from .prompts import build_messages, prompt_version
from .taie import TaintFlow, TaintFlowGraph, node_method

VERDICTS = ("vulnerable", "not_vulnerable", "uncertain")


@dataclass
class Evidence:
    methods: List[str]
    path_text: str
    snippets_text: str
    # file (relative to a source root) -> list of (first_line, last_line) shown
    shown: Dict[str, List[Tuple[int, int]]] = field(default_factory=dict)


@dataclass
class TriageDecision:
    flow_id: str
    flow_key: str
    verdict: str                 # final verdict after voting
    reason: str
    kept: bool                   # whether the flow stays in the report
    v3_ok: Optional[bool]        # None when V3 disabled or not applicable
    v3_problems: List[str] = field(default_factory=list)
    evidence: List[dict] = field(default_factory=list)
    explanation: str = ""
    samples: List[str] = field(default_factory=list)
    methods_shown: List[str] = field(default_factory=list)
    override: str = ""           # set when a symbolic rule overruled the LLM verdict


def build_evidence(flow: TaintFlow, tfg: TaintFlowGraph, facts: ProgramFacts, max_methods: int = 6,
                   max_lines: int = 60) -> Evidence:
    path = tfg.path(flow)
    methods: List[str] = []
    if path:
        for n in path:
            m = node_method(n)
            if m and m not in methods:
                methods.append(m)
    else:
        methods = tfg.methods_between(flow)
    for m in (flow.source.method, flow.sink.method):
        if m not in methods:
            methods.insert(0 if m == flow.source.method else len(methods), m)
    # keep application methods only (driver and library code have no useful source here)
    mindex = facts.method_index()
    app_methods = [m for m in methods if m in mindex]
    # prefer the sink method and its neighbours when we must cut
    if len(app_methods) > max_methods:
        sink_m = flow.sink.method
        keep = [m for m in app_methods if m == sink_m]
        others = [m for m in app_methods if m != sink_m]
        app_methods = others[:max_methods - len(keep)] + keep

    if path:
        steps = []
        for i, n in enumerate(path, 1):
            label = n.split("\n")[-1]
            steps.append(f"{i}. {label[:300]}")
        path_text = "\n".join(steps)
    else:
        path_text = "(no complete application-code path in the taint flow graph; the flow passes through " \
                    "library code). Methods involved: " + ", ".join(app_methods or methods)

    blocks = []
    shown: Dict[str, List[Tuple[int, int]]] = {}
    for m in app_methods:
        mi = mindex[m]
        ms = parse_taie_signature(m)
        ci = facts.app_classes.get(ms.owner) if ms else None
        src = facts.sources.file_for_class(ms.owner, ci.source_file if ci else None) if ms else None
        rng = mi.line_range
        if not src or not rng:
            blocks.append(f"### {m}\n(source not available)")
            continue
        text, lo, hi = facts.sources.snippet(src, rng[0], rng[1], context=3, max_lines=max_lines)
        rel = facts.sources.rel(src)
        # A long snippet omits its middle. Record only printed line numbers,
        # not the enclosing lo..hi range, so unseen lines cannot satisfy V3.
        shown.setdefault(rel, []).extend(_shown_line_ranges(text))
        blocks.append(f"### {m}\nfile: {rel}\n{text}")
    return Evidence(app_methods, path_text, "\n\n".join(blocks) or "(no application code available)", shown)


def _shown_line_ranges(text: str) -> List[Tuple[int, int]]:
    """Contiguous ranges of numbered source lines actually printed in a snippet."""
    ranges: List[Tuple[int, int]] = []
    for match in re.finditer(r"^\s*(\d+) \|", text, re.M):
        line = int(match.group(1))
        if ranges and line == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], line)
        else:
            ranges.append((line, line))
    return ranges


def check_v3(answer: dict, ev: Evidence) -> Tuple[bool, List[str]]:
    """Require each citation to match a shown file and numbered line.

    File matching accepts suffixes and basenames; snippets may include context
    and reachable-method fallback evidence, so this is not a route proof.
    """
    problems = []
    cites = answer.get("evidence") or []
    if not isinstance(cites, list) or not cites:
        return False, ["no evidence lines cited"]
    for c in cites:
        if not isinstance(c, dict):
            problems.append(f"malformed citation {c!r}")
            continue
        f = str(c.get("file", "")).strip().lstrip("./")
        try:
            line = int(c.get("line"))
        except (TypeError, ValueError):
            problems.append(f"no line number in {c!r}")
            continue
        ranges = None
        for shown_file, rs in ev.shown.items():
            if f and (shown_file.endswith(f) or f.endswith(shown_file) or Path(shown_file).name == Path(f).name):
                ranges = rs
                break
        if ranges is None:
            problems.append(f"{f}:{line} is not in a file shown for the path")
        elif not any(lo <= line <= hi for lo, hi in ranges):
            problems.append(f"{f}:{line} is outside the code shown for the path")
    return not problems, problems


def apply_trusted_sink_rule(d: TriageDecision, sink_sigs: List[str], trusted: Optional[Set[str]]) -> TriageDecision:
    """V3 reason-consistency rule: N3 may not remove a flow as
    "not_dangerous_sink" when the sink comes from a trusted specification (Tai-e's curated config
    for the CWE, or an N2 label chosen unanimously). N3 still judges sources, sanitisers and paths."""
    if not trusted or d.verdict != "not_vulnerable" or d.reason.strip().lower() != "not_dangerous_sink":
        return d
    for sig in sink_sigs:
        norm = normalize_taie_signature(sig) or sig
        if norm in trusted:
            d.kept = True
            d.v3_ok = False
            d.v3_problems = list(d.v3_problems) + [f"sink {norm} is a trusted specification; "
                                                   "N3 may not overrule it (trusted-sink rule)"]
            d.override = "trusted-sink"
            break
    return d


def triage_flow(flow: TaintFlow, tfg: TaintFlowGraph, facts: ProgramFacts, llm: BaseLLM, cwe: dict, cwe_id: str,
                cfg: dict, validators: bool = True, trusted_sinks: Optional[Set[str]] = None) -> TriageDecision:
    ev = build_evidence(flow, tfg, facts, int(cfg.get("max_methods", 6)), int(cfg.get("snippet_max_lines", 60)))
    flow_text = f"source: {flow.source.raw}\nsink:   {flow.sink.raw}"
    if flow.source.in_driver:
        flow_text += ("\n(note: the source is the analysis driver, which models attacker input passed to an "
                      "entry point of the project)")
    values = {"cwe_id": cwe_id, "cwe_name": cwe.get("name", ""), "cwe_description": cwe.get("description", ""),
              "flow": flow_text, "path": ev.path_text, "snippets": ev.snippets_text}
    msgs = build_messages("n3_triage", values)
    samples = max(1, int(cfg.get("samples", 1)))
    offset = int(cfg.get("sample_offset", 0))
    answers: List[dict] = []
    for s in range(samples):
        resp = llm.chat(msgs, stage="N3-triage", temperature=0.0 if s == 0 else float(cfg.get("sample_temperature", 0.7)),
                        max_tokens=int(cfg.get("max_tokens", 8192)), sample=offset + s)
        try:
            a = extract_json(resp.text)
            if not isinstance(a, dict):
                a = {"verdict": "uncertain", "reason": "unparseable"}
        except ValueError:
            a = {"verdict": "uncertain", "reason": "unparseable"}
        v = str(a.get("verdict", "uncertain")).strip().lower()
        a["verdict"] = v if v in VERDICTS else "uncertain"
        answers.append(a)
    tally = Counter(a["verdict"] for a in answers)
    verdict, n = tally.most_common(1)[0]
    if n * 2 <= samples and samples > 1:
        verdict = "uncertain"
    chosen = next(a for a in answers if a["verdict"] == verdict) if verdict != "uncertain" or \
        any(a["verdict"] == "uncertain" for a in answers) else answers[0]

    v3_ok: Optional[bool] = None
    problems: List[str] = []
    kept = True
    if verdict == "not_vulnerable":
        if validators:
            v3_ok, problems = check_v3(chosen, ev)
            kept = not v3_ok
        else:
            kept = False
    d = TriageDecision(flow.short_id, flow.key, verdict, str(chosen.get("reason", "")), kept, v3_ok, problems,
                       chosen.get("evidence") if isinstance(chosen.get("evidence"), list) else [],
                       str(chosen.get("explanation", ""))[:2000], [a["verdict"] for a in answers], ev.methods)
    return apply_trusted_sink_rule(d, tfg.sink_entries(flow.sink), trusted_sinks)


def triage_all(flows: List[TaintFlow], tfg: TaintFlowGraph, facts: ProgramFacts, llm: BaseLLM, cwe: dict,
               cwe_id: str, cfg: dict, validators: bool = True,
               trusted_sinks: Optional[Set[str]] = None) -> List[TriageDecision]:
    limit = int(cfg.get("max_flows", 200))
    out = []
    for i, f in enumerate(flows):
        if i >= limit:
            out.append(TriageDecision(f.short_id, f.key, "unjudged", "over-max-flows", True, None))
            continue
        out.append(triage_flow(f, tfg, facts, llm, cwe, cwe_id, cfg, validators, trusted_sinks))
    return out


def save_decisions(decisions: List[TriageDecision], path: Path) -> None:
    Path(path).write_text(json.dumps({"prompt_version": prompt_version("n3_triage"),
                                      "decisions": [asdict(d) for d in decisions]}, indent=2))
