"""Offline heuristic 'LLM' used by tests and `--mock` dry runs.

It is NOT a baseline and must not be reported as a result: it only produces well-formed
answers so the whole pipeline (prompts -> parsing -> validators -> Tai-e -> metrics) can be
exercised without network access or tokens.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List

from .jvm import parse_taie_signature

_SINK_NAMES = re.compile(r"^(exec|run|eval|execute|evaluate|createValueExpression|buildConstraintViolationWithTemplate|"
                         r"start|command|parseExpression|getValue)$", re.I)
_SOURCE_NAMES = re.compile(r"^(entryName|getName|readLine|getParameter|getHeader|getQueryString|getPathInfo|"
                           r"getRequestURI|nextEntry|getNextEntry)$")


def _n1(user: str) -> str:
    from .driver import TAINTED_EXPR
    from .jvm import default_value_expr, java_source_type
    calls, entries = [], []
    for line in user.splitlines():
        m = re.match(r"^- (<.+?\)>) \| (\S+), (static|instance) \| ctors: (.*)$", line.strip())
        if not m:
            continue
        ms = parse_taie_signature(m.group(1))
        if not ms:
            continue
        static = m.group(3) == "static"
        ctors = re.findall(r"\(([^)]*)\)", m.group(4))
        args = ", ".join(TAINTED_EXPR.get(p, default_value_expr(p)) for p in ms.params)
        owner = java_source_type(ms.owner)
        if ms.name == "<init>":
            stmt = f"new {owner}({args});"
        elif static:
            stmt = f"{owner}.{ms.name}({args});"
        elif ctors:
            cparams = [p.strip() for p in ctors[0].split(",") if p.strip()]
            cargs = ", ".join('"benign"' if p == "java.lang.String" else default_value_expr(p) for p in cparams)
            stmt = f"{owner} r = new {owner}({cargs}); r.{ms.name}({args});"
        else:
            continue
        calls.append(f"        try {{ {stmt} }} catch (Throwable t) {{}}")
        entries.append({"signature": ms.taie, "tainted_params": [i for i, p in enumerate(ms.params) if p in TAINTED_EXPR],
                        "why": "mock: public API taking external input"})
        if len(calls) >= 10:
            break
    code = "package nesy;\npublic class NesyDriver {\n    public static void main(String[] args) {\n" + \
           "\n".join(calls) + "\n    }\n}\n"
    return "```json\n" + json.dumps({"entries": entries}) + "\n```\n```java\n" + code + "```\n"


def _n2(user: str) -> str:
    labels: List[Dict] = []
    for line in user.splitlines():
        m = re.match(r"^(\d+) \| (<.+?\)>) \|", line.strip())
        if not m:
            continue
        i, sig = int(m.group(1)), parse_taie_signature(m.group(2))
        if not sig:
            continue
        str_args = [k for k, p in enumerate(sig.params) if p in ("java.lang.String", "java.lang.CharSequence")]
        if sig.owner == "java.io.File" and sig.name == "<init>" and len(sig.params) == 2:
            labels.append({"id": i, "role": "sink", "index": "1", "why": "mock: child path argument"})
        elif _SINK_NAMES.match(sig.name) and str_args:
            labels.append({"id": i, "role": "sink", "index": str(str_args[0]), "why": "mock: executes its argument"})
        elif _SOURCE_NAMES.match(sig.name) and sig.ret != "void":
            labels.append({"id": i, "role": "source", "index": "result", "why": "mock: returns external data"})
    return "```json\n" + json.dumps(labels) + "\n```"


def _n3(user: str) -> str:
    # cite the line of a canonical-path prefix check if one is visible, else the sink line
    snippet_lines = re.findall(r"^\s*(\d+) \| (.*)$", user, re.M)
    file_m = re.search(r"^file: (\S+)$", user, re.M)
    f = file_m.group(1) if file_m else "?"
    has_canon = "getCanonical" in user
    for num, text in snippet_lines:
        if has_canon and "startsWith" in text:
            return "```json\n" + json.dumps({
                "verdict": "not_vulnerable", "reason": "sanitized",
                "evidence": [{"file": f, "line": int(num), "note": "mock: canonical prefix check"}],
                "explanation": "mock: the path is canonicalised and checked against the base directory."}) + "\n```"
    sink_line = re.search(r"sink:\s+<.+?\)>\[\d+@L(\d+)\]", user)
    line = int(sink_line.group(1)) if sink_line else 0
    return "```json\n" + json.dumps({
        "verdict": "vulnerable", "reason": "exploitable",
        "evidence": [{"file": f, "line": line, "note": "mock: tainted value reaches the sink"}],
        "explanation": "mock: no sanitizer visible on the path."}) + "\n```"


def heuristic_responder(messages: List[Dict[str, str]], stage: str) -> str:
    user = messages[-1]["content"]
    if stage.startswith("N1-repair"):
        code = re.search(r"```java\n(.*?)```", user, re.S)
        return "```java\n" + (code.group(1) if code else "") + "```"
    if stage.startswith("N1"):
        return _n1(user)
    if stage.startswith("N2"):
        return _n2(user)
    if stage.startswith("N3"):
        return _n3(user)
    return "{}"
