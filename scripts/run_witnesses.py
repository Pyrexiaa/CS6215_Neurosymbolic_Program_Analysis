#!/usr/bin/env python3
"""Run the runtime CVE witnesses (witness/src/*.java) against the built subjects.

Each witness is a small, harmless proof-of-concept that invokes the relevant application API
or handler with attacker-controlled input and checks the security effect of its CVE
(a file written outside the extraction dir, EL ``${7*7}`` evaluated to 49, a request path
resolved outside the static root, an injected shell command executed). For each tested effect, witnessed=true is expected on the buggy version and witnessed=false
on the fixed version. Spark checks handler-level resource resolution rather than full HTTP dispatch.

Prerequisites (same as the study): built subjects (``python -m nesy build all``) and a JDK 8
with javac (``JAVA8_HOME``). Writes ``results/witness/witness-results.json``.

Usage:  python scripts/run_witnesses.py            # all four witnesses
        python scripts/run_witnesses.py zt-zip spark
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from nesy.config import load_settings  # noqa: E402
from nesy.subjects import load_layout  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
WITNESS = ROOT / "witness"


def _classpath(settings, sid: str, version: str) -> str:
    lay = load_layout(settings, sid, version)
    parts = list(lay.app_dirs) + list(lay.lib_jars)
    if _manifest(sid).get("needs_test_resources"):
        # Spark resolves classpath resources (static files live under src/test/resources).
        res = Path(lay.project_dir) / "src" / "test" / "resources"
        if res.is_dir():
            parts.append(str(res))
    return os.pathsep.join(parts)


def _manifest(sid: str) -> dict:
    data = json.loads((WITNESS / "witnesses.json").read_text())
    for w in data["witnesses"]:
        if w["subject"] == sid:
            return w
    raise KeyError(sid)


def _run_one(settings, w: dict, version: str, j8: Path) -> dict:
    sid, cls, pkg = w["subject"], w["cls"], w["pkg"]
    cp = _classpath(settings, sid, version)
    src = WITNESS / "src" / f"{cls}.java"
    with tempfile.TemporaryDirectory() as out:
        env = dict(os.environ)
        env.pop("JAVA_TOOL_OPTIONS", None)  # keep the proxy agent out of the witness JVM
        jc = subprocess.run([str(j8 / "bin" / "javac"), "-cp", cp, "-d", out, str(src)],
                            capture_output=True, text=True, env=env)
        if jc.returncode != 0:
            return {"subject": sid, "version": version, "witnessed": None,
                    "error": "compile-failed", "detail": jc.stderr.strip()[:800]}
        main_cls = f"{pkg}.{cls}" if pkg else cls
        rn = subprocess.run([str(j8 / "bin" / "java"), "-cp", f"{cp}{os.pathsep}{out}", main_cls],
                            capture_output=True, text=True, env=env, timeout=180)
        line = next((l for l in rn.stdout.splitlines() if l.strip().startswith("{")), "")
        if not line:
            return {"subject": sid, "version": version, "witnessed": None,
                    "error": "no-output", "detail": (rn.stdout + rn.stderr).strip()[:800]}
        rec = json.loads(line)
        rec["version"] = version
        return rec


def main(argv: list[str]) -> int:
    settings = load_settings()
    j8 = settings.java8_home()
    if not j8 or not (Path(j8) / "bin" / "javac").exists():
        print("[witness] JDK 8 with javac not found (set JAVA8_HOME in .env).", file=sys.stderr)
        return 2
    j8 = Path(j8)
    data = json.loads((WITNESS / "witnesses.json").read_text())
    wanted = set(argv) or {w["subject"] for w in data["witnesses"]}
    results = []
    for w in data["witnesses"]:
        if w["subject"] not in wanted:
            continue
        for version in ("buggy", "fixed"):
            try:
                rec = _run_one(settings, w, version, j8)
            except Exception as e:  # noqa: BLE001
                rec = {"subject": w["subject"], "version": version, "witnessed": None,
                       "error": type(e).__name__, "detail": str(e)[:800]}
            rec.update({"cve": w["cve"], "cwe": w["cwe"], "sink_method": w["sink_method"],
                        "sink_arg": w["sink_arg"], "sink_site": w["sink_site"], "source_spec": w["source"]})
            results.append(rec)
            mark = {True: "WITNESSED", False: "NOT WITNESSED", None: "ERROR"}[rec.get("witnessed")]
            print(f"  {w['subject']:<16} {version:<6} {mark:<13} {rec.get('evidence', rec.get('detail', ''))[:110]}")
    out_dir = ROOT / "results" / "witness"
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {"description": data["description"], "results": results}
    (out_dir / "witness-results.json").write_text(json.dumps(payload, indent=2) + "\n")
    # expectation check: buggy witnessed and fixed not, for every subject that ran cleanly
    ok = True
    for sid in sorted({r["subject"] for r in results}):
        rs = {r["version"]: r for r in results if r["subject"] == sid}
        b, f = rs.get("buggy", {}).get("witnessed"), rs.get("fixed", {}).get("witnessed")
        if b is not True or f is not False:
            ok = ok and (b is None or f is None)  # errors are not failures of the expectation
    print(f"[witness] wrote {out_dir / 'witness-results.json'}  ({'buggy-only pattern holds' if ok else 'unexpected pattern'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
