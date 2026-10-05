#!/usr/bin/env python3
"""Score each configuration against the runtime CVE witnesses.

Runtime witnesses (scripts/run_witnesses.py) check the CVE effects on buggy and fixed versions.
Patch-method overlap alone can credit unrelated flows, such as zt-zip flows through the trusted
output-directory argument. This score additionally requires a reported buggy-version flow to
match the subject-specific sink predicate and overlap a recorded patch method.

The predicates match sink signatures or enclosing methods and, for zt-zip, argument 1. They
connect static alarms to the witnessed sink behaviour; they do not replay every static route
or prove its feasibility. The matching rules are visible below for inspection.
Writes results/witness/witness-detection.csv and prints a summary.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "results" / "runs"

# Per-subject "witnessed sink" predicate. `s` is the Tai-e sink string; `c` is its callee part
# (everything after "invoke...", i.e. the actual sink call, not the enclosing method); `a` is the
# sink argument index. The predicates use subject-specific signature/site patterns, with an
# explicit argument check for zt-zip. They exclude incidental sinks such as the trusted output
# directory and perfecto-plugin build-log `fatalError` calls; they are not route-feasibility checks.
def _callee(s: str) -> str:
    i = s.find("invoke")
    return s[i:] if i >= 0 else s


MATCHERS = {
    # entry name (arg 1) reaching new File(outputDir, name) in the unpack callback;
    # arg 0 is the trusted output directory, which is why B1's only patch-overlap flag does not count
    "zt-zip": lambda s, c, a: a == 1 and bool(re.search(r"ZipUtil\$(Unpacker|Unwraper): void process", s)),
    # user cron text reaching buildConstraintViolationWithTemplate (the EL-interpolated template)
    "cron-utils": lambda s, c, a: "buildConstraintViolationWithTemplate" in s
                                  or "CronValidator: boolean isValid" in s,
    # request path reaching the static-resource read (ResourceUtils.getFile / getResourceAsStream / loadStream)
    "spark": lambda s, c, a: "getResourceAsStream" in s or "ResourceUtils" in s or "loadStream" in s,
    # pcParameters reaching the OS-command sink: Runtime.exec(cmdArgs) / new ProcessBuilder(cmdArgs).
    # Matched on the callee, so the build-log fatalError and the wrong-sink new URL(...) do not count.
    "perfecto-plugin": lambda s, c, a: ".exec(" in c or "cmdArgs" in c,
}

CONFIGS = ["B1", "B2", "v1", "v2", "v3", "v4", "iris-like",
           "v3-noval", "v3-noV2", "v3-noV3"]


def _arg_of(flow: dict) -> int:
    key = flow.get("key", "")
    m = re.search(r"/(\d+)$", key)
    return int(m.group(1)) if m else -1


def _runs(subject: str, version: str, config: str):
    d = RUNS / subject / version / config
    if not d.is_dir():
        return
    for rp in sorted(d.glob("run*.json")):
        yield json.loads(rp.read_text())


def main() -> int:
    subjects = list(MATCHERS)
    rows = []
    for subject in subjects:
        match = MATCHERS[subject]
        for config in CONFIGS:
            runs = list(_runs(subject, "buggy", config))
            if not runs:
                continue
            reach_runs, confirm_runs, confirm_flows = 0, 0, []
            for r in runs:
                reached = [f for f in r["flows"]
                           if f.get("reported") and match(f.get("sink", ""), _callee(f.get("sink", "")), _arg_of(f))]
                # witness-confirmed = reaches the witnessed sink AND the route is patch-relevant (GT)
                confirmed = [f for f in reached if f.get("gt")]
                reach_runs += int(bool(reached))
                confirm_runs += int(bool(confirmed))
                confirm_flows.append(len(confirmed))
            n = len(runs)
            rows.append({
                "subject": subject, "config": config, "runs": n,
                "reaches_sink_any": int(reach_runs > 0),
                "witness_confirmed_any": int(confirm_runs > 0),
                "witness_confirm_rate": round(confirm_runs / n, 3) if n else 0.0,
                "mean_confirmed_flows": round(sum(confirm_flows) / n, 2) if n else 0.0,
            })
    out = ROOT / "results" / "witness"
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "witness-detection.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["subject", "config", "runs", "reaches_sink_any",
                                          "witness_confirmed_any", "witness_confirm_rate",
                                          "mean_confirmed_flows"])
        w.writeheader()
        w.writerows(rows)

    # pivot: config x subject -> witness-confirmed? (GT-relevant flow into the witnessed sink)
    print("Witness-confirmed detection on buggy versions")
    print("(reports a patch-relevant flow matching a subject-specific witnessed-sink predicate)\n")
    header = f"{'config':<10}" + "".join(f"{s:<16}" for s in subjects) + "n/4"
    print(header)
    for config in CONFIGS:
        cells, got = "", 0
        for s in subjects:
            r = next((x for x in rows if x["subject"] == s and x["config"] == config), None)
            if r is None:
                cells += f"{'-':<16}"
            else:
                mark = "yes" if r["witness_confirmed_any"] else "no"
                got += r["witness_confirmed_any"]
                cells += f"{mark + ' (' + str(r['witness_confirm_rate']) + ')':<16}"
        print(f"{config:<10}{cells}{got}/4")
    print(f"\nwrote {out / 'witness-detection.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
