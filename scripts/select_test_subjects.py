#!/usr/bin/env python3
"""Deterministic candidate-selection protocol for a planned held-out evaluation.

Select candidates from repositories outside the development set using the protocol below.
This script prints candidates; building both versions and accepting a subject remain separate steps:

  pool    build status 'success', JDK 8, Maven (no Gradle), CWE in {022, 078, 094}
          (the development CWEs), GitHub repository not used by any development subject,
          repository size <= 40,000 KB (the size of xxl-job, the largest subject already prepared;
          snapshot of GitHub's 'size' field in config/heldout/repo_sizes.json).
  order   per CWE, candidates sorted by slug, then shuffled with random.Random(6215).
  accept  the first candidate per CWE whose buggy AND fixed versions build with `nesy build`.
          A candidate that fails to build is skipped and listed as skipped in the report.
          No Tai-e or LLM result is inspected before acceptance.

The unevaluated xxl-job subject (CWE-079) is included separately as the fourth,
out-of-distribution candidate.

Usage:  python scripts/select_test_subjects.py            # prints the ordered candidate lists
        python scripts/select_test_subjects.py --yaml N   # YAML stanzas for the first N per CWE
"""
import argparse
import csv
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "config" / "cwe-bench-java"
SIZES = ROOT / "config" / "heldout" / "repo_sizes.json"
CWES = ["CWE-022", "CWE-078", "CWE-094"]
DEV_REPOS = {"perwendel/spark", "zeroturnaround/zt-zip", "jmrozanec/cron-utils",
             "jenkinsci/perfecto-plugin", "xuxueli/xxl-job"}
MAX_KB = 40000
SEED = 6215


def candidates():
    build = {r["project_slug"]: r for r in csv.DictReader(open(BENCH / "build_info.csv"))}
    sizes = json.loads(SIZES.read_text())
    out = {c: [] for c in CWES}
    for r in csv.DictReader(open(BENCH / "project_info.csv")):
        b = build.get(r["project_slug"], {})
        repo = f"{r['github_username']}/{r['github_repository_name']}"
        if (r["cwe_id"] in out and b.get("status") == "success" and b.get("jdk_version") == "8"
                and not b.get("gradle_version") and repo not in DEV_REPOS
                and isinstance(sizes.get(repo), int) and sizes[repo] <= MAX_KB):
            out[r["cwe_id"]].append({**r, "mvn": b.get("mvn_version") or "3.5.0", "size_kb": sizes[repo]})
    rng = random.Random(SEED)
    for c in CWES:
        out[c].sort(key=lambda r: r["project_slug"])
        rng.shuffle(out[c])
    return out


def stanza(r):
    fixes = [f for f in r["fix_commit_ids"].split(";") if f]
    sid = r["github_repository_name"].lower()
    return "\n".join([
        f"  - id: {sid}",
        f"    slug: {r['project_slug']}",
        "    role: test",
        f"    cve: {r['cve_id']}",
        f"    cwe: {r['cwe_id']}",
        f"    repo: {r['github_url']}.git",
        f"    tag: \"{r['github_tag']}\"",
        f"    buggy_commit: {r['buggy_commit_id']}",
        f"    fixed_commit: {fixes[-1]}   # last fix commit",
        f"    all_fix_commits: [{', '.join(fixes)}]",
        "    jdk: 8",
        f"    maven: \"{r['mvn']}\"",
        f"    why: \"Held-out test subject ({r['cwe_id']}), drawn by scripts/select_test_subjects.py.\"",
    ])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--yaml", type=int, default=0, help="print YAML stanzas for the first N candidates per CWE")
    a = ap.parse_args()
    cand = candidates()
    if a.yaml:
        for c in CWES:
            for r in cand[c][:a.yaml]:
                print(stanza(r))
        return
    for c in CWES:
        print(f"{c} ({len(cand[c])} eligible), in draw order:")
        for i, r in enumerate(cand[c], 1):
            print(f"  {i:2d}. {r['project_slug']}  ({r['size_kb']} KB)")


if __name__ == "__main__":
    main()
