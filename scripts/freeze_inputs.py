#!/usr/bin/env python3
"""Freeze the scientific inputs of the study by content hash.

Writes ``results/provenance/input-freeze.json``: a sorted sha256 per file for the source, prompts,
configuration, label sheets + sampling manifest, and the archived run records, plus the recorded
dependency classpaths/layouts when ``work/`` is present. A single ``combined_sha256`` over the sorted
(path, hash) pairs of each group lets a later rebuild prove it started from the same inputs before any
build command can overwrite a classpath file. Study inputs are read-only; the default command
writes the manifest, while --check only compares it with the current hashes.

  python scripts/freeze_inputs.py              # hash source/prompts/config/labels/records (+ classpaths)
  python scripts/freeze_inputs.py --jars       # also hash every dependency jar listed in nesy-cp.txt
  python scripts/freeze_inputs.py --check       # recompute and diff against the stored freeze (exit 1 on drift)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "provenance" / "input-freeze.json"

# (group, iterable of globs relative to ROOT). Missing files/dirs are skipped and reported.
GROUPS = {
    "source": ["src/**/*.py", "scripts/*.py"],
    "prompts": ["prompts/**/*"],
    "config": ["config/**/*"],
    "labels": ["labels/*.csv", "labels/sampling_manifest.json"],
    "run_records": ["results/runs/**/*.json"],
    "classpaths": ["work/subjects/*/nesy-cp.txt", "work/subjects/*/*/nesy-cp.txt",
                   "work/subjects/*/*.layout.json"],
}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _rel(p: Path) -> str:
    return str(p.relative_to(ROOT)).replace("\\", "/")


def hash_jars_from_classpaths() -> dict:
    out = {}
    import os
    for cpf in ROOT.glob("work/subjects/*/nesy-cp.txt"):
        for part in cpf.read_text().strip().split(os.pathsep):
            part = part.strip()
            jp = Path(part)
            if part.endswith(".jar") and jp.is_file() and part not in out:
                out[part] = sha256_file(jp)
    return dict(sorted(out.items()))


def build_freeze(with_jars: bool = False) -> dict:
    groups, missing = {}, {}
    for group, globs in GROUPS.items():
        files = {}
        for pat in globs:
            for p in sorted(ROOT.glob(pat)):
                if p.is_file():
                    files[_rel(p)] = sha256_file(p)
            if not any(ROOT.glob(pat)):
                missing.setdefault(group, []).append(pat)
        files = dict(sorted(files.items()))
        combined = hashlib.sha256(
            "".join(f"{k} {v}\n" for k, v in files.items()).encode()).hexdigest()
        groups[group] = {"n_files": len(files), "combined_sha256": combined, "files": files}
    freeze = {
        "note": "Content freeze of study inputs (sha256). Hashing only; no operational dates recorded.",
        "root": str(ROOT.name),
        "groups": groups,
        "missing_globs": missing,
    }
    if with_jars:
        jars = hash_jars_from_classpaths()
        freeze["dependency_jars"] = {
            "n_files": len(jars),
            "combined_sha256": hashlib.sha256(
                "".join(f"{k} {v}\n" for k, v in jars.items()).encode()).hexdigest(),
            "files": jars,
        }
    return freeze


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jars", action="store_true", help="also hash dependency jars listed in nesy-cp.txt")
    ap.add_argument("--check", action="store_true", help="diff against the stored freeze; exit 1 on drift")
    args = ap.parse_args()
    freeze = build_freeze(with_jars=args.jars)

    if args.check:
        if not OUT.exists():
            print(f"[freeze] no stored freeze at {OUT}; run without --check first", file=sys.stderr)
            return 2
        stored = json.loads(OUT.read_text())
        drift = []
        for group, data in freeze["groups"].items():
            old = stored.get("groups", {}).get(group, {})
            if old.get("combined_sha256") != data["combined_sha256"]:
                old_files, new_files = old.get("files", {}), data["files"]
                for k in sorted(set(old_files) | set(new_files)):
                    if old_files.get(k) != new_files.get(k):
                        drift.append(f"{group}: {k} ({'added' if k not in old_files else 'removed' if k not in new_files else 'changed'})")
        if drift:
            print("[freeze] DRIFT from stored input-freeze.json:")
            for d in drift[:200]:
                print("  " + d)
            return 1
        print("[freeze] inputs match the stored freeze.")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(freeze, indent=2) + "\n")
    for group, data in freeze["groups"].items():
        miss = freeze["missing_globs"].get(group)
        tail = f"  (missing: {', '.join(miss)})" if miss else ""
        print(f"  {group:<12} {data['n_files']:>5} files  {data['combined_sha256'][:12]}{tail}")
    if "dependency_jars" in freeze:
        print(f"  {'dep_jars':<12} {freeze['dependency_jars']['n_files']:>5} jars   {freeze['dependency_jars']['combined_sha256'][:12]}")
    print(f"[freeze] wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
