#!/usr/bin/env python3
"""Freeze and validate an existing study label sample before changing run outputs.

Standard library only. Reads inputs; creates a new manifest and never overwrites
an existing one. Do not regenerate this manifest from corrected/new run outputs:
the probabilities describe the population from which the labels were sampled.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

MAIN_CONFIGS = ("B1", "B2", "v1", "v2", "v3", "v4", "iris-like")
SCHEMA = "nesy-frozen-label-sampling-v1"


def build_manifest(repo: Path, per_config: int = 10) -> dict:
    groups, inputs = defaultdict(list), {}
    paths = sorted((repo / "results" / "runs").rglob("run*.json"))
    if not paths:
        raise ValueError("No run records found")
    for path in paths:
        raw = path.read_bytes()
        record = json.loads(raw)
        groups[record["subject"], record["version"]].append(record)
        inputs[str(path.relative_to(repo))] = hashlib.sha256(raw).hexdigest()
    frames = {}
    for (subject, version), runs in sorted(groups.items()):
        sheet = repo / "labels" / f"{subject}-{version}.csv"
        inputs[str(sheet.relative_to(repo))] = hashlib.sha256(sheet.read_bytes()).hexdigest()
        with sheet.open(newline="") as stream:
            labels = {row["flow_key"]: row for row in csv.DictReader(stream)}
        gt, ids = defaultdict(bool), {}
        by_config = {config: set() for config in MAIN_CONFIGS}
        for run in runs:
            for flow in run["flows"]:
                key = flow["key"]
                gt[key] |= bool(flow["gt"])
                ids[key] = flow["id"]
                if flow["reported"] and run["config"] in by_config:
                    by_config[run["config"]].add(key)
        selected_by, strata, expected = defaultdict(list), {}, {}
        for config in MAIN_CONFIGS:
            for is_gt, name, priority in ((True, "gt", "1"), (False, "other", "2")):
                stratum_id = f"{config}|{name}"
                candidates = sorted(key for key in by_config[config] if gt[key] == is_gt)
                seed = f"{subject}|{version}|{config}|{name}"
                rng = random.Random(seed)
                chosen = candidates if len(candidates) <= per_config else rng.sample(candidates, per_config)
                strata[stratum_id] = {"config": config, "union_gt": is_gt,
                                      "population_n": len(candidates), "sample_n": len(chosen), "seed": seed}
                for key in chosen:
                    expected[key] = priority
                    selected_by[key].append(stratum_id)
        actual = {key: row["priority"] for key, row in labels.items() if row.get("priority")}
        if actual != expected:
            raise ValueError(f"Stored sample does not exactly match reconstructed design for {subject}/{version}: "
                             f"missing={len(set(expected)-set(actual))}, extra={len(set(actual)-set(expected))}, "
                             f"wrong priority={sum(expected[k] != actual[k] for k in set(expected) & set(actual))}")
        # Uncertain/missing labels are preserved as such; selecting an item does
        # not certify its label, and later estimation checks current decisions.
        flows = {}
        for key in sorted(gt):
            memberships = [f"{config}|{'gt' if gt[key] else 'other'}" for config in MAIN_CONFIGS
                           if key in by_config[config]]
            missed = 1.0
            for membership in memberships:
                stratum = strata[membership]
                missed *= 1 - stratum["sample_n"] / stratum["population_n"]
            flows[key] = {"flow_id": ids[key], "inclusion_probability": 1 - missed,
                          "selected": key in expected, "priority": expected.get(key, ""),
                          "union_gt": gt[key], "eligible_strata": memberships,
                          "selected_by": selected_by[key],
                          "label_at_freeze": (labels.get(key, {}).get("label") or "").strip().upper()}
        frames[f"{subject}|{version}"] = {
            "subject": subject, "version": version, "flow_count": len(flows),
            "selected_count": len(expected), "strata": strata, "flows": flows}
    manifest = {
        "schema": SCHEMA,
        "design": {"name": "independent SRSWOR by main configuration and union-GT stratum, then union",
                   "main_configs": list(MAIN_CONFIGS), "per_config_sample": per_config,
                   "flow_identity": "existing flow_key; all driver source call sites collapse to DRIVER",
                   "inclusion_probability": "1 - product over eligible strata of (1 - sample_n/population_n)",
                   "estimator": "Horvitz-Thompson domain TP total / known reported flow count",
                   "zero_alarm_precision": None,
                   "uncertainty": "Current labels other than TP/FP are missing judgements, never FP.",
                   "do_not_resample": "Keep this original manifest after corrected runs; new or zero-probability flows make affected-domain precision unknown."},
        "source_run_count": len(paths),
        "selected_count": sum(frame["selected_count"] for frame in frames.values()),
        "source_input_sha256": inputs,
        "frames": frames,
    }
    # Check no file changed while the manifest was being assembled.
    for relative, digest in inputs.items():
        if hashlib.sha256((repo / relative).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Source changed while freezing sampling frame: {relative}")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--per-config", type=int, default=10)
    args = parser.parse_args()
    if args.per_config < 1:
        parser.error("--per-config must be positive")
    if args.manifest.exists():
        raise SystemExit("Refusing to overwrite frozen sampling manifest")
    manifest = build_manifest(args.repo.resolve(), args.per_config)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    with args.manifest.open("x") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"manifest": str(args.manifest.resolve()), "schema": SCHEMA,
                      "source_run_count": manifest["source_run_count"],
                      "selected_count": manifest["selected_count"],
                      "sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest()}, indent=2))


if __name__ == "__main__":
    main()
