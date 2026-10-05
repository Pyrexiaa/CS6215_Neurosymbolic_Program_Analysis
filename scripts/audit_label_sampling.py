#!/usr/bin/env python3
"""Historical sensitivity audit of the pre-validator-refresh sampling frame.

Reads existing artifacts only. Never changes labels, run records, or report tables.
Reconstructs the exact deterministic sampler before estimating anything. Outputs
historical descriptive, Horvitz--Thompson (HT), and Hajek ratio estimates. These
estimates remain conditional on the correctness of the existing LLM labels.

For current results, use ``python -m nesy evaluate`` with the frozen
``labels/sampling_manifest.json``. This historical reconstruction intentionally
refuses repositories containing that manifest: corrected run sets need not
reproduce the original deterministic sample. To reproduce the historical audit,
extract ``results/history/pre-validator-refresh.tar.gz`` into a scratch directory,
add the original label CSVs under its ``labels/`` directory (without a manifest),
and pass that directory as ``--repo``.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import statistics
from collections import defaultdict
from pathlib import Path

MAIN_CONFIGS = ("B1", "B2", "v1", "v2", "v3", "v4", "iris-like")


def write_csv(path, rows):
    if not rows:
        return
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def mean(values):
    values = [value for value in values if value is not None]
    return statistics.mean(values) if values else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--per-config", type=int, default=10)
    args = parser.parse_args()
    if args.per_config < 1:
        parser.error("--per-config must be positive")
    repo, dest = args.repo.resolve(), args.output_dir.resolve()
    if (repo / "labels" / "sampling_manifest.json").is_file():
        parser.error(
            "This script reconstructs the historical pre-validator-refresh sampling frame. "
            "For current results use `python -m nesy evaluate` with the frozen "
            "labels/sampling_manifest.json. To reproduce the historical audit, extract "
            "results/history/pre-validator-refresh.tar.gz into a scratch directory, add "
            "the original label CSVs under labels/ without a manifest, and pass that "
            "scratch directory as --repo."
        )
    dest.mkdir(parents=True, exist_ok=True)
    grouped = defaultdict(list)
    inputs = []
    for path in sorted((repo / "results" / "runs").rglob("run*.json")):
        record = json.loads(path.read_text())
        grouped[record["subject"], record["version"]].append(record)
        inputs.append(path)
    if not grouped:
        raise SystemExit("No run records found")

    sampling_rows, per_run, checks = [], [], []
    for (subject, version), runs in sorted(grouped.items()):
        label_path = repo / "labels" / f"{subject}-{version}.csv"
        inputs.append(label_path)
        with label_path.open(newline="") as stream:
            labels = {row["flow_key"]: row for row in csv.DictReader(stream)}
        union_gt = defaultdict(bool)
        reported_by = {config: set() for config in MAIN_CONFIGS}
        ids = {}
        for record in runs:
            for flow in record["flows"]:
                key = flow["key"]
                ids[key] = flow["id"]
                union_gt[key] |= bool(flow["gt"])
                if flow["reported"] and record["config"] in reported_by:
                    reported_by[record["config"]].add(key)
        strata = {}
        selected_by = defaultdict(list)
        expected = {}
        for config in MAIN_CONFIGS:
            for gt, name, priority in ((True, "gt", "1"), (False, "other", "2")):
                candidates = sorted(key for key in reported_by[config] if union_gt[key] == gt)
                strata[config, gt] = candidates
                rng = random.Random(f"{subject}|{version}|{config}|{name}")
                picked = candidates if len(candidates) <= args.per_config else rng.sample(candidates, args.per_config)
                for key in picked:
                    expected[key] = priority
                    selected_by[key].append(config)
        actual = {key: row.get("priority", "") for key, row in labels.items() if row.get("priority")}
        missing, extra = sorted(set(expected) - set(actual)), sorted(set(actual) - set(expected))
        wrong_strata = sorted(key for key in set(expected) & set(actual) if expected[key] != actual[key])
        unlabelled = sorted(key for key in expected if labels.get(key, {}).get("label", "").strip().upper() not in ("TP", "FP"))
        check = {"subject": subject, "version": version, "expected_n": len(expected),
                 "actual_n": len(actual), "exact_match": not (missing or extra or wrong_strata),
                 "missing": missing, "extra": extra, "wrong_strata": wrong_strata,
                 "unlabelled_sample": unlabelled}
        checks.append(check)
        if not check["exact_match"] or unlabelled:
            continue
        probabilities = {}
        for key in sorted(union_gt):
            memberships = [config for config in MAIN_CONFIGS if key in reported_by[config]]
            not_selected = 1.0
            for config in memberships:
                population_n = len(strata[config, union_gt[key]])
                not_selected *= 1 - min(args.per_config / population_n, 1.0)
            probability = 1 - not_selected
            probabilities[key] = probability
            sampling_rows.append({"subject": subject, "version": version, "flow_id": ids[key],
                                  "flow_key": key, "sampling_stratum": "gt" if union_gt[key] else "other",
                                  "eligible_configs": ";".join(memberships),
                                  "selected_by": ";".join(selected_by[key]),
                                  "selected": key in expected, "inclusion_probability": probability,
                                  "label": labels.get(key, {}).get("label", "")})
        for record in runs:
            reported = [flow for flow in record["flows"] if flow["reported"]]
            observed = [flow for flow in reported if flow["key"] in expected]
            uncovered = sum(probabilities.get(flow["key"], 0) == 0 for flow in reported)
            descriptive_tp, descriptive_known = 0.0, True
            for gt in (True, False):
                stratum = [flow for flow in reported if bool(flow["gt"]) == gt]
                judged = [flow for flow in stratum if labels.get(flow["key"], {}).get("label", "") in ("TP", "FP")]
                if stratum and not judged:
                    descriptive_known = False
                elif stratum:
                    descriptive_tp += len(stratum) * sum(labels[flow["key"]]["label"] == "TP" for flow in judged) / len(judged)
            weighted_tp = sum((labels[flow["key"]]["label"] == "TP") / probabilities[flow["key"]] for flow in observed)
            weighted_n = sum(1 / probabilities[flow["key"]] for flow in observed)
            per_run.append({"subject": subject, "version": version, "config": record["config"],
                            "run": record["run"], "reported_n": len(reported),
                            "sampled_reported_n": len(observed),
                            "sampled_reported_tp": sum(labels[flow["key"]]["label"] == "TP" for flow in observed),
                            "zero_probability_reported_n": uncovered,
                            "weighted_tp_total": weighted_tp, "weighted_population_total": weighted_n,
                            "descriptive_precision": descriptive_tp / len(reported) if reported and descriptive_known else None,
                            "ht_precision": weighted_tp / len(reported) if reported and not uncovered else None,
                            "hajek_precision": weighted_tp / weighted_n if weighted_n and not uncovered else None})

    metadata = {"repo": str(repo), "per_config": args.per_config,
                "reconstruction_valid": all(row["exact_match"] and not row["unlabelled_sample"] for row in checks),
                "checks": checks,
                "definitions": {
                    "inclusion_probability": "1 - product over eligible config/union-GT strata of (1-min(sample size / stratum size, 1))",
                    "ht_precision": "sum over sampled reported flows of TP / inclusion_probability, divided by all reported flows",
                    "hajek_precision": "inverse-probability-weighted TP total / inverse-probability-weighted population total",
                    "aggregation": "Mean over nonempty runs per subject/version/config; headline mean over subjects on buggy versions, omitting undefined subject precision, as historical report does."},
                "limitations": [
                    "Inference is justified only when the reconstructed exact sample matches the artifacts and all selected flows are labelled.",
                    "Assumes independent simple random draws per config/stratum, as implemented by the seeded sampler.",
                    "HT estimates can leave [0,1]; Hajek is a ratio estimator and is not exactly unbiased.",
                    "No confidence intervals are provided. Labels are correlated, grouped LLM judgements, not independently verified truth.",
                    "Historical and corrected precision are conditional on reporting at least one alarm. Empty-run coverage is shown separately.",
                    "A flow shared across configurations has one label, although its driver and route can differ."],
                "input_sha256": {str(path.relative_to(repo)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}}
    (dest / "sampling_audit.json").write_text(json.dumps(metadata, indent=2) + "\n")
    if not metadata["reconstruction_valid"]:
        raise SystemExit("Sample reconstruction or completeness check failed; inspect sampling_audit.json. No estimates exported.")
    write_csv(dest / "sampling_inclusion_probabilities.csv", sampling_rows)
    write_csv(dest / "precision_per_run.csv", per_run)
    groups = defaultdict(list)
    for row in per_run:
        groups[row["subject"], row["version"], row["config"]].append(row)
    by_subject = []
    for (subject, version, config), rows in sorted(groups.items()):
        by_subject.append({"subject": subject, "version": version, "config": config,
                           "total_runs": len(rows), "nonempty_runs": sum(row["reported_n"] > 0 for row in rows),
                           **{key: mean([row[key] for row in rows]) for key in ("descriptive_precision", "ht_precision", "hajek_precision")}})
    write_csv(dest / "precision_by_subject.csv", by_subject)
    headline = []
    for config in sorted({row["config"] for row in by_subject}):
        rows = [row for row in by_subject if row["config"] == config and row["version"] == "buggy"]
        headline.append({"config": config, "subjects": len(rows),
                         "subjects_with_nonempty_runs": sum(row["nonempty_runs"] > 0 for row in rows),
                         "total_runs": sum(row["total_runs"] for row in rows),
                         "nonempty_runs": sum(row["nonempty_runs"] for row in rows),
                         **{key: mean([row[key] for row in rows]) for key in ("descriptive_precision", "ht_precision", "hajek_precision")}})
    write_csv(dest / "precision_sensitivity.csv", headline)
    print(json.dumps({"exact_sample_match": True, "selected_flows": sum(row["expected_n"] for row in checks),
                      "output_dir": str(dest), "headline": headline}, indent=2))


if __name__ == "__main__":
    main()
