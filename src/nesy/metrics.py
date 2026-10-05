"""Aggregate run records into the tables used for RQ1-RQ4, plus manual-label sheets.

Precision needs explicit TP/FP judgements: ``python -m nesy label-sheet`` writes ``labels/<subject>-<version>.csv``
listing every distinct reported flow; fill the ``label`` column with TP or FP (keep notes).
The ``priority`` column marks a stratified random sample to label: ``1`` = flows through the
fixed methods (GT stratum), ``2`` = other flows; up to ``per_config`` of each per main configuration.
Precision uses a frozen sampling manifest and an inverse-inclusion-probability
Horvitz--Thompson TP total divided by the known number of reported flows. The
manifest describes the ORIGINAL sample, even after corrected run records change.
Missing judgements and flows outside that sampling frame stay unknown.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import REPO_ROOT, Settings

LABEL_DIR = REPO_ROOT / "labels"
LABEL_FIELDS = ["priority", "flow_id", "flow_key", "gt_methods", "configs", "source", "sink", "label", "notes"]
# configurations whose alarms are sampled for labelling (ablations reuse v3's flows)
MAIN_CONFIGS = ("B1", "B2", "v1", "v2", "v3", "v4", "iris-like")
PER_CONFIG_SAMPLE = 10
SAMPLING_SCHEMA = "nesy-frozen-label-sampling-v1"


def load_runs(results_dir: Path) -> List[dict]:
    out = []
    for p in sorted((Path(results_dir) / "runs").rglob("run*.json")):
        try:
            out.append(json.loads(p.read_text()))
        except json.JSONDecodeError:
            continue
    return out


# ----------------------------------------------------------------- labels

def label_path(subject: str, version: str) -> Path:
    return LABEL_DIR / f"{subject}-{version}.csv"


def read_labels(subject: str, version: str) -> Dict[str, dict]:
    p = label_path(subject, version)
    if not p.exists():
        return {}
    with open(p, newline="") as f:
        return {r["flow_key"]: r for r in csv.DictReader(f)}


def load_sampling_manifest() -> dict:
    """Read the original sampling frame; never rebuild it from current results."""
    path = LABEL_DIR / "sampling_manifest.json"
    if not path.exists():
        return {}
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != SAMPLING_SCHEMA or not isinstance(manifest.get("frames"), dict):
        raise ValueError(f"Invalid frozen label-sampling manifest: {path}")
    return manifest


def sampling_frame(manifest: dict, subject: str, version: str) -> dict:
    return manifest.get("frames", {}).get(f"{subject}|{version}", {})


def write_label_sheet(runs: List[dict], subject: str, version: str,
                      per_config: int = PER_CONFIG_SAMPLE) -> Path:
    """Create/refresh the sheet, preserving labels and notes already filled in."""
    old = read_labels(subject, version)
    rows: Dict[str, dict] = {}
    reported_by: Dict[str, set] = defaultdict(set)
    for r in runs:
        if r["subject"] != subject or r["version"] != version:
            continue
        for f in r["flows"]:
            row = rows.setdefault(f["key"], {
                "flow_id": f["id"], "flow_key": f["key"], "gt_methods": set(), "configs": set(),
                "source": f["source"], "sink": f["sink"], "label": "", "notes": ""})
            # the same flow key can match the fixed methods in one run and not in another (the route
            # differs per driver/spec), so the sheet shows the union over all runs
            row["gt_methods"].update(f["gt"])
            if f["reported"]:
                row["configs"].add(r["config"])
                reported_by[r["config"]].add(f["key"])
    for k, row in rows.items():
        row["configs"] = ",".join(sorted(row["configs"]))
        row["gt_methods"] = ";".join(sorted(row["gt_methods"]))
        row["priority"] = ""
    frame = sampling_frame(load_sampling_manifest(), subject, version)
    if frame:
        # A corrected run must not silently replace the probability sample.
        # New flows stay unsampled until an explicit new design is recorded.
        for key, row in rows.items():
            row["priority"] = frame["flows"].get(key, {}).get("priority", "")
    else:
        # initial deterministic draws, before a manifest has been frozen.
        for c in MAIN_CONFIGS:
            keys = sorted(reported_by.get(c, ()))
            for stratum, prio in (("gt", "1"), ("other", "2")):
                cand = [k for k in keys if bool(rows[k]["gt_methods"]) == (stratum == "gt")]
                rng = random.Random(f"{subject}|{version}|{c}|{stratum}")
                for k in (cand if len(cand) <= per_config else rng.sample(cand, per_config)):
                    if not rows[k]["priority"] or prio < rows[k]["priority"]:
                        rows[k]["priority"] = prio
    for k, row in rows.items():
        if k in old:
            row["label"] = old[k].get("label", "")
            row["notes"] = old[k].get("notes", "")
    for k, row in old.items():          # keep labels of flows no longer reported
        priority = frame["flows"].get(k, {}).get("priority", "") if frame else row.get("priority", "")
        rows.setdefault(k, dict(row, priority=priority))
    p = label_path(subject, version)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=LABEL_FIELDS)
        w.writeheader()
        # sampled rows first (1, then 2), GT-relevant before others, similar sinks next to each other
        for row in sorted(rows.values(), key=lambda x: (x.get("priority") or "9", not x["gt_methods"],
                                                        x.get("sink", ""), x["flow_key"])):
            w.writerow({k: row.get(k, "") for k in LABEL_FIELDS})
    return p


# ----------------------------------------------------------------- aggregation

def _mean_sd(xs: List[float]) -> Tuple[Optional[float], Optional[float]]:
    xs = [x for x in xs if x is not None]
    if not xs:
        return None, None
    return round(statistics.mean(xs), 3), (round(statistics.stdev(xs), 3) if len(xs) > 1 else 0.0)


def _jaccard_mean(sets: List[set]) -> Optional[float]:
    if len(sets) < 2:
        return None
    vals = []
    for i in range(len(sets)):
        for j in range(i + 1, len(sets)):
            u = sets[i] | sets[j]
            vals.append(len(sets[i] & sets[j]) / len(u) if u else 1.0)
    return round(sum(vals) / len(vals), 3)


def _label(labels: Dict[str, dict], key: str) -> str:
    return (labels.get(key, {}).get("label") or "").strip().upper()


def descriptive_precision_of(run: dict, labels: Dict[str, dict]) -> Tuple[Optional[float], int, int]:
    """Historical descriptive estimate retained only as a diagnostic.

    Stratified estimate: reported flows are split into GT-relevant and other flows; in each
    stratum the TP share of the labelled flows is weighted by the number of reported flows in that
    stratum. None when a non-empty stratum has no labelled flow."""
    rep = [f for f in run["flows"] if f["reported"]]
    if not rep:
        return None, 0, 0
    est_tp, n_lab = 0.0, 0
    for in_gt in (True, False):
        stratum = [f for f in rep if bool(f["gt"]) == in_gt]
        lab = [_label(labels, f["key"]) for f in stratum if _label(labels, f["key"]) in ("TP", "FP")]
        n_lab += len(lab)
        if stratum and not lab:
            return None, n_lab, len(rep)
        if stratum:
            est_tp += len(stratum) * lab.count("TP") / len(lab)
    return round(est_tp / len(rep), 3), n_lab, len(rep)


def precision_diagnostics_of(run: dict, labels: Dict[str, dict], frame: Optional[dict] = None) -> dict:
    """HT domain estimate and coverage, using original inclusion probabilities.

    The estimand is precision among this run's known set of reported flow keys.
    Additional ad-hoc labels do not enter the HT sum. For a fully covered domain,
    an empty intersection with the random sample gives HT=0 with coverage zero;
    it does NOT assert that the unobserved flows are false positives. Excluding
    such domains would condition the macro mean on having sampled a flow.

    Precision is unknown if any reported key was outside the original positive-
    probability frame, or an originally selected reported key lacks a TP/FP
    judgement. Labels missing outside this domain do not affect its estimate.
    HT is not clipped to [0,1]: clipping would change the estimator.
    """
    reported = {flow["key"] for flow in run["flows"] if flow["reported"]}
    result = {"precision": None, "status": "no-reported-flows", "reported": len(reported),
              "sampled_reported": 0, "labelled_sampled_reported": 0,
              "missing_sampled_labels": 0, "uncovered_reported": 0,
              "weighted_tp_total": None, "label_coverage": None}
    if not reported:
        return result
    if frame is None:
        frame = sampling_frame(load_sampling_manifest(), run["subject"], run["version"])
    if not frame:
        result.update(status="missing-sampling-frame", uncovered_reported=len(reported), label_coverage=0.0)
        return result
    population = frame["flows"]
    weighted_tp = 0.0
    for key in reported:
        item = population.get(key)
        if item is None:
            result["uncovered_reported"] += 1
            continue
        probability = item["inclusion_probability"]
        if not isinstance(probability, (int, float)) or not math.isfinite(probability) or not 0 <= probability <= 1:
            raise ValueError(f"Invalid frozen inclusion probability for {key!r}: {probability!r}")
        if probability == 0:
            result["uncovered_reported"] += 1
            continue
        if item["selected"]:
            result["sampled_reported"] += 1
            label = _label(labels, key)
            if label not in ("TP", "FP"):
                result["missing_sampled_labels"] += 1
            else:
                result["labelled_sampled_reported"] += 1
                weighted_tp += (label == "TP") / probability
    result["label_coverage"] = result["labelled_sampled_reported"] / len(reported)
    if result["uncovered_reported"]:
        result["status"] = "uncovered-reported-flows"
    elif result["missing_sampled_labels"]:
        result["status"] = "missing-sampled-labels"
    else:
        result.update(precision=weighted_tp / len(reported), weighted_tp_total=weighted_tp,
                      status="ok" if result["sampled_reported"] else "no-sampled-reported-flows")
    return result


def precision_of(run: dict, labels: Dict[str, dict], frame: Optional[dict] = None) -> Tuple[Optional[float], int, int]:
    """(HT precision estimate, #judged sampled reported flows, #reported flows)."""
    result = precision_diagnostics_of(run, labels, frame)
    return result["precision"], result["labelled_sampled_reported"], result["reported"]


def iris_metrics_of(run: dict) -> Tuple[Optional[float], int, float]:
    """IRIS's automatic metrics for one run (Li et al., ICLR 2025, Sec. 5): a reported flow counts as a
    vulnerable path when it passes through a fixed location (our `gt`). Returns (Prec, Rec, F1);
    Prec is None when nothing is reported (IRIS averages FDR only over projects with paths)."""
    rep = [f for f in run["flows"] if f["reported"]]
    rec = 1 if run.get("detected") else 0
    if not rep:
        return None, rec, 0.0
    prec = sum(1 for f in rep if f["gt"]) / len(rep)
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return prec, rec, f1


def confirmed_of(run: dict, labels: Dict[str, dict]) -> Optional[bool]:
    """True: a reported GT-relevant flow is labelled TP. False: none is (all labelled FP, or no GT flow
    reported). None: unknown, because some reported GT-relevant flows are still unlabelled."""
    gt = [f for f in run["flows"] if f["reported"] and f["gt"]]
    labs = [_label(labels, f["key"]) for f in gt]
    if "TP" in labs:
        return True
    if all(x == "FP" for x in labs):
        return False
    return None


def tp_reported_of(run: dict, labels: Dict[str, dict]) -> Optional[bool]:
    """True when the run reports at least one flow labelled TP, in either stratum. Unlike
    `confirmed_of` this also credits a real flow that the method-level GT misses (e.g. a route that
    leaves the application code). None when the subject/version has no labels at all."""
    if not any(_label(labels, k) in ("TP", "FP") for k in labels):
        return None
    return any(_label(labels, f["key"]) == "TP" for f in run["flows"] if f["reported"])


FP_CATEGORIES = ["DRV", "SPEC-FP", "IMP", "SAN", "HALLU", "TOOL"]
_CAT_RE = re.compile(r"\b(DRV|SPEC-FP|IMP|SAN|HALLU|TOOL)\b")


def fp_category(row: dict) -> str:
    """Taxonomy code of an FP label, read from the notes column (first code mentioned); '?' if none."""
    m = _CAT_RE.search(row.get("notes") or "")
    return m.group(1) if m else "?"


def label_breakdown(runs: List[dict]) -> List[dict]:
    """per configuration, the distinct labelled flows it reported in any run (buggy and fixed
    versions, all subjects), split into TP and FP categories."""
    cache: Dict[Tuple[str, str], Dict[str, dict]] = {}
    seen: Dict[str, set] = defaultdict(set)
    for r in runs:
        labels = cache.setdefault((r["subject"], r["version"]), read_labels(r["subject"], r["version"]))
        for f in r["flows"]:
            if f["reported"] and _label(labels, f["key"]) in ("TP", "FP"):
                seen[r["config"]].add((r["subject"], r["version"], f["key"]))
    out = []
    for c in sorted(seen, key=lambda c: (c[0] != "B", c)):
        row = {"config": c, "labelled": len(seen[c]), "TP": 0, **{k: 0 for k in FP_CATEGORIES}, "?": 0}
        for s, v, k in seen[c]:
            lab = cache[(s, v)][k]
            if _label(cache[(s, v)], k) == "TP":
                row["TP"] += 1
            else:
                row[fp_category(lab)] += 1
        out.append(row)
    return out


def recall_of(run: dict, labels: Dict[str, dict]) -> Optional[float]:
    """Relative ("pooled") recall: share of all TP-labelled flows of that subject/version (union over
    configurations) that this run reports. The pool is what the labelled sample found, not all bugs;
    CVE-level recall is `confirmed_detected_rate`."""
    tps = {k for k, v in labels.items() if v.get("label", "").strip().upper() == "TP"}
    if not tps:
        return None
    found = {f["key"] for f in run["flows"] if f["reported"]} & tps
    return round(len(found) / len(tps), 3)


def summarise(runs: List[dict]) -> List[dict]:
    groups: Dict[Tuple[str, str, str], List[dict]] = defaultdict(list)
    for r in runs:
        groups[(r["subject"], r["version"], r["config"])].append(r)
    rows = []
    label_cache: Dict[Tuple[str, str], Dict[str, dict]] = {}
    manifest = load_sampling_manifest()
    for (s, v, c), rs in sorted(groups.items()):
        labels = label_cache.setdefault((s, v), read_labels(s, v))
        frame = sampling_frame(manifest, s, v)
        precs, cover, recs, diagnostics, descriptive = [], [], [], [], []
        for r in rs:
            diagnostic = precision_diagnostics_of(r, labels, frame)
            diagnostics.append(diagnostic)
            precs.append(diagnostic["precision"])
            cover.append(diagnostic["label_coverage"])
            descriptive.append(descriptive_precision_of(r, labels)[0])
            recs.append(recall_of(r, labels))
        def m(path):
            vals = []
            for r in rs:
                x = r
                for k in path:
                    x = x.get(k) if isinstance(x, dict) else None
                vals.append(x if isinstance(x, (int, float)) else None)
            return _mean_sd(vals)
        has_labels = any(_label(labels, k) in ("TP", "FP") for k in labels)
        confirmed = [confirmed_of(r, labels) for r in rs] if has_labels else []
        known = [c for c in confirmed if c is not None]
        tp_rep = [tp_reported_of(r, labels) for r in rs]
        tp_rep = [x for x in tp_rep if x is not None]
        prec_m, prec_sd = _mean_sd(precs)
        unknown_nonempty = sum(d["reported"] > 0 and d["precision"] is None for d in diagnostics)
        # Empty runs have undefined precision and are omitted. Unsupported
        # nonempty runs must not disappear from the mean as if they were empty.
        if unknown_nonempty:
            prec_m, prec_sd = None, None
        rec_m, _ = _mean_sd(recs)
        if prec_m is None or rec_m is None:
            f1 = None
        else:
            f1 = round(2 * prec_m * rec_m / (prec_m + rec_m), 3) if prec_m + rec_m else 0.0
        rows.append({
            "subject": s, "version": v, "config": c, "runs": len(rs),
            "detected_rate": round(sum(1 for r in rs if r["detected"]) / len(rs), 3),
            # detection confirmed by an explicit label (GT-relevant flow labelled TP); method-level GT
            # matching alone can credit a flow that reaches a fixed method for the wrong reason
            "confirmed_detected_rate": round(sum(known) / len(known), 3) if known else None,
            "confirmed_known_runs": len(known),
            # run reports any flow labelled TP (either stratum)
            "tp_reported_rate": round(sum(tp_rep) / len(tp_rep), 3) if tp_rep else None,
            "reported_mean": m(["counts", "reported"])[0], "reported_sd": m(["counts", "reported"])[1],
            "reported_gt_mean": m(["counts", "reported_gt"])[0],
            "raw_flows_mean": m(["counts", "raw"])[0],
            "removed_by_triage_mean": m(["counts", "removed_by_triage"])[0],
            "removed_gt_by_triage_mean": m(["counts", "removed_gt_by_triage"])[0],
            "v3_rejected_mean": m(["counts", "v3_rejected"])[0],
            "precision_mean": prec_m, "precision_sd": prec_sd,
            "precision_estimator": "HT-frozen-sample-v1",
            "precision_known_runs": sum(p is not None for p in precs),
            "precision_nonempty_runs": sum(d["reported"] > 0 for d in diagnostics),
            "precision_unknown_nonempty_runs": unknown_nonempty,
            "precision_zero_sample_runs": sum(d["status"] == "no-sampled-reported-flows" for d in diagnostics),
            "precision_status": ",".join(sorted({d["status"] for d in diagnostics})),
            "precision_descriptive_mean": _mean_sd(descriptive)[0],
            # IRIS-inspired patch-method metrics; engine/path/aggregation differences prevent direct score comparison
            "auto_precision_mean": _mean_sd([iris_metrics_of(r)[0] for r in rs])[0],
            "auto_fdr_mean": (round(1 - _mean_sd([iris_metrics_of(r)[0] for r in rs])[0], 3)
                              if _mean_sd([iris_metrics_of(r)[0] for r in rs])[0] is not None else None),
            "auto_f1_mean": _mean_sd([iris_metrics_of(r)[2] for r in rs])[0],
            "label_coverage_mean": _mean_sd(cover)[0],
            "recall_mean": rec_m, "f1": f1,
            "flowset_jaccard": _jaccard_mean([{f["key"] for f in r["flows"] if f["reported"]} for r in rs]),
            "taie_s_mean": m(["taie", "elapsed_s"])[0], "total_s_mean": m(["timings", "total_s"])[0],
            "tokens_mean": _mean_sd([(r["usage"]["total"].get("prompt_tokens", 0) +
                                      r["usage"]["total"].get("completion_tokens", 0)) for r in rs])[0],
            "llm_calls_mean": m(["usage", "total", "calls"])[0],
            "driver_kind": ",".join(sorted({r["driver"]["kind"] for r in rs})),
            "spec_accepted_mean": _mean_sd([(r.get("spec") or {}).get("accepted") for r in rs])[0],
            "spec_rejected_mean": _mean_sd([(r.get("spec") or {}).get("rejected") for r in rs])[0],
            "spec_agreement_mean": _mean_sd([(r.get("spec") or {}).get("mean_vote_agreement") for r in rs])[0],
            "taie_failures": sum(1 for r in rs if not r["taie"]["ok"]),
            # of which crashes caused by invalid N2 entries in the V2-off ablations
            "taie_failures_invalid_spec": sum(1 for r in rs if r["taie"].get("expected_failure")),
            "llm_driver_fallbacks": sum(1 for r in rs if r["driver"]["kind"] == "llm-fallback-template"),
        })
    return rows


def cve_table(rows: List[dict]) -> List[dict]:
    """One row per subject x config: detected on buggy, residual GT flows on fixed."""
    by = {(r["subject"], r["version"], r["config"]): r for r in rows}
    out = []
    for (s, v, c), r in sorted(by.items()):
        if v != "buggy":
            continue
        fx = by.get((s, "fixed", c))
        out.append({"subject": s, "config": c, "detected_rate_buggy": r["detected_rate"],
                    "confirmed_detected_rate_buggy": r.get("confirmed_detected_rate"),
                    "gt_flows_buggy": r["reported_gt_mean"],
                    "gt_flows_fixed": fx["reported_gt_mean"] if fx else None,
                    "differential_ok": (r["detected_rate"] > 0 and fx is not None and
                                        (fx["reported_gt_mean"] or 0) < (r["reported_gt_mean"] or 0))})
    return out


def headline_table(rows: List[dict], cves: List[dict]) -> List[dict]:
    """One row per configuration over all subjects (buggy versions): the numbers for the abstract."""
    out = []
    configs = sorted({r["config"] for r in rows}, key=lambda c: (c[0] != "B", c))
    for c in configs:
        rb = [r for r in rows if r["config"] == c and r["version"] == "buggy"]
        rf = {r["subject"]: r for r in rows if r["config"] == c and r["version"] == "fixed"}
        if not rb:
            continue
        conf = [r["confirmed_detected_rate"] for r in rb if r.get("confirmed_detected_rate") is not None]
        prec = [r["precision_mean"] for r in rb if r.get("precision_mean") is not None]
        unknown_precision = sum(r.get("precision_unknown_nonempty_runs", 0) > 0 for r in rb)
        tpr = [r["tp_reported_rate"] for r in rb if r.get("tp_reported_rate") is not None]
        out.append({
            "config": c, "subjects": len(rb),
            "cves_detected": sum(1 for r in rb if r["detected_rate"] > 0),
            "detection_rate_mean": round(statistics.mean(r["detected_rate"] for r in rb), 3),
            "cves_confirmed": sum(1 for x in conf if x > 0) if conf else None,
            "confirmed_rate_mean": round(statistics.mean(conf), 3) if conf else None,
            "precision_mean": round(statistics.mean(prec), 3) if prec and not unknown_precision else None,
            "precision_subjects": len(prec),
            "precision_unknown_subjects": unknown_precision,
            "precision_known_runs": sum(r.get("precision_known_runs", 0) for r in rb),
            "precision_nonempty_runs": sum(r.get("precision_nonempty_runs", 0) for r in rb),
            "precision_zero_sample_runs": sum(r.get("precision_zero_sample_runs", 0) for r in rb),
            "precision_descriptive_mean": _mean_sd([r.get("precision_descriptive_mean") for r in rb])[0],
            "cves_tp_reported": sum(1 for x in tpr if x > 0) if tpr else None,
            "tp_reported_rate_mean": round(statistics.mean(tpr), 3) if tpr else None,
            "alarms_buggy_total": round(sum(r["reported_mean"] or 0 for r in rb), 1),
            "alarms_fixed_total": round(sum((rf[s]["reported_mean"] or 0) for s in rf), 1),
            "differential_ok": sum(1 for x in cves if x["config"] == c and x["differential_ok"]),
            "iris_avg_fdr": (round(statistics.mean(r["auto_fdr_mean"] for r in rb if r.get("auto_fdr_mean")
                                                   is not None), 3)
                             if any(r.get("auto_fdr_mean") is not None for r in rb) else None),
            "iris_avg_f1": round(statistics.mean(r.get("auto_f1_mean") or 0 for r in rb), 3),
            "llm_driver_fallbacks": sum(r.get("llm_driver_fallbacks") or 0 for r in rb + list(rf.values())),
            "taie_failures": sum(r.get("taie_failures") or 0 for r in rb + list(rf.values())),
        })
    return out


def write_csv(rows: List[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    keys = list(rows[0].keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def markdown_table(rows: List[dict], cols: List[str]) -> str:
    if not rows:
        return "_no data_\n"
    out = ["| " + " | ".join(cols) + " |", "| " + " | ".join("---" for _ in cols) + " |"]
    for r in rows:
        out.append("| " + " | ".join("" if r.get(c) is None else str(r.get(c)) for c in cols) + " |")
    return "\n".join(out) + "\n"


def triage_breakdown(runs: List[dict]) -> List[dict]:
    rows: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in runs:
        for f in r["flows"]:
            t = f.get("triage")
            if not t:
                continue
            d = rows[(r["config"], r["subject"])]
            d[t["verdict"]] += 1
            d["v3_rejected"] += 1 if t.get("v3_ok") is False else 0
            d["removed"] += 0 if t["kept"] else 1
            d["removed_gt"] += 1 if (not t["kept"] and f["gt"]) else 0
    out = []
    for (c, s), d in sorted(rows.items()):
        out.append({"config": c, "subject": s, **{k: d.get(k, 0) for k in
                    ("vulnerable", "not_vulnerable", "uncertain", "v3_rejected", "removed", "removed_gt")}})
    return out


def subjects_table(runs: List[dict]) -> List[dict]:
    """One row per subject/version: size of the analysed code and baseline cost (evaluation setting)."""
    out: Dict[Tuple[str, str], dict] = {}
    for r in sorted(runs, key=lambda x: (x["config"] != "B1", x["run"])):
        key = (r["subject"], r["version"])
        if key in out:
            continue
        st, fa = r.get("subject_stats") or {}, r.get("facts") or {}
        b1 = next((x for x in runs if x["subject"] == r["subject"] and x["version"] == r["version"]
                   and x["config"] == "B1"), None)
        out[key] = {"subject": r["subject"], "version": r["version"], "cve": r.get("cve"), "cwe": r.get("cwe"),
                    "java_files": st.get("java_files"), "non_blank_loc": st.get("non_blank_loc"),
                    "dependency_jars": st.get("dependency_jars"), "app_classes": fa.get("app_classes"),
                    "app_methods": fa.get("app_methods"), "external_apis": fa.get("external_apis"),
                    "entry_candidates": fa.get("entry_candidates"),
                    "gt_methods": len(r.get("gt_methods") or []),
                    "b1_reachable_methods": (b1 or {}).get("taie", {}).get("reachable_methods"),
                    "b1_taie_s": (b1 or {}).get("taie", {}).get("elapsed_s"),
                    "b1_ok": (b1 or {}).get("taie", {}).get("ok")}
    return list(out.values())


def budget_table(runs: List[dict]) -> List[dict]:
    """Resource budget per configuration (the brief asks to report it and its effect on scope)."""
    agg: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
    models: Dict[str, set] = defaultdict(set)
    replayed: Dict[str, bool] = defaultdict(bool)
    for r in runs:
        a = agg[r["config"]]
        replayed[r["config"]] |= (r.get("result_revision") or {}).get("kind") == "validator-correction-replay"
        a["runs"] += 1
        u = (r.get("usage") or {}).get("total") or {}
        for k in ("calls", "cached_calls", "prompt_tokens", "completion_tokens", "fresh_prompt_tokens",
                  "fresh_completion_tokens", "latency_s", "truncated"):
            a[k] += float(u.get(k, 0) or 0)
        a["taie_s"] += float((r.get("taie") or {}).get("elapsed_s") or 0)
        a["total_s"] += float((r.get("timings") or {}).get("total_s") or 0)
        models[r["config"]].update(r.get("served_models") or ([r["model"]] if r.get("model") else []))
    rows = []
    for c, a in sorted(agg.items()):
        recorded_tokens = int(a["fresh_prompt_tokens"] + a["fresh_completion_tokens"])
        recorded_hours = round(a["latency_s"] / 3600, 2)
        rows.append({"config": c, "runs": int(a["runs"]), "llm_calls": int(a["calls"]),
                     "tokens_in": int(a["prompt_tokens"]), "tokens_out": int(a["completion_tokens"]),
                     # Replay records mix historical driver statistics and
                     # cached/replayed stages: these are not actual fresh spend.
                     "fresh_tokens": None if replayed[c] else recorded_tokens,
                     "llm_hours": None if replayed[c] else recorded_hours,
                     "recorded_stage_fresh_tokens": recorded_tokens,
                     "recorded_stage_llm_hours": recorded_hours,
                     "cost_semantics": ("mixed-stage-validator-replay; fresh spend: results/provenance"
                                        if replayed[c] else "recorded-run-stage-cost"),
                     "taie_hours": round(a["taie_s"] / 3600, 2),
                     "truncated_answers": int(a["truncated"]), "models": ",".join(sorted(models[c])) or "-"})
    return rows


_SIG = re.compile(r"<([\w.$]+): \S+ ([\w<>$]+)\([^)]*\)>")


def _short(key: str, width: int = 160) -> str:
    """Abbreviate Tai-e signatures: <a.b.Outer$In: void m(x,y)> -> Outer$In.m()."""
    key = _SIG.sub(lambda m: f"{m.group(1).rsplit('.', 1)[-1]}.{m.group(2)}()", key)
    return key if len(key) <= width else key[:width - 3] + "..."


def case_candidates(runs: List[dict]) -> str:
    """Markdown list of flows worth a case study: wins, losses, triage mistakes, misses, residuals."""
    by: Dict[Tuple[str, str], Dict[str, List[dict]]] = defaultdict(lambda: defaultdict(list))
    for r in runs:
        by[(r["subject"], r["version"])][r["config"]].append(r)
    lines = ["# Case-study candidates", "",
             "Generated by `python -m nesy evaluate`. Use these to pick representative successes, failures,",
             "false positives/negatives and unexpected behaviour for the report (RQ3). Keys: `source => sink@line/arg`.", ""]
    for (s, v), cfgs in sorted(by.items()):
        lines.append(f"## {s} / {v}")
        labels = read_labels(s, v)

        def gt_keys(c):
            return {f["key"] for r in cfgs.get(c, []) for f in r["flows"] if f["reported"] and f["gt"]}

        def rep_keys(c):
            return {f["key"] for r in cfgs.get(c, []) for f in r["flows"] if f["reported"]}
        gt_any = set().union(*[gt_keys(c) for c in cfgs]) if cfgs else set()
        anyrun = next(iter(next(iter(cfgs.values()))), {})
        if v == "buggy" and not gt_any:
            lines.append(f"- **No configuration reports a patch-relevant flow.** Fixed methods: "
                         f"{', '.join(anyrun.get('gt_methods') or []) or '?'} -> false-negative analysis "
                         "(entry not reached? missing spec? lost flow?)")
        for a, b in (("v3", "B1"), ("v3", "B2"), ("v1", "B1")):
            if a in cfgs and b in cfgs:
                win, loss = gt_keys(a) - gt_keys(b), gt_keys(b) - gt_keys(a)
                if win:
                    lines.append(f"- GT-relevant flows found by **{a}** but not {b}:")
                    lines += [f"  - `{_short(k)}`" for k in sorted(win)[:8]]
                if loss:
                    lines.append(f"- GT-relevant flows found by {b} but **lost by {a}**:")
                    lines += [f"  - `{_short(k)}`" for k in sorted(loss)[:8]]
        for c, rs in sorted(cfgs.items()):
            for r in rs:
                for f in r["flows"]:
                    t = f.get("triage")
                    if not t:
                        continue
                    lab = labels.get(f["key"], {}).get("label", "").strip().upper()
                    if not t["kept"] and (f["gt"] or lab == "TP"):
                        lines.append(f"- Triage in {c} run{r['run']} **removed a flow** "
                                     f"(patch-method overlap: {'yes' if f['gt'] else 'no'}; "
                                     f"saved label: {lab or 'unlabelled'}; "
                                     f"reason: {t.get('reason')}): `{_short(f['key'])}`")
                    elif t.get("v3_ok") is False:
                        lines.append(f"- V3 rejected a 'not_vulnerable' verdict in {c} run{r['run']} "
                                     f"({'; '.join(t.get('v3_problems') or [])[:120]}): `{_short(f['key'])}`")
        fps = defaultdict(int)
        for k, row in labels.items():
            if row.get("label", "").strip().upper() == "FP":
                fps[fp_category(row)] += 1
        if fps:
            lines.append("- FP categories in the saved labels: " + ", ".join(f"{k}={n}" for k, n in sorted(fps.items())))
        only_b1 = rep_keys("B1") - rep_keys("v3") if "B1" in cfgs and "v3" in cfgs else set()
        if only_b1:
            lines.append(f"- {len(only_b1)} B1 alarms not reported by v3 (driver/triage effect), e.g. "
                         f"`{_short(sorted(only_b1)[0])}`")
        lines.append("")
    return "\n".join(lines)


def latex_table(rows: List[dict], cols: List[str], caption: str, label: str) -> str:
    def esc(x):
        return str(x).replace("_", "\\_").replace("%", "\\%").replace("&", "\\&")
    out = ["\\begin{table}[t]", "\\centering\\small", f"\\caption{{{caption}}}", f"\\label{{{label}}}",
           "\\resizebox{\\columnwidth}{!}{%",
           "\\begin{tabular}{" + "l" * min(3, len(cols)) + "r" * max(0, len(cols) - 3) + "}", "\\toprule",
           " & ".join(esc(c) for c in cols) + " \\\\", "\\midrule"]
    for r in rows:
        out.append(" & ".join("--" if r.get(c) is None else esc(r.get(c)) for c in cols) + " \\\\")
    out += ["\\bottomrule", "\\end{tabular}}", "\\end{table}", ""]
    return "\n".join(out)


def evaluate_test(runs: List[dict], out: Path) -> Path:
    """Held-out test set: the same automatic metrics as the development set, written to
    results/summary/test/. No flow labels exist for these subjects, so label-based columns stay empty."""
    out.mkdir(parents=True, exist_ok=True)
    rows = summarise(runs)
    write_csv(rows, out / "by_config.csv")
    cves = cve_table(rows)
    write_csv(cves, out / "cve_detection.csv")
    head = headline_table(rows, cves)
    write_csv(head, out / "headline.csv")
    write_csv(triage_breakdown(runs), out / "triage.csv")
    subj = subjects_table(runs)
    write_csv(subj, out / "subjects.csv")
    budget = budget_table(runs)
    write_csv(budget, out / "budget.csv")
    md = ["# Held-out test set", "",
          "Frozen analyzer, subjects never used during development. Automatic metrics only (no labels).", "",
          "## Headline - test subjects, buggy versions", "",
          markdown_table(head, ["config", "subjects", "cves_detected", "detection_rate_mean", "iris_avg_fdr",
                                "iris_avg_f1", "alarms_buggy_total", "alarms_fixed_total", "differential_ok",
                                "llm_driver_fallbacks", "taie_failures"]),
          "## CVE detection and differential check", "",
          markdown_table(cves, ["subject", "config", "detected_rate_buggy", "gt_flows_buggy", "gt_flows_fixed",
                                "differential_ok"]),
          "## Per subject, version, configuration", "",
          markdown_table(rows, ["subject", "version", "config", "runs", "detected_rate", "reported_mean",
                                "reported_gt_mean", "auto_fdr_mean", "auto_f1_mean", "driver_kind",
                                "taie_failures"]),
          "## Subjects", "",
          markdown_table(subj, ["subject", "version", "cve", "cwe", "non_blank_loc", "dependency_jars",
                                "external_apis", "gt_methods", "b1_taie_s", "b1_ok"]),
          "## Resource budget", "",
          markdown_table(budget, ["config", "runs", "llm_calls", "fresh_tokens", "llm_hours", "taie_hours"])]
    (out / "summary.md").write_text("\n".join(md))
    return out


def evaluate(settings: Settings) -> Path:
    all_runs = load_runs(settings.results_dir)
    # held-out test subjects are reported separately and never mixed into development numbers.
    test_ids = {s.id for s in settings.subjects.values() if s.role == "test"}
    runs = [r for r in all_runs if r["subject"] not in test_ids]
    test_runs = [r for r in all_runs if r["subject"] in test_ids]
    out = settings.results_dir / "summary"
    if test_runs:
        evaluate_test(test_runs, out / "test")
    rows = summarise(runs)
    write_csv(rows, out / "by_config.csv")
    manifest = load_sampling_manifest()
    label_cache = {(s, v): read_labels(s, v) for s, v in sorted({(r["subject"], r["version"]) for r in runs})}
    precision_runs = []
    for run in runs:
        subject, version = run["subject"], run["version"]
        labels = label_cache[subject, version]
        precision_runs.append({"subject": subject, "version": version, "config": run["config"], "run": run["run"],
                               **precision_diagnostics_of(run, labels, sampling_frame(manifest, subject, version)),
                               "descriptive_precision": descriptive_precision_of(run, labels)[0]})
    write_csv(precision_runs, out / "precision_per_run.csv")
    manifest_path = LABEL_DIR / "sampling_manifest.json"
    provenance = {
        "estimator": "HT-frozen-sample-v1",
        "formula": "sum(originally sampled AND currently reported TP / original inclusion probability) / current reported count",
        "manifest": "labels/sampling_manifest.json",
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_path.exists() else None,
        "original_run_count": manifest.get("source_run_count"), "original_sample_count": manifest.get("selected_count"),
        "current_label_sha256": {f"{s}-{v}.csv": hashlib.sha256(label_path(s, v).read_bytes()).hexdigest()
                                 for s, v in sorted(label_cache) if label_path(s, v).exists()},
        "empty_runs": "Precision undefined; omit from precision means.",
        "unknown_nonempty_runs": "Unseen or zero-probability reported flow, missing sampling frame, or missing sampled reported label. Propagate unknown to subject/config and headline precision.",
        "zero_sample_domains": "Covered nonempty domain with no sampled member has HT=0 and coverage=0; retained in means. This is an estimate, not a judgement that unseen flows are FP.",
        "uncertain_labels": "Only current TP/FP labels count; UNSURE, ?, and empty are missing judgements. Ad-hoc labels outside the original sample do not enter HT.",
        "limits": "HT may exceed 1 and is not clipped. The frozen design corrects unequal sampling, not LLM labelling errors, route-dependent label identity, or selection after inspecting labels. No confidence interval is claimed.",
    }
    (out / "precision_provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    cves = cve_table(rows)
    write_csv(cves, out / "cve_detection.csv")
    head = headline_table(rows, cves)
    write_csv(head, out / "headline.csv")
    tri = triage_breakdown(runs)
    write_csv(tri, out / "triage.csv")
    labs = label_breakdown(runs)
    write_csv(labs, out / "labels.csv")
    subj = subjects_table(runs)
    write_csv(subj, out / "subjects.csv")
    budget = budget_table(runs)
    write_csv(budget, out / "budget.csv")
    (out / "cases.md").write_text(case_candidates(runs))
    rq1_cols = ["subject", "version", "config", "runs", "detected_rate", "reported_mean", "reported_gt_mean",
                "auto_fdr_mean", "auto_f1_mean", "confirmed_detected_rate", "confirmed_known_runs",
                "tp_reported_rate", "precision_mean", "precision_known_runs", "precision_nonempty_runs",
                "precision_status", "label_coverage_mean", "recall_mean", "f1"]
    md = ["# Results summary", "",
          "Generated by `python -m nesy evaluate`. Automatic metrics use patch-method overlap; "
          "label-based measures use the TP/FP judgments in `labels/` (see README).",
          "Case-study candidates: `cases.md`. LaTeX versions of the main tables: `tables.tex`.", "",
          "## Headline - all subjects, buggy versions (one row per configuration)", "",
          "cves_detected / cves_confirmed: subjects (of `subjects`) where at least one run flagged the CVE "
          "(method-level) / where a flagged flow is labelled TP. precision_mean: mean over subjects of the "
          "Horvitz-Thompson domain precision estimate using the frozen original sampling probabilities. "
          "Empty-run precision is undefined and omitted. Unsupported nonempty runs make the subject and headline precision unknown. "
          "differential_ok: subjects where GT flows drop from buggy to fixed.", "",
          markdown_table(head, ["config", "subjects", "cves_detected", "detection_rate_mean", "iris_avg_fdr",
                                "iris_avg_f1", "cves_confirmed", "confirmed_rate_mean", "cves_tp_reported",
                                "tp_reported_rate_mean", "precision_mean", "precision_subjects", "precision_unknown_subjects",
                                "alarms_buggy_total", "alarms_fixed_total", "differential_ok",
                                "llm_driver_fallbacks", "taie_failures"]),
          "iris_avg_fdr / iris_avg_f1: automatic patch-method metrics following IRIS's definitions. "
          "A flow counts as relevant when its source, sink or connecting TFG route matches a recorded fixed method; "
          "this is not an exploitability judgment. FDR = 1 - patch precision, with recall = detected per run. "
          "Scores are averaged over runs and then subjects; engine, path extraction and aggregation differences "
          "prevent direct comparison with published IRIS scores. These metrics need no flow labels. "
          "precision_mean and cves_confirmed are separate label-based estimates and counts. cves_tp_reported "
          "counts subjects where at least one run reports a TP-labelled flow, including flows outside the "
          "recorded patch methods. The study labels are provisional LLM judgments without human verification.", "",
          "Sampling: `labels/sampling_manifest.json` freezes the original 10-per-config/union-GT draws. "
          "For a flow eligible in several independent draws, inclusion probability is one minus the product of its nonselection probabilities. "
          "Only originally selected current TP/FP judgements enter the weighted TP total. "
          "A covered domain containing no sampled flow has HT=0 and coverage=0; that estimate does not label unseen flows FP. "
          "A new/zero-probability reported key or a missing selected judgement makes the affected estimate unknown. "
          "`precision_per_run.csv` gives denominators, coverage and statuses; `precision_provenance.json` records hashes and assumptions. "
          "The old descriptive estimator is retained as `precision_descriptive_mean` only. "
          "These estimates remain conditional on the judgement quality; HT is not clipped and no confidence interval is claimed.", "",
          "## Labelled flows by outcome (distinct flows reported by each configuration, all versions)", "",
          markdown_table(labs, ["config", "labelled", "TP"] + FP_CATEGORIES + ["?"]),
          "## Subjects (evaluation setting)", "",
          markdown_table(subj, ["subject", "version", "cve", "cwe", "java_files", "non_blank_loc", "dependency_jars",
                                "app_classes", "app_methods", "external_apis", "entry_candidates", "gt_methods",
                                "b1_reachable_methods", "b1_taie_s", "b1_ok"]),
          "## RQ1 - effectiveness (per subject, version, configuration)", "",
          markdown_table(rows, rq1_cols),
          "## CVE detection and differential check (buggy vs fixed)", "",
          markdown_table(cves, ["subject", "config", "detected_rate_buggy", "confirmed_detected_rate_buggy",
                                "gt_flows_buggy", "gt_flows_fixed",
                                "differential_ok"]),
          "## RQ2 - stage contributions", "",
          markdown_table(rows, ["subject", "version", "config", "driver_kind", "spec_accepted_mean",
                                "spec_rejected_mean", "removed_by_triage_mean", "removed_gt_by_triage_mean",
                                "v3_rejected_mean"]),
          "## RQ3 - triage verdicts", "", markdown_table(tri, ["config", "subject", "vulnerable", "not_vulnerable",
                                                              "uncertain", "v3_rejected", "removed", "removed_gt"]),
          "## RQ4 - cost and stability", "",
          markdown_table(rows, ["subject", "version", "config", "taie_s_mean", "total_s_mean", "llm_calls_mean",
                                "tokens_mean", "flowset_jaccard", "spec_agreement_mean", "taie_failures"]),
          "## Resource budget (all runs)", "",
          ("Replay cost warning: corrected run records mix historical stage statistics with cached/replayed stages. "
           "Their `fresh_tokens` and `llm_hours` are intentionally unknown. The original counters are preserved "
           "as `recorded_stage_fresh_tokens` and `recorded_stage_llm_hours` in `budget.csv`, with `cost_semantics`. "
           "Use the original-study and correction-replay fresh-spend records in `results/provenance/` for actual API costs."
           if any(b["cost_semantics"].startswith("mixed-stage-") for b in budget)
           else "Fresh-token and model-latency fields sum recorded stage costs for these runs."), "",
          markdown_table(budget, ["config", "runs", "llm_calls", "tokens_in", "tokens_out", "fresh_tokens",
                                  "llm_hours", "taie_hours", "truncated_answers", "models"])]
    (out / "summary.md").write_text("\n".join(md))
    tex = [latex_table(head, ["config", "cves_detected", "detection_rate_mean", "iris_avg_fdr", "iris_avg_f1",
                              "cves_confirmed", "precision_mean", "alarms_buggy_total", "differential_ok"],
                       "Headline results over all subjects",
                       "tab:headline"),
           latex_table(subj, ["subject", "version", "cve", "non_blank_loc", "app_classes", "external_apis",
                              "gt_methods"], "Evaluation subjects", "tab:subjects"),
           latex_table([r for r in rows if r["version"] == "buggy"],
                       ["subject", "config", "detected_rate", "reported_mean", "precision_mean", "recall_mean"],
                       "Effectiveness on the buggy versions", "tab:rq1"),
           latex_table(cves, ["subject", "config", "detected_rate_buggy", "gt_flows_buggy", "gt_flows_fixed"],
                       "CVE detection and buggy/fixed differential", "tab:cve"),
           latex_table(budget, ["config", "runs", "llm_calls", "fresh_tokens", "llm_hours", "taie_hours"],
                       "Resource budget", "tab:budget")]
    (out / "tables.tex").write_text("% Generated by python -m nesy evaluate (needs \\usepackage{booktabs})\n" +
                                    "\n".join(tex))
    return out
