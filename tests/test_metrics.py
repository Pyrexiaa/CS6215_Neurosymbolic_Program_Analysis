import csv
import json
import importlib.util
from pathlib import Path

import pytest

import nesy.metrics as M


def _run(config, run, keys, gt=(), version="buggy", reported=None):
    flows = [{"id": k[:4], "key": k, "source": "s", "sink": "t", "gt": list(gt) if k.startswith("g") else [],
              "reported": True if reported is None else reported.get(k, True), "triage": None} for k in keys]
    rep = [f for f in flows if f["reported"]]
    return {"subject": "s1", "version": version, "config": config, "run": run, "flows": flows,
            "detected": any(f["gt"] for f in rep),
            "counts": {"reported": len(rep), "reported_gt": sum(1 for f in rep if f["gt"]), "raw": 10,
                       "removed_by_triage": len(flows) - len(rep), "removed_gt_by_triage": 0, "v3_rejected": 0},
            "taie": {"ok": True, "elapsed_s": 5.0}, "timings": {"total_s": 6.0},
            "usage": {"total": {"prompt_tokens": 100 * run, "completion_tokens": 10, "calls": 2}},
            "driver": {"kind": "template"}, "spec": {"accepted": 3, "rejected": 1, "mean_vote_agreement": 0.9}}


def _frame(probabilities, selected=None):
    selected = set(probabilities) if selected is None else set(selected)
    return {"flows": {key: {"inclusion_probability": probability, "selected": key in selected,
                            "priority": "2" if key in selected else ""}
                      for key, probability in probabilities.items()}}


def _install_census(monkeypatch, runs):
    frames = {}
    for run in runs:
        frame = frames.setdefault(f"{run['subject']}|{run['version']}", {"flows": {}})
        for flow in run["flows"]:
            frame["flows"][flow["key"]] = {"inclusion_probability": 1.0, "selected": True,
                                           "priority": "1" if flow["gt"] else "2"}
    monkeypatch.setattr(M, "load_sampling_manifest", lambda: {"schema": M.SAMPLING_SCHEMA, "frames": frames})


def test_summary_precision_recall_jaccard(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "LABEL_DIR", tmp_path)
    runs = [_run("v3", 0, ["g1", "f1"], gt=["A.m"]), _run("v3", 1, ["g1", "f2"], gt=["A.m"]),
            _run("B1", 0, ["f1"]), _run("v3", 0, ["f1"], version="fixed")]
    p = M.write_label_sheet(runs, "s1", "buggy")
    rows = list(csv.DictReader(open(p)))
    assert rows[0]["flow_key"] == "g1" and rows[0]["gt_methods"] == "A.m"     # GT-relevant flows first
    for r in rows:
        r["label"] = "TP" if r["flow_key"] == "g1" else "FP"
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=M.LABEL_FIELDS)
        w.writeheader()
        w.writerows(rows)
    M.write_label_sheet(runs, "s1", "buggy")                                     # refresh keeps labels
    assert {r["flow_key"]: r["label"] for r in csv.DictReader(open(p))}["g1"] == "TP"
    _install_census(monkeypatch, runs)
    summ = {(r["config"], r["version"]): r for r in M.summarise(runs)}
    v3 = summ[("v3", "buggy")]
    assert v3["runs"] == 2 and v3["detected_rate"] == 1.0 and v3["precision_mean"] == 0.5
    assert v3["recall_mean"] == 1.0 and v3["flowset_jaccard"] == round(1 / 3, 3)
    assert v3["confirmed_detected_rate"] == 1.0
    assert summ[("B1", "buggy")]["detected_rate"] == 0.0
    cve = {r["config"]: r for r in M.cve_table(M.summarise(runs))}
    assert cve["v3"]["differential_ok"] is True and cve["B1"]["differential_ok"] is False


def test_markdown_table():
    md = M.markdown_table([{"a": 1, "b": None}], ["a", "b"])
    assert md.splitlines()[2] == "| 1 |  |"


def test_report_outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "LABEL_DIR", tmp_path)
    b1 = _run("B1", 0, ["g1", "f1"], gt=["A.m"])
    v3 = _run("v3", 0, ["g2", "f1"], gt=["A.m"])
    for r in (b1, v3):
        r.update({"cve": "CVE-1", "cwe": "CWE-022", "subject_stats": {"non_blank_loc": 100, "java_files": 3},
                  "facts": {"app_classes": 4}, "gt_methods": ["A.m"], "served_models": ["qwen"]})
        r["taie"].update({"reachable_methods": 10})
    v3["flows"].append({"id": "x", "key": "g3", "source": "s", "sink": "t", "gt": ["A.m"], "reported": False,
                        "triage": {"verdict": "not_vulnerable", "reason": "sanitized", "kept": False, "v3_ok": True}})
    subj = M.subjects_table([b1, v3])
    assert subj[0]["non_blank_loc"] == 100 and subj[0]["b1_reachable_methods"] == 10
    budget = {r["config"]: r for r in M.budget_table([b1, v3])}
    assert budget["v3"]["models"] == "qwen" and budget["B1"]["llm_calls"] == 2
    cases = M.case_candidates([b1, v3])
    assert "found by **v3** but not B1" in cases and "lost by v3" in cases
    assert "removed a flow" in cases and "patch-method overlap: yes; saved label: unlabelled" in cases
    tex = M.latex_table(subj, ["subject", "non_blank_loc"], "Subjects", "tab:s")
    assert "\\begin{tabular}{ll}" in tex and "s1 & 100" in tex


def test_budget_withholds_fresh_spend_for_mixed_replay_records():
    ordinary = _run("B1", 0, ["f1"])
    ordinary["usage"]["total"].update(fresh_prompt_tokens=70, fresh_completion_tokens=30, latency_s=1800)
    historical = _run("v3", 0, ["f1"])
    historical["usage"]["total"].update(fresh_prompt_tokens=120, fresh_completion_tokens=30, latency_s=3600)
    replay = _run("v3", 1, ["f1"])
    replay["usage"]["total"].update(fresh_prompt_tokens=20, fresh_completion_tokens=10, latency_s=600)
    replay["result_revision"] = {"kind": "validator-correction-replay"}
    budget = {row["config"]: row for row in M.budget_table([ordinary, historical, replay])}
    assert budget["B1"]["fresh_tokens"] == 100 and budget["B1"]["llm_hours"] == 0.5
    assert budget["B1"]["cost_semantics"] == "recorded-run-stage-cost"
    # A replay mixed with historical statistics is neither original nor replay
    # API spend, but the recorded numbers must remain available for inspection.
    assert budget["v3"]["fresh_tokens"] is None and budget["v3"]["llm_hours"] is None
    assert budget["v3"]["recorded_stage_fresh_tokens"] == 180
    assert budget["v3"]["recorded_stage_llm_hours"] == 1.17
    assert budget["v3"]["llm_calls"] == 4
    assert "results/provenance" in budget["v3"]["cost_semantics"]


def test_label_sheet_gt_is_union_over_runs(tmp_path, monkeypatch):
    """A flow key can be GT-relevant in one run and not in another; the sheet must show it as GT."""
    import nesy.metrics as M
    monkeypatch.setattr(M, "label_path", lambda s, v: tmp_path / f"{s}-{v}.csv")
    monkeypatch.setattr(M, "read_labels", lambda s, v: {})
    f = {"id": "a1", "key": "K", "source": "src", "sink": "snk", "reported": True}
    runs = [{"subject": "s", "version": "buggy", "config": "v1", "flows": [dict(f, gt=[])]},
            {"subject": "s", "version": "buggy", "config": "B2", "flows": [dict(f, gt=["C.m"])]}]
    p = M.write_label_sheet(runs, "s", "buggy")
    text = p.read_text()
    assert "C.m" in text and "B2,v1" in text


def test_label_sheet_priority_sample_is_stratified_and_stable(tmp_path, monkeypatch):
    """up to N flows per main configuration and stratum are marked to label, deterministically."""
    monkeypatch.setattr(M, "LABEL_DIR", tmp_path)
    keys = [f"g{i:02d}" for i in range(30)] + [f"f{i:02d}" for i in range(40)]
    runs = [_run("v1", 0, keys, gt=["A.m"]), _run("v3", 0, ["g00", "f00", "f01"], gt=["A.m"]),
            _run("v3-noV2", 0, ["f39"], gt=["A.m"])]
    p = M.write_label_sheet(runs, "s1", "buggy", per_config=5)
    rows = {r["flow_key"]: r for r in csv.DictReader(open(p))}
    p1 = [k for k, r in rows.items() if r["priority"] == "1"]
    p2 = [k for k, r in rows.items() if r["priority"] == "2"]
    assert all(k.startswith("g") for k in p1) and all(k.startswith("f") for k in p2)
    assert "g00" in p1 and {"f00", "f01"} <= set(p2)          # v3's small strata are taken whole
    assert len(p1) <= 6 and len(p2) <= 7
    assert rows["f39"]["priority"] == ""                      # ablation-only flows are not sampled
    first = [r["flow_key"] for r in csv.DictReader(open(p))][:3]
    M.write_label_sheet(runs, "s1", "buggy", per_config=5)
    assert {k for k, r in ((r["flow_key"], r) for r in csv.DictReader(open(p))) if r["priority"]} == set(p1 + p2)
    assert [r["flow_key"] for r in csv.DictReader(open(p))][:3] == first


def test_historical_descriptive_precision_and_confirmed_states():
    """Preserve the old diagnostic without confusing it with the HT estimator."""
    run = _run("v1", 0, ["g1", "g2", "f1", "f2", "f3", "f4"], gt=["A.m"])
    labels = {"g1": {"label": "TP"}, "f1": {"label": "FP"}, "f2": {"label": "TP"}}
    p, nl, nr = M.descriptive_precision_of(run, labels)
    assert (nl, nr) == (3, 6) and p == round((2 * 1.0 + 4 * 0.5) / 6, 3)
    assert M.descriptive_precision_of(run, {"g1": {"label": "TP"}})[0] is None  # other stratum unlabelled
    assert M.confirmed_of(run, labels) is True
    assert M.confirmed_of(run, {"g1": {"label": "FP"}}) is None             # g2 still open
    assert M.confirmed_of(run, {"g1": {"label": "FP"}, "g2": {"label": "fp"}}) is False
    assert M.confirmed_of(_run("v1", 0, ["f1"]), {}) is False               # no GT flow reported


def test_headline_table_counts_cves():
    rows = [{"config": "v3", "version": "buggy", "subject": s, "detected_rate": d, "reported_mean": 10,
             "confirmed_detected_rate": c, "precision_mean": p, "llm_driver_fallbacks": 0, "taie_failures": 0}
            for s, d, c, p in (("a", 1.0, 0.5, 0.4), ("b", 0.0, 0.0, 0.2))]
    rows.append(dict(rows[0], version="fixed", reported_mean=2))
    h = M.headline_table(rows, [{"config": "v3", "differential_ok": True}])[0]
    assert (h["cves_detected"], h["cves_confirmed"], h["precision_mean"]) == (1, 1, 0.3)
    assert (h["alarms_buggy_total"], h["alarms_fixed_total"], h["differential_ok"]) == (20, 2, 1)


def test_iris_automatic_metrics():
    """IRIS (ICLR 2025): Prec = vulnerable paths / paths, Rec = detected, F1 per project."""
    run = _run("v3", 0, ["g1", "f1", "f2", "f3"], gt=["A.m"])
    prec, rec, f1 = M.iris_metrics_of(run)
    assert (prec, rec) == (0.25, 1) and round(f1, 3) == round(2 * 0.25 / 1.25, 3)
    assert M.iris_metrics_of(_run("v3", 0, [], gt=["A.m"])) == (None, 0, 0.0)
    assert M.iris_metrics_of(_run("v3", 0, ["f1"]))[2] == 0.0
    row = {r["config"]: r for r in M.summarise([run])}["v3"]
    assert row["auto_fdr_mean"] == 0.75 and row["auto_f1_mean"] == round(2 * 0.25 / 1.25, 3)



def test_pooled_f1_distinguishes_zero_from_unknown(monkeypatch):
    """A known all-FP result has zero F1; absent labels still mean unknown."""
    run = _run("B1", 0, ["f1"])
    _install_census(monkeypatch, [run])
    labels = {"g1": {"label": "TP"}, "f1": {"label": "FP"}}
    monkeypatch.setattr(M, "read_labels", lambda subject, version: labels)
    row = M.summarise([run])[0]
    assert row["precision_mean"] == 0.0 and row["recall_mean"] == 0.0
    assert row["f1"] == 0.0

    monkeypatch.setattr(M, "read_labels", lambda subject, version: {})
    row = M.summarise([run])[0]
    assert row["precision_mean"] is None and row["recall_mean"] is None
    assert row["f1"] is None


def test_ht_uses_union_inclusion_probability_and_ignores_ad_hoc_labels():
    # Two independent half-population draws give this shared flow pi=3/4.
    frame = _frame({"shared": 0.75, "one_draw": 0.5, "unsampled": 0.25}, {"shared", "one_draw"})
    labels = {"shared": {"label": "TP"}, "one_draw": {"label": "FP"}, "unsampled": {"label": "TP"}}
    run = _run("v4", 0, ["shared", "one_draw", "unsampled"])
    precision, labelled, reported = M.precision_of(run, labels, frame)
    assert precision == pytest.approx((1 / 0.75) / 3)
    assert (labelled, reported) == (2, 3)
    # A changed domain retains the original pi, rather than re-estimating the
    # selection chance from the now-smaller result. Do not clip HT estimates.
    assert M.precision_of(_run("corrected", 0, ["shared"]), labels, frame)[0] == pytest.approx(1 / 0.75)


def test_ht_exact_expectation_for_overlapping_draws_and_small_domains():
    # Draw one from {a,b} and independently one from {a,c}. Enumerate all
    # four equally likely samples; a's inclusion chance is 3/4, b/c's 1/2.
    labels = {"a": {"label": "TP"}, "b": {"label": "FP"}, "c": {"label": "TP"}}
    full_estimates, c_estimates = [], []
    for first in ("a", "b"):
        for second in ("a", "c"):
            frame = _frame({"a": 0.75, "b": 0.5, "c": 0.5}, {first, second})
            full_estimates.append(M.precision_of(_run("v4", 0, ["a", "b", "c"]), labels, frame)[0])
            c_estimates.append(M.precision_of(_run("v4", 0, ["c"]), labels, frame)[0])
    assert sum(full_estimates) / 4 == pytest.approx(2 / 3)
    assert sum(c_estimates) / 4 == pytest.approx(1.0)
    assert sorted(c_estimates) == [0.0, 0.0, 2.0, 2.0]


def test_ht_distinguishes_missing_judgements_from_unsampled_flows():
    frame = _frame({"a": 0.5, "b": 0.5, "c": 0.5}, {"a", "b"})
    labels = {"a": {"label": "TP"}, "b": {"label": "UNSURE"}}
    result = M.precision_diagnostics_of(_run("v4", 0, ["a", "b", "c"]), labels, frame)
    assert result["precision"] is None and result["status"] == "missing-sampled-labels"
    assert result["missing_sampled_labels"] == 1 and result["labelled_sampled_reported"] == 1
    # Uncertain b lies outside the revised run's domain and need not be guessed.
    assert M.precision_of(_run("v4", 0, ["a", "c"]), labels, frame)[0] == 1.0
    for unknown in ("", "?", "UNCERTAIN"):
        labels["b"]["label"] = unknown
        assert M.precision_of(_run("v4", 0, ["b"]), labels, frame)[0] is None


def test_ht_zero_sample_domain_is_zero_but_empty_run_is_undefined():
    frame = _frame({"a": 0.5, "b": 0.5}, {"a"})
    result = M.precision_diagnostics_of(_run("v4", 0, ["b"]), {}, frame)
    assert result["precision"] == 0.0 and result["label_coverage"] == 0.0
    assert result["status"] == "no-sampled-reported-flows"
    assert M.precision_of(_run("v4", 0, []), {}, frame) == (None, 0, 0)


def test_ht_new_and_zero_probability_reported_flows_are_unknown():
    frame = _frame({"covered": 1.0, "zero": 0.0}, {"covered"})
    labels = {"covered": {"label": "TP"}, "new": {"label": "TP"}, "zero": {"label": "FP"}}
    for key in ("new", "zero"):
        result = M.precision_diagnostics_of(_run("v4", 0, ["covered", key]), labels, frame)
        assert result["precision"] is None
        assert result["status"] == "uncovered-reported-flows" and result["uncovered_reported"] == 1


def test_summary_keeps_zero_sample_domains_and_propagates_unknown(monkeypatch):
    frame = _frame({"a": 0.5, "b": 0.5}, {"a"})
    monkeypatch.setattr(M, "load_sampling_manifest", lambda: {"frames": {"s1|buggy": frame}})
    monkeypatch.setattr(M, "read_labels", lambda s, v: {"a": {"label": "TP"}})
    runs = [_run("v4", 0, ["a"]), _run("v4", 1, ["b"]), _run("v4", 2, [])]
    row = M.summarise(runs)[0]
    assert row["precision_mean"] == 1.0  # mean of HT=2 and HT=0; empty excluded
    assert row["precision_known_runs"] == 2 and row["precision_nonempty_runs"] == 2
    assert row["precision_zero_sample_runs"] == 1
    rows = M.summarise(runs + [_run("v4", 3, ["new"])])
    assert rows[0]["precision_mean"] is None and rows[0]["precision_unknown_nonempty_runs"] == 1
    headline = M.headline_table(rows, [])[0]
    assert headline["precision_mean"] is None and headline["precision_unknown_subjects"] == 1


def test_label_sheet_refresh_keeps_frozen_sample_membership(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "LABEL_DIR", tmp_path)
    monkeypatch.setattr(M, "load_sampling_manifest", lambda: {})
    sheet = M.write_label_sheet([_run("v1", 0, ["a", "b"])], "s1", "buggy")
    frame = _frame({"a": 0.5, "b": 0.5}, {"a"})
    monkeypatch.setattr(M, "load_sampling_manifest", lambda: {"frames": {"s1|buggy": frame}})
    # The new result excludes a and introduces new; it must not redraw labels.
    M.write_label_sheet([_run("v1", 0, ["b", "new"])], "s1", "buggy")
    rows = {row["flow_key"]: row for row in csv.DictReader(sheet.open())}
    assert rows["a"]["priority"] == "2"
    assert rows["b"]["priority"] == rows["new"]["priority"] == ""


def test_freeze_reconstructs_union_sample_and_rejects_changed_membership(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts" / "freeze_label_sampling.py"
    spec = importlib.util.spec_from_file_location("freeze_label_sampling", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    runs = [_run("v1", 0, ["a", "b", "c"]), _run("v4", 0, ["a"])]
    monkeypatch.setattr(M, "LABEL_DIR", tmp_path / "labels")
    monkeypatch.setattr(M, "load_sampling_manifest", lambda: {})
    for run in runs:
        path = tmp_path / "results" / "runs" / run["config"] / "run0.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(run))
    sheet = M.write_label_sheet(runs, "s1", "buggy", per_config=1)
    manifest = module.build_manifest(tmp_path, per_config=1)
    flows = manifest["frames"]["s1|buggy"]["flows"]
    assert manifest["source_run_count"] == 2
    assert flows["a"]["inclusion_probability"] == 1.0
    assert flows["b"]["inclusion_probability"] == pytest.approx(1 / 3)
    assert flows["c"]["inclusion_probability"] == pytest.approx(1 / 3)
    rows = list(csv.DictReader(sheet.open()))
    next(row for row in rows if row["flow_key"] == "a")["priority"] = ""
    with sheet.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=M.LABEL_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(ValueError, match="does not exactly match"):
        module.build_manifest(tmp_path, per_config=1)
