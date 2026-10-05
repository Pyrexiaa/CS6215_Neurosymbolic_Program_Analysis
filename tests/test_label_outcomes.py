"""TP reported in either stratum, and the FP-category breakdown read from the notes column."""
import nesy.metrics as M
from test_metrics import _run


def test_tp_reported_counts_both_strata():
    run = _run("v4", 0, ["g1", "f1"], gt=["A.m"])
    assert M.tp_reported_of(run, {}) is None                                  # no labels at all
    assert M.tp_reported_of(run, {"f1": {"label": "TP"}, "g1": {"label": "FP"}}) is True
    assert M.tp_reported_of(run, {"f1": {"label": "FP"}}) is False
    assert M.confirmed_of(run, {"f1": {"label": "TP"}, "g1": {"label": "FP"}}) is False


def test_fp_category_from_notes():
    assert M.fp_category({"notes": "[claude-labelled, pending student review] SPEC-FP: log sink"}) == "SPEC-FP"
    assert M.fp_category({"notes": "IMP - context merging"}) == "IMP"
    assert M.fp_category({"notes": "no code"}) == "?"


def test_label_breakdown_distinct_flows(monkeypatch):
    labels = {"g1": {"label": "TP", "notes": ""}, "f1": {"label": "FP", "notes": "DRV: x"},
              "f2": {"label": "FP", "notes": "IMP: y"}}
    monkeypatch.setattr(M, "read_labels", lambda s, v: labels)
    runs = [_run("v4", 0, ["g1", "f1", "f2"], gt=["A.m"]), _run("v4", 1, ["g1", "f1"], gt=["A.m"])]
    row = M.label_breakdown(runs)[0]
    assert (row["labelled"], row["TP"], row["DRV"], row["IMP"], row["SPEC-FP"]) == (3, 1, 1, 1, 0)


def test_case_candidates_separates_patch_overlap_labels_and_categories(monkeypatch):
    labels = {
        "g_fp": {"label": "FP", "notes": "[claude-labelled, pending student review] SPEC-FP: log sink"},
        "g_tp": {"label": "TP", "notes": ""},
        "f_tp": {"label": "TP", "notes": ""},
        "f_unknown": {"label": "FP", "notes": "no taxonomy code"},
    }
    monkeypatch.setattr(M, "read_labels", lambda s, v: labels)
    run = _run("v3", 0, list(labels), gt=["A.m"], reported={k: False for k in labels})
    for flow in run["flows"]:
        flow["triage"] = {"kept": False, "reason": "not_vulnerable", "v3_ok": True}
    cases = M.case_candidates([run])
    assert "patch-method overlap: yes; saved label: FP" in cases
    assert "patch-method overlap: yes; saved label: TP" in cases
    assert "patch-method overlap: no; saved label: TP" in cases
    assert "FP categories in the saved labels: ?=1, SPEC-FP=1" in cases
    assert "[claude-labelled," not in cases
    assert "GT/TP flow" not in cases
