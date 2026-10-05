"""Review evidence must use the exact raw flow retained in the selected run."""
import json
from types import SimpleNamespace

import pytest

from nesy.cli import _flow_report
from nesy.taie import parse_flow_line
from nesy.triage import Evidence


def _flow(line):
    return parse_flow_line(
        f"TaintFlow{{<nesy.NesyDriver: void main(java.lang.String[])>[{line}@L{line}] "
        "v = invokestatic nesy.Taint.src()/result -> "
        "<app.Example: void run(java.lang.String)>[4@L20] invoke sink(v)/0}"
    )


def test_report_keeps_selected_raw_representative_when_flow_ids_collide(tmp_path, monkeypatch):
    first, last = _flow(8), _flow(45)
    assert first.short_id == last.short_id
    (tmp_path / "result.json").write_text(json.dumps({"flows": [first.to_json(), last.to_json()]}))
    record = {
        "config": "v3", "run": 0, "taie": {"out_dir": str(tmp_path)},
        "flows": [{"id": first.short_id, "key": first.key, "source": first.source.raw,
                   "sink": first.sink.raw, "reported": True, "gt": []}],
    }
    ctx = SimpleNamespace(subject=SimpleNamespace(id="example"), version="buggy", facts=object())
    seen = []

    def evidence(flow, graph, facts, **kwargs):
        seen.append(flow.source.raw)
        return Evidence([], "route from " + flow.source.raw, "source snippets")

    monkeypatch.setattr("nesy.triage.build_evidence", evidence)
    cache = {}
    text = _flow_report([record], ctx, first.short_id, cache=cache)
    assert seen == [first.source.raw]
    assert "route from " + first.source.raw in text
    # Both representatives must remain available when the raw-result cache is reused.
    record["flows"][0]["source"] = last.source.raw
    _flow_report([record], ctx, last.short_id, cache=cache)
    assert seen == [first.source.raw, last.source.raw]


def test_report_refuses_missing_exact_representative(tmp_path):
    first, last = _flow(8), _flow(45)
    (tmp_path / "result.json").write_text(json.dumps({"flows": [last.to_json()]}))
    record = {
        "config": "B2", "run": 0, "taie": {"out_dir": str(tmp_path)},
        "flows": [{"id": first.short_id, "key": first.key, "source": first.source.raw,
                   "sink": first.sink.raw, "reported": True, "gt": []}],
    }
    ctx = SimpleNamespace(subject=SimpleNamespace(id="example"), version="buggy", facts=object())
    with pytest.raises(ValueError, match="exact source/sink representative"):
        _flow_report([record], ctx, first.short_id)


def test_label_pack_preserves_labels_and_documents_evidence_limits(tmp_path, monkeypatch):
    import argparse
    import csv
    import nesy.cli as C
    import nesy.metrics as M
    import nesy.pipeline as P

    labels = tmp_path / "labels"
    labels.mkdir()
    sheet = labels / "example-buggy.csv"
    with sheet.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=M.LABEL_FIELDS)
        writer.writeheader()
        writer.writerow({"priority": "1", "flow_id": "sample", "flow_key": "raw-key",
                         "label": "FP", "notes": "IMP: provisional judgment"})
    original = sheet.read_bytes()
    monkeypatch.setattr(M, "LABEL_DIR", labels)
    monkeypatch.setattr(M, "load_runs", lambda _: [])
    monkeypatch.setattr(C, "_subjects", lambda *args: [SimpleNamespace(id="example")])
    monkeypatch.setattr(P, "SubjectContext", lambda *args: object())
    monkeypatch.setattr(C, "_flow_report", lambda *args, **kwargs: "exact selected evidence")
    settings = SimpleNamespace(results_dir=tmp_path / "results")
    args = argparse.Namespace(subject="example", all=True, max_methods=6, max_lines=60)
    assert C.cmd_label_pack(settings, args) == 0
    pack = (labels / "review" / "example-buggy.md").read_text()
    assert sheet.read_bytes() == original
    assert "exact selected evidence" in pack
    assert "saved labels remain unchanged" in pack
    assert "canonical key may group different drivers or routes" in pack
    assert "labels/sampling_manifest.json" in pack
    assert "Write TP or FP" not in pack
