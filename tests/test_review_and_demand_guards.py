"""Demand-mode inference must use the recorded B1 graph, not an unrelated cached graph."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nesy.pipeline import PipelineError, _reachable_app_methods


def demand_context(tmp_path):
    return SimpleNamespace(root=tmp_path / "work/runs/example/buggy", version="buggy",
                           subject=SimpleNamespace(id="example"),
                           settings=SimpleNamespace(results_dir=tmp_path / "results"))


def write_graph(directory, name):
    directory.mkdir(parents=True)
    (directory / "taint-flow-graph.dot").write_text(
        f'"VarNode{{<app.Example: void {name}()>#a}}" -> "VarNode{{<app.Example: void {name}()>#b}}";\n'
    )


def b1_record(ctx, out_dir, ok=True):
    path = ctx.settings.results_dir / "runs/example/buggy/B1/run0.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"subject": "example", "version": "buggy", "config": "B1", "run": 0,
                                "taie": {"ok": ok, "out_dir": str(out_dir)}}))


def test_demand_selects_recorded_b1_graph_not_first_cached_graph(tmp_path):
    ctx = demand_context(tmp_path)
    write_graph(ctx.root / "taie/000-unrelated", "wrong")
    selected = ctx.root / "taie/zzz-b1"
    write_graph(selected, "correct")
    b1_record(ctx, selected)
    assert _reachable_app_methods(ctx) == {"<app.Example: void correct()>"}


def test_demand_requires_b1_even_when_other_graphs_exist(tmp_path):
    ctx = demand_context(tmp_path)
    write_graph(ctx.root / "taie/unrelated", "wrong")
    with pytest.raises(PipelineError, match="preliminary B1"):
        _reachable_app_methods(ctx)


def test_demand_rejects_failed_b1(tmp_path):
    ctx = demand_context(tmp_path)
    selected = ctx.root / "taie/b1"
    write_graph(selected, "partial")
    b1_record(ctx, selected, ok=False)
    with pytest.raises(PipelineError, match="preliminary B1"):
        _reachable_app_methods(ctx)


def test_demand_resolves_graph_in_moved_checkout(tmp_path):
    ctx = demand_context(tmp_path)
    selected = ctx.root / "taie/b1"
    write_graph(selected, "moved")
    b1_record(ctx, tmp_path / "absent-original-work/taie/b1")
    assert _reachable_app_methods(ctx) == {"<app.Example: void moved()>"}
