"""`nesy show-flow` prints what a labeller needs for one alarm (route + code + N3 verdict)."""
import argparse
import copy
import json
from dataclasses import asdict

import pytest

from conftest import FIXTURE, taie_available


def test_show_flow_prints_route_and_code(settings, built_fixture, tmp_path, capsys, monkeypatch):
    if not taie_available(settings):
        pytest.skip("Tai-e not available")
    from nesy.cli import cmd_show_flow, make_llm_factory
    from nesy.config import Subject
    from nesy.groundtruth import FixedMethod
    from nesy.pipeline import SubjectContext, run_config
    from nesy.subjects import BuildLayout
    s = copy.deepcopy(settings)
    s.raw["work_dir"], s.raw["results_dir"] = str(tmp_path / "w"), str(tmp_path / "r")
    subj = Subject(id="minizip", slug="minizip", role="primary", cve="DEMO", cwe="CWE-022", repo="fixture",
                   buggy_commit="-", fixed_commit="-")
    s.subjects = {"minizip": subj}
    lay = BuildLayout(str(FIXTURE), [str(built_fixture / "app")], [str(built_fixture / "acme-util.jar")],
                      [str(FIXTURE / "app" / "src")], True)
    (tmp_path / "w" / "subjects" / "minizip").mkdir(parents=True)
    (tmp_path / "w" / "subjects" / "minizip" / "buggy.layout.json").write_text(json.dumps(asdict(lay)))
    ctx = SubjectContext(s, subj, "buggy")
    ctx.fixed_methods = [FixedMethod("app/src/demo/app/Extractor.java", "Extractor", "extract", 13, 20, "")]
    rec = run_config(ctx, "v3", 0, make_llm_factory(s, mock=True))
    fid = next(f["id"] for f in rec["flows"] if f["gt"])
    rc = cmd_show_flow(s, argparse.Namespace(subject="minizip", version="buggy", flow=fid, config="",
                                             max_methods=6, max_lines=60))
    out = capsys.readouterr().out
    assert rc == 0 and "Extractor.extract" in out and "## Route" in out
    assert "File out = new File(destDir, name);" in out and "reported by: v3 run0" in out

    # label-pack: one review file with the evidence of every open priority row
    import nesy.metrics as M
    from nesy.cli import cmd_label_pack
    monkeypatch.setattr(M, "LABEL_DIR", tmp_path / "labels")
    sheet = M.write_label_sheet(M.load_runs(s.results_dir), "minizip", "buggy")
    rc = cmd_label_pack(s, argparse.Namespace(subject="minizip", all=False, max_methods=6, max_lines=60))
    pack = (tmp_path / "labels" / "review" / "minizip-buggy.md").read_text()
    assert rc == 0 and fid in pack and "File out = new File(destDir, name);" in pack
    assert sheet.exists()
