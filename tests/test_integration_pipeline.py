"""End-to-end: S1 -> drivers -> specs -> Tai-e -> triage -> ground truth, on the mini fixture.

Uses the offline heuristic LLM, so it checks the plumbing, not LLM quality. Needs Java 17,
a JDK 8 rt.jar and tools/tai-e-all-0.5.4.jar (about 1-2 minutes)."""
import copy

import pytest

from conftest import FIXTURE, taie_available
from nesy.cli import make_llm_factory
from nesy.config import Subject
from nesy.groundtruth import FixedMethod
from nesy.pipeline import SubjectContext, run_config
from nesy.subjects import BuildLayout

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def ctx(settings, built_fixture, tmp_path_factory):
    if not taie_available(settings):
        pytest.skip("Tai-e jar / JDK 17 / JDK 8 rt.jar not available")
    s = copy.deepcopy(settings)
    w = tmp_path_factory.mktemp("work")
    s.raw["work_dir"], s.raw["results_dir"] = str(w), str(w / "results")
    subj = Subject(id="minizip", slug="minizip", role="test", cve="DEMO", cwe="CWE-022", repo="fixture",
                   buggy_commit="-", fixed_commit="-")
    lay = BuildLayout(str(FIXTURE), [str(built_fixture / "app")], [str(built_fixture / "acme-util.jar")],
                      [str(FIXTURE / "app" / "src")], True)
    c = SubjectContext(s, subj, "buggy", lay)
    # the fixture's "CVE" is the Zip Slip in Extractor.extract
    c.fixed_methods = [FixedMethod("app/src/demo/app/Extractor.java", "Extractor", "extract", 13, 20, "")]
    return c, make_llm_factory(s, mock=True)


def _sinks(rec):
    return {(f["sink_method"].split(": ")[1].split("(")[0].split()[-1], f["sink_line"], f["key"].rsplit("/", 1)[1])
            for f in rec["flows"] if f["reported"]}


def test_b1_misses_library_specific_flows(ctx):
    c, llm = ctx
    rec = run_config(c, "B1", 0, None)
    assert rec["taie"]["ok"] and rec["driver"]["kind"] == "template"
    s = _sinks(rec)
    assert ("extract", 17, "1") not in s          # entry name of the archive is not a known source/sink
    assert ("runHook", 39, "0") not in s          # Shell.run is not a known sink
    assert rec["usage"]["total"] == {}            # no LLM used


def test_v1_spec_inference_finds_them(ctx):
    c, llm = ctx
    rec = run_config(c, "v1", 0, llm)
    s = _sinks(rec)
    assert ("extract", 17, "1") in s and ("runHook", 39, "0") in s
    assert rec["detected"] and rec["spec"]["accepted"] >= 2 and rec["usage"]["N2"]["calls"] >= 1


def test_v3_triage_removes_sanitised_flow_only(ctx):
    c, llm = ctx
    rec = run_config(c, "v3", 0, llm)
    removed = [f for f in rec["flows"] if not f["reported"]]
    assert removed and all("extractSafely" in f["sink_method"] for f in removed)
    assert all(f["triage"]["v3_ok"] for f in removed)
    assert rec["detected"] and rec["counts"]["removed_gt_by_triage"] == 0
    assert rec["driver"]["kind"] == "llm"


def test_rerun_hits_caches(ctx):
    c, llm = ctx
    rec = run_config(c, "v3", 0, llm)
    assert rec["timings"]["taie_s"] < 5               # Tai-e result reused
    assert rec["usage"]["N3"].get("cached_calls") == rec["usage"]["N3"].get("calls")


def test_spec_cache_rebuilt_after_prompt_change(ctx, monkeypatch):
    """a cached N2 spec from an older prompt must not be reused."""
    import nesy.pipeline as pl
    from nesy.pipeline import get_llm_spec
    c, factory = ctx
    llm = factory()
    first = get_llm_spec(c, llm, 0, True)
    assert get_llm_spec(c, llm, 0, True).prompt_version == first.prompt_version
    monkeypatch.setattr(pl, "prompt_version", lambda name: "changed")
    calls = []
    monkeypatch.setattr(pl, "infer_spec", lambda *a, **k: calls.append(1) or first)
    get_llm_spec(c, llm, 0, True)
    assert calls, "spec should be re-inferred when the prompt version differs"


def test_only_app_mode_keeps_string_flows(settings, built_fixture, tmp_path_factory):
    """only-app (used for large subjects such as perfecto-plugin) + call-site mode + chain transfers
    must still find the command injection that goes through string concatenation."""
    if not taie_available(settings):
        pytest.skip("Tai-e not available")
    s = copy.deepcopy(settings)
    w = tmp_path_factory.mktemp("work-oa")
    s.raw["work_dir"], s.raw["results_dir"] = str(w), str(w / "results")
    subj = Subject(id="minizip-oa", slug="minizip", role="test", cve="DEMO", cwe="CWE-022", repo="fixture",
                   buggy_commit="-", fixed_commit="-", taie={"only_app": True})
    lay = BuildLayout(str(FIXTURE), [str(built_fixture / "app")], [str(built_fixture / "acme-util.jar")],
                      [str(FIXTURE / "app" / "src")], True)
    c = SubjectContext(s, subj, "buggy", lay)
    assert c.taie.only_app
    rec = run_config(c, "v1", 0, make_llm_factory(s, mock=True))
    s1 = _sinks(rec)
    assert ("extract", 17, "1") in s1 and ("runHook", 39, "0") in s1
    assert rec["taie"]["elapsed_s"] < 30
