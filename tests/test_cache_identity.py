"""Prevent silent cross-model/settings reuse while supporting explicit legacy migration."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nesy import pipeline
from nesy.classfile import ClassIndex
from nesy.driver import DriverResult, ENTRY_CHECK_VERSION
from nesy.facts import EntryCandidate, ProgramFacts
from nesy.llm import LLMResponse, OpenAICompatClient
from nesy.sources import SourceLocator
from nesy.spec import SpecResult, SPEC_VOTE_VERSION

MESSAGES = [{"role": "user", "content": "test"}]


class OfflineClient(OpenAICompatClient):
    def _complete(self, *args, **kwargs):
        raise AssertionError("unexpected network/cache miss")


def client(cache, endpoint="https://example.invalid/v1", model="default", extra=None):
    return OfflineClient(endpoint, "secret-never-in-identity", model, cache_dir=cache, extra_body=extra)


def test_transport_keys_include_endpoint_and_body_but_not_credentials(tmp_path):
    a = client(tmp_path)
    key = a._cache_key(MESSAGES, 0, 100, 0)
    assert key != client(tmp_path, endpoint="https://other.invalid/v1")._cache_key(MESSAGES, 0, 100, 0)
    assert key != client(tmp_path, extra={"chat_template_kwargs": {"enable_thinking": False}})._cache_key(MESSAGES, 0, 100, 0)
    assert key == client(tmp_path, endpoint="https://example.invalid/v1/")._cache_key(MESSAGES, 0, 100, 0)
    assert "secret-never" not in json.dumps(a.cache_identity())


def test_legacy_answers_need_matching_attested_identity_and_served_model(tmp_path):
    llm = client(tmp_path)
    old = llm._legacy_cache_key(MESSAGES, 0.0, 100, 0)
    llm._cache_put(old, LLMResponse("historical", "historical-model"))
    with pytest.raises(AssertionError):
        llm.chat(MESSAGES, "N2", max_tokens=100)
    llm.allow_legacy_cache(["historical-model"], "Verified original experiment endpoint and empty request body")
    result = llm.chat(MESSAGES, "N2", max_tokens=100)
    assert result.cached and result.text == "historical"
    assert llm._cache_get(llm._cache_key(MESSAGES, 0.0, 100, 0)) is not None
    with pytest.raises(AssertionError):
        client(tmp_path, endpoint="https://other.invalid/v1").chat(MESSAGES, "N2", max_tokens=100)
    with pytest.raises(AssertionError):
        client(tmp_path, extra={"seed": 12}).chat(MESSAGES, "N2", max_tokens=100)


def test_legacy_served_model_mismatch_is_not_accepted(tmp_path):
    llm = client(tmp_path)
    llm._cache_put(llm._legacy_cache_key(MESSAGES, 0.0, 100, 0), LLMResponse("old", "wrong-model"))
    llm.allow_legacy_cache(["expected-model"], "Checked model provenance")
    with pytest.raises(AssertionError):
        llm.chat(MESSAGES, "N2", max_tokens=100)


def context(tmp_path):
    raw = {"driver": {}, "spec": {}, "llm": {}}
    settings = SimpleNamespace(section=lambda name: dict(raw.get(name, {})))
    facts = ProgramFacts({}, {}, [], ClassIndex([]), SourceLocator([]))
    bytecode = tmp_path / "input.class"
    bytecode.write_bytes(b"v1")
    ctx = SimpleNamespace(root=tmp_path / "stages", settings=settings, facts=facts,
                          base_files=[], compile_cp=[bytecode], javac="missing-javac",
                          layout=SimpleNamespace(project_dir=str(tmp_path), source_roots=[]),
                          subject=SimpleNamespace(repo="fixture", id="fixture"), cwe_id="CWE-078", cwe={})
    return ctx, raw, bytecode


def test_stage_identity_tracks_repair_prompt_facts_settings_model_and_bytes(monkeypatch, tmp_path):
    ctx, raw, bytecode = context(tmp_path)
    versions = {"n1_driver": "a", "n1_repair": "b"}
    monkeypatch.setattr(pipeline, "prompt_version", lambda name: versions[name])
    llm = client(tmp_path / "cache")
    def identity():
        return pipeline._stage_identity(ctx, "driver", pipeline._driver_cfg(ctx, 0, True), llm)
    original = identity()
    versions["n1_repair"] = "c"
    assert identity() != original
    versions["n1_repair"] = "b"
    raw["driver"]["max_repairs"] = 1
    assert identity() != original
    raw["driver"].clear()
    llm.model = "another-model"
    assert identity() != original
    llm.model = "default"
    bytecode.write_bytes(b"v2")
    assert identity() != original
    bytecode.write_bytes(b"v1")
    ctx.facts.entries.append(EntryCandidate("<A: void m()>", "A", "m", [], True, "library-api", 1))
    assert identity() != original


def test_spec_stage_reuses_identical_inputs_and_invalidates_changed_model(monkeypatch, tmp_path):
    ctx, raw, bytecode = context(tmp_path)
    monkeypatch.setattr(pipeline, "prompt_version", lambda name: "prompt")
    calls = []
    def infer(*args, **kwargs):
        calls.append(1)
        return SpecResult("", {"vote_version": SPEC_VOTE_VERSION}, prompt_version="prompt")
    monkeypatch.setattr(pipeline, "infer_spec", infer)
    llm = client(tmp_path / "cache")
    pipeline.get_llm_spec(ctx, llm, 0, True)
    pipeline.get_llm_spec(ctx, llm, 0, True)
    assert len(calls) == 1
    llm.model = "other"
    pipeline.get_llm_spec(ctx, llm, 0, True)
    assert len(calls) == 2
    raw["spec"]["samples"] = 1
    pipeline.get_llm_spec(ctx, llm, 0, True)
    assert len(calls) == 3


def test_explicit_adoption_preserves_frozen_fallback_driver(monkeypatch, tmp_path):
    ctx, _, _ = context(tmp_path)
    monkeypatch.setattr(pipeline, "prompt_version", lambda name: "prompt")
    work = pipeline.llm_driver_dir(ctx, 1, True)
    source, classes = work / "fallback/src/NesyDriver.java", work / "fallback/classes"
    source.parent.mkdir(parents=True); source.write_text("class NesyDriver {}")
    (classes / "nesy").mkdir(parents=True); (classes / "nesy/NesyDriver.class").write_bytes(b"existing")
    DriverResult("llm-fallback-template", True, str(classes), str(source), prompt_version="prompt").save(work / "driver.json")
    llm = client(tmp_path / "cache")
    with pytest.raises(ValueError):
        pipeline.adopt_legacy_stage(ctx, "driver", "", llm, 1, entry_check=True)
    pipeline.adopt_legacy_stage(ctx, "driver", "Verified model, prompts, settings and frozen bytecode", llm, 1, entry_check=True)
    monkeypatch.setattr(pipeline, "build_llm_driver", lambda *args, **kwargs: pytest.fail("frozen driver rebuilt"))
    assert pipeline.get_llm_driver(ctx, llm, 1, entry_check=True).kind == "llm-fallback-template"


def test_adoption_does_not_stamp_uncorrected_spec(monkeypatch, tmp_path):
    ctx, _, _ = context(tmp_path)
    monkeypatch.setattr(pipeline, "prompt_version", lambda name: "prompt")
    SpecResult("", {}, prompt_version="prompt").save(ctx.root / "run0/spec-llm")
    with pytest.raises(ValueError, match="voting version"):
        pipeline.adopt_legacy_stage(ctx, "spec", "Verified", client(tmp_path / "cache"))


def test_template_cache_invalidates_entry_limit_and_missing_class(monkeypatch, tmp_path):
    ctx, raw, _ = context(tmp_path)
    calls = []
    def build(facts, work, cp, javac, limit, release):
        calls.append(limit)
        source, classes = work / "src/NesyDriver.java", work / "classes"
        source.parent.mkdir(parents=True); source.write_text("class NesyDriver {}")
        (classes / "nesy").mkdir(parents=True); (classes / "nesy/NesyDriver.class").write_bytes(b"class")
        result = DriverResult("template", True, str(classes), str(source))
        result.save(work / "driver.json")
        return result
    monkeypatch.setattr(pipeline, "build_template_driver", build)
    first = pipeline.get_template_driver(ctx)
    pipeline.get_template_driver(ctx)
    assert calls == [300]
    raw["driver"]["max_entries_template"] = 10
    second = pipeline.get_template_driver(ctx)
    assert calls == [300, 10]
    (Path(second.classes_dir) / "nesy/NesyDriver.class").unlink()
    pipeline.get_template_driver(ctx)
    assert calls == [300, 10, 10]


def test_log_distinguishes_cached_response_latency_from_fresh_work(tmp_path):
    llm = client(tmp_path)
    llm._cache_put(llm._cache_key(MESSAGES, 0.0, 100, 0), LLMResponse("cached", "model", latency_s=2.5))
    llm.chat(MESSAGES, "N2", max_tokens=100)
    assert llm.usage["N2"]["latency_s"] == 0
    assert llm.usage["N2"]["response_latency_s"] == 2.5
