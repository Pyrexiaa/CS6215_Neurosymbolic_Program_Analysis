"""Regression tests for independently counted N2 votes and exact V3 evidence."""
import json
from types import SimpleNamespace

from nesy.classfile import ClassIndex, ClassInfo, MethodInfo, ACC_PUBLIC
from nesy.facts import ExternalApi, ProgramFacts
from nesy.llm import MockLLM
from nesy.sources import SourceLocator
from nesy import spec
from nesy.triage import build_evidence, check_v3


def _facts():
    apis = [ExternalApi(f"<lib.{name}: void use(java.lang.String)>", f"lib.{name}",
                        "use", ["java.lang.String"], "void", True, False)
            for name in ("A", "B")]
    return ProgramFacts({}, {a.signature: a for a in apis}, [], ClassIndex([]), SourceLocator([]))


def _infer(monkeypatch, answers, batch_size=25, validators=True):
    # The regressions concern response aggregation, independent of prompt wording.
    monkeypatch.setattr(spec, "build_messages", lambda name, values: [{"role": "user", "content": values["apis"]}])
    it = iter(answers)
    llm = MockLLM(lambda messages, stage: json.dumps(next(it)))
    return spec.infer_spec(_facts(), llm, {}, "CWE-078", "fixture",
                           {"samples": 3, "batch_size": batch_size}, {}, validators=validators)


def test_duplicate_labels_in_one_answer_do_not_form_a_majority(monkeypatch):
    label = {"id": 0, "role": "sink", "index": "0"}
    result = _infer(monkeypatch, [[label, label, label], [], []])
    assert result.accepted == []


def test_same_extra_label_in_multiple_batches_is_one_sample_vote(monkeypatch):
    label = {"signature": "<lib.Extra: void exec(java.lang.String)>", "role": "sink", "index": "0"}
    # The extra signature is proposed in replicate 0 of both batches, never in 1 or 2.
    result = _infer(monkeypatch, [[label], [], [], [label], [], []], batch_size=1, validators=False)
    assert result.accepted == []


def test_distinct_labels_keep_independent_votes_and_unanimity(monkeypatch):
    sink = {"id": 0, "role": "sink", "index": "0"}
    source = {"id": 0, "role": "source", "index": "0"}
    result = _infer(monkeypatch, [[sink, sink, source], [sink, source], [source]])
    assert {a["role"]: a["votes"] for a in result.accepted} == {"sink": 2, "source": 3}
    assert all(a["votes"] <= a["samples"] for a in result.accepted)
    assert result.stats["mean_vote_agreement"] <= 1
    assert result.stats["vote_version"] == spec.SPEC_VOTE_VERSION


def test_extra_label_needs_distinct_replicates_even_across_batches(monkeypatch):
    label = {"signature": "<lib.Extra: void exec(java.lang.String)>", "role": "sink", "index": "0"}
    result = _infer(monkeypatch, [[label], [], [], [], [label], []], batch_size=1, validators=False)
    assert len(result.accepted) == 1
    assert result.accepted[0]["votes"] == 2


def test_v3_rejects_citation_to_omitted_middle_of_long_method(tmp_path):
    src = tmp_path / "Example.java"
    src.write_text("\n".join(f"// source line {n}" for n in range(1, 201)))
    method = MethodInfo("Example", "entry", "()V", ACC_PUBLIC, lines=[10, 190])
    cls = ClassInfo("Example", "java.lang.Object", [], ACC_PUBLIC, "Example.java", [], [method], [], 52)
    facts = ProgramFacts({"Example": cls}, {}, [], ClassIndex([]), SourceLocator([tmp_path]))
    endpoint = SimpleNamespace(method=method.sig.taie)
    flow = SimpleNamespace(source=endpoint, sink=endpoint)
    graph = SimpleNamespace(path=lambda flow: [], methods_between=lambda flow: [method.sig.taie])
    evidence = build_evidence(flow, graph, facts, max_lines=60)
    assert "  100 |" not in evidence.snippets_text
    assert not check_v3({"evidence": [{"file": "Example.java", "line": 100}]}, evidence)[0]
    assert check_v3({"evidence": [{"file": "Example.java", "line": 10}]}, evidence)[0]
    assert check_v3({"evidence": [{"file": "Example.java", "line": 190}]}, evidence)[0]


def test_old_aggregation_cache_is_rebuilt_then_reused(monkeypatch, tmp_path):
    from nesy import pipeline
    monkeypatch.setattr(pipeline, "prompt_version", lambda name: "unchanged-prompt")
    ctx = SimpleNamespace(root=tmp_path, settings=SimpleNamespace(section=lambda name: {}),
                          base_files=[], facts=_facts(), cwe={}, cwe_id="CWE-078",
                          subject=SimpleNamespace(repo="fixture", id="fixture"))
    spec.SpecResult("", {"accepted": 0}, prompt_version="unchanged-prompt").save(tmp_path / "run0/spec-llm")
    calls = []
    def infer(*args, **kwargs):
        calls.append(1)
        return spec.SpecResult("", {"accepted": 0, "vote_version": spec.SPEC_VOTE_VERSION},
                               prompt_version="unchanged-prompt")
    monkeypatch.setattr(pipeline, "infer_spec", infer)
    llm = MockLLM(lambda messages, stage: "[]")
    pipeline.get_llm_spec(ctx, llm, 0, True)
    pipeline.get_llm_spec(ctx, llm, 0, True)
    assert len(calls) == 1
