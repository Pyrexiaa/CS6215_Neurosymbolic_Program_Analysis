import json

from conftest import DATA
from nesy.llm import MockLLM
from nesy.mock import heuristic_responder
from nesy.taie import TaintFlowGraph, filter_flows, parse_flows_from_log
from nesy.triage import Evidence, build_evidence, check_v3, triage_flow

CWE = {"name": "Path Traversal", "description": "d"}


def _flows():
    _, flows = parse_flows_from_log((DATA / "taie_console_sample.log").read_text())
    return filter_flows(flows, {"demo.app.Extractor"})


def test_v3_checks():
    ev = Evidence([], "", "", {"demo/app/Extractor.java": [(20, 40)]})
    assert check_v3({"evidence": [{"file": "demo/app/Extractor.java", "line": 29}]}, ev) == (True, [])
    ok, probs = check_v3({"evidence": [{"file": "Extractor.java", "line": 99}]}, ev)
    assert not ok and "outside" in probs[0]
    ok, probs = check_v3({"evidence": [{"file": "Other.java", "line": 25}]}, ev)
    assert not ok and "not in a file shown" in probs[0]
    assert check_v3({"evidence": []}, ev)[0] is False


def test_evidence_contains_path_methods(fixture_facts):
    tfg = TaintFlowGraph.load(DATA / "taint-flow-graph.sample.dot")
    f = next(x for x in _flows() if "extractSafely" in x.sink.method)
    ev = build_evidence(f, tfg, fixture_facts)
    assert "<demo.app.Extractor: void extractSafely(java.lang.String,java.lang.String)>" in ev.methods
    assert "getCanonicalFile" in ev.snippets_text and "demo/app/Extractor.java" in ev.shown


def test_triage_keeps_flow_when_citation_is_fabricated(fixture_facts):
    tfg = TaintFlowGraph.load(DATA / "taint-flow-graph.sample.dot")
    f = next(x for x in _flows() if "extractSafely" in x.sink.method)
    liar = MockLLM(lambda m, s: json.dumps({"verdict": "not_vulnerable", "reason": "sanitized",
                                            "evidence": [{"file": "demo/app/Extractor.java", "line": 500}]}))
    d = triage_flow(f, tfg, fixture_facts, liar, CWE, "CWE-022", {})
    assert d.verdict == "not_vulnerable" and d.v3_ok is False and d.kept          # V3 rejects -> kept
    d2 = triage_flow(f, tfg, fixture_facts, liar, CWE, "CWE-022", {}, validators=False)
    assert d2.kept is False                                                      # ablation trusts the LLM


def test_triage_removes_sanitised_flow_with_valid_citation(fixture_facts):
    tfg = TaintFlowGraph.load(DATA / "taint-flow-graph.sample.dot")
    f = next(x for x in _flows() if "extractSafely" in x.sink.method)
    d = triage_flow(f, tfg, fixture_facts, MockLLM(heuristic_responder), CWE, "CWE-022", {})
    assert d.verdict == "not_vulnerable" and d.v3_ok and not d.kept


def test_triage_voting(fixture_facts):
    tfg = TaintFlowGraph.load(DATA / "taint-flow-graph.sample.dot")
    f = _flows()[0]
    answers = iter(['{"verdict":"vulnerable"}', '{"verdict":"not_vulnerable","evidence":[]}', '{"verdict":"vulnerable"}'])
    d = triage_flow(f, tfg, fixture_facts, MockLLM(lambda m, s: next(answers)), CWE, "CWE-022", {"samples": 3})
    assert d.samples == ["vulnerable", "not_vulnerable", "vulnerable"] and d.verdict == "vulnerable" and d.kept
