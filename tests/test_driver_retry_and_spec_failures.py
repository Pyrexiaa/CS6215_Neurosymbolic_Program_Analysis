"""N1 answers cut off by max_tokens are retried instead of silently falling back to the template
driver; Tai-e crashes in the V2-off ablations are explained by the invalid N2 entries."""
from nesy.llm import LLMResponse, MockLLM
from test_analysis_guards import _APP, _LIB, _compile


class _CutOffLLM(MockLLM):
    """Returns a cut-off answer (no code block, finish_reason=length) when max_tokens is small."""

    def __init__(self, responder, limit):
        super().__init__(responder)
        self.limit = limit
        self.budgets = []

    def _complete(self, messages, temperature, max_tokens, seed):
        self.budgets.append(max_tokens)
        if max_tokens <= self.limit:
            return LLMResponse(text="<think>long reasoning ...", model=self.model, prompt_tokens=10,
                               completion_tokens=max_tokens, finish_reason="length")
        return super()._complete(messages, temperature, max_tokens, seed)


def test_cut_off_n1_answer_is_retried_with_larger_budget(javac, tmp_path):
    from nesy.driver import build_llm_driver
    from nesy.facts import extract_facts
    lib, app = tmp_path / "lib", tmp_path / "app"
    _compile(javac, _LIB, lib)
    _compile(javac, _APP, app, cp=str(lib))
    facts = extract_facts([app], [lib], [], [])

    def responder(msgs, stage):
        return ('```json\n{"entries": [{"signature": "app.W: void run(java.lang.String)", "tainted_params": [0]}]}\n```\n'
                "```java\npackage nesy;\npublic class NesyDriver { public static void main(String[] a) {\n"
                "  new app.W().run(nesy.Taint.src());\n} }\n```")
    llm = _CutOffLLM(responder, limit=100)
    res = build_llm_driver(facts, llm, tmp_path / "work", [lib, app], javac, {"name": "x"}, "CWE-078", "demo",
                           None, {"max_tokens": 100})
    assert res.kind == "llm" and res.ok
    assert llm.budgets == [100, 200]
    assert any("cut off" in e for e in res.errors)


def test_answer_without_code_and_not_cut_off_is_not_retried(javac, tmp_path):
    from nesy.driver import build_llm_driver
    from nesy.facts import extract_facts
    lib, app = tmp_path / "lib", tmp_path / "app"
    _compile(javac, _LIB, lib)
    _compile(javac, _APP, app, cp=str(lib))
    facts = extract_facts([app], [lib], [], [])
    llm = _CutOffLLM(lambda msgs, stage: "I cannot write this driver.", limit=0)
    res = build_llm_driver(facts, llm, tmp_path / "work", [lib, app], javac, {"name": "x"}, "CWE-078", "demo",
                           None, {"max_tokens": 100})
    assert res.kind == "llm-fallback-template"
    assert llm.budgets == [100]


def test_invalid_spec_entries_explain_v2_ablation_crash(fixture_facts, tmp_path):
    from nesy.spec import invalid_spec_entries
    f = tmp_path / "llm-inferred.yml"
    f.write_text(
        "sources:\n"
        '  - { kind: "call", method: "<java.util.zip.ZipEntry: java.lang.String getName()>", index: "result" }\n'
        "sinks:\n"
        '  - { method: "<java.lang.Thread: java.lang.String getName()>", index: "0" }\n'
        "transfers:\n"
        '  - { method: "<java.lang.String: java.lang.String valueOf(java.lang.Object)>", from: "0", to: "base" }\n'
        '  - { method: "<java.lang.String: java.lang.String trim()>", from: "base", to: "result" }\n')
    bad = invalid_spec_entries(f, fixture_facts)
    assert len(bad) == 2
    assert any("Thread" in b and "arg-out-of-range" in b for b in bad)
    assert any("valueOf" in b and "base-of-static" in b for b in bad)


def test_v2_off_crash_is_reproduced_and_marked_expected(settings, built_fixture, tmp_path):
    """With V2 disabled, a transfer to the receiver of a static method crashes Tai-e
    (ClassCastException InvokeStatic -> InvokeInstanceExp). The run record identifies
    the expected ablation failure and its offending entry."""
    import copy
    import re
    import pytest
    from conftest import FIXTURE, taie_available
    from nesy.config import Subject
    from nesy.pipeline import SubjectContext, run_config
    from nesy.subjects import BuildLayout
    if not taie_available(settings):
        pytest.skip("Tai-e not available")
    s = copy.deepcopy(settings)
    s.raw["work_dir"], s.raw["results_dir"] = str(tmp_path / "w"), str(tmp_path / "r")
    s.raw["configs"]["x-noV2"] = {"driver": "template", "spec": ["base", "llm"], "triage": False,
                                  "spec_validator": False}
    subj = Subject(id="minizip", slug="minizip", role="test", cve="DEMO", cwe="CWE-022", repo="fixture",
                   buggy_commit="-", fixed_commit="-")
    lay = BuildLayout(str(FIXTURE), [str(built_fixture / "app")], [str(built_fixture / "acme-util.jar")],
                      [str(FIXTURE / "app" / "src")], True)
    ctx = SubjectContext(s, subj, "buggy", lay)
    ctx.fixed_methods = []

    def responder(msgs, stage):   # label every static method with an argument as "transfer 0 -> base"
        labs = [f'{{"id": {m.group(1)}, "role": "transfer", "from": "0", "to": "base"}}'
                for m in re.finditer(r"^(\d+) \| (<[^|]+>) \| idx: ([^|]*)\|", msgs[-1]["content"], re.M)
                if "base=" not in m.group(3) and "0=" in m.group(3)]
        return "```json\n[" + ",".join(labs) + "]\n```"
    rec = run_config(ctx, "x-noV2", 0, lambda: MockLLM(responder))
    assert rec["taie"]["ok"] is False and rec["taie"]["expected_failure"] is True
    assert any("base-of-static" in e for e in rec["taie"]["invalid_spec_entries"])
    # `nesy recheck` re-runs Tai-e with and without the invalid entries
    from nesy.pipeline import recheck_crash
    r = recheck_crash(ctx, "x-noV2", 0)
    assert r["original_ok"] is False and "ClassCastException" in r["original_error"]
    assert r["removed"] >= 1 and r["cleaned_ok"] is True
