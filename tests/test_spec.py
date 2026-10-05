import json

import yaml

from nesy.jvm import parse_taie_signature
from nesy.llm import MockLLM
from nesy.spec import (base_config_files, infer_spec, select_candidates, signatures_in_config, to_taie_yaml,
                       validate_label)

FILE2 = parse_taie_signature("<java.io.File: void <init>(java.io.File,java.lang.String)>")
RUN = parse_taie_signature("<com.acme.util.Shell: int run(java.lang.String)>")
NAME = parse_taie_signature("<com.acme.util.Archive: java.lang.String entryName(int)>")
SIZE = parse_taie_signature("<com.acme.util.Archive: int size()>")


def test_validate_label_rules():
    assert validate_label({"role": "sink", "index": "1"}, FILE2, False)[0] == {"method": FILE2.taie, "index": 1}
    assert validate_label({"role": "sink", "index": "5"}, FILE2, False) == (None, "arg-out-of-range")
    assert validate_label({"role": "source", "index": "result"}, FILE2, False) == (None, "result-of-void")
    assert validate_label({"role": "sink", "index": "base"}, RUN, True) == (None, "base-of-static")
    assert validate_label({"role": "source", "index": "result"}, SIZE, False) == (None, "primitive-type")
    assert validate_label({"role": "transfer", "from": "0", "to": "0"}, RUN, True)[1] == "transfer-to-self"
    assert validate_label({"role": "sanitizer", "index": "result"}, NAME, False)[1] == "sanitizer-needs-arg-index"
    assert validate_label({"role": "weird"}, NAME, False)[1] == "bad-role"
    e, _ = validate_label({"role": "source", "index": "result"}, NAME, False)
    assert e == {"kind": "call", "method": NAME.taie, "index": "result"}


def test_base_config_selection(settings):
    files = base_config_files(settings.cwes, "CWE-022")
    names = {f.name for f in files}
    assert "path-traversal.yml" in names and "string-transfers.yml" in names
    sigs = signatures_in_config(files)
    assert "<java.io.File: void <init>(java.lang.String)>" in sigs["sink"]


def _responder_factory(answers):
    """answers: list of label lists, one per call (cycled)."""
    state = {"i": 0}

    def responder(msgs, stage):
        a = answers[state["i"] % len(answers)]
        state["i"] += 1
        # translate signatures into the batch ids shown in the prompt
        ids = {}
        for line in msgs[-1]["content"].splitlines():
            parts = line.split(" | ")
            if len(parts) >= 3 and parts[0].strip().isdigit():
                ids[parts[1].strip()] = int(parts[0])
        out = []
        for lab in a:
            lab = dict(lab)
            sig = lab.pop("sig", None)
            if sig is not None:
                if sig not in ids:
                    continue
                lab["id"] = ids[sig]
            out.append(lab)
        return "```json\n" + json.dumps(out) + "\n```"
    return responder


def test_infer_spec_voting_and_validation(fixture_facts, settings, tmp_path):
    good = [{"sig": NAME.taie, "role": "source", "index": "result"},
            {"sig": RUN.taie, "role": "sink", "index": "0"},
            {"sig": RUN.taie, "role": "sink", "index": "base"},                      # V2: static -> rejected
            {"id": 999, "role": "sink", "index": "0"},                               # unknown id
            {"signature": "<java.io.File: void <init>(java.io.File,java.lang.String)>", "role": "sink", "index": "1"},
            {"signature": "<java.io.File: void explode(java.lang.String)>", "role": "sink", "index": "0"}]  # hallucinated
    minority = [{"sig": NAME.taie, "role": "source", "index": "result"}]
    llm = MockLLM(_responder_factory([good, minority, good]), cache_dir=None)
    known = signatures_in_config(base_config_files(settings.cwes, "CWE-022"))
    cfg = {"batch_size": 50, "samples": 3, "include_jdk_apis": True}
    res = infer_spec(fixture_facts, llm, settings.cwes["cwes"]["CWE-022"], "CWE-022", "demo", cfg, known)
    acc = {(a["signature"], a["role"], json.dumps(a["entry"], sort_keys=True)) for a in res.accepted}
    sigs = {(s, r) for s, r, _ in acc}
    assert (NAME.taie, "source") in sigs                       # 3/3 votes
    assert (RUN.taie, "sink") in sigs                          # 2/3 votes -> majority
    assert (FILE2.taie, "sink") in sigs                        # extra signature verified against rt.jar/javap
    reasons = res.stats["rejected_by_reason"]
    assert reasons.get("base-of-static", 0) >= 2 and reasons.get("unknown-id", 0) >= 2
    assert reasons.get("signature-not-found", 0) + reasons.get("signature-unverifiable", 0) >= 2
    doc = yaml.safe_load(res.yaml_text)                        # emitted YAML must parse
    assert {e["method"] for e in doc["sinks"]} >= {RUN.taie, FILE2.taie}
    assert len(llm.calls) == 3                                 # one batch x 3 samples


def test_infer_spec_without_validators_keeps_bad_labels(fixture_facts, settings):
    bad = [{"sig": RUN.taie, "role": "sink", "index": "base"}]
    llm = MockLLM(_responder_factory([bad]))
    res = infer_spec(fixture_facts, llm, settings.cwes["cwes"]["CWE-022"], "CWE-022", "demo",
                     {"batch_size": 50, "samples": 1}, {}, validators=False)
    assert any(a["entry"].get("index") == "base" for a in res.accepted)


def test_candidates_keep_known_sinks_with_annotation(fixture_facts, settings):
    from nesy.spec import _api_line, known_entries
    files = base_config_files(settings.cwes, "CWE-022")
    known = signatures_in_config(files)
    cands = select_candidates(fixture_facts, known, include_jdk=True)
    c = {a.signature for a in cands}
    assert FILE2.taie in c                                  # base sink on arg 0 only -> still asked
    assert "<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>" not in c  # known transfer
    assert NAME.taie in c and RUN.taie in c
    api = next(a for a in cands if a.signature == FILE2.taie)
    line = _api_line(0, api, fixture_facts, 1, known_entries(files))
    assert "already configured: sink[0]" in line and "extractSafely" in line


def test_yaml_dedup():
    acc = [{"role": "sink", "entry": {"method": RUN.taie, "index": 0}}] * 2
    assert to_taie_yaml(acc).count("run(java.lang.String)") == 1


def test_runs_use_independent_samples(fixture_facts, settings):
    """Run k must not reuse run 0's cached answers (otherwise stability is trivially 1.0)."""
    llm = MockLLM(_responder_factory([[]]))
    for run in (0, 1):
        infer_spec(fixture_facts, llm, settings.cwes["cwes"]["CWE-022"], "CWE-022", "demo",
                   {"batch_size": 50, "samples": 2, "sample_offset": run * 1000}, {})
    assert [c["sample"] for c in llm.calls] == [0, 1, 1000, 1001]


def test_api_line_spells_out_index_slots(fixture_facts):
    """Each API prompt line lists valid receiver and argument indexes."""
    from nesy.facts import ExternalApi
    from nesy.spec import _index_slots
    ctor = ExternalApi("<java.io.File: void <init>(java.io.File,java.lang.String)>", "java.io.File", "<init>",
                       ["java.io.File", "java.lang.String"], "void", is_static=False, from_jdk=True)
    assert _index_slots(ctor) == "idx: 0=File, 1=String, base=new object"
    getter = ExternalApi("<java.io.File: java.lang.String getPath()>", "java.io.File", "getPath", [],
                         "java.lang.String", is_static=False, from_jdk=True)
    assert _index_slots(getter) == "idx: base=receiver, result=String"
    static = ExternalApi("<java.lang.Runtime: java.lang.Runtime getRuntime()>", "java.lang.Runtime", "getRuntime", [],
                         "java.lang.Runtime", is_static=True, from_jdk=True)
    assert _index_slots(static) == "idx: result=Runtime"


def test_noval_does_not_count_none_labels_as_rejections(fixture_facts, settings):
    from nesy.llm import MockLLM
    llm = MockLLM(lambda m, st: '[{"id": 0, "role": "none"}, {"id": 1, "role": "none"}]')
    res = infer_spec(fixture_facts, llm, settings.cwes["cwes"]["CWE-022"], "CWE-022", "demo",
                     {"batch_size": 50, "samples": 1}, {}, validators=False)
    assert res.stats["rejected"] == 0 and res.stats["accepted"] == 0
