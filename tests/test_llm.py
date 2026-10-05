import json

import pytest

from nesy.llm import MockLLM, extract_code_block, extract_json, load_env_file, strip_reasoning


def test_extract_json_variants():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('<think>maybe {"no": 1</think> Answer: [{"id": 2, "role": "sink"}] done') == [{"id": 2, "role": "sink"}]
    assert extract_json('text {"s": "brace } in string", "n": [1, 2]} tail') == {"s": "brace } in string", "n": [1, 2]}
    with pytest.raises(ValueError):
        extract_json("no json here")


def test_code_block_and_reasoning():
    t = "<think>plan</think>\n```java\nclass A {}\n```"
    assert strip_reasoning(t).startswith("```java")
    assert extract_code_block(t) == "class A {}"


def test_mock_cache_ledger_usage(tmp_path):
    n = {"calls": 0}

    def responder(msgs, stage):
        n["calls"] += 1
        return "pong"
    llm = MockLLM(responder, cache_dir=tmp_path / "c", ledger=tmp_path / "l.jsonl")
    llm.context = {"subject": "s"}
    msgs = [{"role": "user", "content": "ping"}]
    a = llm.chat(msgs, stage="N2-spec")
    b = llm.chat(msgs, stage="N2-spec")
    c = llm.chat(msgs, stage="N2-spec", sample=1)
    assert a.text == b.text == "pong" and not a.cached and b.cached and not c.cached
    assert n["calls"] == 2
    rows = [json.loads(l) for l in (tmp_path / "l.jsonl").read_text().splitlines()]
    assert len(rows) == 3 and rows[0]["subject"] == "s" and rows[1]["cached"]
    u = llm.usage["N2-spec"]
    assert u["calls"] == 3 and u["cached_calls"] == 1 and u["fresh_prompt_tokens"] < u["prompt_tokens"]
    assert llm.served_models == {"mock"}


def test_env_file(tmp_path):
    p = tmp_path / ".env"
    p.write_text("# c\nA=1\nB = 'two'\n\nbad line\n")
    assert load_env_file(p) == {"A": "1", "B": "two"}
