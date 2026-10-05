"""Optional smoke test against the real SoCLaaS endpoint.

Run with:  NESY_LIVE_LLM=1 python -m pytest -m live_llm -q
Needs .env with SOCLAAS_* and the NUS network/VPN."""
import os

import pytest

from nesy.llm import client_from_env, extract_json

pytestmark = pytest.mark.live_llm


@pytest.mark.skipif(os.environ.get("NESY_LIVE_LLM") != "1", reason="set NESY_LIVE_LLM=1 to call SoCLaaS")
def test_live_json_answer(settings):
    c = client_from_env(settings.env, None, None, model=settings.section("llm").get("model"))
    r = c.chat([{"role": "user", "content": 'Return exactly this JSON and nothing else: {"ok": true}'}],
               stage="live-test", max_tokens=1500, use_cache=False)
    assert extract_json(r.text) == {"ok": True}
    assert r.prompt_tokens > 0
