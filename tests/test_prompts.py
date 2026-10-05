import re

import pytest

from nesy.prompts import build_messages, load_template

NEEDED = {
    "n1_driver": ["cwe_id", "cwe_name", "cwe_description", "project", "readme", "candidates", "taint_api", "max_calls"],
    "n1_repair": ["errors", "code"],
    "n2_spec": ["cwe_id", "cwe_name", "cwe_description", "project", "apis"],
    "n3_triage": ["cwe_id", "cwe_name", "cwe_description", "flow", "path", "snippets"],
}


@pytest.mark.parametrize("name", sorted(NEEDED))
def test_templates_render(name):
    t = load_template(name)
    used = set(re.findall(r"\{\{(\w+)\}\}", t.get("system", "") + t["user"]))
    assert used == set(NEEDED[name]), f"{name}: placeholders {used} != {NEEDED[name]}"
    msgs = build_messages(name, {k: f"<{k}>" for k in NEEDED[name]})
    assert msgs[-1]["role"] == "user" and "{{" not in msgs[-1]["content"]


def test_missing_value_raises():
    with pytest.raises(KeyError):
        build_messages("n1_repair", {"errors": "x"})
