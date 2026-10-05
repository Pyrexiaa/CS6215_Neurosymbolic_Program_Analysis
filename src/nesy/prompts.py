"""Prompt templates live in ``prompts/*.md`` so they can be versioned and cited in the report.

A template file has a ``## system`` and a ``## user`` section; ``{{name}}`` placeholders are
replaced with values (no other templating logic, on purpose).
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, List

from .config import REPO_ROOT

PROMPT_DIR = REPO_ROOT / "prompts"


def load_template(name: str) -> Dict[str, str]:
    text = (PROMPT_DIR / f"{name}.md").read_text()
    parts = re.split(r"^## (system|user)\s*$", text, flags=re.M)
    out: Dict[str, str] = {}
    for i in range(1, len(parts) - 1, 2):
        out[parts[i]] = parts[i + 1].strip("\n")
    if "user" not in out:
        raise ValueError(f"prompt {name} has no '## user' section")
    return out


def render(template: str, values: Dict[str, object]) -> str:
    def sub(m):
        key = m.group(1)
        if key not in values:
            raise KeyError(f"missing prompt value {key!r}")
        return str(values[key])
    return re.sub(r"\{\{(\w+)\}\}", sub, template)


def build_messages(name: str, values: Dict[str, object]) -> List[Dict[str, str]]:
    t = load_template(name)
    msgs = []
    if t.get("system"):
        msgs.append({"role": "system", "content": render(t["system"], values)})
    msgs.append({"role": "user", "content": render(t["user"], values)})
    return msgs


def prompt_version(name: str) -> str:
    """Short hash of a template, recorded with results so prompt changes are traceable."""
    return hashlib.sha1((PROMPT_DIR / f"{name}.md").read_bytes()).hexdigest()[:8]
