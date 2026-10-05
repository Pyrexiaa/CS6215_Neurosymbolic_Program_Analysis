"""T01 freeze helper: hashing is stable and detects a changed byte."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("freeze_inputs", ROOT / "scripts" / "freeze_inputs.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_sha256_file_stable_and_sensitive(tmp_path):
    fz = _load()
    p = tmp_path / "a.txt"
    p.write_text("hello")
    h1 = fz.sha256_file(p)
    assert h1 == fz.sha256_file(p)          # stable
    p.write_text("hell0")
    assert fz.sha256_file(p) != h1          # one byte changes the digest


def test_build_freeze_has_source_group():
    fz = _load()
    freeze = fz.build_freeze()
    assert "source" in freeze["groups"]
    src = freeze["groups"]["source"]
    assert src["n_files"] >= 1 and len(src["combined_sha256"]) == 64
