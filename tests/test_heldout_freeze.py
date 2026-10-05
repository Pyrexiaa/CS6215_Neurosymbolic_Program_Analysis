"""The held-out runner must stop before analysis when its frozen inputs change."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.fixture
def frozen_repo(tmp_path):
    if not shutil.which("git") or not shutil.which("bash"):
        pytest.skip("git and bash required")
    source = Path(__file__).resolve().parents[1] / "scripts/run_test.sh"
    (tmp_path / "scripts").mkdir()
    shutil.copyfile(source, tmp_path / "scripts/run_test.sh")
    (tmp_path / "config").mkdir()
    (tmp_path / "config/subjects.yaml").write_text("subjects: []\n")
    (tmp_path / "config/cwe.yaml").write_text("cwes: {}\n")
    (tmp_path / ".gitignore").write_text("config/ignored.yml\n")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "freeze"], cwd=tmp_path, check=True)
    subprocess.run(["git", "tag", "heldout-freeze"], cwd=tmp_path, check=True)
    # The initial subject-list query is harmless; any later Python invocation fails the test.
    fake = tmp_path / "fake-python"
    fake.write_text('#!/bin/sh\nif [ "$1" = "-c" ]; then exit 0; fi\necho "UNEXPECTED_ANALYSIS"\nexit 99\n')
    fake.chmod(0o755)
    return tmp_path, {**os.environ, "PYTHON": str(fake)}


@pytest.mark.parametrize("path", ["config/subjects.yaml", "config/cwe.yaml", "scripts/run_test.sh"])
def test_changed_frozen_inputs_stop_before_analysis(frozen_repo, path):
    repo, env = frozen_repo
    with (repo / path).open("a") as stream:
        stream.write("\n# changed\n")
    run = subprocess.run(["bash", "scripts/run_test.sh", "run"], cwd=repo, env=env,
                         capture_output=True, text=True)
    assert run.returncode == 1
    assert "changed since 'heldout-freeze'" in run.stdout
    assert "UNEXPECTED_ANALYSIS" not in run.stdout


@pytest.mark.parametrize("path", ["config/new.yml", "config/ignored.yml"])
def test_untracked_including_ignored_config_stops_before_analysis(frozen_repo, path):
    repo, env = frozen_repo
    (repo / path).write_text("sinks: []\n")
    run = subprocess.run(["bash", "scripts/run_test.sh", "run"], cwd=repo, env=env,
                         capture_output=True, text=True)
    assert run.returncode == 1
    assert "untracked analyzer/configuration inputs" in run.stdout
    assert path in run.stdout
    assert "UNEXPECTED_ANALYSIS" not in run.stdout
