"""Build-failure, dependency-scope and cached-layout regression guards.

These are behaviour tests with the subprocess layer stubbed, so they need neither Maven nor a JDK:
  * a failed custom prerequisite build must not be masked by a later successful Maven run;
  * the dependency scope sent to `dependency:build-classpath` is explicit and correct
    (full scope by default -- no filter; `-DincludeScope=<s>` when NESY_DEP_SCOPE is set --
    and never the old, silently-ignored `-Dmdep.includeScope`);
  * SubjectContext refuses a disk layout that did not build cleanly (ok=False), unless a layout is
    injected explicitly or NESY_ALLOW_PREBUILT_LAYOUT=1.
"""
import copy
import json
import subprocess
from dataclasses import asdict

import pytest

import nesy.subjects as S
from nesy.config import Subject
from nesy.subjects import BuildLayout, layout_path


def _toy(**kw):
    base = dict(id="toy", slug="toy", role="t", cve="X", cwe="CWE-022", repo="-",
                buggy_commit="-", fixed_commit="-")
    base.update(kw)
    return Subject(**base)


def _settings(settings, tmp_path):
    s = copy.deepcopy(settings)
    s.raw["work_dir"] = str(tmp_path / "w")
    s.subjects = {"toy": _toy()}
    return s


def _capture_run(monkeypatch, prereq_rc=0, mvn_rc=0):
    calls = []

    def fake_run(cmd, cwd=None, env=None, timeout=3600, log=None):
        calls.append(list(cmd))
        is_prereq = cmd[:2] == ["bash", "-lc"]
        return subprocess.CompletedProcess(cmd, prereq_rc if is_prereq else mvn_rc, "", "")

    monkeypatch.setattr(S, "_run", fake_run)
    return calls


def _mk_pom(s, version="buggy"):
    proj = S.subject_dir(s, "toy", version)
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "pom.xml").write_text("<project/>\n")
    return proj


def test_failed_prerequisite_is_not_masked(tmp_path, settings, monkeypatch):
    s = _settings(settings, tmp_path)
    _mk_pom(s)
    calls = _capture_run(monkeypatch, prereq_rc=1, mvn_rc=0)   # prereq fails, mvn would pass
    lay = S.build(s, _toy(build_cmd="do-prereq"), "buggy")
    assert lay.ok is False
    assert ["bash", "-lc", "do-prereq"] in calls              # prerequisite ran
    assert not any("dependency:build-classpath" in c for c in calls)  # mvn was not reached


def test_dependency_scope_default_is_full(tmp_path, settings, monkeypatch):
    s = _settings(settings, tmp_path)
    _mk_pom(s)
    monkeypatch.delenv("NESY_DEP_SCOPE", raising=False)
    calls = _capture_run(monkeypatch)
    S.build(s, _toy(), "buggy")
    mvn = next(c for c in calls if "dependency:build-classpath" in c)
    assert not any("includeScope" in str(x) for x in mvn)     # full scope: no filter
    assert not any("mdep.includeScope" in str(x) for x in mvn)  # the old no-op flag is gone


def test_dependency_scope_restricted_when_set(tmp_path, settings, monkeypatch):
    s = _settings(settings, tmp_path)
    _mk_pom(s)
    monkeypatch.setenv("NESY_DEP_SCOPE", "compile")
    calls = _capture_run(monkeypatch)
    S.build(s, _toy(), "buggy")
    mvn = next(c for c in calls if "dependency:build-classpath" in c)
    assert "-DincludeScope=compile" in mvn
    assert not any("mdep.includeScope" in str(x) for x in mvn)


def test_subjectcontext_rejects_not_ok_disk_layout(tmp_path, settings, monkeypatch):
    from nesy.pipeline import SubjectContext, PipelineError
    s = _settings(settings, tmp_path)
    appdir = tmp_path / "classes"
    appdir.mkdir()
    lay = BuildLayout(str(tmp_path), [str(appdir)], [], [], False)   # ok=False
    lp = layout_path(s, "toy", "buggy")
    lp.parent.mkdir(parents=True, exist_ok=True)
    lp.write_text(json.dumps(asdict(lay)))
    monkeypatch.delenv("NESY_ALLOW_PREBUILT_LAYOUT", raising=False)
    with pytest.raises(PipelineError):
        SubjectContext(s, _toy(), "buggy")   # disk-loaded, ok=False -> rejected before fact extraction
