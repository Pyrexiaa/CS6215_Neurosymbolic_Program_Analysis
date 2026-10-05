from nesy.subjects import discover_layout


def test_discover_multimodule_layout(tmp_path):
    p = tmp_path / "proj"
    for mod in ("core", "admin"):
        (p / mod / "target" / "classes" / "x").mkdir(parents=True)
        (p / mod / "src" / "main" / "java" / "x").mkdir(parents=True)
    jar = tmp_path / "dep.jar"
    jar.write_bytes(b"PK")
    (p / "admin" / "nesy-cp.txt").write_text(f"{jar}:{tmp_path}/missing.jar")
    lay = discover_layout(p, ["admin"])
    assert lay.app_dirs == [str(p / "admin" / "target" / "classes")]
    assert str(p / "core" / "target" / "classes") in lay.lib_jars and str(jar) in lay.lib_jars
    assert all("missing" not in j for j in lay.lib_jars)
    assert lay.source_roots == [str(p / "admin" / "src" / "main" / "java")]
    full = discover_layout(p)
    assert len(full.app_dirs) == 2


def test_subjects_config(settings):
    ids = [s.id for s in settings.subjects.values() if s.role == "primary"]
    assert ids == ["spark", "zt-zip", "cron-utils", "perfecto-plugin"]
    for s in settings.subjects.values():
        assert len(s.buggy_commit) == 40 and len(s.fixed_commit) == 40 and s.cwe in settings.cwes["cwes"]


def _git(cwd, *args):
    import subprocess
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd, check=True,
                   capture_output=True)


def test_fetch_fixed_backport(tmp_path, settings):
    """fixed = buggy commit + src/main part of the fix commit (build files stay as in buggy)."""
    import copy
    import subprocess
    from nesy.config import Subject
    from nesy.subjects import fetch
    up = tmp_path / "upstream"
    (up / "src/main/java").mkdir(parents=True)
    _git(tmp_path, "init", "-q", str(up))
    (up / "pom.xml").write_text("<target>8</target>\n")
    (up / "src/main/java/A.java").write_text("class A { String m() { return \"bad\"; } }\n")
    _git(up, "add", "-A"); _git(up, "commit", "-qm", "buggy")
    buggy = subprocess.run(["git", "rev-parse", "HEAD"], cwd=up, capture_output=True, text=True).stdout.strip()
    (up / "pom.xml").write_text("<target>16</target>\n")
    (up / "src/main/java/A.java").write_text("class A { String m() { return \"good\"; } }\n")
    _git(up, "add", "-A"); _git(up, "commit", "-qm", "fix + java 16")
    fix = subprocess.run(["git", "rev-parse", "HEAD"], cwd=up, capture_output=True, text=True).stdout.strip()
    s = copy.deepcopy(settings)
    s.raw["work_dir"] = str(tmp_path / "work")
    subj = Subject(id="toy", slug="toy", role="t", cve="X", cwe="CWE-022", repo=str(up), buggy_commit=buggy,
                   fixed_commit=fix, fixed_backport=[fix])
    t = fetch(s, subj, "fixed")
    assert "good" in (t / "src/main/java/A.java").read_text()
    assert (t / "pom.xml").read_text().strip() == "<target>8</target>"      # build setup of the buggy version
    assert fetch(s, subj, "fixed") == t                                       # idempotent
    b = fetch(s, subj, "buggy")
    assert "bad" in (b / "src/main/java/A.java").read_text()
