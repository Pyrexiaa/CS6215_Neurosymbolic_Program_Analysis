from nesy.driver import build_template_driver, error_lines, make_template_driver, static_check, template_call


def test_template_calls(fixture_facts):
    code, entries = make_template_driver(fixture_facts, 10)
    assert "nesy.Taint.src()" in code and len(entries) == 3
    e = next(x for x in fixture_facts.entries if x.name == "runHook")
    assert template_call(e) == 'demo.app.Extractor r = new demo.app.Extractor(); r.runHook(nesy.Taint.src());'


def test_template_driver_compiles_and_repairs(fixture_facts, built_fixture, javac, tmp_path):
    # inject an entry that cannot compile (private-looking inner class) to exercise deterministic repair
    from copy import deepcopy
    from nesy.facts import EntryCandidate
    facts = deepcopy(fixture_facts)
    facts.entries.append(EntryCandidate("<demo.app.Missing: void go(java.lang.String)>", "demo.app.Missing", "go",
                                        ["java.lang.String"], True, "library-api", 1.0))
    res = build_template_driver(facts, tmp_path, [built_fixture / "app", built_fixture / "acme-util.jar"], javac, 10)
    assert res.ok and res.attempts == 2
    assert res.removed_entries == ["<demo.app.Missing: void go(java.lang.String)>"]
    assert res.app_calls >= 3 and res.taint_calls >= 3
    assert static_check(tmp_path / "classes", {"demo.app.Extractor"}) == (res.app_calls, res.taint_calls)


def test_error_line_parser():
    out = "/x/nesy/NesyDriver.java:7: error: cannot find symbol\n/x/nesy/NesyDriver.java:9: error: ';' expected"
    assert error_lines(out) == [7, 9]


def test_driver_compiles_despite_crashing_annotation_processor(fixture_facts, built_fixture, javac, tmp_path):
    """Regression (cron-utils): an annotation processor on the class path (old Lombok) crashed javac."""
    import os
    import subprocess
    from pathlib import Path
    src = tmp_path / "proc" / "evil"
    src.mkdir(parents=True)
    (src / "Evil.java").write_text(
        "package evil;\n"
        "@javax.annotation.processing.SupportedAnnotationTypes(\"*\")\n"
        "public class Evil extends javax.annotation.processing.AbstractProcessor {\n"
        "  public synchronized void init(javax.annotation.processing.ProcessingEnvironment e) {\n"
        "    throw new IllegalAccessError(\"boom\"); }\n"
        "  public boolean process(java.util.Set<? extends javax.lang.model.element.TypeElement> a,\n"
        "                         javax.annotation.processing.RoundEnvironment r) { return false; } }\n")
    classes = tmp_path / "proc" / "classes"
    env = dict(os.environ)
    env.pop("JAVA_TOOL_OPTIONS", None)
    subprocess.run([javac, "-d", str(classes), str(src / "Evil.java")], check=True, env=env, capture_output=True)
    svc = classes / "META-INF" / "services"
    svc.mkdir(parents=True)
    (svc / "javax.annotation.processing.Processor").write_text("evil.Evil\n")
    jar = tmp_path / "evil.jar"
    jarbin = str(Path(javac).with_name("jar"))
    subprocess.run([jarbin, "cf", str(jar), "-C", str(classes), "."], check=True, env=env)
    res = build_template_driver(fixture_facts, tmp_path / "drv",
                                [built_fixture / "app", built_fixture / "acme-util.jar", jar], javac, 10)
    assert res.ok, res.errors
