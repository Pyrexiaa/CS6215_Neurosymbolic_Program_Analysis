"""Regression tests for crash handling, patch-method matching and symbolic validation rules."""
import sys
import time
from pathlib import Path

from conftest import DATA
from nesy.groundtruth import FixedMethod
from nesy.pipeline import gt_tiers
from nesy.taie import TaintFlow, TaintFlowGraph, TaintPoint, parse_flows_from_log, run_watched


def _py(code):
    return [sys.executable, "-c", code]


def test_watcher_kills_jvm_that_lingers_after_main_thread_crash(tmp_path):
    # mimics Tai-e: stack trace in main, then a non-daemon timer keeps the process alive
    code = ("import sys,time; print('Exception in thread \"main\" java.lang.ClassCastException: x', flush=True);"
            "print('\\tat pascal.taie.Main.main(Main.java:51)', flush=True); time.sleep(120)")
    t0 = time.time()
    rc, timed_out, crashed = run_watched(_py(code), tmp_path, tmp_path / "log", None, 60, poll_s=0.2, grace_s=0.5)
    assert crashed and rc == 1 and not timed_out
    assert time.time() - t0 < 15
    assert "ClassCastException" in (tmp_path / "log").read_text()


def test_watcher_normal_exit_and_timeout(tmp_path):
    rc, to, cr = run_watched(_py("print('Detected 0 taint flow(s):')"), tmp_path, tmp_path / "a", None, 30, poll_s=0.2)
    assert (rc, to, cr) == (0, False, False)
    rc, to, cr = run_watched(_py("import time; time.sleep(60)"), tmp_path, tmp_path / "b", None, 1, poll_s=0.2)
    assert to and rc == -9 and not cr


def _fm(cls, method):
    return FixedMethod(f"src/main/java/demo/app/{cls}.java", cls, method, 1, 99, "")


def test_strict_gt_uses_route_not_reachability():
    tfg = TaintFlowGraph.load(DATA / "taint-flow-graph.sample.dot")
    _, flows = parse_flows_from_log((DATA / "taie_console_sample.log").read_text())
    f = next(x for x in flows if "extract(java.lang.String,java.lang.String)>[9@L17]" in x.sink.raw
             and x.sink.index == "1" and "entryName" in x.source.raw)
    gt, weak = gt_tiers(f, tfg, [_fm("Extractor", "extract")])
    assert gt == ["Extractor.extract"] and weak == []


def test_reachable_but_off_route_method_is_only_weak():
    # no complete route in the (application-only) TFG: src -> B.other (dead end), A.m -> sink.
    # One-sided reachability to B.other counts only as weak relevance, not a connecting route.
    src = TaintPoint("<d.S: void s()>", 1, 1, "x", "result", "<d.S: void s()>[1@L1] x/result")
    snk = TaintPoint("<d.A: void m(java.lang.String)>", 2, 5, "y", "0", "<d.A: void m(java.lang.String)>[2@L5] y/0")
    a = "VarNode{<d.A: void m(java.lang.String)>/v}"
    b = "VarNode{<d.B: void other(java.lang.String)>/w}"
    tfg = TaintFlowGraph([(a, "cfg\n" + snk.raw, ""), ("cfg\n" + src.raw, b, "")])
    fixed = [FixedMethod("src/main/java/d/B.java", "B", "other", 1, 9, "")]
    gt, weak = gt_tiers(TaintFlow(src, snk), tfg, fixed)
    assert gt == [] and weak == ["B.other"]


# ----------------------------------------------------------------- array-element and trusted-sink rules

def _acc(method, index, votes=3):
    return {"signature": method, "role": "sink", "entry": {"method": method, "index": index},
            "votes": votes, "samples": 3, "why": ""}


def test_array_element_rule_adds_element_sinks_only_for_array_args():
    from nesy.spec import array_element_sinks, to_taie_yaml
    exec_ = "<java.lang.Runtime: java.lang.Process exec(java.lang.String[])>"
    file_ = "<java.io.File: void <init>(java.lang.String)>"
    pb = "<java.lang.ProcessBuilder: void <init>(java.lang.String[])>"
    added = array_element_sinks([_acc(exec_, 0), _acc(file_, 0), _acc(pb, 0), _acc(pb, "0[*]")])
    assert [(a["entry"]["method"], a["entry"]["index"]) for a in added] == [(exec_, "0[*]")]
    assert 'index: "0[*]"' in to_taie_yaml(added)


def test_sink_entries_read_from_tfg_labels():
    tfg = TaintFlowGraph.load(DATA / "taint-flow-graph.sample.dot")
    _, flows = parse_flows_from_log((DATA / "taie_console_sample.log").read_text())
    f = next(x for x in flows if "extract(java.lang.String,java.lang.String)>[9@L17]" in x.sink.raw)
    sigs = tfg.sink_entries(f.sink)
    assert sigs and all(s.startswith("<java.io.File: void <init>(") for s in sigs)


def test_trusted_sink_rule_keeps_flow_and_counts_as_v3_rejection():
    from nesy.triage import TriageDecision, apply_trusted_sink_rule
    sink = "<javax.validation.ConstraintValidatorContext: javax.validation.ConstraintValidatorContext$ConstraintViolationBuilder buildConstraintViolationWithTemplate(java.lang.String)>"

    def dec(reason):
        return TriageDecision("id", "k", "not_vulnerable", reason, False, True)
    d = apply_trusted_sink_rule(dec("not_dangerous_sink"), [sink], {sink})
    assert d.kept and d.v3_ok is False and d.override == "trusted-sink"
    # other reasons (e.g. sanitised) are still N3's call; untrusted sinks can still be dropped
    assert not apply_trusted_sink_rule(dec("sanitized"), [sink], {sink}).kept
    assert not apply_trusted_sink_rule(dec("not_dangerous_sink"), [sink], {"<a.B: void c()>"}).kept
    assert not apply_trusted_sink_rule(dec("not_dangerous_sink"), [sink], None).kept


# ----------------------------------------------------------------- deterministic evidence and driver calls

def test_tfg_evidence_is_independent_of_hash_seed():
    """N3 prompts must not depend on PYTHONHASHSEED, or the LLM cache misses and verdicts drift."""
    import subprocess
    from conftest import ROOT
    code = ("import sys; sys.path.insert(0, %r); sys.path.insert(0, %r)\n"
            "from conftest import DATA\n"
            "from nesy.taie import TaintFlowGraph, parse_flows_from_log\n"
            "tfg = TaintFlowGraph.load(DATA / 'taint-flow-graph.sample.dot')\n"
            "_, flows = parse_flows_from_log((DATA / 'taie_console_sample.log').read_text())\n"
            "print([(tfg.path(f), tfg.methods_between(f), tfg.route_methods(f)) for f in flows])\n"
            % (str(ROOT / "src"), str(ROOT / "tests")))
    outs = set()
    for seed in ("1", "2", "3"):
        env = dict(__import__("os").environ, PYTHONHASHSEED=seed)
        outs.add(subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env,
                                check=True).stdout)
    assert len(outs) == 1


def test_crash_error_message_skips_duplicate_class_warnings(tmp_path):
    from nesy.taie import TaieSettings, run_taie
    log = ("Duplicate classes (total 4) introduced by a.jar and b.jar,\n"
           "[org.xmlpull.v1.XmlPullParserException, org.foo.LogConfigurationException] is founded in both containers\n"
           'Exception in thread "main" java.lang.ClassCastException: class pascal.taie.ir.exp.InvokeStatic\n'
           "\tat pascal.taie.Main.main(Main.java:51)\n")
    script = tmp_path / "fake_taie.py"
    script.write_text("import sys\nsys.stdout.write(%r)\nsys.stdout.flush()\nsys.exit(1)\n" % log)
    s = TaieSettings(jar=script, java_bin=Path(sys.executable), jre_version=None, home=tmp_path / "home")
    import nesy.taie as T
    orig = T.build_command
    T.build_command = lambda *a, **k: [sys.executable, str(script)]
    try:
        r = run_taie(s, [], [], "x", tmp_path / "cfg", tmp_path / "out")
    finally:
        T.build_command = orig
    assert not r.ok and r.error.startswith("CRASH")
    assert r.error.splitlines()[1].startswith('Exception in thread "main" java.lang.ClassCastException')


_LIB = {
    "lib/AbstractBuild.java": "package lib; public class AbstractBuild {}",
    "lib/Build.java": "package lib; public class Build extends AbstractBuild {}",
    "lib/Base.java": "package lib; public class Base { public void setUp(Build b) {} }",
}
_APP = {"app/W.java": "package app; public class W extends lib.Base {"
                      " public void setUp(lib.AbstractBuild b) {} public void run(String s) {}"
                      " public void setP(String p) {} }"}


def _compile(javac, files, out, cp=None):
    import subprocess
    srcs = []
    for rel, text in files.items():
        p = out.parent / ("src-" + out.name) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        srcs.append(str(p))
    cmd = [javac, "-d", str(out)] + (["-cp", cp] if cp else []) + srcs
    subprocess.run(cmd, check=True, capture_output=True)


def test_entry_check_flags_wrong_overload_and_missing_entry(javac, tmp_path):
    from nesy.classfile import iter_classes_in_dir
    from nesy.driver import entry_call_mismatches
    lib, app = tmp_path / "lib", tmp_path / "app"
    _compile(javac, _LIB, lib)
    _compile(javac, _APP, app, cp=str(lib))
    apps = {ci.name: ci for ci in iter_classes_in_dir(app)}
    declared = ["app.W: void setUp(lib.AbstractBuild)", "app.W: void run(java.lang.String)"]

    def driver(body, name):
        d = tmp_path / name
        _compile(javac, {"nesy/NesyDriver.java": "package nesy; public class NesyDriver { public static void "
                                                 "main(String[] a) { app.W w = new app.W(); " + body + " } }"},
                 d, cp=f"{lib}:{app}")
        return d
    bad = entry_call_mismatches(driver("w.setUp(null);", "bad"), apps, declared)
    assert len(bad) == 2
    assert "inherited library method <void setUp(lib.Build)>" in bad[0] and "(lib.AbstractBuild) null" in bad[0]
    assert "void run(java.lang.String)" in bad[1] and "never called" in bad[1]
    good = entry_call_mismatches(driver("w.setUp((lib.AbstractBuild) null); w.run(\"x\");", "good"), apps, declared)
    assert good == []


def test_entry_check_drives_n1_repair_loop(javac, tmp_path):
    """End to end through build_llm_driver with a scripted LLM: the first driver compiles but calls the
    inherited overload; the entry-call check sends it to N1-repair; the repaired driver is accepted."""
    from nesy.driver import build_llm_driver
    from nesy.facts import extract_facts
    from nesy.llm import MockLLM
    lib, app = tmp_path / "lib", tmp_path / "app"
    _compile(javac, _LIB, lib)
    _compile(javac, _APP, app, cp=str(lib))
    facts = extract_facts([app], [lib], [], [])
    entries = '{"entries": [{"signature": "app.W: void setUp(lib.AbstractBuild)", "tainted_params": []}]}'

    def drv(call):
        return ("```java\npackage nesy;\npublic class NesyDriver { public static void main(String[] a) {\n"
                "  app.W w = new app.W(); w.run(nesy.Taint.src());\n  " + call + "\n} }\n```")
    seen = []

    def responder(msgs, stage):
        seen.append((stage, msgs[-1]["content"]))
        if stage == "N1-driver":
            return "```json\n" + entries + "\n```\n" + drv("w.setUp(null);")
        return drv("w.setUp((lib.AbstractBuild) null);")
    cfg = {"entry_check": True, "max_repairs": 2}
    res = build_llm_driver(facts, MockLLM(responder), tmp_path / "work", [lib, app], javac,
                           {"name": "x"}, "CWE-078", "demo", None, cfg)
    assert res.kind == "llm" and res.ok and res.entry_mismatches == []
    assert [s for s, _ in seen] == ["N1-driver", "N1-repair"]
    assert "inherited library method" in seen[1][1]
    # without the check (v2/v3 behaviour) the wrong driver is accepted as is
    res2 = build_llm_driver(facts, MockLLM(responder), tmp_path / "work2", [lib, app], javac,
                            {"name": "x"}, "CWE-078", "demo", None, {"max_repairs": 2})
    assert res2.kind == "llm" and res2.attempts == 1



# ----------------------------------------------------------------- receiver-state checks

def test_receiver_state_check_flags_split_state_only(javac, tmp_path):
    from nesy.classfile import iter_classes_in_dir
    from nesy.driver import receiver_state_problems
    lib, app = tmp_path / "lib", tmp_path / "app"
    _compile(javac, _LIB, lib)
    _compile(javac, _APP, app, cp=str(lib))
    apps = {ci.name: ci for ci in iter_classes_in_dir(app)}
    declared = ["<app.W: void setUp(lib.AbstractBuild)>"]
    split = """
        try { app.W w = new app.W(); w.setUp((lib.AbstractBuild) null); } catch (Throwable t) {}
        try { app.W w1 = new app.W(); w1.setP(nesy.Taint.src()); } catch (Throwable t) {}   // w.setUp( in a comment
    """
    probs = receiver_state_problems(split, declared, apps)
    assert len(probs) == 1 and "`w.setUp(...)`" in probs[0] and "w1" in probs[0] and "w.setP(nesy.Taint.src())" in probs[0]
    same = """
        try { app.W w = new app.W(); w.setP(nesy.Taint.src()); w.setUp((lib.AbstractBuild) null); }
        catch (Throwable t) {}
    """
    assert receiver_state_problems(same, declared, apps) == []
    # null framework arguments without any tainted W elsewhere (e.g. a servlet filter's doFilter(null, ...))
    # may still reach sources in call-site mode: not flagged
    alone = "try { app.W w = new app.W(); w.setUp((lib.AbstractBuild) null); } catch (Throwable t) {}"
    assert receiver_state_problems(alone, declared, apps) == []
