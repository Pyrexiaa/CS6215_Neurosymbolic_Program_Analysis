from pathlib import Path

from conftest import DATA
from nesy.taie import TaintFlowGraph, build_command, TaieSettings, filter_flows, parse_flow_line, \
    parse_flows_from_log, parse_point


def test_parse_points():
    p = parse_point("<nesy.NesyDriver: void main(java.lang.String[])>[3@L5] %v5 = invokestatic nesy.Taint.src()/result")
    assert (p.stmt_index, p.line, p.index) == (3, 5, "result") and p.in_driver
    q = parse_point("<a.Controller: void doGet(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)>/0")
    assert q.line == -1 and q.index == "0"
    r = parse_point("<java.io.File: void <init>(java.lang.String)>[2@L93] invokespecial %v3.<init>($1)/0")
    assert r.method == "<java.io.File: void <init>(java.lang.String)>" and r.line == 93


def test_parse_flow_line_with_init_and_arrays():
    line = ("TaintFlow{<nesy.NesyDriver: void main(java.lang.String[])>[3@L5] %v5 = invokestatic nesy.Taint.src()/result "
            "-> <demo.app.Extractor: void extract(java.lang.String,java.lang.String)>[9@L17] invokespecial out.<init>(destDir, name)/1}")
    f = parse_flow_line(line)
    assert f.sink.method.endswith("extract(java.lang.String,java.lang.String)>") and f.sink.index == "1"
    assert f.key == "DRIVER => <demo.app.Extractor: void extract(java.lang.String,java.lang.String)>@L17/1"


def test_parse_real_log_sample():
    detected, flows = parse_flows_from_log((DATA / "taie_console_sample.log").read_text())
    assert detected and detected > 0 and len(flows) >= 4
    kept = filter_flows(flows, {"demo.app.Extractor"})
    assert all(not f.sink.owner.startswith("java.") for f in kept)
    assert len({f.key for f in kept}) == len(kept)       # merged by key


def test_tfg_path_and_methods():
    tfg = TaintFlowGraph.load(DATA / "taint-flow-graph.sample.dot")
    _, flows = parse_flows_from_log((DATA / "taie_console_sample.log").read_text())
    f = next(x for x in flows if "extract(java.lang.String,java.lang.String)>[9@L17]" in x.sink.raw
             and x.sink.index == "1" and "entryName" in x.source.raw)
    path = tfg.path(f)
    assert path and path[0].endswith(f.source.raw) and path[-1].endswith(f.sink.raw)
    assert "<demo.app.Extractor: void extract(java.lang.String,java.lang.String)>" in tfg.methods_between(f)


def test_build_command(tmp_path):
    s = TaieSettings(jar=Path("tools/x.jar"), java_bin=Path("/j/bin/java"), jre_version=8, cs="1-call",
                     extra_pta_options={"merge-string-builders": "false"})
    cmd = build_command(s, [tmp_path / "app"], [tmp_path / "lib.jar"], "nesy.NesyDriver", tmp_path / "cfg", tmp_path / "out")
    pta = cmd[cmd.index("-a") + 1]
    assert cmd[cmd.index("-java") + 1] == "8" and "-acp" in cmd and "-cp" in cmd
    assert pta.startswith("pta=cs:1-call;only-app:false;taint-config:") and "merge-string-builders:false" in pta
