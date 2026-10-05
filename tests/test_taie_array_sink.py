"""Array-element sinks: `Runtime.exec(String[])` is configured in Tai-e's commonly-used config with
`index: 0`, i.e. the array object itself. When only an *element* of the command array is tainted
(the usual case: `new String[]{"sh", "-c", userInput}`), the sink fires only with `index: "0[*]"`."""
import os
import subprocess

import pytest

from conftest import taie_available
from nesy.pipeline import taie_settings
from nesy.taie import run_taie

pytestmark = pytest.mark.integration

APP = """package app;
public class Cmd {
    public void run(String arg) throws Exception {
        String[] cmd = new String[] {"sh", "-c", "echo " + arg};
        Runtime.getRuntime().exec(cmd);
    }
}
"""
DRV = """package nesy;
public class NesyDriver { public static void main(String[] a) throws Exception { new app.Cmd().run(Taint.src()); } }
"""


@pytest.mark.parametrize("index,expected", [("0", 0), ("0[*]", 1)])
def test_exec_array_needs_element_index(settings, javac, tmp_path, index, expected):
    if not taie_available(settings):
        pytest.skip("Tai-e not available")
    from nesy.driver import TAINT_JAVA
    (tmp_path / "src/app").mkdir(parents=True)
    (tmp_path / "src/nesy").mkdir(parents=True)
    (tmp_path / "src/app/Cmd.java").write_text(APP)
    (tmp_path / "src/nesy/NesyDriver.java").write_text(DRV)
    (tmp_path / "src/nesy/Taint.java").write_text(TAINT_JAVA)
    env = dict(os.environ)
    env.pop("JAVA_TOOL_OPTIONS", None)
    srcs = [str(p) for p in (tmp_path / "src").rglob("*.java")]
    subprocess.run([javac, "--release", "8", "-g", "-d", str(tmp_path / "cls"), *srcs], check=True, env=env)
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "c.yml").write_text(
        'sources:\n  - { kind: call, method: "<nesy.Taint: java.lang.String src()>", index: result }\n'
        f'sinks:\n  - {{ method: "<java.lang.Runtime: java.lang.Process exec(java.lang.String[])>", index: "{index}" }}\n'
        'transfers:\n'
        '  - { method: "<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>", from: 0, to: base }\n'
        '  - { method: "<java.lang.StringBuilder: java.lang.String toString()>", from: base, to: result }\n'
        "call-site-mode: true\n")
    t = taie_settings(settings)
    t.home = tmp_path / "taie-home"
    res = run_taie(t, [tmp_path / "cls"], [], "nesy.NesyDriver", cfg, tmp_path / "out")
    assert res.ok
    assert sum(1 for f in res.flows if ".exec(" in f.sink.stmt) == expected
