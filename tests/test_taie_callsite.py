"""Tai-e call-site mode: a sink declared on an interface method that has no implementation in the
analysed program (like javax.validation.ConstraintValidatorContext in cron-utils) only fires in
call-site mode. Guards the `taie.call_site_mode: true` default."""
import os
import subprocess

import pytest

from conftest import taie_available
from nesy.pipeline import taie_settings
from nesy.taie import run_taie

pytestmark = pytest.mark.integration

VAL = """package app;
public class Val {
    public interface Ctx { void buildMessage(String template); }
    public boolean isValid(String value, Ctx ctx) { ctx.buildMessage("bad: " + value); return false; }
}
"""
DRV = """package nesy;
public class NesyDriver { public static void main(String[] a) { new app.Val().isValid(Taint.src(), (app.Val.Ctx) null); } }
"""


@pytest.mark.parametrize("mode,expected", [(False, 0), (True, 1)])
def test_interface_sink_needs_call_site_mode(settings, javac, tmp_path, mode, expected):
    if not taie_available(settings):
        pytest.skip("Tai-e not available")
    from nesy.driver import TAINT_JAVA
    (tmp_path / "src/app").mkdir(parents=True)
    (tmp_path / "src/nesy").mkdir(parents=True)
    (tmp_path / "src/app/Val.java").write_text(VAL)
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
        'sinks:\n  - { method: "<app.Val$Ctx: void buildMessage(java.lang.String)>", index: 0 }\n'
        'transfers:\n'
        '  - { method: "<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>", from: 0, to: base }\n'
        '  - { method: "<java.lang.StringBuilder: java.lang.String toString()>", from: base, to: result }\n'
        f"call-site-mode: {str(mode).lower()}\n")
    t = taie_settings(settings)
    t.home = tmp_path / "taie-home"
    res = run_taie(t, [tmp_path / "cls"], [], "nesy.NesyDriver", cfg, tmp_path / "out")
    assert res.ok
    assert sum(1 for f in res.flows if "app.Val" in f.sink.method) == expected
