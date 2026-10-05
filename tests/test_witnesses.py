"""Witness manifest sanity and sink-matcher behaviour (no JDK/subjects needed)."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(script):
    spec = importlib.util.spec_from_file_location(script.stem, script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_witness_manifest_valid():
    data = json.loads((ROOT / "witness" / "witnesses.json").read_text())
    subjects = {w["subject"] for w in data["witnesses"]}
    assert subjects == {"zt-zip", "spark", "cron-utils", "perfecto-plugin"}
    for w in data["witnesses"]:
        assert (ROOT / "witness" / "src" / f"{w['cls']}.java").exists()
        assert w["cve"].startswith("CVE-") and w["cwe"].startswith("CWE-")


def test_sink_matchers_discriminate():
    score = _load(ROOT / "scripts" / "score_witnesses.py")
    m, callee = score.MATCHERS, score._callee
    # zt-zip: entry name (arg 1) is the Zip Slip; arg 0 (output dir) is not
    sink = "<org.zeroturnaround.zip.ZipUtil$Unpacker: void process(a,b)>[7] invokespecial file.<init>(d, name)"
    assert m["zt-zip"](sink, callee(sink), 1)
    assert not m["zt-zip"](sink, callee(sink), 0)
    # perfecto: the exec/cmdArgs sink counts, the build-log fatalError does not
    exec_sink = "<...getTunnelId(...)>[9] invokevirtual p.exec(cmdArgs)"
    log_sink = "<...getTunnelId(...)>[3] invokeinterface listener.fatalError(x)"
    assert m["perfecto-plugin"](exec_sink, callee(exec_sink), "0[*]")
    assert not m["perfecto-plugin"](log_sink, callee(log_sink), 0)
    # cron-utils: the EL-interpolated template sink
    cron = "<...CronValidator: boolean isValid(...)>[14] invokeinterface ctx.buildConstraintViolationWithTemplate(v)"
    assert m["cron-utils"](cron, callee(cron), 0)


def test_adjudicate_witnessed_sink_helper():
    adj = _load(ROOT / "scripts" / "adjudicate.py")
    zt = "<org.zeroturnaround.zip.ZipUtil$Unwraper: void process(a,b)>[1] invokespecial file.<init>(d, n)/1"
    assert adj.witnessed_sink("zt-zip", zt, zt + "/1")
    assert not adj.witnessed_sink("zt-zip", zt.replace("/1", "/0"), zt + "/0")
