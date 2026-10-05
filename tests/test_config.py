import stat

import nesy.config as C


def _fake_home(root, name, version_text, javac=True):
    h = root / name
    (h / "bin").mkdir(parents=True)
    java = h / "bin" / "java"
    java.write_text(f"#!/bin/sh\necho '{version_text}' 1>&2\n")
    java.chmod(java.stat().st_mode | stat.S_IEXEC)
    if javac:
        (h / "bin" / "javac").write_text("#!/bin/sh\n")
    return h


def test_prefers_jdk_over_plugin_jre(tmp_path, monkeypatch):
    plugin = _fake_home(tmp_path, "JavaAppletPlugin.plugin", 'java version "1.8.0_202"', javac=False)
    jdk8 = _fake_home(tmp_path, "zulu-8.jdk", 'openjdk version "1.8.0_402"')
    jdk21 = _fake_home(tmp_path, "jdk-21", 'openjdk version "21.0.2"')
    jdk17 = _fake_home(tmp_path, "jdk-17", 'openjdk version "17.0.10"')
    monkeypatch.setattr(C, "_macos_java_homes", lambda: [plugin, jdk21])
    monkeypatch.setattr(C, "_candidate_homes", lambda: [jdk8, jdk17])
    assert C.find_java_home(8) == jdk8
    assert C.find_java_home(17) == jdk17          # lowest version that satisfies >= 17
    monkeypatch.setattr(C, "_candidate_homes", lambda: [])
    assert C.find_java_home(8) == plugin          # a JRE is still usable for rt.jar when nothing else exists
    assert not C.is_jdk(plugin) and C.is_jdk(jdk8)
    assert C.find_java_home(8, explicit=str(jdk8)) == jdk8
