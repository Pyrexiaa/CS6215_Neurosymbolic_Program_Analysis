"""`nesy check-manual`: form-only checks of hand-written B2 specs."""
from nesy.spec import check_manual_spec


def test_check_manual_flags_form_errors(fixture_facts, tmp_path):
    f = tmp_path / "m.yml"
    f.write_text(
        'sources:\n'
        '  - { kind: call, method: "<java.util.zip.ZipEntry: java.lang.String getName()>", index: result }\n'
        'sinks:\n'
        '  - { method: "<java.lang.Runtime: java.lang.Process exec(java.lang.String[])>", index: "0[*]" }\n'
        '  - { method: "<java.io.File: void <init>(java.io.File, java.lang.String)>", index: 1 }\n'
        '  - { method: "<java.io.File: void <init>(java.io.File,java.lang.String)>", index: 2 }\n'
        '  - { method: "<pkg.Cls: java.lang.String getX()>", index: result }\n'
        'transfers:\n'
        '  - { method: "<java.io.File: java.lang.String getPath()>", from: base, to: result }\n'
        'sanitizers:\n'
        '  - { kind: param, method: "<java.io.File: java.lang.String getNamez(java.lang.String)>", index: 0 }\n')
    n, problems = check_manual_spec(f, fixture_facts)
    text = "\n".join(problems)
    assert n == 7
    assert "sinks[1]: write the signature exactly" in text
    assert "arg-out-of-range" in text
    assert "pkg.Cls" in text and "cannot verify" in text
    assert "getNamez" in text and "not found" in text
    assert "getName()" not in text and "exec(" not in text and "getPath" not in text


def test_check_manual_empty_template_is_ok(fixture_facts, tmp_path):
    f = tmp_path / "m.yml"
    f.write_text("# comment\nsources: []\nsinks: []\ntransfers: []\n")
    assert check_manual_spec(f, fixture_facts) == (0, [])
