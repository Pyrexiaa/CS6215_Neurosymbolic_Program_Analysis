from nesy.classfile import ClassIndex, iter_classes


def test_parse_fixture_classes(built_fixture):
    classes = {c.name: c for c in iter_classes(built_fixture / "app")}
    ex = classes["demo.app.Extractor"]
    assert ex.source_file == "Extractor.java" and ex.super_name == "java.lang.Object"
    m = {x.name: x for x in ex.methods}
    assert m["extract"].line_range == (14, 20)
    calls = [(c.owner, c.name, c.line) for c in m["extract"].calls]
    assert ("com.acme.util.Archive", "entryName", 16) in calls
    assert ("java.io.File", "<init>", 17) in calls
    assert m["runHook"].sig.taie == "<demo.app.Extractor: int runHook(java.lang.String)>"


def test_jar_index_and_resolution(built_fixture, settings):
    idx = ClassIndex([built_fixture / "acme-util.jar"] + settings.jre8_jars())
    assert "com.acme.util.Shell" in idx
    run = idx.resolve_method("com.acme.util.Shell", "run", "(Ljava/lang/String;)I")
    assert run is not None and run.is_static
    if settings.jre8_jars():
        # FileOutputStream.close() is declared in FileOutputStream itself; write(byte[]) too
        m = idx.resolve_method("java.io.FileOutputStream", "write", "([B)V")
        assert m is not None and m.owner == "java.io.FileOutputStream"
        # inherited: StringBuilder.length() is declared in AbstractStringBuilder (JDK 8)
        m = idx.resolve_method("java.lang.StringBuilder", "length", "()I")
        assert m is not None
