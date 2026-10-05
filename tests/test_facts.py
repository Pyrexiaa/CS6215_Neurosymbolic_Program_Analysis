def test_external_apis_and_entries(fixture_facts):
    f = fixture_facts
    assert set(f.app_classes) == {"demo.app.Extractor"}
    apis = f.external_apis
    assert "<com.acme.util.Archive: java.lang.String entryName(int)>" in apis
    assert apis["<com.acme.util.Shell: int run(java.lang.String)>"].is_static
    assert apis["<com.acme.util.Archive: java.lang.String entryName(int)>"].origin == "acme-util.jar"
    names = [e.name for e in f.entries]
    assert {"extract", "extractSafely", "runHook"} <= set(names)
    assert all(e.kind == "library-api" for e in f.entries)


def test_snippet(fixture_facts):
    f = fixture_facts
    p = f.sources.file_for_class("demo.app.Extractor", "Extractor.java")
    text, lo, hi = f.sources.snippet(p, 14, 20, context=1)
    assert lo == 13 and hi == 21 and "   16 |" in text and "entryName" in text
