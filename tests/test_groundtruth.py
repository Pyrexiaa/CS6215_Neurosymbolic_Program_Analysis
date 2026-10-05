from nesy.groundtruth import FixedMethod, load_fixed_methods, relevant_methods


def test_load_zt_zip():
    fm = load_fixed_methods("zeroturnaround__zt-zip_CVE-2018-1002201_1.12")
    assert {(m.class_name, m.method) for m in fm} == {("Unpacker", "process"), ("Unwraper", "getRootName"),
                                                       ("Unwraper", "process")}


def test_tests_excluded():
    fm = load_fixed_methods("jmrozanec__cron-utils_CVE-2021-41269_9.1.5")
    assert all("src/test" not in m.file for m in fm) and {m.method for m in fm} == {"parse", "isValid"}


def test_matching_inner_class_and_ctor():
    fm = load_fixed_methods("zeroturnaround__zt-zip_CVE-2018-1002201_1.12")
    sig = "<org.zeroturnaround.zip.ZipUtil$Unpacker: void process(java.io.InputStream,java.util.zip.ZipEntry)>"
    assert relevant_methods([sig], fm) == ["Unpacker.process"]
    assert relevant_methods(["<other.pkg.ZipUtil$Unpacker: void process(java.io.InputStream)>"], fm) == []
    ctor = FixedMethod("src/main/java/a/b/Foo.java", "Foo", "Foo", 1, 2, "Foo(String)")
    assert ctor.matches("<a.b.Foo: void <init>(java.lang.String)>")


def test_all_subjects_have_ground_truth(settings):
    for s in settings.subjects.values():
        assert load_fixed_methods(s.slug), s.id
