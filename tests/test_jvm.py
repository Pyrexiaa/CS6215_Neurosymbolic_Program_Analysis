from nesy.jvm import (MethodSig, default_value_expr, java_source_type, normalize_taie_signature,
                      parse_field_descriptor, parse_method_descriptor, parse_taie_signature, simple_class_name)


def test_descriptors():
    assert parse_field_descriptor("[[Ljava/lang/String;") == "java.lang.String[][]"
    assert parse_method_descriptor("(Ljava/io/File;I[B)V") == (["java.io.File", "int", "byte[]"], "void")
    assert parse_method_descriptor("()Ljava/util/Map$Entry;") == ([], "java.util.Map$Entry")


def test_taie_signature_roundtrip():
    s = MethodSig.from_descriptor("java/io/File", "<init>", "(Ljava/io/File;Ljava/lang/String;)V")
    assert s.taie == "<java.io.File: void <init>(java.io.File,java.lang.String)>"
    p = parse_taie_signature(s.taie)
    assert p == s and p.is_constructor


def test_normalize_spaces_from_llm():
    assert normalize_taie_signature("<a.B: int m(java.lang.String, int)>") == "<a.B: int m(java.lang.String,int)>"
    assert parse_taie_signature("not a signature") is None


def test_names():
    assert simple_class_name("org.zt.ZipUtil$Unpacker") == "Unpacker"
    assert java_source_type("a.Outer$Inner") == "a.Outer.Inner"
    assert default_value_expr("boolean") == "false"
    assert default_value_expr("java.util.List") == "(java.util.List) null"
