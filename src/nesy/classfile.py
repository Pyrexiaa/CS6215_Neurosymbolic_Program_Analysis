"""A small, dependency-free Java class-file reader.

It extracts what the neuro-symbolic pipeline needs from compiled bytecode:
class hierarchy, method signatures and access flags, line ranges (from the
LineNumberTable), annotations, and every call site (invoke instruction) with
its resolved owner/name/descriptor and source line.

Only reading is supported. Unknown attributes are skipped, so class files from
Java 1.1 to recent versions parse fine.
"""
from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from .jvm import MethodSig, internal_to_dotted, parse_field_descriptor

ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_SYNCHRONIZED = 0x0020
ACC_BRIDGE = 0x0040
ACC_VARARGS = 0x0080
ACC_NATIVE = 0x0100
ACC_INTERFACE = 0x0200
ACC_ABSTRACT = 0x0400
ACC_SYNTHETIC = 0x1000
ACC_ANNOTATION = 0x2000
ACC_ENUM = 0x4000

INVOKE_OPS = {0xB6: "virtual", 0xB7: "special", 0xB8: "static", 0xB9: "interface"}


class ClassFormatError(Exception):
    pass


@dataclass
class CallSite:
    kind: str           # virtual | special | static | interface
    owner: str          # dotted owner as written in the constant pool
    name: str
    descriptor: str
    line: int           # -1 when unknown
    pc: int

    @property
    def sig(self) -> MethodSig:
        return MethodSig.from_descriptor(self.owner.replace(".", "/"), self.name, self.descriptor)


@dataclass
class MethodInfo:
    owner: str
    name: str
    descriptor: str
    access: int
    annotations: List[str] = field(default_factory=list)       # dotted annotation types
    param_annotations: List[List[str]] = field(default_factory=list)
    lines: List[int] = field(default_factory=list)              # source lines with code
    calls: List[CallSite] = field(default_factory=list)
    exceptions: List[str] = field(default_factory=list)

    @property
    def sig(self) -> MethodSig:
        return MethodSig.from_descriptor(self.owner.replace(".", "/"), self.name, self.descriptor)

    @property
    def is_static(self) -> bool:
        return bool(self.access & ACC_STATIC)

    @property
    def is_public(self) -> bool:
        return bool(self.access & ACC_PUBLIC)

    @property
    def is_abstract(self) -> bool:
        return bool(self.access & ACC_ABSTRACT)

    @property
    def is_synthetic(self) -> bool:
        return bool(self.access & (ACC_SYNTHETIC | ACC_BRIDGE))

    @property
    def line_range(self) -> Optional[Tuple[int, int]]:
        if not self.lines:
            return None
        return min(self.lines), max(self.lines)


@dataclass
class ClassInfo:
    name: str                    # dotted
    super_name: Optional[str]
    interfaces: List[str]
    access: int
    source_file: Optional[str]
    annotations: List[str]
    methods: List[MethodInfo]
    fields: List[Tuple[str, str, int]]   # (name, dotted type, access)
    major_version: int
    origin: str = ""             # file or jar!entry it was read from

    @property
    def is_interface(self) -> bool:
        return bool(self.access & ACC_INTERFACE)

    @property
    def is_abstract(self) -> bool:
        return bool(self.access & ACC_ABSTRACT)

    @property
    def is_public(self) -> bool:
        return bool(self.access & ACC_PUBLIC)

    @property
    def package(self) -> str:
        return self.name.rsplit(".", 1)[0] if "." in self.name else ""

    @property
    def is_inner(self) -> bool:
        return "$" in self.name.rsplit(".", 1)[-1]

    def find_method(self, name: str, descriptor: str) -> Optional[MethodInfo]:
        for m in self.methods:
            if m.name == name and m.descriptor == descriptor:
                return m
        return None

    def source_path_guess(self) -> Optional[str]:
        """Relative source path, e.g. ``org/acme/Foo.java`` (outer class file)."""
        if not self.source_file:
            return None
        pkg = self.package.replace(".", "/")
        return f"{pkg}/{self.source_file}" if pkg else self.source_file


# ---------------------------------------------------------------- parsing

def _insn_length(code: bytes, pc: int) -> int:
    op = code[pc]
    if op in (0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3A, 0xA9, 0xBC):
        return 2
    if op in (0x11, 0x13, 0x14, 0x84) or 0x99 <= op <= 0xA8 or 0xB2 <= op <= 0xB8 \
            or op in (0xBB, 0xBD, 0xC0, 0xC1, 0xC6, 0xC7):
        return 3
    if op in (0xB9, 0xBA, 0xC8, 0xC9):
        return 5
    if op == 0xC5:
        return 4
    if op == 0xC4:  # wide
        return 6 if code[pc + 1] == 0x84 else 4
    if op == 0xAA:  # tableswitch
        p = pc + 1 + ((4 - (pc + 1) % 4) % 4)
        low, high = struct.unpack(">ii", code[p + 4:p + 12])
        return (p + 12 + 4 * (high - low + 1)) - pc
    if op == 0xAB:  # lookupswitch
        p = pc + 1 + ((4 - (pc + 1) % 4) % 4)
        npairs = struct.unpack(">i", code[p + 4:p + 8])[0]
        return (p + 8 + 8 * npairs) - pc
    return 1


class _Reader:
    def __init__(self, data: bytes):
        self.d = data
        self.p = 0

    def u1(self) -> int:
        v = self.d[self.p]
        self.p += 1
        return v

    def u2(self) -> int:
        v = struct.unpack_from(">H", self.d, self.p)[0]
        self.p += 2
        return v

    def u4(self) -> int:
        v = struct.unpack_from(">I", self.d, self.p)[0]
        self.p += 4
        return v

    def bytes(self, n: int) -> bytes:
        v = self.d[self.p:self.p + n]
        self.p += n
        return v


def _decode_mutf8(b: bytes) -> str:
    # Modified UTF-8 differs from UTF-8 only for NUL and supplementary chars;
    # 'surrogatepass' keeps decoding robust for both.
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.replace(b"\xc0\x80", b"\x00").decode("utf-8", errors="replace")


def _skip_element_value(r: _Reader) -> None:
    tag = chr(r.u1())
    if tag in "BCDFIJSZsc":
        r.u2()
    elif tag == "e":
        r.u2(); r.u2()
    elif tag == "@":
        _read_annotation(r, None)
    elif tag == "[":
        for _ in range(r.u2()):
            _skip_element_value(r)
    else:
        raise ClassFormatError(f"bad element_value tag {tag!r}")


def _read_annotation(r: _Reader, utf8) -> Optional[str]:
    type_idx = r.u2()
    for _ in range(r.u2()):
        r.u2()
        _skip_element_value(r)
    if utf8 is None:
        return None
    try:
        return parse_field_descriptor(utf8(type_idx))
    except Exception:
        return None


def parse_class(data: bytes, origin: str = "", with_code: bool = True) -> ClassInfo:
    r = _Reader(data)
    if r.u4() != 0xCAFEBABE:
        raise ClassFormatError(f"not a class file: {origin}")
    r.u2()  # minor version
    major = r.u2()
    n = r.u2()
    cp: List[object] = [None] * n
    i = 1
    while i < n:
        tag = r.u1()
        if tag == 1:
            cp[i] = ("utf8", _decode_mutf8(r.bytes(r.u2())))
        elif tag in (3, 4):
            r.u4(); cp[i] = ("num",)
        elif tag in (5, 6):
            r.u4(); r.u4(); cp[i] = ("num",); i += 1
        elif tag == 7:
            cp[i] = ("class", r.u2())
        elif tag == 8:
            cp[i] = ("string", r.u2())
        elif tag in (9, 10, 11):
            cp[i] = ("ref", tag, r.u2(), r.u2())
        elif tag == 12:
            cp[i] = ("nat", r.u2(), r.u2())
        elif tag == 15:
            r.u1(); r.u2(); cp[i] = ("mh",)
        elif tag == 16:
            r.u2(); cp[i] = ("mt",)
        elif tag in (17, 18):
            r.u2(); r.u2(); cp[i] = ("indy",)
        elif tag in (19, 20):
            r.u2(); cp[i] = ("modpkg",)
        else:
            raise ClassFormatError(f"unknown constant tag {tag} in {origin}")
        i += 1

    def utf8(idx: int) -> str:
        e = cp[idx]
        assert e and e[0] == "utf8", (idx, e)
        return e[1]  # type: ignore[index]

    def class_name(idx: int) -> str:
        e = cp[idx]
        return internal_to_dotted(utf8(e[1]))  # type: ignore[index]

    def member_ref(idx: int) -> Tuple[str, str, str]:
        e = cp[idx]
        _, _tag, cidx, natidx = e  # type: ignore[misc]
        _, nidx, didx = cp[natidx]  # type: ignore[misc]
        return class_name(cidx), utf8(nidx), utf8(didx)

    access = r.u2()
    this_name = class_name(r.u2())
    super_idx = r.u2()
    super_name = class_name(super_idx) if super_idx else None
    interfaces = [class_name(r.u2()) for _ in range(r.u2())]

    fields: List[Tuple[str, str, int]] = []
    for _ in range(r.u2()):
        facc = r.u2(); fname = utf8(r.u2()); fdesc = utf8(r.u2())
        for _ in range(r.u2()):
            r.u2(); r.bytes(r.u4())
        try:
            fields.append((fname, parse_field_descriptor(fdesc), facc))
        except ValueError:
            pass

    methods: List[MethodInfo] = []
    for _ in range(r.u2()):
        macc = r.u2(); mname = utf8(r.u2()); mdesc = utf8(r.u2())
        mi = MethodInfo(this_name, mname, mdesc, macc)
        for _ in range(r.u2()):
            aname = utf8(r.u2()); alen = r.u4()
            body = r.bytes(alen)
            if aname == "Code" and with_code:
                _parse_code(body, mi, member_ref, utf8)
            elif aname == "RuntimeVisibleAnnotations" or aname == "RuntimeInvisibleAnnotations":
                ar = _Reader(body)
                for _ in range(ar.u2()):
                    t = _read_annotation(ar, utf8)
                    if t:
                        mi.annotations.append(t)
            elif aname == "RuntimeVisibleParameterAnnotations":
                ar = _Reader(body)
                plist: List[List[str]] = []
                for _ in range(ar.u1()):
                    anns = []
                    for _ in range(ar.u2()):
                        t = _read_annotation(ar, utf8)
                        if t:
                            anns.append(t)
                    plist.append(anns)
                mi.param_annotations = plist
            elif aname == "Exceptions":
                ar = _Reader(body)
                mi.exceptions = [class_name(ar.u2()) for _ in range(ar.u2())]
        methods.append(mi)

    source_file = None
    annotations: List[str] = []
    for _ in range(r.u2()):
        aname = utf8(r.u2()); alen = r.u4()
        body = r.bytes(alen)
        if aname == "SourceFile":
            source_file = utf8(struct.unpack(">H", body[:2])[0])
        elif aname in ("RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations"):
            ar = _Reader(body)
            for _ in range(ar.u2()):
                t = _read_annotation(ar, utf8)
                if t:
                    annotations.append(t)

    return ClassInfo(this_name, super_name, interfaces, access, source_file,
                     annotations, methods, fields, major, origin)


def _parse_code(body: bytes, mi: MethodInfo, member_ref, utf8) -> None:
    r = _Reader(body)
    r.u2(); r.u2()  # max_stack, max_locals
    code_len = r.u4()
    code = r.bytes(code_len)
    for _ in range(r.u2()):
        r.bytes(8)
    line_table: List[Tuple[int, int]] = []
    for _ in range(r.u2()):
        aname = utf8(r.u2()); alen = r.u4()
        abody = r.bytes(alen)
        if aname == "LineNumberTable":
            ar = _Reader(abody)
            for _ in range(ar.u2()):
                line_table.append((ar.u2(), ar.u2()))
    line_table.sort()
    mi.lines = sorted({ln for _, ln in line_table})

    def line_at(pc: int) -> int:
        best = -1
        for start, ln in line_table:
            if start <= pc:
                best = ln
            else:
                break
        return best

    pc = 0
    while pc < len(code):
        op = code[pc]
        if op in INVOKE_OPS:
            idx = struct.unpack(">H", code[pc + 1:pc + 3])[0]
            try:
                owner, name, desc = member_ref(idx)
                if owner.startswith("["):   # array clone() etc.
                    owner = "java.lang.Object"
                mi.calls.append(CallSite(INVOKE_OPS[op], owner, name, desc, line_at(pc), pc))
            except Exception:
                pass
        pc += _insn_length(code, pc)


# ---------------------------------------------------------------- loading

def iter_classes_in_dir(root: Path, with_code: bool = True) -> Iterator[ClassInfo]:
    for p in sorted(Path(root).rglob("*.class")):
        if p.name == "module-info.class":
            continue
        try:
            yield parse_class(p.read_bytes(), str(p), with_code)
        except Exception:
            continue


def iter_classes_in_jar(jar: Path, with_code: bool = True) -> Iterator[ClassInfo]:
    try:
        zf = zipfile.ZipFile(jar)
    except (zipfile.BadZipFile, OSError):
        return
    with zf:
        for n in zf.namelist():
            if n.endswith(".class") and not n.endswith("module-info.class") and not n.startswith("META-INF/versions/"):
                try:
                    yield parse_class(zf.read(n), f"{jar}!{n}", with_code)
                except Exception:
                    continue


def iter_classes(path: Path, with_code: bool = True) -> Iterator[ClassInfo]:
    path = Path(path)
    if path.is_dir():
        yield from iter_classes_in_dir(path, with_code)
    elif path.suffix in (".jar", ".zip", ".war") and path.exists():
        yield from iter_classes_in_jar(path, with_code)


class ClassIndex:
    """Lazy class lookup over a list of jars/directories (application + libraries + JRE).

    Used by validator V2 to check that an LLM-proposed signature really exists and
    to resolve a call-site owner to the class that actually declares the method.
    """

    def __init__(self, paths: List[Path]):
        self._where: Dict[str, Tuple[Path, str]] = {}
        self._cache: Dict[str, Optional[ClassInfo]] = {}
        for p in paths:
            p = Path(p)
            if p.is_dir():
                for f in p.rglob("*.class"):
                    rel = f.relative_to(p).as_posix()[:-6]
                    self._where.setdefault(rel.replace("/", "."), (f, ""))
            elif p.exists() and p.suffix in (".jar", ".zip"):
                try:
                    with zipfile.ZipFile(p) as zf:
                        for n in zf.namelist():
                            if n.endswith(".class") and not n.startswith("META-INF/"):
                                self._where.setdefault(n[:-6].replace("/", "."), (p, n))
                except (zipfile.BadZipFile, OSError):
                    continue

    def __contains__(self, name: str) -> bool:
        return name in self._where

    def __len__(self) -> int:
        return len(self._where)

    def get(self, name: str) -> Optional[ClassInfo]:
        if name in self._cache:
            return self._cache[name]
        loc = self._where.get(name)
        info = None
        if loc:
            path, entry = loc
            try:
                if entry:
                    with zipfile.ZipFile(path) as zf:
                        info = parse_class(zf.read(entry), f"{path}!{entry}", with_code=False)
                else:
                    info = parse_class(Path(path).read_bytes(), str(path), with_code=False)
            except Exception:
                info = None
        self._cache[name] = info
        return info

    def supertypes(self, name: str) -> Iterator[str]:
        """Superclasses first, then interfaces (breadth-first), excluding ``name``."""
        seen = {name}
        queue = [name]
        while queue:
            cur = queue.pop(0)
            ci = self.get(cur)
            if not ci:
                continue
            nxt = ([ci.super_name] if ci.super_name else []) + ci.interfaces
            for s in nxt:
                if s and s not in seen:
                    seen.add(s)
                    yield s
                    queue.append(s)

    def resolve_method(self, owner: str, name: str, descriptor: str) -> Optional[MethodInfo]:
        """JVM-style resolution: the class declaring ``name+descriptor`` seen from ``owner``."""
        ci = self.get(owner)
        if ci:
            m = ci.find_method(name, descriptor)
            if m:
                return m
        for s in self.supertypes(owner):
            sci = self.get(s)
            if sci:
                m = sci.find_method(name, descriptor)
                if m and not (m.access & ACC_PRIVATE):
                    return m
        return None

    def find_by_signature(self, sig: MethodSig) -> Optional[MethodInfo]:
        ci = self.get(sig.owner)
        if not ci:
            return None
        for m in ci.methods:
            if m.name == sig.name:
                try:
                    if m.sig == sig:
                        return m
                except ValueError:
                    continue
        return None
