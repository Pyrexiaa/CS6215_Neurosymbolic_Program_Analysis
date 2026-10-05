"""JVM naming helpers: descriptors, Tai-e signatures and Java source type names.

Tai-e writes method signatures as ``<declaring.Class: retType name(p1,p2)>`` with
fully-qualified, dot-separated type names, ``[]`` for arrays, no spaces between
parameters, and ``<init>`` / ``<clinit>`` for constructors and static initialisers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

PRIMITIVES = {
    "B": "byte", "C": "char", "D": "double", "F": "float",
    "I": "int", "J": "long", "S": "short", "Z": "boolean", "V": "void",
}
PRIMITIVE_NAMES = set(PRIMITIVES.values())

# Packages treated as "the Java library" (never application code).
JDK_PREFIXES = ("java.", "javax.", "jdk.", "sun.", "com.sun.", "org.w3c.", "org.xml.", "org.ietf.", "org.omg.")


def is_jdk_class(name: str) -> bool:
    return name.startswith(JDK_PREFIXES)


def internal_to_dotted(name: str) -> str:
    """``java/lang/String`` -> ``java.lang.String``."""
    return name.replace("/", ".")


def _parse_field_type(desc: str, i: int) -> Tuple[str, int]:
    dims = 0
    while desc[i] == "[":
        dims += 1
        i += 1
    c = desc[i]
    if c == "L":
        end = desc.index(";", i)
        base = internal_to_dotted(desc[i + 1:end])
        i = end + 1
    elif c in PRIMITIVES:
        base = PRIMITIVES[c]
        i += 1
    else:
        raise ValueError(f"bad descriptor {desc!r} at {i}")
    return base + "[]" * dims, i


def parse_field_descriptor(desc: str) -> str:
    t, i = _parse_field_type(desc, 0)
    if i != len(desc):
        raise ValueError(f"trailing chars in descriptor {desc!r}")
    return t


def parse_method_descriptor(desc: str) -> Tuple[List[str], str]:
    """``(Ljava/lang/String;I)V`` -> (["java.lang.String", "int"], "void")."""
    if not desc.startswith("("):
        raise ValueError(f"bad method descriptor {desc!r}")
    i = 1
    params: List[str] = []
    while desc[i] != ")":
        t, i = _parse_field_type(desc, i)
        params.append(t)
    ret, j = _parse_field_type(desc, i + 1)
    if j != len(desc):
        raise ValueError(f"trailing chars in descriptor {desc!r}")
    return params, ret


@dataclass(frozen=True)
class MethodSig:
    """A method signature in Tai-e form."""
    owner: str          # dotted, e.g. java.io.File (inner classes keep '$')
    name: str           # method name, <init> for constructors
    params: Tuple[str, ...]
    ret: str

    @property
    def subsig(self) -> str:
        return f"{self.ret} {self.name}({','.join(self.params)})"

    @property
    def taie(self) -> str:
        return f"<{self.owner}: {self.subsig}>"

    @property
    def is_constructor(self) -> bool:
        return self.name == "<init>"

    @property
    def simple_owner(self) -> str:
        return simple_class_name(self.owner)

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.taie

    @staticmethod
    def from_descriptor(owner_internal: str, name: str, desc: str) -> "MethodSig":
        params, ret = parse_method_descriptor(desc)
        return MethodSig(internal_to_dotted(owner_internal), name, tuple(params), ret)


_TAIE_SIG = re.compile(r"^<([^:<>\s]+):\s+(\S+)\s+(<?[\w$]+>?)\((.*)\)>$")


def parse_taie_signature(sig: str) -> Optional[MethodSig]:
    """Parse ``<a.B: int m(java.lang.String,int)>``; returns None when malformed."""
    m = _TAIE_SIG.match(sig.strip())
    if not m:
        return None
    owner, ret, name, params = m.groups()
    plist = tuple(p.strip() for p in params.split(",") if p.strip()) if params.strip() else tuple()
    return MethodSig(owner, name, plist, ret)


def normalize_taie_signature(sig: str) -> Optional[str]:
    """Canonical spacing for a Tai-e signature (LLMs often add spaces after commas)."""
    ms = parse_taie_signature(sig)
    return ms.taie if ms else None


def simple_class_name(dotted: str) -> str:
    """``a.b.Outer$Inner`` -> ``Inner``; ``a.b.C`` -> ``C``."""
    last = dotted.rsplit(".", 1)[-1]
    return last.rsplit("$", 1)[-1]


def outer_class_name(dotted: str) -> str:
    """``a.b.Outer$Inner`` -> ``a.b.Outer``."""
    return dotted.split("$", 1)[0]


def java_source_type(t: str) -> str:
    """Tai-e/dotted type -> type usable in Java source (``Outer$Inner`` -> ``Outer.Inner``)."""
    return t.replace("$", ".")


def default_value_expr(t: str) -> str:
    """A Java expression of type ``t`` with a harmless default value."""
    if t in ("int", "short", "byte", "long", "float", "double", "char"):
        return {"long": "0L", "float": "0f", "double": "0d", "char": "'a'"}.get(t, f"({t}) 0")
    if t == "boolean":
        return "false"
    return f"({java_source_type(t)}) null"
