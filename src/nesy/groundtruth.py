"""Ground truth from CWE-Bench-Java: the methods changed by each CVE's fix.

A reported flow is *CVE-relevant* when its source method, sink method, or any application
method on its taint-flow-graph route is one of the fixed methods. The CVE counts as
*detected* in a run when at least one reported flow on the buggy version is CVE-relevant.
On the fixed version, remaining CVE-relevant flows are *residual* alarms.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from .config import REPO_ROOT
from .jvm import parse_taie_signature, simple_class_name

FIX_INFO = REPO_ROOT / "config" / "cwe-bench-java" / "fix_info.csv"


@dataclass(frozen=True)
class FixedMethod:
    file: str
    class_name: str     # simple name (inner classes by their own name)
    method: str         # constructor rows use the class name
    start: int
    end: int
    signature: str

    @property
    def package_path(self) -> str:
        """``src/main/java/org/acme/Foo.java`` -> ``org/acme``."""
        parts = Path(self.file).parts
        if "java" in parts:
            i = len(parts) - 1 - list(reversed(parts)).index("java")
            return "/".join(parts[i + 1:-1])
        return "/".join(parts[:-1])

    def matches(self, taie_sig: str) -> bool:
        ms = parse_taie_signature(taie_sig)
        if not ms:
            return False
        if simple_class_name(ms.owner) != self.class_name:
            return False
        name = self.class_name if ms.name == "<init>" else ms.name
        if name != self.method:
            return False
        pkg = ms.owner.rsplit(".", 1)[0].replace(".", "/") if "." in ms.owner else ""
        return not self.package_path or pkg == self.package_path or self.package_path.endswith(pkg)


def load_fixed_methods(slug: str, path: Path = FIX_INFO, include_tests: bool = False) -> List[FixedMethod]:
    out = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("project_slug") != slug:
                continue
            file = row.get("file", "")
            if not include_tests and ("/src/test/" in f"/{file}" or file.startswith("src/test")):
                continue
            if not row.get("method"):
                continue

            def num(x: Optional[str]) -> int:
                try:
                    return int(x or -1)
                except ValueError:
                    return -1
            out.append(FixedMethod(file, row.get("class", ""), row["method"], num(row.get("method_start")),
                                   num(row.get("method_end")), row.get("signature", "")))
    return out


def relevant_methods(methods: Iterable[str], fixed: List[FixedMethod]) -> List[str]:
    """Fixed methods (as 'Class.method') matched by any of ``methods`` (Tai-e signatures)."""
    hits = []
    for m in methods:
        for fm in fixed:
            if fm.matches(m):
                tag = f"{fm.class_name}.{fm.method}"
                if tag not in hits:
                    hits.append(tag)
    return hits
