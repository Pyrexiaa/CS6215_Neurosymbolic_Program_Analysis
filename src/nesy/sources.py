"""Locate Java source files and cut numbered snippets for prompts and validators."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .jvm import outer_class_name


class SourceLocator:
    def __init__(self, roots: Iterable[Path]):
        self.roots = [Path(r) for r in roots if Path(r).is_dir()]
        self._file_cache: Dict[str, Optional[Path]] = {}
        self._text_cache: Dict[Path, List[str]] = {}

    @staticmethod
    def find_source_roots(project_dir: Path) -> List[Path]:
        """All ``src/main/java`` (Maven/Gradle) or ``src`` directories under a project."""
        project_dir = Path(project_dir)
        roots = []
        for p in project_dir.rglob("src/main/java"):
            rel_parts = p.relative_to(project_dir).parts
            if p.is_dir() and "target" not in rel_parts and "build" not in rel_parts:
                roots.append(p)
        if not roots and (project_dir / "src").is_dir():
            roots = [project_dir / "src"]
        return sorted(roots)

    def file_for_class(self, dotted: str, source_file: Optional[str] = None) -> Optional[Path]:
        key = f"{dotted}|{source_file}"
        if key in self._file_cache:
            return self._file_cache[key]
        outer = outer_class_name(dotted)
        pkg_path = outer.rsplit(".", 1)[0].replace(".", "/") if "." in outer else ""
        names = []
        if source_file:
            names.append(f"{pkg_path}/{source_file}" if pkg_path else source_file)
        names.append(outer.replace(".", "/") + ".java")
        found = None
        for root in self.roots:
            for n in names:
                p = root / n
                if p.is_file():
                    found = p
                    break
            if found:
                break
        self._file_cache[key] = found
        return found

    def lines(self, path: Path) -> List[str]:
        if path not in self._text_cache:
            try:
                self._text_cache[path] = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._text_cache[path] = []
        return self._text_cache[path]

    def snippet(self, path: Path, start: int, end: int, context: int = 2,
                max_lines: int = 80) -> Tuple[str, int, int]:
        """Numbered lines ``start-context .. end+context`` (1-based, clipped).

        Returns (text, first_line, last_line). Long ranges are cut in the middle so the
        beginning and end of the method stay visible.
        """
        src = self.lines(path)
        if not src:
            return "", 0, 0
        lo = max(1, start - context)
        hi = min(len(src), end + context)
        idx = list(range(lo, hi + 1))
        if len(idx) > max_lines:
            half = max_lines // 2
            idx = idx[:half] + [-1] + idx[-half:]
        out = []
        for i in idx:
            if i == -1:
                out.append("      | ... (lines omitted) ...")
            else:
                out.append(f"{i:5d} | {src[i - 1]}")
        return "\n".join(out), lo, hi

    def rel(self, path: Path) -> str:
        for root in self.roots:
            try:
                return Path(path).relative_to(root).as_posix()
            except ValueError:
                continue
        return Path(path).name
