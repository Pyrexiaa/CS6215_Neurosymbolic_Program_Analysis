"""Configuration loading: experiment.yaml, subjects.yaml, cwe.yaml, .env and Java discovery."""
from __future__ import annotations

import glob
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .llm import load_env_file

REPO_ROOT = Path(__file__).resolve().parents[2]


def repo_path(p: str | Path) -> Path:
    p = Path(p)
    return p if p.is_absolute() else REPO_ROOT / p


@dataclass
class Subject:
    id: str
    slug: str
    role: str
    cve: str
    cwe: str
    repo: str
    buggy_commit: str
    fixed_commit: str
    jdk: int = 8
    maven: str = ""
    tag: str = ""
    why: str = ""
    all_fix_commits: List[str] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    build_cmd: Optional[str] = None
    taie: Dict[str, Any] = field(default_factory=dict)
    extra_lib_jars: List[str] = field(default_factory=list)
    # Fixed version = buggy commit + the src/main changes of these fix commits (used when the
    # upstream fix commit cannot be built with the subject's JDK, e.g. the project moved to Java 16).
    fixed_backport: List[str] = field(default_factory=list)
    fixed_note: str = ""

    def commit(self, version: str) -> str:
        if version == "buggy":
            return self.buggy_commit
        if version == "fixed":
            return self.fixed_commit
        raise ValueError(f"version must be buggy|fixed, got {version!r}")


@dataclass
class Settings:
    raw: Dict[str, Any]
    env: Dict[str, str]
    subjects: Dict[str, Subject]
    cwes: Dict[str, Any]

    # ---------------------------------------------------------------- paths
    @property
    def work_dir(self) -> Path:
        return repo_path(self.raw.get("work_dir", "work"))

    @property
    def results_dir(self) -> Path:
        return repo_path(self.raw.get("results_dir", "results"))

    def section(self, name: str) -> Dict[str, Any]:
        return dict(self.raw.get(name) or {})

    def get_env(self, key: str, default: str = "") -> str:
        return os.environ.get(key) or self.env.get(key) or default

    # ---------------------------------------------------------------- java
    def java17_home(self) -> Optional[Path]:
        return find_java_home(17, self.get_env("JAVA17_HOME"))

    def java8_home(self) -> Optional[Path]:
        return find_java_home(8, self.get_env("JAVA8_HOME"))

    def java_home_for(self, version: int) -> Optional[Path]:
        if version <= 8:
            return self.java8_home()
        return find_java_home(version, self.get_env(f"JAVA{version}_HOME")) or self.java17_home()

    def jre8_jars(self) -> List[Path]:
        home = self.java8_home()
        return jre_library_jars(home) if home else []

    def pinned_maven_dir(self) -> Path:
        ver = str((self.raw.get("build") or {}).get("maven_version", "3.5.4"))
        return REPO_ROOT / "tools" / f"apache-maven-{ver}"

    def maven_bin(self) -> str:
        """MAVEN_BIN from .env, else the pinned Maven in tools/ (scripts/setup_tools.sh), else mvn on PATH.

        The pinned version matters: Maven 3.9+ rejects POMs that older Maven only warned about
        (e.g. duplicate dependency declarations in perfecto-plugin), and CWE-Bench-Java built
        these subjects with Maven 3.5."""
        explicit = self.get_env("MAVEN_BIN")
        if explicit:
            return explicit
        pinned = self.pinned_maven_dir() / "bin" / "mvn"
        if pinned.exists():
            return str(pinned)
        return shutil.which("mvn") or "mvn"

    def configs(self) -> Dict[str, Dict[str, Any]]:
        return dict(self.raw.get("configs") or {})


def load_settings(experiment: str | Path = "config/experiment.yaml", subjects: str | Path = "config/subjects.yaml",
                  cwe: str | Path = "config/cwe.yaml", env_file: str | Path = ".env") -> Settings:
    raw = yaml.safe_load(repo_path(experiment).read_text()) or {}
    subj_raw = yaml.safe_load(repo_path(subjects).read_text()) or {}
    subs: Dict[str, Subject] = {}
    for s in subj_raw.get("subjects", []):
        known = {k: v for k, v in s.items() if k in Subject.__dataclass_fields__}
        subs[s["id"]] = Subject(**known)
    cwes = yaml.safe_load(repo_path(cwe).read_text()) or {}
    env = load_env_file(repo_path(env_file))
    return Settings(raw, env, subs, cwes)


# ---------------------------------------------------------------- java discovery

def java_version_of(home: Path) -> Optional[int]:
    java = Path(home) / "bin" / "java"
    if not java.exists():
        return None
    try:
        env = dict(os.environ)
        env.pop("JAVA_TOOL_OPTIONS", None)
        out = subprocess.run([str(java), "-version"], capture_output=True, text=True, timeout=30, env=env)
        text = out.stderr + out.stdout
    except Exception:
        return None
    import re
    m = re.search(r'version "(\d+)(?:\.(\d+))?', text)
    if not m:
        return None
    major = int(m.group(1))
    return int(m.group(2)) if major == 1 and m.group(2) else major


def _candidate_homes() -> List[Path]:
    pats = [
        "/usr/lib/jvm/*",                                   # Debian/Ubuntu
        "/Library/Java/JavaVirtualMachines/*/Contents/Home", # macOS
        os.path.expanduser("~/.sdkman/candidates/java/*"),  # SDKMAN!
        os.path.expanduser("~/Library/Java/JavaVirtualMachines/*/Contents/Home"),
        "/opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
        "/usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
    ]
    out = []
    for p in pats:
        out += [Path(x) for x in sorted(glob.glob(p))]
    if os.environ.get("JAVA_HOME"):
        out.insert(0, Path(os.environ["JAVA_HOME"]))
    return [p for p in out if (p / "bin" / "java").exists()]


def _macos_java_homes() -> List[Path]:
    """All JVMs registered with macOS (``/usr/libexec/java_home -V`` prints them to stderr)."""
    if platform.system() != "Darwin" or not Path("/usr/libexec/java_home").exists():
        return []
    try:
        out = subprocess.run(["/usr/libexec/java_home", "-V"], capture_output=True, text=True, timeout=20)
    except Exception:
        return []
    homes = []
    for line in (out.stderr + out.stdout).splitlines():
        i = line.find(" /")
        if i >= 0:
            p = Path(line[i + 1:].strip())
            if (p / "bin" / "java").exists():
                homes.append(p)
    return homes


def is_jdk(home: Path) -> bool:
    """A JDK has javac; a JRE (e.g. the old macOS 'JavaAppletPlugin' Java 8) does not."""
    return (Path(home) / "bin" / "javac").exists()


def find_java_home(version: int, explicit: str = "") -> Optional[Path]:
    """Find a Java home of ``version`` (17 means 'at least 17').

    Full JDKs (with ``javac``) are preferred over JREs: the Java 8 browser-plugin JRE that
    ``/usr/libexec/java_home -v 1.8`` often returns on macOS has an rt.jar but cannot build
    the subjects.
    """
    if explicit:
        p = Path(explicit)
        return p if (p / "bin" / "java").exists() else None
    seen, candidates = set(), []
    for h in _macos_java_homes() + _candidate_homes():
        key = str(Path(h).resolve())
        if key not in seen:
            seen.add(key)
            candidates.append(Path(h))
    matches = []
    for home in candidates:
        v = java_version_of(home)
        if v is None:
            continue
        if (version == 8 and v == 8) or (version >= 9 and v >= version):
            matches.append((not is_jdk(home), v if version >= 9 else 0, "JavaAppletPlugin" in str(home), home))
    if not matches:
        return None
    matches.sort(key=lambda m: (m[0], m[2], m[1]))   # JDK first, plugin last, lowest matching version
    return matches[0][3]


def jre_library_jars(java8_home: Path) -> List[Path]:
    """rt.jar and friends of a JDK 8 (``jre/lib`` for a JDK, ``lib`` for a JRE)."""
    for lib in (Path(java8_home) / "jre" / "lib", Path(java8_home) / "lib"):
        if (lib / "rt.jar").exists():
            names = ["rt.jar", "jce.jar", "jsse.jar", "charsets.jar"]
            return [lib / n for n in names if (lib / n).exists()]
    return []
