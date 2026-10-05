"""Fetching and building evaluation subjects (buggy and fixed versions)."""
from __future__ import annotations

import csv
import json
import os
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

from .config import REPO_ROOT, Settings, Subject
from .sources import SourceLocator

MAVEN_SKIPS = ["-DskipTests", "-Dmaven.test.skip.exec=true", "-Dmaven.javadoc.skip=true", "-Dcheckstyle.skip=true",
               "-Drat.skip=true", "-Dlicense.skip=true", "-Denforcer.skip=true", "-Dfindbugs.skip=true",
               "-Dspotbugs.skip=true", "-Dpmd.skip=true", "-Djacoco.skip=true", "-Danimal.sniffer.skip=true",
               "-Dgpg.skip=true", "-Dspotless.check.skip=true", "-Dmaven.source.skip=true"]
CP_FILE = "nesy-cp.txt"


@dataclass
class BuildLayout:
    project_dir: str
    app_dirs: List[str] = field(default_factory=list)      # target/classes of analysed modules
    lib_jars: List[str] = field(default_factory=list)      # dependency jars (and sibling module classes)
    source_roots: List[str] = field(default_factory=list)
    ok: bool = False
    log: str = ""
    elapsed_s: float = 0.0

    def save(self, path: Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2))

    @staticmethod
    def load(path: Path) -> "BuildLayout":
        return BuildLayout(**json.loads(Path(path).read_text()))


def subject_dir(settings: Settings, sid: str, version: str) -> Path:
    return settings.work_dir / "subjects" / sid / version


def layout_path(settings: Settings, sid: str, version: str) -> Path:
    return settings.work_dir / "subjects" / sid / f"{version}.layout.json"


def _run(cmd: List[str], cwd: Optional[Path] = None, env: Optional[dict] = None, timeout: int = 3600,
         log: Optional[Path] = None) -> subprocess.CompletedProcess:
    if log:
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "a") as f:
            f.write(f"\n$ {' '.join(shlex.quote(c) for c in cmd)}  (cwd={cwd})\n")
            f.flush()
            return subprocess.run(cmd, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT, timeout=timeout,
                                  text=True)
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)


def fetch(settings: Settings, subject: Subject, version: str) -> Path:
    """Clone once into work/repos/<id> and check out ``version`` as a git worktree.

    For ``fixed`` with ``fixed_backport`` set, the worktree is the buggy commit plus the
    ``src/main`` part of each listed fix commit (recorded in ``.nesy-backport``).
    """
    repos = settings.work_dir / "repos"
    repos.mkdir(parents=True, exist_ok=True)
    mirror = repos / subject.id
    log = settings.work_dir / "logs" / f"fetch-{subject.id}.log"
    if not (mirror / ".git").exists() and not (mirror / "HEAD").exists():
        r = _run(["git", "clone", "--no-checkout", subject.repo, str(mirror)], log=log)
        if r.returncode != 0:
            raise RuntimeError(f"git clone failed for {subject.repo}; see {log}")
    target = subject_dir(settings, subject.id, version)
    backport = subject.fixed_backport if version == "fixed" else []
    commit = subject.buggy_commit if backport else subject.commit(version)
    marker = target / ".nesy-backport"
    want_marker = ",".join(backport)
    if target.exists() and (target / ".git").exists():
        head = _run(["git", "rev-parse", "HEAD"], cwd=target).stdout.strip()
        have_marker = marker.read_text().strip() if marker.exists() else ""
        if head == commit and have_marker == want_marker:
            return target
        # stale checkout (e.g. the subject definition changed): replace it
        _run(["git", "worktree", "remove", "--force", str(target.resolve())], cwd=mirror, log=log)
    _run(["git", "fetch", "--all", "--tags"], cwd=mirror, log=log)
    target.parent.mkdir(parents=True, exist_ok=True)
    _run(["git", "worktree", "prune"], cwd=mirror, log=log)
    r = _run(["git", "worktree", "add", "--force", "--detach", str(target.resolve()), commit], cwd=mirror, log=log)
    if r.returncode != 0:
        raise RuntimeError(f"cannot check out {commit} for {subject.id}; see {log}")
    for c in backport:
        diff = _run(["git", "diff", "--binary", f"{c}^1", c, "--", "src/main"], cwd=mirror)
        if diff.returncode != 0:
            raise RuntimeError(f"cannot diff fix commit {c} of {subject.id}")
        patch = target / f".nesy-{c[:10]}.patch"
        patch.write_text(diff.stdout)
        r = _run(["git", "apply", "--3way", "--whitespace=nowarn", str(patch.resolve())], cwd=target, log=log)
        if r.returncode != 0:
            raise RuntimeError(f"fix commit {c} does not apply to {subject.buggy_commit[:10]}; see {log}")
    if backport:
        marker.write_text(want_marker + "\n")
    return target


def _custom_build_cmd(subject: Subject) -> Optional[str]:
    if subject.build_cmd:
        return subject.build_cmd
    p = REPO_ROOT / "config" / "cwe-bench-java" / "build_cmds.csv"
    if p.exists():
        for row in csv.DictReader(open(p)):
            if row.get("project_slug") == subject.slug:
                return row.get("build_cmd")
    return None


def build(settings: Settings, subject: Subject, version: str) -> BuildLayout:
    proj = subject_dir(settings, subject.id, version)
    if not proj.exists():
        raise FileNotFoundError(f"{proj} missing: run `python -m nesy fetch {subject.id}` first")
    log = settings.work_dir / "logs" / f"build-{subject.id}-{version}.log"
    if log.exists():
        log.unlink()
    env = dict(os.environ)
    jhome = settings.java_home_for(subject.jdk)
    if jhome:
        env["JAVA_HOME"] = str(jhome)
        env["PATH"] = f"{jhome}/bin{os.pathsep}{env.get('PATH', '')}"
    t0 = time.time()
    mvn = settings.maven_bin()

    def _finish(ok: bool) -> BuildLayout:
        layout = discover_layout(proj, subject.modules)
        layout.ok = ok and bool(layout.app_dirs)
        layout.log = str(log)
        layout.elapsed_s = round(time.time() - t0, 1)
        layout.save(layout_path(settings, subject.id, version))
        return layout

    # Dependency scope for `dependency:build-classpath`. The recorded study used the full resolved
    # scope: the earlier `-Dmdep.includeScope=compile` set a non-existent property (the documented
    # one is `includeScope`; see docs/evaluation.md [E4]) and was silently ignored, so test-scoped
    # jars -- e.g. Apache BVal, which the cron-utils CVE needs -- were on the analysed classpath.
    # Full scope is kept as the documented default so the recorded classpaths and results reproduce;
    # set NESY_DEP_SCOPE (e.g. "compile") to restrict it for a *separately identified* future study.
    dep_scope = os.environ.get("NESY_DEP_SCOPE", "").strip()

    if (proj / "pom.xml").exists():
        custom = _custom_build_cmd(subject)
        if custom and "gradle" not in custom:
            rp = _run(["bash", "-lc", custom], cwd=proj, env=env, log=log)
            if rp.returncode != 0:
                # A failed custom prerequisite must not be masked by a later successful Maven run.
                return _finish(False)
        cmd = [mvn, "-B", "-q", *MAVEN_SKIPS, "compile", "dependency:build-classpath",
               f"-Dmdep.outputFile={CP_FILE}"]
        if dep_scope:
            cmd.append(f"-DincludeScope={dep_scope}")
        r = _run(cmd, cwd=proj, env=env, log=log)
        return _finish(r.returncode == 0)
    if (proj / "build.gradle").exists() or (proj / "build.gradle.kts").exists():
        custom = _custom_build_cmd(subject) or "./gradlew --no-daemon -q classes"
        r = _run(["bash", "-lc", custom], cwd=proj, env=env, log=log)
        return _finish(r.returncode == 0)
    raise RuntimeError(f"no pom.xml/build.gradle in {proj}")


def discover_layout(proj: Path, modules: Optional[List[str]] = None) -> BuildLayout:
    """Find compiled classes, dependency jars and source roots of a (multi-module) build."""
    proj = Path(proj)
    class_dirs = sorted(p for p in proj.rglob("target/classes") if p.is_dir())
    class_dirs += sorted(p for p in proj.rglob("build/classes/java/main") if p.is_dir())
    if modules:
        wanted = [proj / m for m in modules]
        app = [d for d in class_dirs if any(_is_under(d, w) for w in wanted)]
        siblings = [d for d in class_dirs if d not in app]
    else:
        app, siblings = class_dirs, []
    jars: List[str] = []
    for cpf in proj.rglob(CP_FILE):
        if modules and not any(_is_under(cpf, proj / m) for m in modules):
            continue
        for part in cpf.read_text().strip().split(os.pathsep):
            part = part.strip()
            if part and part.endswith(".jar") and Path(part).exists() and part not in jars:
                jars.append(part)
    libs = [str(d) for d in siblings] + jars
    roots = SourceLocator.find_source_roots(proj)
    if modules:
        roots = [r for r in roots if any(_is_under(r, proj / m) for m in modules)]
    return BuildLayout(str(proj), [str(d) for d in app], libs, [str(r) for r in roots])


def _is_under(p: Path, root: Path) -> bool:
    try:
        Path(p).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def load_layout(settings: Settings, sid: str, version: str) -> BuildLayout:
    p = layout_path(settings, sid, version)
    if not p.exists():
        raise FileNotFoundError(f"{p} missing: run `python -m nesy build {sid} --version {version}` first")
    return BuildLayout.load(p)
