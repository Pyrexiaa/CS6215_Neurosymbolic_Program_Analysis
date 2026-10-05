"""S1 - symbolic fact extraction from compiled bytecode (deterministic, no LLM).

Produces:
  * the application classes and their methods (with line ranges),
  * every external API the application calls (resolved to the declaring class),
    together with the call sites that use it,
  * ranked entry-point candidates (web handlers, plugin hooks, public library API).
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .classfile import ACC_PUBLIC, ClassIndex, ClassInfo, MethodInfo, iter_classes
from .jvm import MethodSig, is_jdk_class
from .sources import SourceLocator

# Types whose values an attacker can plausibly control.
TAINTABLE_TYPES = {
    "java.lang.String", "java.lang.String[]", "java.lang.CharSequence", "java.lang.Object",
    "byte[]", "char[]", "java.io.InputStream", "java.io.Reader", "java.io.File", "java.nio.file.Path",
    "java.net.URL", "java.net.URI", "java.util.Map", "java.util.List", "java.util.Collection",
    "java.util.Properties", "java.util.zip.ZipInputStream", "java.util.zip.ZipFile",
}

WEB_ANNOTATIONS = (
    "org.springframework.web.bind.annotation.",   # @RequestMapping, @GetMapping, ...
    "javax.ws.rs.", "jakarta.ws.rs.",              # JAX-RS
    "org.kohsuke.stapler.WebMethod", "org.kohsuke.stapler.verb.",
    "org.kohsuke.stapler.interceptor.RequirePOST",
    "io.micronaut.http.annotation.", "io.javalin.",
)
PLUGIN_ANNOTATIONS = (
    "org.kohsuke.stapler.DataBoundConstructor", "org.kohsuke.stapler.DataBoundSetter",
)
SERVLET_BASES = ("javax.servlet.http.HttpServlet", "javax.servlet.GenericServlet",
                 "javax.servlet.Filter", "jakarta.servlet.http.HttpServlet")
JENKINS_BASES = ("hudson.tasks.Builder", "hudson.tasks.Recorder", "hudson.tasks.BuildWrapper",
                 "hudson.tasks.Publisher", "hudson.model.Descriptor", "jenkins.tasks.SimpleBuildStep",
                 "hudson.model.AbstractDescribableImpl", "hudson.model.Action")
NAME_HINTS = re.compile(
    r"(extract|unzip|unpack|unwrap|explode|archive|parse|eval|exec|execute|run|process|handle|"
    r"load|read|open|resolve|render|resource|validate|compile|template|command|script|upload|"
    r"download|file|path|query|search|perform|setup|do[A-Z])", re.I)
OBJECT_METHODS = {"equals", "hashCode", "toString", "getClass", "notify", "notifyAll", "wait",
                  "clone", "finalize"}


@dataclass
class CallSiteRef:
    caller: str          # Tai-e signature of the app method containing the call
    line: int
    source_file: Optional[str] = None


@dataclass
class ExternalApi:
    signature: str                   # Tai-e signature, resolved to declaring class when possible
    owner: str
    name: str
    params: List[str]
    ret: str
    is_static: bool
    from_jdk: bool
    origin: str = ""                 # jar or "JDK"
    call_sites: List[CallSiteRef] = field(default_factory=list)


@dataclass
class EntryCandidate:
    signature: str
    owner: str
    name: str
    params: List[str]
    is_static: bool
    kind: str                        # web | servlet | plugin | library-api
    score: float
    annotations: List[str] = field(default_factory=list)
    constructors: List[List[str]] = field(default_factory=list)  # public ctor param lists of owner
    owner_is_abstract: bool = False


@dataclass
class ProgramFacts:
    app_classes: Dict[str, ClassInfo]
    external_apis: Dict[str, ExternalApi]
    entries: List[EntryCandidate]
    index: ClassIndex
    sources: SourceLocator

    # ------------------------------------------------------------ queries
    def app_method(self, taie_sig: str) -> Optional[MethodInfo]:
        return self.method_index().get(taie_sig)

    def method_index(self) -> Dict[str, MethodInfo]:
        cached = getattr(self, "_method_index", None)
        if cached is not None:
            return cached
        out: Dict[str, MethodInfo] = {}
        for ci in self.app_classes.values():
            for m in ci.methods:
                try:
                    out[m.sig.taie] = m
                except ValueError:
                    continue
        self._method_index = out
        return out

    def is_app_class(self, name: str) -> bool:
        return name in self.app_classes

    def summary(self) -> dict:
        return {
            "app_classes": len(self.app_classes),
            "app_methods": sum(len(c.methods) for c in self.app_classes.values()),
            "external_apis": len(self.external_apis),
            "external_apis_jdk": sum(1 for a in self.external_apis.values() if a.from_jdk),
            "entry_candidates": len(self.entries),
            "entry_kinds": _count(e.kind for e in self.entries),
        }

    def dump(self, path: Path) -> None:
        data = {
            "summary": self.summary(),
            "external_apis": [asdict(a) for a in self.external_apis.values()],
            "entries": [asdict(e) for e in self.entries],
        }
        Path(path).write_text(json.dumps(data, indent=2))


def _count(it: Iterable[str]) -> Dict[str, int]:
    d: Dict[str, int] = {}
    for x in it:
        d[x] = d.get(x, 0) + 1
    return d


def _matches_any(name: str, prefixes: Sequence[str]) -> bool:
    return any(name.startswith(p) for p in prefixes)


def extract_facts(app_paths: Sequence[Path], lib_paths: Sequence[Path], jre_paths: Sequence[Path],
                  source_roots: Sequence[Path], exclude_packages: Sequence[str] = ("nesy.",)) -> ProgramFacts:
    """Run S1 over application class dirs/jars ``app_paths``.

    ``lib_paths`` are dependency jars, ``jre_paths`` the Java library jars (e.g. rt.jar) used
    to resolve JDK call targets. ``exclude_packages`` drops generated driver classes.
    """
    app: Dict[str, ClassInfo] = {}
    for p in app_paths:
        for ci in iter_classes(Path(p), with_code=True):
            if _matches_any(ci.name, exclude_packages):
                continue
            app.setdefault(ci.name, ci)
    index = ClassIndex(list(app_paths) + list(lib_paths) + list(jre_paths))
    sources = SourceLocator(source_roots)

    external: Dict[str, ExternalApi] = {}
    for ci in app.values():
        for m in ci.methods:
            try:
                caller = m.sig.taie
            except ValueError:
                continue
            for cs in m.calls:
                if cs.owner in app or cs.name in OBJECT_METHODS:
                    continue
                if cs.name == "<clinit>":
                    continue
                decl = index.resolve_method(cs.owner, cs.name, cs.descriptor)
                owner = decl.owner if decl else cs.owner
                try:
                    sig = MethodSig.from_descriptor(owner.replace(".", "/"), cs.name, cs.descriptor)
                except ValueError:
                    continue
                key = sig.taie
                api = external.get(key)
                if api is None:
                    api = ExternalApi(key, owner, cs.name, list(sig.params), sig.ret,
                                      is_static=bool(decl.is_static) if decl else cs.kind == "static",
                                      from_jdk=is_jdk_class(owner),
                                      origin="JDK" if is_jdk_class(owner) else _origin(index, owner))
                    external[key] = api
                if len(api.call_sites) < 50:
                    api.call_sites.append(CallSiteRef(caller, cs.line, ci.source_file))

    entries = _entry_candidates(app, index)
    return ProgramFacts(app, external, entries, index, sources)


def _origin(index: ClassIndex, owner: str) -> str:
    ci = index.get(owner)
    if ci and "!" in ci.origin:
        return Path(ci.origin.split("!")[0]).name
    return "unknown" if not ci else Path(ci.origin).name


def _public_ctors(ci: ClassInfo) -> List[List[str]]:
    out = []
    for m in ci.methods:
        if m.name == "<init>" and m.access & ACC_PUBLIC:
            try:
                out.append(list(m.sig.params))
            except ValueError:
                continue
    return sorted(out, key=len)


def _entry_candidates(app: Dict[str, ClassInfo], index: ClassIndex) -> List[EntryCandidate]:
    out: List[EntryCandidate] = []
    for ci in app.values():
        supers = set(index.supertypes(ci.name))
        is_servlet = any(s in supers for s in SERVLET_BASES)
        is_jenkins = any(s in supers for s in JENKINS_BASES)
        class_web = any(_matches_any(a, WEB_ANNOTATIONS) or "Controller" in a for a in ci.annotations)
        ctors = _public_ctors(ci)
        for m in ci.methods:
            if m.is_synthetic or m.name in ("<clinit>",) or m.name in OBJECT_METHODS:
                continue
            if not m.is_public:
                # Stapler/JAX-RS handlers can be non-public only rarely; skip.
                continue
            try:
                sig = m.sig
            except ValueError:
                continue
            anns = list(m.annotations) + [a for pa in m.param_annotations for a in pa]
            taintable = sum(1 for p in sig.params if p in TAINTABLE_TYPES)
            kind = None
            score = 0.0
            if any(_matches_any(a, WEB_ANNOTATIONS) for a in anns) or (class_web and taintable):
                kind, score = "web", 10.0
            elif is_servlet and m.name in ("doGet", "doPost", "doPut", "doDelete", "service", "doFilter"):
                kind, score = "servlet", 9.0
            elif any(_matches_any(a, PLUGIN_ANNOTATIONS) for a in anns) or \
                    (is_jenkins and (m.name.startswith("do") or m.name in ("perform", "setUp", "configure"))):
                kind, score = "plugin", 8.0
            elif ci.is_public and not ci.is_interface and m.name != "<init>" and taintable:
                kind, score = "library-api", 2.0
            elif ci.is_public and m.name == "<init>" and taintable and is_jenkins:
                kind, score = "plugin", 6.0
            if kind is None:
                continue
            if NAME_HINTS.search(m.name):
                score += 3.0
            score += min(taintable, 3) * 1.0
            if m.is_static:
                score += 0.5
            if ci.is_inner and not ci.is_public:
                score -= 2.0
            out.append(EntryCandidate(sig.taie, ci.name, m.name, list(sig.params), m.is_static, kind,
                                      score, anns, ctors, ci.is_abstract or ci.is_interface))
    out.sort(key=lambda e: (-e.score, e.signature))
    return out
