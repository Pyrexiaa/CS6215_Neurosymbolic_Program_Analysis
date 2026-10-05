"""Orchestration: one (subject, version, configuration, run) -> one run record.

Stage artifacts are cached under ``work/runs/<subject>/<version>/`` and shared between
configurations that use the same inputs (e.g. v2 and v3 share the N1 driver, the N2 spec and
the Tai-e run; v3 only adds triage). Re-running is cheap and, thanks to the LLM disk cache,
reproducible without network access.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import yaml
from dataclasses import asdict
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .config import Settings, Subject, repo_path
from .driver import ENTRY_CHECK_VERSION, DRIVER_CLASS, DRIVER_SOURCES_YAML, DriverResult, TEMPLATE_VERSION, build_llm_driver, build_template_driver, javac_path
from .facts import ProgramFacts, extract_facts
from .groundtruth import load_fixed_methods, relevant_methods
from .llm import BaseLLM
from .prompts import prompt_version
from .spec import (SPEC_VOTE_VERSION, SpecResult, array_element_sinks, assemble_config, to_taie_yaml, base_config_files, chain_transfers_yaml, infer_spec, known_entries,
                   invalid_spec_entries, manual_config_file, signatures_in_config)
from .subjects import BuildLayout, load_layout
from .taie import TaieResult, TaieSettings, TaintFlow, TaintFlowGraph, filter_flows, run_taie
from .triage import TriageDecision, save_decisions, triage_all

LLMFactory = Callable[[], BaseLLM]


class PipelineError(RuntimeError):
    pass


def taie_settings(settings: Settings, subject: Optional[Subject] = None) -> TaieSettings:
    t = settings.section("taie")
    if subject and subject.taie:
        t.update(subject.taie)
    j17 = settings.java17_home()
    java_bin = Path(j17) / "bin" / "java" if j17 else Path(shutil.which("java") or "java")
    jre_version = t.get("jre_version", 8)
    jre_jars = settings.jre8_jars() if jre_version == 8 else []
    if jre_version == 8 and not jre_jars:
        raise PipelineError("taie.jre_version is 8 but no JDK 8 rt.jar was found: set JAVA8_HOME in .env "
                            "(or set taie.jre_version: null to analyse against Tai-e's own JRE)")
    return TaieSettings(
        jar=repo_path(t.get("jar", "tools/tai-e-all-0.5.4.jar")), java_bin=java_bin, jre_version=jre_version,
        jre_jars=jre_jars, home=settings.work_dir / "taie-home", cs=str(t.get("cs", "ci")),
        only_app=bool(t.get("only_app", False)), time_limit_s=int(t.get("time_limit_s", 1800)),
        wall_timeout_s=int(t.get("wall_timeout_s", 3600)), xmx=str(t.get("xmx", "6g")),
        extra_pta_options={k: str(v) for k, v in (t.get("extra_pta_options") or {}).items()})


def _hash_files(paths: List[Path], extra: str = "") -> str:
    h = hashlib.sha1(extra.encode())
    for p in paths:
        p = Path(p)
        files = sorted(p.rglob("*")) if p.is_dir() else [p]
        for f in files:
            if f.is_file():
                h.update(f.relative_to(p).as_posix().encode() if p.is_dir() else f.name.encode())
                h.update(f.read_bytes())
    return h.hexdigest()[:16]


class SubjectContext:
    """Facts and paths for one built subject version (computed once, reused by all configs)."""

    def __init__(self, settings: Settings, subject: Subject, version: str, layout: Optional[BuildLayout] = None):
        self.settings = settings
        self.subject = subject
        self.version = version
        injected_layout = layout is not None
        self.layout = layout or load_layout(settings, subject.id, version)
        if not self.layout.app_dirs:
            raise PipelineError(f"{subject.id}/{version}: no compiled application classes found")
        # A layout loaded from disk must record a successful build (layout.ok): a failed or partial
        # build leaves app_dirs set but ok=False and must not be silently reused as a stale layout.
        # An explicitly injected layout (tests, demand helpers) or NESY_ALLOW_PREBUILT_LAYOUT=1 opts out.
        if (not injected_layout and not self.layout.ok
                and os.environ.get("NESY_ALLOW_PREBUILT_LAYOUT") != "1"):
            raise PipelineError(
                f"{subject.id}/{version}: build layout is not ok=true (failed/partial build); rebuild "
                f"with `python -m nesy build {subject.id} --version {version}`, or set "
                f"NESY_ALLOW_PREBUILT_LAYOUT=1 to analyse a hand-provided layout. See {self.layout.log}")
        self.root = settings.work_dir / "runs" / subject.id / version
        self.root.mkdir(parents=True, exist_ok=True)
        self.app_paths = [Path(p) for p in self.layout.app_dirs]
        self.lib_paths = [Path(p) for p in self.layout.lib_jars] + [Path(p) for p in subject.extra_lib_jars]
        t0 = time.time()
        jre = settings.jre8_jars()
        self.facts: ProgramFacts = extract_facts(self.app_paths, self.lib_paths, jre,
                                                 [Path(p) for p in self.layout.source_roots])
        self.facts_s = round(time.time() - t0, 2)
        self.facts.dump(self.root / "facts.json")
        self.cwe_id = subject.cwe
        cwes = settings.cwes.get("cwes") or {}
        if self.cwe_id not in cwes:
            raise PipelineError(f"{self.cwe_id} missing in config/cwe.yaml")
        self.cwe = cwes[self.cwe_id]
        self.base_files = base_config_files(settings.cwes, self.cwe_id)
        self.fixed_methods = load_fixed_methods(subject.slug)
        self.stats = subject_stats(self.layout, self.lib_paths)
        j17 = settings.java17_home()
        self.javac = javac_path(j17)
        self.compile_cp = self.app_paths + self.lib_paths
        self.taie = taie_settings(settings, subject)


def subject_stats(layout: BuildLayout, lib_paths: List[Path]) -> dict:
    """Size of the analysed code, for the subject table of the report."""
    files = loc = 0
    for root in layout.source_roots:
        for p in Path(root).rglob("*.java"):
            files += 1
            try:
                loc += sum(1 for line in p.read_text(errors="replace").splitlines() if line.strip())
            except OSError:
                pass
    return {"java_files": files, "non_blank_loc": loc, "dependency_jars": len(lib_paths),
            "modules_analysed": len(layout.app_dirs)}


# ----------------------------------------------------------------- stages with caching

# Content hashes are memoized only while size/mtime remain unchanged within this process.
_FILE_HASHES = {}


def _content_identity(paths) -> str:
    rows = []
    for raw in paths:
        path = Path(raw)
        files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
        for p in files:
            if not p.is_file():
                rows.append((str(p), "missing"))
                continue
            stat = p.stat()
            key = (str(p.resolve()), stat.st_size, stat.st_mtime_ns)
            if key not in _FILE_HASHES:
                _FILE_HASHES[key] = hashlib.sha256(p.read_bytes()).hexdigest()
            rows.append((str(p), _FILE_HASHES[key]))
    return hashlib.sha256(json.dumps(rows).encode()).hexdigest()


def _stage_identity(ctx, stage: str, cfg: dict, llm=None) -> dict:
    """Fingerprint actual stage inputs, including facts, source/build content and prompts."""
    facts = ctx.facts
    fact_data = {
        "entries": [asdict(x) for x in facts.entries],
        "external_apis": {k: asdict(v) for k, v in facts.external_apis.items()},
        "app_classes": {k: asdict(v) for k, v in facts.app_classes.items()},
    }
    layout = getattr(ctx, "layout", None)
    sources = list(getattr(layout, "source_roots", []))
    project_dir = getattr(layout, "project_dir", None)
    readmes = [Path(project_dir) / n for n in ("README.md", "README.markdown", "README.adoc", "README.txt", "README")] if project_dir else []
    jre = ctx.settings.jre8_jars() if hasattr(ctx.settings, "jre8_jars") else []
    paths = list(getattr(ctx, "compile_cp", [])) + list(jre) + sources
    if stage in ("template", "driver"):
        paths += [p for p in readmes if p.is_file()]
        javac = getattr(ctx, "javac", "")
        if javac:
            paths.append(Path(shutil.which(javac) or javac))
    if stage == "spec":
        paths += list(ctx.base_files)
    modules = ["facts.py", "classfile.py", "sources.py", "prompts.py", "jvm.py",
               "spec.py" if stage == "spec" else "driver.py"]
    identity = {
        "version": 1, "stage": stage, "settings": cfg,
        "facts_sha256": hashlib.sha256(json.dumps(fact_data, sort_keys=True, default=str).encode()).hexdigest(),
        "files_sha256": _content_identity(paths),
        "implementation_sha256": _content_identity([Path(__file__).with_name(n) for n in modules]),
        "project": {"repo": ctx.subject.repo, "id": ctx.subject.id},
        "cwe_id": ctx.cwe_id, "cwe": ctx.cwe,
    }
    if stage == "driver":
        identity["prompts"] = {n: prompt_version(n) for n in ("n1_driver", "n1_repair")}
        identity["entry_check_version"] = ENTRY_CHECK_VERSION
        identity["template_version"] = TEMPLATE_VERSION
    elif stage == "template":
        identity["template_version"] = TEMPLATE_VERSION
    else:
        identity["prompts"] = {"n2_spec": prompt_version("n2_spec")}
        identity["vote_version"] = SPEC_VOTE_VERSION
        if cfg.get("mode") == "demand":
            reachable = _reachable_app_methods(ctx)
            identity["reachable_methods"] = sorted(reachable) if reachable is not None else None
    if llm is not None:
        identity["llm"] = llm.cache_identity()
    return identity


def _identity_matches(work: Path, expected: dict) -> bool:
    path = work / "cache-identity.json"
    try:
        return json.loads(path.read_text())["identity"] == expected
    except (OSError, ValueError, KeyError, TypeError):
        return False


def _save_identity(work: Path, identity: dict, provenance: str = "computed from current inputs") -> None:
    work.mkdir(parents=True, exist_ok=True)
    (work / "cache-identity.json").write_text(json.dumps({"identity": identity, "provenance": provenance}, indent=2))


def _driver_cfg(ctx, run: int, entry_check: bool) -> dict:
    cfg = dict(ctx.settings.section("driver"))
    cfg.setdefault("max_tokens", ctx.settings.section("llm").get("max_tokens", 8192))
    cfg.setdefault("temperature", ctx.settings.section("llm").get("temperature", 0.0))
    cfg["sample_offset"] = run * 1000
    cfg["entry_check"] = entry_check
    return cfg


def _spec_cfg(ctx, run: int) -> dict:
    cfg = dict(ctx.settings.section("spec"))
    lcfg = ctx.settings.section("llm")
    cfg.setdefault("temperature", lcfg.get("temperature", 0.0))
    cfg.setdefault("sample_temperature", lcfg.get("sample_temperature", 0.7))
    cfg.setdefault("max_tokens", lcfg.get("max_tokens", 8192))
    cfg["sample_offset"] = run * 1000
    return cfg


def adopt_legacy_stage(ctx, stage: str, provenance: str, llm=None, run: int = 0,
                       entry_check: bool = False, validators: bool = True) -> Path:
    """Explicit migration after independently verifying historical settings/model/inputs.

    Never called automatically. The caller must check historical provenance against
    CURRENT inputs; old artifacts did not store enough data to infer it. This helper
    checks versions and payload availability, then records that attestation without
    rebuilding a frozen driver or spending tokens. Repair-prompt provenance is part
    of the caller's verification. Corrected N2 artifacts must already be refreshed.
    """
    if not provenance.strip():
        raise ValueError("legacy adoption requires an explicit provenance attestation")
    if stage == "template":
        work, cfg = ctx.root / "template-driver", ctx.settings.section("driver")
    elif stage == "driver":
        if llm is None:
            raise ValueError("driver adoption requires the historical model client")
        work, cfg = llm_driver_dir(ctx, run, entry_check), _driver_cfg(ctx, run, entry_check)
    elif stage == "spec":
        if llm is None:
            raise ValueError("spec adoption requires the historical model client")
        work = ctx.root / f"run{run}" / ("spec-llm" if validators else "spec-llm-noval")
        cfg = {**_spec_cfg(ctx, run), "validators": validators}
    else:
        raise ValueError("stage must be template, driver or spec")
    if stage == "spec":
        artifact = SpecResult(**json.loads((work / "spec.json").read_text()))
        if artifact.prompt_version != prompt_version("n2_spec") or artifact.stats.get("vote_version") != SPEC_VOTE_VERSION:
            raise ValueError("spec prompt/voting version differs; rebuild from raw response cache first")
        if not (work / "inferred.yml").is_file():
            raise ValueError("inferred.yml missing")
    else:
        artifact = DriverResult(**json.loads((work / "driver.json").read_text()))
        if not artifact.ok or not Path(artifact.source_path).is_file() or not (Path(artifact.classes_dir) / "nesy/NesyDriver.class").is_file():
            raise ValueError("driver is failed or source/compiled output is missing")
        if stage == "driver" and artifact.prompt_version != prompt_version("n1_driver"):
            raise ValueError("driver prompt version differs")
        if stage == "driver" and entry_check and artifact.kind != "llm-fallback-template" and artifact.check_version != ENTRY_CHECK_VERSION:
            raise ValueError("driver entry-check version differs")
        if stage == "template" and (work / "template.version").read_text().strip() != str(TEMPLATE_VERSION):
            raise ValueError("template version differs")
    _save_identity(work, _stage_identity(ctx, stage, cfg, llm if stage != "template" else None), provenance)
    return work / "cache-identity.json"



def get_template_driver(ctx: SubjectContext, force: bool = False) -> DriverResult:
    work = ctx.root / "template-driver"
    cfg = ctx.settings.section("driver")
    identity = _stage_identity(ctx, "template", cfg)
    meta = work / "driver.json"
    if meta.exists() and not force:
        cached = DriverResult(**json.loads(meta.read_text()))
        stamp = work / "template.version"
        current = stamp.exists() and stamp.read_text().strip() == str(TEMPLATE_VERSION)
        if (cached.ok and current and _identity_matches(work, identity)
                and Path(cached.source_path).is_file()
                and (Path(cached.classes_dir) / "nesy/NesyDriver.class").is_file()):          # never reuse a failed or outdated build
            return cached
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    (work / "template.version").write_text(str(TEMPLATE_VERSION))
    d = ctx.settings.section("driver")
    result = build_template_driver(ctx.facts, work, ctx.compile_cp, ctx.javac,
                                   int(d.get("max_entries_template", 300)), int(d.get("javac_release", 8)))
    _save_identity(work, identity)
    return result


def llm_driver_dir(ctx: SubjectContext, run: int, entry_check: bool = False) -> Path:
    return ctx.root / f"run{run}" / ("llm-driver-entrycheck" if entry_check else "llm-driver")


def get_llm_driver(ctx: SubjectContext, llm: BaseLLM, run: int, force: bool = False,
                   entry_check: bool = False) -> DriverResult:
    work = llm_driver_dir(ctx, run, entry_check)
    cfg = _driver_cfg(ctx, run, entry_check)
    identity = _stage_identity(ctx, "driver", cfg, llm)
    meta = work / "driver.json"
    if meta.exists() and not force:
        cached = DriverResult(**json.loads(meta.read_text()))
        check_ok = (not entry_check) or cached.kind == "llm-fallback-template" or cached.check_version == ENTRY_CHECK_VERSION
        # Rebuild a cached missing-code fallback if no larger-budget retry was recorded.
        cut_off = cached.kind == "llm-fallback-template" and not any("retried with" in e for e in cached.errors) \
            and any(e in ("N1: no java block in answer", "repair answer had no java block") for e in cached.errors)
        if (cached.ok and cached.prompt_version == prompt_version("n1_driver") and check_ok and not cut_off
                and _identity_matches(work, identity)
                and Path(cached.source_path).is_file()
                and (Path(cached.classes_dir) / "nesy/NesyDriver.class").is_file()):
            return cached
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    before = llm.usage_snapshot()
    res = build_llm_driver(ctx.facts, llm, work, ctx.compile_cp, ctx.javac, ctx.cwe, ctx.cwe_id,
                           f"{ctx.subject.repo} ({ctx.subject.id})", Path(ctx.layout.project_dir), cfg,
                           int(cfg.get("javac_release", 8)))
    _save_usage(work / "usage.json", BaseLLM.usage_diff(llm.usage_snapshot(), before))
    _save_identity(work, identity)
    return res


def get_llm_spec(ctx: SubjectContext, llm: BaseLLM, run: int, validators: bool, force: bool = False) -> SpecResult:
    work = ctx.root / f"run{run}" / ("spec-llm" if validators else "spec-llm-noval")
    cfg = _spec_cfg(ctx, run)
    identity = _stage_identity(ctx, "spec", {**cfg, "validators": validators}, llm)
    meta = work / "spec.json"
    if meta.exists() and not force:
        cached = SpecResult(**json.loads(meta.read_text()))
        if (cached.prompt_version == prompt_version("n2_spec")
                and cached.stats.get("vote_version") == SPEC_VOTE_VERSION
                and _identity_matches(work, identity)):
            return cached
    before = llm.usage_snapshot()
    known = signatures_in_config(ctx.base_files)
    reachable = None
    if cfg.get("mode") == "demand":
        reachable = _reachable_app_methods(ctx)
    res = infer_spec(ctx.facts, llm, ctx.cwe, ctx.cwe_id, f"{ctx.subject.repo} ({ctx.subject.id})", cfg, known,
                     validators=validators, reachable_methods=reachable, known_tags=known_entries(ctx.base_files))
    res.save(work)
    _save_usage(work / "usage.json", BaseLLM.usage_diff(llm.usage_snapshot(), before))
    _save_identity(work, identity)
    return res


def _reachable_app_methods(ctx: SubjectContext) -> set:
    """Experimental demand mode: methods represented in the saved B1 run's TFG.

    This is a taint-graph heuristic, not all call-graph-reachable methods. Require
    a successful preliminary B1 run; never select another configuration's graph
    by its cache-directory order or silently fall back to full inference.
    """
    record_path = ctx.settings.results_dir / "runs" / ctx.subject.id / ctx.version / "B1" / "run0.json"
    prerequisite = (f"spec.mode=demand requires a successful preliminary B1 run with its TFG: "
                    f"run `python -m nesy run {ctx.subject.id} --version {ctx.version} --configs B1` first")
    try:
        record = json.loads(record_path.read_text())
        valid = (record.get("subject") == ctx.subject.id and record.get("version") == ctx.version
                 and record.get("config") == "B1" and record.get("run") == 0
                 and record.get("taie", {}).get("ok"))
        out_dir = Path(record["taie"]["out_dir"])
    except (OSError, ValueError, KeyError, TypeError):
        raise PipelineError(prerequisite) from None
    if not valid:
        raise PipelineError(prerequisite)
    graph = out_dir / "taint-flow-graph.dot"
    if not graph.is_file():
        # A moved checkout may retain an absolute original output path in its record.
        graph = ctx.root / "taie" / out_dir.name / "taint-flow-graph.dot"
    if not graph.is_file():
        raise PipelineError(prerequisite + f"; missing graph for {record_path}")
    tfg = TaintFlowGraph.load(graph)
    from .taie import node_method
    return {m for m in (node_method(n) for n in tfg.nodes) if m}


def _save_usage(path: Path, usage: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(usage, indent=2))


def _load_usage(path: Path) -> dict:
    return json.loads(path.read_text()) if path.exists() else {}


def run_taie_cached(ctx: SubjectContext, driver: DriverResult, config_dir: Path, force: bool = False) -> TaieResult:
    # A changed subject/dependency/JRE/Tai-e binary must never reuse old propagation.
    inputs = list(ctx.app_paths) + list(ctx.lib_paths) + list(ctx.taie.jre_jars) + [ctx.taie.jar]
    key = _hash_files([Path(driver.classes_dir), config_dir],
                      json.dumps({"settings": asdict(ctx.taie), "inputs": _content_identity(inputs)},
                                 default=str, sort_keys=True))
    out = ctx.root / "taie" / key
    res_file = out / "result.json"
    if res_file.exists() and not force:
        d = json.loads(res_file.read_text())
        # failed runs are not reused: a crash is re-run (cheap since crashes are detected within
        # seconds, see taie.run_watched) so transient failures (memory pressure) do not stick
        if d.get("ok"):
            flows = [TaintFlow.from_json(f) for f in d.pop("flows")]
            r = TaieResult(**{k: v for k, v in d.items() if k in TaieResult.__dataclass_fields__ and k != "flows"})
            r.flows = flows
            return r
    app = ctx.app_paths + [Path(driver.classes_dir)]
    return run_taie(ctx.taie, app, ctx.lib_paths, DRIVER_CLASS, config_dir, out)


# ----------------------------------------------------------------- one configuration

def run_config(ctx: SubjectContext, config_name: str, run: int, llm_factory: Optional[LLMFactory],
               force: bool = False) -> dict:
    cfg = ctx.settings.configs().get(config_name)
    if cfg is None:
        raise PipelineError(f"unknown configuration {config_name!r} (see config/experiment.yaml)")
    validators = bool(cfg.get("validators", True))
    # `validators: false` switches off both; `spec_validator` / `triage_validator` override one of them
    # (ablations v3-noV2 / v3-noV3 isolate V2 and V3; v3-noval switches off both)
    spec_val = bool(cfg.get("spec_validator", validators))
    triage_val = bool(cfg.get("triage_validator", validators))
    needs_llm = cfg.get("driver") == "llm" or "llm" in cfg.get("spec", []) or cfg.get("triage")
    llm = None
    if needs_llm:
        if llm_factory is None:
            raise PipelineError(f"{config_name} needs an LLM (use --mock for a dry run)")
        llm = llm_factory()
        llm.context = {"subject": ctx.subject.id, "version": ctx.version, "config": config_name, "run": run}
    t_start = time.time()
    timings = {"facts_s": ctx.facts_s}

    # driver
    t0 = time.time()
    if cfg.get("driver") == "llm":
        entry_check = bool(cfg.get("driver_entry_check", False))
        driver = get_llm_driver(ctx, llm, run, force, entry_check)
        driver_usage = _load_usage(llm_driver_dir(ctx, run, entry_check) / "usage.json")
    else:
        driver = get_template_driver(ctx, force)
        driver_usage = {}
    timings["driver_s"] = round(time.time() - t0, 2)
    if not driver.ok:
        raise PipelineError(f"{ctx.subject.id}/{ctx.version}/{config_name}: driver did not compile; "
                            f"see {Path(driver.classes_dir).parent}/driver.json")

    # specification layers
    t0 = time.time()
    layers: Dict[str, List[Path]] = {"base": list(ctx.base_files)}
    extra = {"driver-sources.yml": DRIVER_SOURCES_YAML}
    if ctx.settings.section("taie").get("call_site_mode", True):
        # match sources/sinks by the statically resolved call target instead of call-graph edges:
        # sinks declared on library interfaces with no implementation in the analysed closed world
        # (e.g. javax.validation.ConstraintValidatorContext) otherwise never fire
        extra["taie-options.yml"] = "call-site-mode: true\n"
    if ctx.taie.only_app:
        # without library bodies, `sb.append(x).append(y)` loses taint on the returned builder:
        # add result transfers for StringBuilder/StringBuffer chaining
        extra["only-app-chain-transfers.yml"] = chain_transfers_yaml(ctx.base_files)
    spec_stats, spec_usage = None, {}
    spec = None
    manual_entries = None
    if "manual" in cfg.get("spec", []):
        mf = manual_config_file(ctx.subject.id)
        layers["manual"] = [mf] if mf else []
        manual_entries = sum(len(v) for v in signatures_in_config([mf]).values()) if mf else 0
    if "llm" in cfg.get("spec", []):
        spec = get_llm_spec(ctx, llm, run, spec_val, force)
        extra["llm-inferred.yml"] = spec.yaml_text
        spec_stats = dict(spec.stats)
        if cfg.get("spec_array_elements"):
            # symbolic completion of N2 output; a separate file so the cached N2 spec is unchanged
            added = array_element_sinks(spec.accepted)
            spec_stats["array_element_sinks_added"] = len(added)
            if added:
                extra["llm-array-elements.yml"] = to_taie_yaml(added).replace(
                    "Generated by N2 (LLM taint-spec inference) after V2 validation and voting.",
                    "Array-element sinks added symbolically for accepted N2 array sinks.")
        spec_usage = _load_usage(ctx.root / f"run{run}" / ("spec-llm" if spec_val else "spec-llm-noval") / "usage.json")
    timings["spec_s"] = round(time.time() - t0, 2)
    cdir = ctx.root / "configs" / config_name / f"run{run}" / "taint-config"
    assemble_config(cdir, layers, extra, (ctx.settings.cwes.get("common") or {}).get("exclude_lines", []))

    # Tai-e
    t0 = time.time()
    tr = run_taie_cached(ctx, driver, cdir, force)
    timings["taie_s"] = round(time.time() - t0, 2)
    invalid_spec: List[str] = []
    if not tr.ok and not spec_val and (cdir / "llm-inferred.yml").exists():
        # explain the expected V2-ablation crash: list the N2 entries V2 would have rejected
        invalid_spec = invalid_spec_entries(cdir / "llm-inferred.yml", ctx.facts)
    flt = ctx.settings.section("flows")
    flows = filter_flows(tr.flows, set(ctx.facts.app_classes), bool(flt.get("drop_jdk_internal_sinks", True)),
                         bool(flt.get("app_sinks_only", False)), bool(flt.get("drop_jdk_internal_sources", True)))
    tfg = TaintFlowGraph.load(Path(tr.out_dir) / "taint-flow-graph.dot")

    # triage
    t0 = time.time()
    decisions: Dict[str, TriageDecision] = {}
    triage_usage = {}
    if cfg.get("triage") and flows:
        before = llm.usage_snapshot()
        tcfg = dict(ctx.settings.section("triage"))
        tcfg.setdefault("sample_temperature", ctx.settings.section("llm").get("sample_temperature", 0.7))
        tcfg.setdefault("max_tokens", ctx.settings.section("llm").get("max_tokens", 8192))
        tcfg["sample_offset"] = run * 1000
        trusted = None
        if cfg.get("triage_trusted_sinks"):
            # curated base sinks + N2 sinks chosen unanimously by all samples
            trusted = set(signatures_in_config(ctx.base_files).get("sink", set()))
            if spec is not None:
                trusted |= {a["signature"] for a in spec.accepted
                            if a["role"] == "sink" and a.get("votes", 0) >= a.get("samples", 1)}
        ds = triage_all(flows, tfg, ctx.facts, llm, ctx.cwe, ctx.cwe_id, tcfg, triage_val, trusted)
        tdir = ctx.root / "configs" / config_name / f"run{run}"
        save_decisions(ds, tdir / "triage.json")
        decisions = {d.flow_id: d for d in ds}
        triage_usage = BaseLLM.usage_diff(llm.usage_snapshot(), before)
    timings["triage_s"] = round(time.time() - t0, 2)

    # ground truth + record
    flow_rows = []
    for f in flows:
        gt, gt_weak = gt_tiers(f, tfg, ctx.fixed_methods)
        d = decisions.get(f.short_id)
        flow_rows.append({
            "id": f.short_id, "key": f.key, "source": f.source.raw, "sink": f.sink.raw,
            "sink_method": f.sink.method, "sink_line": f.sink.line, "gt": gt, "gt_weak": gt_weak,
            "reported": d.kept if d else True,
            "triage": ({"verdict": d.verdict, "reason": d.reason, "kept": d.kept, "v3_ok": d.v3_ok,
                        "v3_problems": d.v3_problems, "override": d.override} if d else None),
        })
    reported = [r for r in flow_rows if r["reported"]]
    usage = {"N1": _sum_usage(driver_usage), "N2": _sum_usage(spec_usage), "N3": _sum_usage(triage_usage)}
    usage["total"] = _sum_usage({k: v for k, v in usage.items() if v})
    record = {
        "subject": ctx.subject.id, "slug": ctx.subject.slug, "cve": ctx.subject.cve, "cwe": ctx.cwe_id,
        "version": ctx.version, "config": config_name, "run": run, "config_def": cfg,
        "model": getattr(llm, "model", None) if llm else None,
        "served_models": sorted(getattr(llm, "served_models", set())) if llm else [],
        "prompt_versions": {n: prompt_version(n) for n in ("n1_driver", "n1_repair", "n2_spec", "n3_triage")},
        "taie_settings": {k: str(v) for k, v in asdict(ctx.taie).items() if k not in ("jre_jars",)},
        "facts": ctx.facts.summary(),
        "subject_stats": ctx.stats,
        "gt_methods": [f"{m.class_name}.{m.method}" for m in ctx.fixed_methods],
        "driver": {"kind": driver.kind, "ok": driver.ok, "entries": len(driver.entries), "attempts": driver.attempts,
                   "removed_entries": len(driver.removed_entries), "app_calls": driver.app_calls,
                   "taint_calls": driver.taint_calls, "errors": len(driver.errors),
                   "entry_mismatches": len(getattr(driver, "entry_mismatches", []) or [])},
        "spec": spec_stats,
        "manual_spec_entries": manual_entries,
        "taie": {"ok": tr.ok, "returncode": tr.returncode, "elapsed_s": tr.elapsed_s, "timed_out": tr.timed_out,
                 "detected_raw": tr.detected, "reachable_methods": tr.reachable_methods, "out_dir": tr.out_dir,
                 "error": tr.error, "invalid_spec_entries": invalid_spec,
                 "expected_failure": bool(not tr.ok and not spec_val and invalid_spec)},
        "counts": {
            "raw": len(tr.flows), "filtered": len(flows), "reported": len(reported),
            "reported_gt": sum(1 for r in reported if r["gt"]),
            "reported_gt_weak": sum(1 for r in reported if r.get("gt_weak")),
            "removed_by_triage": sum(1 for r in flow_rows if not r["reported"]),
            "removed_gt_by_triage": sum(1 for r in flow_rows if not r["reported"] and r["gt"]),
            "v3_rejected": sum(1 for d in decisions.values() if d.v3_ok is False),
            "trusted_sink_overrides": sum(1 for d in decisions.values() if d.override == "trusted-sink"),
        },
        "detected": any(r["gt"] for r in reported),
        "usage": usage,
        "timings": {**timings, "total_s": round(time.time() - t_start + ctx.facts_s, 2)},
        "flows": flow_rows,
    }
    out = ctx.settings.results_dir / "runs" / ctx.subject.id / ctx.version / config_name / f"run{run}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2))
    return record


def gt_tiers(f: TaintFlow, tfg: TaintFlowGraph, fixed) -> "tuple[list, list]":
    """CVE relevance of a flow.

    * ``gt``  (strict): a fixed method is the source method, the sink method, or on a TFG route
      from source to sink. Used for ``detected`` and ``reported_gt``.
    * ``gt_weak``: no strict match, but a fixed method is merely reachable from the source or
      reaches the sink (the old ``methods_between`` fallback). Reported separately only.
    """
    gt = relevant_methods([f.source.method, f.sink.method] + tfg.route_methods(f), fixed)
    weak = [] if gt else relevant_methods(tfg.methods_between(f), fixed)
    return gt, weak


def rescore_record(rec: dict, fixed, tfg: TaintFlowGraph) -> dict:
    """Recompute ground-truth fields of an existing run record in place (no Tai-e, no LLM)."""
    from .taie import parse_flow_line
    for r in rec.get("flows", []):
        f = parse_flow_line("TaintFlow{" + r["source"] + " -> " + r["sink"] + "}")
        if f is None:
            continue
        r["gt"], r["gt_weak"] = gt_tiers(f, tfg, fixed)
    rows = rec.get("flows", [])
    reported = [r for r in rows if r["reported"]]
    c = rec.setdefault("counts", {})
    c["reported_gt"] = sum(1 for r in reported if r["gt"])
    c["reported_gt_weak"] = sum(1 for r in reported if r.get("gt_weak"))
    c["removed_gt_by_triage"] = sum(1 for r in rows if not r["reported"] and r["gt"])
    rec["detected"] = any(r["gt"] for r in reported)
    rec["gt_rule"] = "strict-v1 (endpoint or TFG route)"
    return rec


def _sum_usage(stages: Dict[str, Dict[str, float]]) -> Dict[str, float]:
    tot: Dict[str, float] = {}
    for d in stages.values():
        for k, v in d.items():
            tot[k] = round(tot.get(k, 0) + v, 3)
    return tot


def is_deterministic(cfg: dict) -> bool:
    return cfg.get("driver") != "llm" and "llm" not in cfg.get("spec", []) and not cfg.get("triage")


# ----------------------------------------------------------------- crash re-check

def recheck_crash(ctx: SubjectContext, config_name: str, run: int, out_root: Optional[Path] = None) -> dict:
    """Re-run Tai-e for one stored configuration run twice, with the same driver and settings:
    (a) on the stored taint config, (b) on a copy where only the N2 entries that V2 would reject
    are removed. If (a) crashes and (b) succeeds, the crash is caused by those entries."""
    import re
    cfg = ctx.settings.configs().get(config_name)
    if cfg is None:
        raise PipelineError(f"unknown configuration {config_name!r}")
    cdir = ctx.root / "configs" / config_name / f"run{run}" / "taint-config"
    if not cdir.exists():
        raise PipelineError(f"{cdir} missing: run `nesy run {ctx.subject.id} --configs {config_name}` first")
    if cfg.get("driver") == "llm":
        meta = llm_driver_dir(ctx, run, bool(cfg.get("driver_entry_check"))) / "driver.json"
    else:
        meta = ctx.root / "template-driver" / "driver.json"
    if not meta.exists():
        raise PipelineError(f"{meta} missing: run the configuration first")
    driver = DriverResult(**json.loads(meta.read_text()))
    out_root = Path(out_root or ctx.root / "recheck" / config_name / f"run{run}")
    if out_root.exists():
        shutil.rmtree(out_root)
    app = ctx.app_paths + [Path(driver.classes_dir)]

    original = run_taie(ctx.taie, app, ctx.lib_paths, DRIVER_CLASS, cdir, out_root / "taie-original")
    spec_file = cdir / "llm-inferred.yml"
    invalid = invalid_spec_entries(spec_file, ctx.facts) if spec_file.exists() else []
    result = {"subject": ctx.subject.id, "version": ctx.version, "config": config_name, "run": run,
              "driver": driver.kind, "original_ok": original.ok, "original_error": (original.error or "")[:400],
              "original_flows": len(original.flows), "invalid_entries": invalid}
    if invalid:
        clean = out_root / "taint-config-without-invalid"
        shutil.copytree(cdir, clean)
        data = yaml.safe_load(spec_file.read_text()) or {}
        drop: Dict[str, set] = {}
        for msg in invalid:
            m = re.match(r"^(sources|sinks|transfers|sanitizers)\[(\d+)\]", msg)
            if m:
                drop.setdefault(m.group(1), set()).add(int(m.group(2)))
        for key, idx in drop.items():
            data[key] = [e for i, e in enumerate(data.get(key) or []) if i not in idx]
        (clean / "llm-inferred.yml").write_text(
            "# llm-inferred.yml with the entries V2 would reject removed (nesy recheck)\n" +
            yaml.safe_dump(data, sort_keys=False, width=200))
        cleaned = run_taie(ctx.taie, app, ctx.lib_paths, DRIVER_CLASS, clean, out_root / "taie-without-invalid")
        result.update({"removed": sum(len(v) for v in drop.values()), "cleaned_ok": cleaned.ok,
                       "cleaned_error": (cleaned.error or "")[:400], "cleaned_flows": len(cleaned.flows)})
    (out_root / "recheck.json").write_text(json.dumps(result, indent=1))
    return result
