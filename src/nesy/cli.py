"""Command-line interface: ``python -m nesy <command>`` (run from the repository root).

Commands
  check-env [--llm]                    verify Java, Tai-e, JDK 8 library, Maven, git, and the LLM endpoint
  fetch   <subject|all> [--version]    clone + check out buggy/fixed commits into work/subjects
  build   <subject|all> [--version]    compile with Maven and record the class path layout
  facts   <subject> [--version]        run S1 only and print a summary
  candidates <subject>                 list library APIs to review when writing the B2 manual spec
  check-manual <subject|all>           check config/taint/manual/<id>.yml for syntax/signature/index errors
  recheck <subject|all> --configs C    re-run Tai-e for crashed runs with and without the entries V2 rejects
  show-flow <subject> <version> <id>   print one alarm for labelling: route, code of the methods on it, N3 verdict
  label-pack <subject|all>             write labels/review/<subject>-<version>.md: evidence for every open row
  run     <subject|all> [--version] [--configs B1,v3] [--runs N] [--mock] [--force]
  label-sheet <subject|all>            write/refresh labels/<subject>-<version>.csv for manual labelling
  rescore [--dry-run]                  re-apply the ground-truth rule to existing run records (no Tai-e/LLM)
  evaluate                             aggregate results/runs into results/summary (tables, cases.md, tables.tex)
  export                               copy drivers/specs/triage/TFGs from work/ into results/artifacts (for the repo)
  demo    [--mock|--live]              end-to-end run on the bundled mini fixture (no Maven needed)
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List

from .config import REPO_ROOT, Settings, load_settings
from .llm import BaseLLM, MockLLM, client_from_env
from .mock import heuristic_responder


def _subjects(settings: Settings, which: str, include_reserve: bool = False):
    """'all' = development subjects (role primary); 'test' = held-out test subjects (role test);
    'all --include-reserve' = both."""
    if which == "all":
        return [s for s in settings.subjects.values() if include_reserve or s.role == "primary"]
    if which == "test":
        return [s for s in settings.subjects.values() if s.role == "test"]
    if which not in settings.subjects:
        sys.exit(f"unknown subject {which!r}; known: {', '.join(settings.subjects)}")
    return [settings.subjects[which]]


def _versions(v: str) -> List[str]:
    return ["buggy", "fixed"] if v == "both" else [v]


def make_llm_factory(settings: Settings, mock: bool):
    cache = settings.work_dir / "llm-cache"
    ledger = settings.work_dir / "llm-ledger.jsonl"
    lcfg = settings.section("llm")
    if mock:
        return lambda: MockLLM(heuristic_responder, cache_dir=cache / "mock", ledger=ledger)
    shared = {}

    def factory() -> BaseLLM:
        if "c" not in shared:
            shared["c"] = client_from_env(settings.env, cache, ledger, model=lcfg.get("model"),
                                          timeout_s=float(lcfg.get("timeout_s", 300)),
                                          extra_body=lcfg.get("extra_body") or None)
        return shared["c"]
    return factory


# ----------------------------------------------------------------- commands

def cmd_check_env(settings: Settings, args) -> int:
    ok = True

    def line(name, good, detail=""):
        nonlocal ok
        ok = ok and good
        print(f"[{'ok' if good else '!!'}] {name:28s} {detail}")

    j17 = settings.java17_home()
    line("JDK 17+ (runs Tai-e)", bool(j17), str(j17 or "not found: set JAVA17_HOME"))
    import sys as _sys
    conda_env = os.environ.get("CONDA_DEFAULT_ENV") if os.environ.get("CONDA_PREFIX") and \
        Path(_sys.prefix).resolve() == Path(os.environ["CONDA_PREFIX"]).resolve() else None
    in_venv = _sys.prefix != getattr(_sys, "base_prefix", _sys.prefix)
    if conda_env:
        env_desc = f"conda env '{conda_env}' ({_sys.prefix})" + \
            ("  - base env: a dedicated env is safer (README section 2)" if conda_env == "base" else "")
    elif in_venv:
        env_desc = f"virtualenv ({_sys.prefix})"
    else:
        env_desc = f"system Python {_sys.prefix} (works, but a venv/conda env avoids pip conflicts)"
    line("Python environment", True, f"{env_desc}, Python {_sys.version.split()[0]}")
    j8 = settings.java8_home()
    jars = settings.jre8_jars()
    tj = settings.section("taie")
    need8 = tj.get("jre_version", 8) == 8
    line("JDK 8 (analysed library)", bool(jars) or not need8,
         f"{j8} rt.jar={'yes' if jars else 'no'}" if j8 else "not found: set JAVA8_HOME (needed for -java 8)")
    from .config import is_jdk
    line("JDK 8 javac (builds subjects)", bool(j8 and is_jdk(j8)),
         "ok" if j8 and is_jdk(j8) else
         "this Java 8 is a JRE without javac: install a JDK 8 (macOS: brew install --cask zulu@8) "
         "and set JAVA8_HOME in .env")
    jar = REPO_ROOT / tj.get("jar", "tools/tai-e-all-0.5.4.jar")
    line("Tai-e jar", jar.exists(), str(jar) if jar.exists() else f"missing {jar}: run scripts/setup_tools.sh")
    mvn = settings.maven_bin()
    has_mvn = bool(shutil.which(mvn) or Path(mvn).exists())
    pinned = settings.pinned_maven_dir()
    line("Maven", has_mvn, (shutil.which(mvn) or mvn) if has_mvn else "not found: run scripts/setup_tools.sh "
         "(downloads the pinned Maven) or set MAVEN_BIN in .env")
    line(f"Pinned {pinned.name}", (pinned / "bin" / "mvn").exists(),
         "in use" if str(pinned) in mvn else
         "missing: run scripts/setup_tools.sh (newer Maven rejects some old subject POMs)")
    line("git", bool(shutil.which("git")), shutil.which("git") or "")
    line("Graphviz dot (optional)", True, shutil.which("dot") or "not installed (only for viewing TFGs)")
    env_file = REPO_ROOT / ".env"
    line(".env", env_file.exists(), str(env_file) if env_file.exists() else "copy .env.example to .env")
    if args.llm:
        try:
            c = client_from_env(settings.env, None, None, model=settings.section("llm").get("model"))
            models = c.list_models()
            line("LLM endpoint", True, f"{c.base_url} ({len(models)} models)")
            for m in models:
                print(f"      - {m}")
            t0 = time.time()
            r = c.chat([{"role": "user", "content": "Reply with the single word: pong"}], stage="check",
                       max_tokens=2000, use_cache=False)
            line("LLM completion", "pong" in r.text.lower(),
                 f"model={r.model} {time.time() - t0:.1f}s tokens={r.prompt_tokens}+{r.completion_tokens} "
                 f"answer={r.text.strip()[:60]!r}")
        except Exception as e:  # pragma: no cover - network dependent
            line("LLM endpoint", False, f"{type(e).__name__}: {e} (NUS network or VPN required)")
    return 0 if ok else 1


def cmd_fetch(settings, args) -> int:
    from .subjects import fetch
    for s in _subjects(settings, args.subject, args.include_reserve):
        for v in _versions(args.version):
            print(f"fetch {s.id}/{v} ...", flush=True)
            print("   ->", fetch(settings, s, v))
    return 0


def cmd_build(settings, args) -> int:
    from .subjects import build
    rc = 0
    for s in _subjects(settings, args.subject, args.include_reserve):
        for v in _versions(args.version):
            print(f"build {s.id}/{v} (JDK {s.jdk}) ...", flush=True)
            lay = build(settings, s, v)
            print(f"   ok={lay.ok} app_dirs={len(lay.app_dirs)} lib_jars={len(lay.lib_jars)} "
                  f"src_roots={len(lay.source_roots)} {lay.elapsed_s}s log={lay.log}")
            rc |= 0 if lay.ok else 1
    return rc


def cmd_facts(settings, args) -> int:
    from .pipeline import SubjectContext
    s = _subjects(settings, args.subject, True)[0]
    ctx = SubjectContext(settings, s, args.version)
    print(json.dumps(ctx.facts.summary(), indent=2))
    print("top entry candidates:")
    for e in ctx.facts.entries[:15]:
        print(f"  {e.score:5.1f} {e.kind:12s} {e.signature}")
    return 0


def cmd_run(settings, args) -> int:
    from .pipeline import PipelineError, SubjectContext, is_deterministic, run_config
    configs = args.configs.split(",") if args.configs else list(settings.configs())
    runs = args.runs or int(settings.raw.get("runs", 3))
    factory = make_llm_factory(settings, args.mock)
    if args.mock:
        print("NOTE: --mock uses an offline heuristic instead of the LLM. Results are for pipeline testing only.")
        settings.raw["results_dir"] = str(Path(settings.raw.get("results_dir", "results")) / "mock")
    rc = 0
    for s in _subjects(settings, args.subject, args.include_reserve):
        for v in _versions(args.version):
            try:
                ctx = SubjectContext(settings, s, v)
            except Exception as e:
                print(f"!! {s.id}/{v}: {e}")
                rc = 1
                continue
            print(f"== {s.id}/{v}: {ctx.facts.summary()}", flush=True)
            for c in configs:
                cdef = settings.configs().get(c)
                if cdef is None:
                    sys.exit(f"unknown config {c}")
                n = 1 if is_deterministic(cdef) else runs
                for k in range(n):
                    t0 = time.time()
                    try:
                        rec = run_config(ctx, c, k, factory, force=args.force)
                        if rec.get("manual_spec_entries") == 0:
                            print(f"   WARNING: config/taint/manual/{s.id}.yml has no entries, so {c} equals B1. "
                                  "Write the manual spec first (see README.md, Run the experiments).")
                        cnt = rec["counts"]
                        print(f"   {c:9s} run{k}: reported={cnt['reported']:4d} gt={cnt['reported_gt']:3d} "
                              f"detected={rec['detected']!s:5s} raw={cnt['raw']:5d} removed={cnt['removed_by_triage']:3d} "
                              f"driver={rec['driver']['kind']} tokens={int(rec['usage']['total'].get('prompt_tokens', 0) + rec['usage']['total'].get('completion_tokens', 0))} "
                              f"({time.time() - t0:.0f}s)", flush=True)
                        tr = rec["taie"]
                        if not tr["ok"]:
                            why = "timed out" if tr.get("timed_out") else f"exit code {tr.get('returncode')}"
                            if (tr.get("error") or "").startswith("CRASH"):
                                line = ((tr.get("error") or "").splitlines()[1:2] or ["?"])[0]
                                why = "crashed: " + line.replace('Exception in thread "main" ', "")[:200]
                            hint = " (out of memory)" if "OutOfMemoryError" in (tr.get("error") or "") or \
                                "OutOfMemoryError" in _tail(tr.get("out_dir")) else ""
                            if tr.get("expected_failure"):
                                # validator-off ablation; the crash is the measured V2 effect
                                print(f"   -- Tai-e crashed as expected for this ablation (V2 off: "
                                      f"{len(tr['invalid_spec_entries'])} invalid N2 entr"
                                      f"{'y' if len(tr['invalid_spec_entries']) == 1 else 'ies'} reached Tai-e; "
                                      f"{why}). Recorded as taie.ok=false.")
                                for msg in tr["invalid_spec_entries"][:3]:
                                    print(f"      {msg[:160]}")
                            else:
                                print(f"   !! Tai-e FAILED ({why}{hint}); results above are empty. "
                                      f"See {tr.get('out_dir')}/console.log")
                                rc = 1
                    except PipelineError as e:
                        print(f"   {c:9s} run{k}: FAILED {e}")
                        rc = 1
    return rc


def _tail(out_dir) -> str:
    try:
        return (Path(out_dir) / "console.log").read_text(errors="replace")[-20000:]
    except (OSError, TypeError):
        return ""


def cmd_rescore(settings, args) -> int:
    """Re-apply the ground-truth rule to existing run records (reads the saved TFGs; no Tai-e/LLM)."""
    import json
    from .groundtruth import load_fixed_methods
    from .pipeline import rescore_record
    from .taie import TaintFlowGraph
    root = settings.results_dir / ("mock" if args.mock else "") / "runs"
    n = changed = 0
    for f in sorted(root.glob("*/*/*/run*.json")):
        rec = json.loads(f.read_text())
        before = (rec.get("detected"), rec.get("counts", {}).get("reported_gt"))
        tfg_path = Path(rec["taie"]["out_dir"]) / "taint-flow-graph.dot"
        if not tfg_path.exists():   # moved checkout: resolve relative to work/
            parts = Path(rec["taie"]["out_dir"]).parts
            if "work" in parts:
                tfg_path = settings.work_dir.joinpath(*parts[parts.index("work") + 1:]) / "taint-flow-graph.dot"
        if rec.get("flows") and not tfg_path.exists():
            print(f"   skip {f}: no taint-flow-graph.dot (re-run the configuration instead)")
            continue
        rescore_record(rec, load_fixed_methods(rec["slug"]), TaintFlowGraph.load(tfg_path))
        after = (rec["detected"], rec["counts"]["reported_gt"])
        n += 1
        if before != after:
            changed += 1
            print(f"   {rec['subject']}/{rec['version']}/{rec['config']}/run{rec['run']}: "
                  f"detected {before[0]} -> {after[0]}, reported_gt {before[1]} -> {after[1]} "
                  f"(weak-only {rec['counts']['reported_gt_weak']})")
        if not args.dry_run:
            f.write_text(json.dumps(rec, indent=2))
    print(f"{n} records rescored, {changed} changed" + (" (dry run, nothing written)" if args.dry_run else ""))
    return 0


def cmd_label_sheet(settings, args) -> int:
    from .metrics import load_runs, write_label_sheet
    runs = load_runs(settings.results_dir)
    for s in _subjects(settings, args.subject, True):
        for v in ("buggy", "fixed"):
            if any(r["subject"] == s.id and r["version"] == v for r in runs):
                p = write_label_sheet(runs, s.id, v, args.per_config)
                import csv as _csv
                rows = list(_csv.DictReader(open(p)))
                todo = [r for r in rows if r.get("priority") and not (r.get("label") or "").strip()]
                print(f"wrote {p}: {len(rows)} flows, {sum(1 for r in rows if r.get('priority'))} to label "
                      f"(priority 1: {sum(1 for r in rows if r.get('priority') == '1')}, "
                      f"2: {sum(1 for r in rows if r.get('priority') == '2')}), {len(todo)} still open")
    return 0


def cmd_evaluate(settings, args) -> int:
    from .metrics import evaluate
    if args.mock:
        settings.raw["results_dir"] = str(Path(settings.raw.get("results_dir", "results")) / "mock")
    out = evaluate(settings)
    print(f"wrote {out}/summary.md, headline.csv, by_config.csv, cve_detection.csv, triage.csv")
    return 0


def cmd_candidates(settings, args) -> int:
    """List the library APIs a B2 author should review (the same list N2 receives), so the manual
    baseline and the LLM get identical information."""
    from .pipeline import SubjectContext
    from .spec import _api_line, known_entries, select_candidates, signatures_in_config
    s = _subjects(settings, args.subject, True)[0]
    ctx = SubjectContext(settings, s, args.version)
    known = signatures_in_config(ctx.base_files)
    tags = known_entries(ctx.base_files)
    cands = select_candidates(ctx.facts, known, include_jdk=True)
    out = settings.work_dir / "manual-candidates" / f"{s.id}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# Candidate library APIs for the B2 manual spec of {s.id} ({s.cwe} {ctx.cwe.get('name', '')})", "",
             "Same list the LLM (N2) receives. Format: id | Tai-e signature | library | call sites in the project.",
             "Already-configured sinks are marked; everything else is NOT in the B1 base config.",
             f"Write your choices into config/taint/manual/{s.id}.yml.", ""]
    lib = [a for a in cands if not a.from_jdk]
    jdk = [a for a in cands if a.from_jdk]
    lines.append(f"## Third-party library APIs ({len(lib)})")
    lines += [_api_line(i, a, ctx.facts, 2, tags) for i, a in enumerate(lib)]
    lines += ["", f"## JDK APIs not in the base config ({len(jdk)})"]
    lines += [_api_line(i, a, ctx.facts, 2, tags) for i, a in enumerate(jdk, start=len(lib))]
    out.write_text("\n".join(lines) + "\n")
    print(f"{len(cands)} candidate APIs ({len(lib)} third-party, {len(jdk)} JDK) -> {out}")
    return 0


def cmd_recheck(settings, args) -> int:
    """show that a Tai-e crash is caused by the invalid N2 entries (no LLM calls)."""
    from .pipeline import PipelineError, SubjectContext, recheck_crash
    configs = args.configs.split(",")
    runs = args.runs or int(settings.raw.get("runs", 3))
    rc = 0
    for s in _subjects(settings, args.subject, True):
        for v in _versions(args.version):
            ctx = SubjectContext(settings, s, v)
            for c in configs:
                for k in range(runs):
                    rec_file = settings.results_dir / "runs" / s.id / v / c / f"run{k}.json"
                    if not rec_file.exists():
                        continue
                    if json.loads(rec_file.read_text())["taie"]["ok"] and not args.all_runs:
                        continue
                    try:
                        r = recheck_crash(ctx, c, k)
                    except PipelineError as e:
                        print(f"   {s.id}/{v} {c} run{k}: {e}")
                        rc = 1
                        continue
                    orig = "ok" if r["original_ok"] else "CRASH " + r["original_error"].splitlines()[1:2][0][:110] \
                        if len(r["original_error"].splitlines()) > 1 else "CRASH"
                    print(f"== {s.id}/{v} {c} run{k} (driver={r['driver']})")
                    print(f"   stored config         : {orig}; flows={r['original_flows']}")
                    if r["invalid_entries"]:
                        print(f"   without {r['removed']} invalid entr{'y' if r['removed'] == 1 else 'ies'}: "
                              f"{'ok' if r['cleaned_ok'] else 'CRASH'}; flows={r['cleaned_flows']}")
                        for msg in r["invalid_entries"]:
                            print(f"      removed: {msg[:150]}")
                        if not r["original_ok"] and r["cleaned_ok"]:
                            print("   => the crash is caused by these entries (what V2 rejects)")
                        elif not r["cleaned_ok"]:
                            print("   => still crashes without them: NOT explained by V2; see "
                                  f"{ctx.root}/recheck/{c}/run{k}/taie-without-invalid/console.log")
                            rc = 1
                    elif not r["original_ok"]:
                        print("   => crash with no invalid entries: NOT a V2 effect; see "
                              f"{ctx.root}/recheck/{c}/run{k}/taie-original/console.log")
                        rc = 1
    return rc


def _flow_report(recs: List[dict], ctx, flow_id: str, config: str = "", max_methods: int = 6,
                 max_lines: int = 60, cache: dict = None) -> str:
    """Show one recorded flow's exact endpoints, graph evidence, snippets and N3 verdict.

    Canonical flow ids collapse driver call sites; evidence must still use the
    same raw representative as the selected run record.
    """
    from .taie import TaintFlow, TaintFlowGraph
    from .triage import build_evidence
    cache = {} if cache is None else cache
    hits = [(r, f) for r in recs for f in r["flows"]
            if flow_id in (f["id"], f["key"]) and (not config or r["config"] == config)]
    if not hits:
        raise KeyError(f"flow {flow_id!r} not found in the run records")
    hits.sort(key=lambda x: (not x[1]["reported"], x[0]["config"] != "v3", x[0]["config"], x[0]["run"]))
    rec, fl = hits[0]
    out_dir = Path(rec["taie"]["out_dir"])
    if out_dir not in cache:
        d = json.loads((out_dir / "result.json").read_text())
        cache[out_dir] = ({(f.source.raw, f.sink.raw): f
                           for f in (TaintFlow.from_json(x) for x in d["flows"])},
                          TaintFlowGraph.load(out_dir / "taint-flow-graph.dot"))
    flows, tfg = cache[out_dir]
    representative = flows.get((fl["source"], fl["sink"]))
    if representative is None:
        raise ValueError(f"exact source/sink representative for {fl['id']} is absent from {out_dir}/result.json")
    ev = build_evidence(representative, tfg, ctx.facts, max_methods=max_methods, max_lines=max_lines)
    reported_in = sorted({f"{r['config']} run{r['run']}" for r, f in hits if f["reported"]})
    lines = [f"# {ctx.subject.id}/{ctx.version} ({rec.get('cve', '')}, {rec.get('cwe', '')}) flow {fl['id']}",
             f"key        : {fl['key']}", f"source     : {fl['source']}", f"sink       : {fl['sink']}",
             f"fixed methods on this flow (GT): {', '.join(fl['gt']) or '-'}",
             f"reported by: {', '.join(reported_in) or '(not reported: removed by triage everywhere)'}"]
    t = fl.get("triage") or {}
    if t:
        lines.append(f"N3 ({rec['config']} run{rec['run']}): {t.get('verdict')} / {t.get('reason')} "
                     f"(kept={t.get('kept')}, v3_ok={t.get('v3_ok')})")
        if t.get("explanation"):
            lines.append(f"   {t['explanation'][:600]}")
    lines += ["", "## Route (taint flow graph)", ev.path_text, "",
              "## Application-code evidence (route or reachable-method fallback)", ev.snippets_text]
    return "\n".join(lines)


def cmd_show_flow(settings, args) -> int:
    """everything needed to label one row of a label sheet (no LLM calls)."""
    from .metrics import load_runs
    from .pipeline import SubjectContext
    s = _subjects(settings, args.subject, True)[0]
    recs = [r for r in load_runs(settings.results_dir) if r["subject"] == s.id and r["version"] == args.version]
    try:
        text = _flow_report(recs, SubjectContext(settings, s, args.version), args.flow, args.config,
                            args.max_methods, args.max_lines)
    except (KeyError, OSError, ValueError) as e:
        print(f"cannot show flow {args.flow!r} for {s.id}/{args.version}: {e}")
        return 1
    print(text)
    return 0


def cmd_label_pack(settings, args) -> int:
    """Write evidence packs for selected priority rows without changing the saved labels."""
    import csv
    from .metrics import label_path, load_runs
    from .pipeline import SubjectContext
    runs = load_runs(settings.results_dir)
    total_open = 0
    for s in _subjects(settings, args.subject, True):
        for v in ("buggy", "fixed"):
            sheet = label_path(s.id, v)
            if not sheet.exists():
                continue
            rows = [r for r in csv.DictReader(open(sheet)) if r.get("priority")
                    and (args.all or not (r.get("label") or "").strip())]
            if not rows:
                print(f"{s.id}/{v}: nothing open")
                continue
            recs = [r for r in runs if r["subject"] == s.id and r["version"] == v]
            ctx = SubjectContext(settings, s, v)
            cache: dict = {}
            parts = [f"# Labelling pack: {s.id} / {v}", "",
                     f"{len(rows)} sampled rows selected for review from "
                     f"`{sheet.relative_to(REPO_ROOT) if sheet.is_relative_to(REPO_ROOT) else sheet}` "
                     "(identified by `flow_id`). This command updates evidence packs only; saved labels remain unchanged. "
                     "The study's existing labels are provisional LLM judgments without human verification. "
                     "Evidence uses the exact raw source and sink in the chosen run record, but a canonical key "
                     "may group different drivers or routes; check the attacker model before reusing a label.", "",
                     "The archived study sample is frozen in `labels/sampling_manifest.json`; preserve its rows and probabilities. "
                     "Original evidence packets are retained in `results/history/pre-evidence-refresh.tar.gz`. "
                     "Review criteria: `docs/labelling-guide.md`.", ""]
            for k, r in enumerate(rows, 1):
                parts.append(f"---\n\n## {k}/{len(rows)} flow_id {r['flow_id']} (priority {r['priority']})\n")
                try:
                    parts.append("```text\n" + _flow_report(recs, ctx, r["flow_id"], cache=cache,
                                                             max_methods=args.max_methods,
                                                             max_lines=args.max_lines) + "\n```\n")
                except (KeyError, OSError, ValueError) as e:
                    parts.append(f"(evidence not available: {e})\n")
            out = sheet.parent / "review" / f"{s.id}-{v}.md"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("\n".join(parts))
            total_open += len(rows)
            print(f"{s.id}/{v}: {len(rows)} rows -> {out}")
    print(f"{total_open} rows in the evidence packs")
    return 0


def cmd_check_manual(settings, args) -> int:
    """Form-only check of the B2 manual specs (does not judge which APIs were chosen)."""
    from .pipeline import SubjectContext
    from .spec import check_manual_spec, manual_config_file
    bad = 0
    for s in _subjects(settings, args.subject, True):
        mf = manual_config_file(s.id)
        if mf is None:
            print(f"== {s.id}: no config/taint/manual/{s.id}.yml")
            continue
        try:
            ctx = SubjectContext(settings, s, args.version)
        except FileNotFoundError as e:
            print(f"== {s.id}: cannot check ({e})")
            bad += 1
            continue
        n, problems = check_manual_spec(mf, ctx.facts)
        status = "OK" if not problems else f"{len(problems)} problem(s)"
        print(f"== {s.id}: {n} entries, {status}")
        for msg in problems:
            print(f"   - {msg}")
        bad += bool(problems)
    return 1 if bad else 0


def cmd_export(settings, args) -> int:
    from .export import export_artifacts
    if args.mock:
        settings.raw["results_dir"] = str(Path(settings.raw.get("results_dir", "results")) / "mock")
    out = export_artifacts(settings)
    print(f"exported stage artefacts to {out} (see MANIFEST.json)")
    return 0


def cmd_demo(settings, args) -> int:
    """Build the bundled fixture with javac and run B1, v1 and v3 on it."""
    from .pipeline import SubjectContext, run_config
    from .subjects import BuildLayout
    fx = REPO_ROOT / "tests" / "fixtures" / "minizip"
    build_fixture(settings, fx)
    from .config import Subject
    subj = Subject(id="minizip-demo", slug="minizip-demo", role="demo", cve="DEMO", cwe="CWE-022",
                   repo="tests/fixtures/minizip", buggy_commit="-", fixed_commit="-")
    layout = BuildLayout(str(fx), [str(fx / "build" / "app")], [str(fx / "build" / "acme-util.jar")],
                         [str(fx / "app" / "src")], True)
    settings.raw["work_dir"] = str(Path(settings.raw.get("work_dir", "work")) / "demo")
    settings.raw["results_dir"] = str(Path(settings.raw.get("work_dir")) / "results")
    ctx = SubjectContext(settings, subj, "buggy", layout)
    factory = make_llm_factory(settings, not args.live)
    for c in (args.configs.split(",") if args.configs else ["B1", "v1", "v2", "v3"]):
        rec = run_config(ctx, c, 0, factory, force=args.force)
        print(f"{c:4s} reported={rec['counts']['reported']} raw={rec['counts']['raw']} "
              f"removed_by_triage={rec['counts']['removed_by_triage']} driver={rec['driver']['kind']} "
              f"spec={(rec.get('spec') or {}).get('accepted_by_role')}")
        for f in rec["flows"]:
            mark = "REPORTED" if f["reported"] else "removed "
            print(f"     {mark} {f['sink_method']} L{f['sink_line']} {f['key'].split(' => ')[1].split('/')[-1]}"
                  + (f"  triage={f['triage']['verdict']}" if f.get("triage") else ""))
    return 0


def build_fixture(settings: Settings, fx: Path) -> None:
    j17 = settings.java17_home()
    javac = str(Path(j17) / "bin" / "javac") if j17 else "javac"
    jar = str(Path(j17) / "bin" / "jar") if j17 else "jar"
    env = dict(os.environ)
    env.pop("JAVA_TOOL_OPTIONS", None)
    b = fx / "build"
    (b / "lib").mkdir(parents=True, exist_ok=True)
    (b / "app").mkdir(parents=True, exist_ok=True)
    lib_src = sorted(str(p) for p in (fx / "lib" / "src").rglob("*.java"))
    app_src = sorted(str(p) for p in (fx / "app" / "src").rglob("*.java"))
    subprocess.run([javac, "--release", "8", "-g", "-nowarn", "-d", str(b / "lib"), *lib_src], check=True, env=env,
                   capture_output=True)
    subprocess.run([jar, "cf", str(b / "acme-util.jar"), "-C", str(b / "lib"), "."], check=True, env=env)
    subprocess.run([javac, "--release", "8", "-g", "-nowarn", "-cp", str(b / "acme-util.jar"), "-d", str(b / "app"),
                    *app_src], check=True, env=env, capture_output=True)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="nesy", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--experiment", default="config/experiment.yaml")
    p.add_argument("--subjects", default="config/subjects.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("check-env"); a.add_argument("--llm", action="store_true")
    for name in ("fetch", "build"):
        a = sub.add_parser(name)
        a.add_argument("subject"); a.add_argument("--version", default="both", choices=["buggy", "fixed", "both"])
        a.add_argument("--include-reserve", action="store_true")
    a = sub.add_parser("facts"); a.add_argument("subject"); a.add_argument("--version", default="buggy")
    a = sub.add_parser("run")
    a.add_argument("subject"); a.add_argument("--version", default="both", choices=["buggy", "fixed", "both"])
    a.add_argument("--configs", default=""); a.add_argument("--runs", type=int, default=0)
    a.add_argument("--mock", action="store_true"); a.add_argument("--force", action="store_true")
    a.add_argument("--include-reserve", action="store_true")
    a = sub.add_parser("rescore"); a.add_argument("--dry-run", action="store_true"); a.add_argument("--mock", action="store_true")
    a = sub.add_parser("label-sheet"); a.add_argument("subject")
    a.add_argument("--per-config", type=int, default=10,
                   help="flows sampled per main configuration and stratum (GT / other) for labelling")
    a = sub.add_parser("evaluate"); a.add_argument("--mock", action="store_true")
    a = sub.add_parser("export"); a.add_argument("--mock", action="store_true")
    a = sub.add_parser("candidates"); a.add_argument("subject"); a.add_argument("--version", default="buggy")
    a = sub.add_parser("check-manual"); a.add_argument("subject"); a.add_argument("--version", default="buggy")
    a = sub.add_parser("show-flow"); a.add_argument("subject")
    a.add_argument("version", choices=["buggy", "fixed"]); a.add_argument("flow", help="flow_id or flow_key")
    a.add_argument("--config", default=""); a.add_argument("--max-methods", type=int, default=6)
    a.add_argument("--max-lines", type=int, default=60)
    a = sub.add_parser("label-pack"); a.add_argument("subject")
    a.add_argument("--all", action="store_true", help="include rows that already have a label")
    a.add_argument("--max-methods", type=int, default=6); a.add_argument("--max-lines", type=int, default=60)
    a = sub.add_parser("recheck"); a.add_argument("subject")
    a.add_argument("--version", default="both", choices=["buggy", "fixed", "both"])
    a.add_argument("--configs", default="v3-noval,v3-noV2"); a.add_argument("--runs", type=int, default=0)
    a.add_argument("--all-runs", action="store_true", help="also re-check runs that did not crash")
    a = sub.add_parser("demo"); a.add_argument("--live", action="store_true"); a.add_argument("--force", action="store_true")
    a.add_argument("--configs", default="")

    args = p.parse_args(argv)
    os.chdir(REPO_ROOT)
    settings = load_settings(args.experiment, args.subjects)
    handler = {"check-env": cmd_check_env, "fetch": cmd_fetch, "build": cmd_build, "facts": cmd_facts,
               "run": cmd_run, "label-sheet": cmd_label_sheet, "evaluate": cmd_evaluate, "export": cmd_export,
               "candidates": cmd_candidates, "check-manual": cmd_check_manual, "recheck": cmd_recheck,
               "show-flow": cmd_show_flow, "label-pack": cmd_label_pack, "rescore": cmd_rescore,
               "demo": cmd_demo}[args.cmd]
    return handler(settings, args)


if __name__ == "__main__":
    sys.exit(main())
