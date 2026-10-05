#!/usr/bin/env python3
"""Frozen-buggy-input Tai-e patch comparison; no LLM or triage calls.

python run_controlled_pair.py --repo /path/to/repo --out /path/outside/repo

Reuses each saved buggy v4 symbolic result, then runs the fixed bytecode with
an exact copied buggy driver and assembled taint configuration. Uses each
version's own built dependency classpath. This is NOT end-to-end v4, a new
detection metric, or a patch-only causal estimate when dependencies changed.
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import shutil
import sys
import time
from dataclasses import asdict
from pathlib import Path


def identity(path):
    path = Path(path)
    files = sorted(p for p in path.rglob('*') if p.is_file()) if path.is_dir() else [path]
    rows = [(str(p.relative_to(path)) if path.is_dir() else path.name,
             hashlib.sha256(p.read_bytes()).hexdigest()) for p in files]
    return {'sha256': hashlib.sha256(json.dumps(rows).encode()).hexdigest(), 'files': rows}


def manifest(paths):
    return [{'path': str(p), **identity(p)} for p in paths]


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, default=str) + '\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', required=True, type=Path)
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--subjects', default='cron-utils,perfecto-plugin,zt-zip,spark')
    ap.add_argument('--preflight-only', action='store_true')
    args = ap.parse_args()
    repo, out = args.repo.resolve(), args.out.resolve()
    if out == repo or repo in out.parents:
        raise SystemExit('Output must be outside the repository; original artifacts are read-only.')
    out.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(repo / 'src'))
    from nesy.config import load_settings
    from nesy.classfile import iter_classes
    from nesy.pipeline import SubjectContext, gt_tiers
    from nesy.subjects import load_layout
    from nesy.taie import TaintFlow, TaintFlowGraph, filter_flows, run_taie

    original = load_settings(env_file=out / 'no-secrets.env')
    settings = copy.deepcopy(original)
    settings.raw['work_dir'] = str(out / 'scratch')
    settings.raw['results_dir'] = str(out / 'unused-results')
    rows = []
    fresh_analyses = 0

    def write_tables():
        dump(out / 'controlled_pairs.json', rows)
        fields = ['subject','run','status','skip_reason','buggy_pretriage_alarms',
                  'fixed_pretriage_alarms','alarm_delta_fixed_minus_buggy',
                  'buggy_pretriage_gt','fixed_pretriage_gt','gt_delta_fixed_minus_buggy',
                  'gt_reduction','fixed_taie_s','dependencies_identical',
                  'driver_sha256','taint_config_sha256']
        with (out / 'controlled_pairs.csv').open('w',newline='') as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            w.writeheader();w.writerows(rows)

    for sid in args.subjects.split(','):
        subj = settings.subjects[sid]
        print(f'{sid}: preparing version contexts', flush=True)
        layouts = {v: load_layout(original, sid, v) for v in ('buggy','fixed')}
        contexts = {v: SubjectContext(settings,subj,v,layouts[v]) for v in layouts}
        input_manifest = {v: {'app': manifest(contexts[v].app_paths),
                              'libraries': manifest(contexts[v].lib_paths)} for v in contexts}
        deps_equal = ([x['sha256'] for x in input_manifest['buggy']['libraries']] ==
                      [x['sha256'] for x in input_manifest['fixed']['libraries']])
        for k in range(3):
            row = {'subject':sid,'run':k,'status':'preflight','skip_reason':'',
                   'dependencies_identical':deps_equal,
                   'comparison':'pre-triage Tai-e only, frozen buggy v4 driver/spec; version-specific dependency classpaths',
                   'new_llm_calls':0,'new_triage_calls':0}
            pair = out / 'pairs' / sid / f'run{k}'
            pair.mkdir(parents=True,exist_ok=True)
            record_path = original.results_dir/'runs'/sid/'buggy/v4'/f'run{k}.json'
            record = json.loads(record_path.read_text())
            source_root = original.work_dir/'runs'/sid/'buggy'
            meta = json.loads((source_root/f'run{k}/llm-driver-entrycheck/driver.json').read_text())
            driver_original = Path(meta['classes_dir'])
            config_original = source_root/'configs/v4'/f'run{k}/taint-config'
            buggy_result_path = Path(record['taie']['out_dir'])/'result.json'
            result = json.loads(buggy_result_path.read_text())
            frozen_driver = pair/'frozen/driver-classes'
            frozen_config = pair/'frozen/taint-config'
            if frozen_driver.exists() or frozen_config.exists():
                raise SystemExit(f'{pair}: existing frozen inputs; use a new output directory to avoid overwriting evidence.')
            shutil.copytree(driver_original,frozen_driver)
            shutil.copytree(config_original,frozen_config)
            before = {'driver':identity(driver_original),'taint_config':identity(config_original)}
            assert before['driver']==identity(frozen_driver)
            assert before['taint_config']==identity(frozen_config)
            row['driver_sha256']=before['driver']['sha256']
            row['taint_config_sha256']=before['taint_config']['sha256']
            row['driver_kind']=meta['kind']
            row['buggy_result_sha256']=hashlib.sha256(buggy_result_path.read_bytes()).hexdigest()
            row['buggy_result_origin']=str(buggy_result_path)
            row['record_origin']=str(record_path)

            # Verify exact owner/name/descriptor references from all generated driver classes,
            # including constructors; do not use declared-entry hints as compatibility proof.
            checks=[];missing=[]
            app_names=set(contexts['buggy'].facts.app_classes)
            for ci in iter_classes(frozen_driver,with_code=True):
                for method in ci.methods:
                    for call in method.calls:
                        if call.owner not in app_names:
                            continue
                        target_ci=contexts['fixed'].facts.index.get(call.owner)
                        # Constructors cannot be inherited.
                        target=(target_ci.find_method(call.name,call.descriptor) if target_ci else None) if call.name=='<init>' else contexts['fixed'].facts.index.resolve_method(call.owner,call.name,call.descriptor)
                        check={'caller':method.sig.taie,'line':call.line,
                               'target':call.sig.taie,
                               'resolved_fixed':target.sig.taie if target else None}
                        checks.append(check)
                        if target is None:
                            missing.append(check)
            row['driver_app_reference_count']=len(checks)
            row['unresolved_fixed_app_references']=missing
            row['taie_settings']=asdict(contexts['fixed'].taie)
            dump(pair/'input_manifest.json',{'frozen_inputs':before,'subject_inputs':input_manifest,
                                           'compatibility_checks':checks,'provenance':row})
            if missing:
                row['status']='skipped-incompatible-driver'
                row['skip_reason']='; '.join(x['target'] for x in missing)
                rows.append(row);write_tables()
                print(f'{sid}/run{k}: SKIP {row["skip_reason"]}',flush=True)
                continue
            if not result.get('ok'):
                row['status']='skipped-no-successful-buggy-symbolic-result'
                row['skip_reason']=result.get('error','buggy symbolic analysis failed')
                rows.append(row);write_tables();continue

            def counts(ctx,flows,graph_dir):
                filt=settings.section('flows')
                fs=filter_flows(flows,set(ctx.facts.app_classes),
                                bool(filt.get('drop_jdk_internal_sinks',True)),
                                bool(filt.get('app_sinks_only',False)),
                                bool(filt.get('drop_jdk_internal_sources',True)))
                graph=TaintFlowGraph.load(graph_dir/'taint-flow-graph.dot')
                scored=[{'id':f.short_id,'key':f.key,'source':f.source.raw,'sink':f.sink.raw,
                         'gt':gt_tiers(f,graph,ctx.fixed_methods)[0]} for f in fs]
                return {'raw_alarms':len(flows),'filtered_alarms':len(fs),
                        'gt_alarms':sum(bool(f['gt']) for f in scored),'flows':scored}
            buggy=counts(contexts['buggy'],[TaintFlow.from_json(x) for x in result['flows']],buggy_result_path.parent)
            dump(pair/'buggy_symbolic_counts.json',buggy)
            row['buggy_pretriage_alarms']=buggy['filtered_alarms']
            row['buggy_pretriage_gt']=buggy['gt_alarms']
            # Cached baseline counts should agree with the current stored pre-triage flow list.
            row['buggy_matches_saved_pretriage_count']=len(record['flows'])==buggy['filtered_alarms']
            if not row['buggy_matches_saved_pretriage_count']:
                row['status']='skipped-inconsistent-buggy-baseline'
                row['skip_reason']='Cached raw symbolic count differs from saved run pre-triage list.'
                rows.append(row);write_tables();continue
            if args.preflight_only:
                row['status']='preflight-compatible'
                rows.append(row);write_tables();continue
            if fresh_analyses>=12:
                raise SystemExit('Safety bound reached: at most 12 new fixed analyses.')
            fresh_analyses+=1
            print(f'{sid}/run{k}: fixed Tai-e, frozen inputs; buggy alarms={buggy["filtered_alarms"]}, gt={buggy["gt_alarms"]}',flush=True)
            fixed=run_taie(contexts['fixed'].taie,contexts['fixed'].app_paths+[frozen_driver],
                           contexts['fixed'].lib_paths,'nesy.NesyDriver',frozen_config,pair/'fixed-taie')
            row['fixed_taie_s']=fixed.elapsed_s
            row['fixed_ok']=fixed.ok
            row['fixed_error']=fixed.error
            row['fixed_timeout']=fixed.timed_out
            if fixed.ok:
                scored=counts(contexts['fixed'],fixed.flows,pair/'fixed-taie')
                dump(pair/'fixed_symbolic_counts.json',scored)
                row['status']='completed'
                row['fixed_pretriage_alarms']=scored['filtered_alarms']
                row['fixed_pretriage_gt']=scored['gt_alarms']
                row['alarm_delta_fixed_minus_buggy']=scored['filtered_alarms']-buggy['filtered_alarms']
                row['gt_delta_fixed_minus_buggy']=scored['gt_alarms']-buggy['gt_alarms']
                row['gt_reduction']=buggy['gt_alarms']>scored['gt_alarms']
            else:
                row['status']='fixed-analysis-failed'
                row['skip_reason']=fixed.error
            assert before['driver']==identity(frozen_driver)==identity(driver_original)
            assert before['taint_config']==identity(frozen_config)==identity(config_original)
            rows.append(row);write_tables()
            print(f'{sid}/run{k}: {row["status"]}, fixed alarms={row.get("fixed_pretriage_alarms")}, gt={row.get("fixed_pretriage_gt")}',flush=True)
        after={v:{'app':manifest(contexts[v].app_paths),'libraries':manifest(contexts[v].lib_paths)} for v in contexts}
        assert after==input_manifest,'Subject bytecode or dependency content changed during measurement.'
    dump(out/'study_manifest.json',{'started_inputs':str(repo),'completed_at':time.strftime('%Y-%m-%dT%H:%M:%S'),
        'fresh_fixed_analyses':fresh_analyses,'new_llm_calls':0,'new_triage_calls':0,
        'limitations':['Buggy comparator reuses saved pre-triage Tai-e output, not a new run.',
                       'Inputs are frozen from current buggy v4 artifacts; fixed layouts use their own dependency sets.',
                       'Ground-truth relevance means touching a fix-modified method, not exploitability or confirmed detection.',
                       'No N3 triage; results must not be presented as end-to-end v4.',
                       'Compatibility preflight checks direct driver-to-application method signatures, not all JVM linkage semantics.']})
    print('Done',out,flush=True)


if __name__=='__main__':
    main()
