#!/usr/bin/env python3
"""Single-LLM-judge adjudication of the frozen flow sample (one consistent protocol).

Implements the one-judge policy: a fresh-context LLM judge applies a fixed four-question rubric
(prompts/judge.md) to each sampled flow and returns TP / FP / UNSURE with a reason. Runtime CVE
witnesses (scripts/run_witnesses.py) supply executable evidence about the CVE sinks. The prompt
also includes the saved source/sink records and notes; those notes may contain earlier judgments,
so this pass is not independent of the original labels. Sink matching does not execute or validate
every reported static route.

Decisions are written to a SEPARATE namespace, results/adjudication/decisions.jsonl, and never to
the human_label / my_label columns. The original labels/*.csv are left untouched.

  python scripts/adjudicate.py --dry-run         # no endpoint: witness-anchored decisions only
  python scripts/adjudicate.py                   # live: SoCLaaS judge for the rest (needs .env + NUS net)
  python scripts/adjudicate.py --limit 20        # judge the first 20 rows (smoke test)

The sample is the frozen set in labels/*.csv (rows with a priority). SoCLaaS is only reachable on
the NUS network/VPN; use --dry-run elsewhere.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from nesy.config import load_settings  # noqa: E402

# witnessed sink predicates, shared with scripts/score_witnesses.py
WITNESS = json.loads((ROOT / "witness" / "witnesses.json").read_text())
SINK_HINT = {w["subject"]: w for w in WITNESS["witnesses"]}


def _callee(s: str) -> str:
    i = s.find("invoke")
    return s[i:] if i >= 0 else s


def _arg(flow_key: str) -> str:
    m = re.search(r"/([0-9]+(?:\[\*\])?)$", flow_key)
    return m.group(1) if m else ""


def witnessed_sink(subject: str, sink: str, key: str) -> bool:
    c, a = _callee(sink), _arg(key)
    if subject == "zt-zip":
        return a == "1" and bool(re.search(r"ZipUtil\$(Unpacker|Unwraper): void process", sink))
    if subject == "cron-utils":
        return "buildConstraintViolationWithTemplate" in sink or "CronValidator: boolean isValid" in sink
    if subject == "spark":
        return "getResourceAsStream" in sink or "ResourceUtils" in sink or "loadStream" in sink
    if subject == "perfecto-plugin":
        return ".exec(" in c or "cmdArgs" in c
    return False


def load_witness_results() -> dict:
    p = ROOT / "results" / "witness" / "witness-results.json"
    if not p.exists():
        return {}
    out = {}
    for r in json.loads(p.read_text()).get("results", []):
        if r.get("version") == "buggy":
            out[r["subject"]] = r
    return out


def sample_rows() -> list[dict]:
    rows = []
    for csv_path in sorted((ROOT / "labels").glob("*-*.csv")):
        m = re.match(r"(.+)-(buggy|fixed)\.csv$", csv_path.name)
        if not m:
            continue
        subject, version = m.group(1), m.group(2)
        for r in csv.DictReader(open(csv_path)):
            if (r.get("priority") or "").strip() in ("1", "2"):
                r["_subject"], r["_version"] = subject, version
                rows.append(r)
    return rows


def judge_prompt(row: dict, witness_line: str) -> list[dict]:
    rubric = (ROOT / "prompts" / "judge.md").read_text()
    body = [
        f"CWE / subject: {row['_subject']} ({row['_version']} version)",
        f"Ground-truth methods changed by the fix: {row.get('gt_methods', '')}",
        f"SOURCE: {row.get('source', '')}",
        f"SINK:   {row.get('sink', '')}",
    ]
    if row.get("notes"):
        body.append(f"(route note from evidence: {row['notes'][:300]})")
    if witness_line:
        body.append(f"RUNTIME WITNESS: {witness_line}")
    return [{"role": "system", "content": rubric},
            {"role": "user", "content": "\n".join(body)}]


def parse_decision(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {"decision": "UNSURE", "category": "none", "reason": "unparseable judge output"}
    try:
        d = json.loads(m.group(0))
        if d.get("decision") in ("TP", "FP", "UNSURE"):
            return d
    except Exception:  # noqa: BLE001
        pass
    return {"decision": "UNSURE", "category": "none", "reason": "unparseable judge output"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="no endpoint; decide only witness-anchored flows, rest UNSURE")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    settings = load_settings()
    rows = sample_rows()
    if args.limit:
        rows = rows[:args.limit]
    witnesses = load_witness_results()

    llm = None
    if not args.dry_run:
        from nesy.llm import client_from_env
        cache = settings.work_dir / "llm-cache" / "judge"
        llm = client_from_env(settings.env, cache_dir=cache, ledger=settings.work_dir / "llm-ledger.jsonl",
                              model=None)
        llm.context = {"stage": "judge"}

    out_dir = ROOT / "results" / "adjudication"
    out_dir.mkdir(parents=True, exist_ok=True)
    decisions, counts = [], {"TP": 0, "FP": 0, "UNSURE": 0}
    model_id = "witness-anchored(dry-run)" if args.dry_run else getattr(llm, "model", "soclaas")

    for i, row in enumerate(rows):
        subject, version = row["_subject"], row["_version"]
        is_wsink = witnessed_sink(subject, row.get("sink", ""), row.get("flow_key", ""))
        gt = bool((row.get("gt_methods") or "").strip())
        wline = ""
        if is_wsink and version == "buggy" and witnesses.get(subject, {}).get("witnessed"):
            w = witnesses[subject]
            wline = (f"the sink {SINK_HINT[subject]['sink_site']} is machine-checked exploitable on the "
                     f"buggy version ({w.get('evidence', '')[:140]})")

        if args.dry_run:
            # Apply the witness-anchored sink/patch matching rule. This does not execute
            # each static route. Spark is left to the live judge because its sampled routes
            # need separate review even though the handler-level sink is witnessed.
            auto_tp = is_wsink and gt and version == "buggy" and wline and subject != "spark"
            if auto_tp:
                dec = {"decision": "TP", "category": "none",
                       "reason": "reaches the machine-checked witnessed sink/argument along a patch-relevant route"}
            else:
                dec = {"decision": "UNSURE", "category": "none",
                       "reason": "needs the LLM judge (run without --dry-run)"
                               + ("; sink is witnessed but per-flow route needs checking" if is_wsink else "")}
        else:
            resp = llm.chat(judge_prompt(row, wline), stage="judge", temperature=0.0, max_tokens=512)
            dec = parse_decision(resp.text)

        counts[dec["decision"]] = counts.get(dec["decision"], 0) + 1
        decisions.append({
            "case_id": f"{subject}-{version}-{row.get('flow_id', i)}",
            "subject": subject, "version": version,
            "flow_key": row.get("flow_key", ""),
            "raw_source": row.get("source", ""), "raw_sink": row.get("sink", ""),
            "gt_relevant": gt, "witnessed_sink": is_wsink,
            "decision": dec["decision"], "category": dec.get("category", "none"),
            "reason": dec.get("reason", ""),
            "model_and_prompt_id": f"{model_id}+judge.md",
        })

    (out_dir / "decisions.jsonl").write_text("".join(json.dumps(d) + "\n" for d in decisions))
    meta = {"n": len(decisions), "counts": counts, "model": model_id, "dry_run": args.dry_run,
            "note": "Single-LLM-judge decisions. Not human labels. UNSURE and FP/TP are separate from "
                    "labels/*.csv; metrics may treat UNSURE as unknown (not FP)."}
    (out_dir / "summary.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"[adjudicate] {len(decisions)} flows -> {counts}  (model={model_id})")
    print(f"[adjudicate] wrote {out_dir / 'decisions.jsonl'}")
    if args.dry_run:
        print("[adjudicate] dry-run: only witness-anchored TPs decided; run without --dry-run on the NUS "
              "network to judge the rest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
