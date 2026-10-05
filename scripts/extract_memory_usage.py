#!/usr/bin/env python3
"""Extract Tai-e's sampled memory fields from archived logs, without rerunning analysis.

Each current run record selects its log through taie.out_dir's cache-directory name.
The terminal [Tai-e] line, not an individual phase's line, supplies the measurement.
The logger's peak field is sampled: it can be lower than its start/end observations.
This is neither process RSS nor a guaranteed maximum of JVM memory use.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


MEMORY = re.compile(
    r"^\[Tai-e\].*?Memory usage: start ([0-9.]+)MB, "
    r"peak ([0-9.]+)MB, end ([0-9.]+)MB[^\r\n]*$", re.MULTILINE)
FIELDS = ("subject", "version", "config", "run", "taie_ok", "run_record",
          "source_log", "status", "start_mb", "sampled_peak_mb", "end_mb",
          "end_exceeds_sampled_peak", "memory_line_sha256")


def extract(repo: Path) -> tuple[list[dict], dict]:
    rows = []
    for path in sorted((repo / "results" / "runs").rglob("run*.json")):
        record = json.loads(path.read_text())
        cache_dir = Path(record["taie"]["out_dir"]).name
        folder = (repo / "results" / "artifacts" / record["subject"] /
                  record["version"] / "taie" / cache_dir)
        logs = [p for p in (folder / "console.log", folder / "console.log.gz") if p.is_file()]
        row = {name: record[name] for name in ("subject", "version", "config", "run")}
        row.update(taie_ok=record["taie"]["ok"], run_record=str(path.relative_to(repo)),
                   source_log="", status="missing-log", start_mb="", sampled_peak_mb="",
                   end_mb="", end_exceeds_sampled_peak="", memory_line_sha256="")
        candidates = []
        for log in logs:
            if log.suffix == ".gz":
                with gzip.open(log, "rt", errors="replace") as handle:
                    text = handle.read()
            else:
                text = log.read_text(errors="replace")
            matches = list(MEMORY.finditer(text))
            if len(matches) > 1:
                raise ValueError(f"Multiple terminal Tai-e memory lines: {log}")
            candidates.append((log, matches[0] if matches else None))
        if len(candidates) > 1:
            values = {match.groups() if match else None for _, match in candidates}
            if len(values) > 1:
                raise ValueError(f"Conflicting plain and compressed logs: {folder}")
        if candidates:
            log, match = candidates[0]
            row.update(source_log=str(log.relative_to(repo)), status="no-terminal-memory-line")
            if match:
                start, peak, end = (float(value) for value in match.groups())
                row.update(status="observed", start_mb=start, sampled_peak_mb=peak,
                           end_mb=end, end_exceeds_sampled_peak=end > peak,
                           memory_line_sha256=hashlib.sha256(match.group(0).encode()).hexdigest())
        rows.append(row)

    def summarize(selected: list[dict]) -> dict:
        observed = [row for row in selected if row["status"] == "observed"]
        peaks = [row["sampled_peak_mb"] for row in observed]
        return {
            "records": len(selected), "observed_records": len(observed),
            "successful_records": sum(row["taie_ok"] for row in selected),
            "distinct_observed_logs": len({row["source_log"] for row in observed}),
            "statuses": dict(sorted(Counter(row["status"] for row in selected).items())),
            "sampled_peak_mb_min": min(peaks) if peaks else None,
            "sampled_peak_mb_max": max(peaks) if peaks else None,
            "end_exceeds_sampled_peak_records": sum(row["end_exceeds_sampled_peak"] for row in observed),
        }

    provenance = {
        "schema": "nesy-archived-jvm-memory-v1",
        "generator": "scripts/extract_memory_usage.py",
        "source": "Current results/runs records mapped to results/artifacts console.log or console.log.gz by subject, version and taie.out_dir cache-directory name.",
        "measurement": "start, peak and end memory fields from the terminal [Tai-e] logger line; units retained as printed (MB).",
        "sampling_caveat": "The logger's peak is a sampled field, not a strict maximum: start or end can exceed it. These values are not OS process RSS or a bound on actual maximum memory.",
        "reuse_caveat": "Several configurations reuse the same Tai-e analysis log; record counts are not independent execution counts.",
        "missing_policy": "Missing logs or terminal memory lines remain missing, never zero; failed runs may lack the terminal line.",
        "hash_scope": "CSV hashes cover only the exact terminal memory line, not compressed-file metadata or unrelated dated log lines.",
        "scope": "All current run records; excludes the separately reported controlled-pair extension.",
        "overall": summarize(rows),
        "by_config": {config: summarize([row for row in rows if row["config"] == config])
                      for config in sorted({row["config"] for row in rows})},
    }
    return rows, provenance


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    repo = args.repo.resolve()
    rows, provenance = extract(repo)
    csv_path = repo / "results" / "summary" / "memory_usage.csv"
    json_path = repo / "results" / "provenance" / "memory-usage.json"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    json_path.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    print(json.dumps(provenance["overall"], sort_keys=True))


if __name__ == "__main__":
    main()
