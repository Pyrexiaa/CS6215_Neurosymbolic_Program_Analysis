"""Copy the small, inspectable stage artefacts from work/ into results/artifacts/ for the public repo.

The brief asks the repository to contain "the files used to produce the reported results" and,
when manageable, both original and processed data. Large graphs, results, and console logs
are compressed; the exported audit trail includes:
  drivers (template + N1), inferred specs (N2) with votes/rejections, assembled Tai-e configs,
  triage decisions (N3/V3), taint flow graphs, Tai-e options and console logs, S1 fact summaries.
"""
from __future__ import annotations

import gzip
import json
import shutil
from pathlib import Path
from typing import List

from .config import Settings

PATTERNS = [
    "facts.json",
    "template-driver/driver.json", "template-driver/src/nesy/*.java", "template-driver/cache-identity.json",
    "run*/llm-driver*/driver.json", "run*/llm-driver*/usage.json", "run*/llm-driver*/src/nesy/*.java",
    "run*/llm-driver*/cache-identity.json",
    "run*/llm-driver*/fallback/driver.json", "run*/llm-driver*/fallback/src/nesy/*.java",
    "run*/spec-llm*/inferred.yml", "run*/spec-llm*/spec.json", "run*/spec-llm*/usage.json",
    "run*/spec-llm*/cache-identity.json",
    "configs/*/run*/triage.json",
    "taie/*/options.yml", "taie/*/result.json", "taie/*/taint-flow-graph.dot", "taie/*/console.log",
]


def export_artifacts(settings: Settings, max_mb_per_file: float = 20.0) -> Path:
    src_root = settings.work_dir / "runs"
    dst_root = settings.results_dir / "artifacts"
    copied: List[dict] = []
    for subj_ver in sorted(p for p in src_root.glob("*/*") if p.is_dir()):
        rel_sv = subj_ver.relative_to(src_root)
        for pat in PATTERNS:
            for f in sorted(subj_ver.glob(pat)):
                if not f.is_file():
                    continue
                dst = dst_root / rel_sv / f.relative_to(subj_ver)
                dst.parent.mkdir(parents=True, exist_ok=True)
                size_mb = f.stat().st_size / 1e6
                if f.suffix in (".dot", ".json", ".log") and size_mb > 1:
                    dst = dst.with_suffix(dst.suffix + ".gz")       # compress big graphs / results / logs
                    with open(f, "rb") as fi, open(dst, "wb") as raw:
                        # Do not record the export time or input filename in gzip metadata.
                        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as fo:
                            shutil.copyfileobj(fi, fo)
                elif size_mb <= max_mb_per_file:
                    shutil.copy2(f, dst)
                else:
                    continue
                copied.append({"source": str(f.relative_to(settings.work_dir)), "exported": str(dst.relative_to(dst_root)),
                               "bytes": dst.stat().st_size})
        # assembled taint configs: keep one copy per configuration and run (small YAML files)
        for cdir in sorted(subj_ver.glob("configs/*/run*/taint-config")):
            dst = dst_root / rel_sv / cdir.relative_to(subj_ver)
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(cdir, dst)
            copied.append({"source": str(cdir.relative_to(settings.work_dir)), "exported": str(dst.relative_to(dst_root)),
                           "bytes": sum(p.stat().st_size for p in dst.rglob("*") if p.is_file())})
    dst_root.mkdir(parents=True, exist_ok=True)
    (dst_root / "MANIFEST.json").write_text(json.dumps(copied, indent=1))
    return dst_root
