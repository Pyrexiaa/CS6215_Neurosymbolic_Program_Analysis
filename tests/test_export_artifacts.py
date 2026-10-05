"""Public artifacts must retain the actual driver and failure evidence for each run."""
import gzip
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from nesy.export import export_artifacts


def _write(path, contents):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)


def test_export_keeps_both_driver_variants_and_fallback_provenance(tmp_path):
    settings = SimpleNamespace(work_dir=tmp_path / "work", results_dir=tmp_path / "results")
    run_root = settings.work_dir / "runs" / "subject" / "fixed"
    expected = {
        "template-driver/driver.json": '{"kind": "template"}',
        "template-driver/src/nesy/NesyDriver.java": "class TemplateDriver {}",
        "template-driver/src/nesy/Taint.java": "class Taint {}",
        "template-driver/cache-identity.json": '{"identity": "template"}',
        "run2/spec-llm/cache-identity.json": '{"identity": "spec"}',
    }
    for variant in ("llm-driver", "llm-driver-entrycheck"):
        prefix = f"run2/{variant}"
        expected.update({
            f"{prefix}/driver.json": json.dumps({"variant": variant}),
            f"{prefix}/usage.json": '{"calls": 1}',
            f"{prefix}/src/nesy/NesyDriver.java": f"// {variant}\nclass NesyDriver {{}}",
            f"{prefix}/src/nesy/Taint.java": "class Taint {}",
            f"{prefix}/cache-identity.json": json.dumps({"identity": variant}),
        })
    expected.update({
        "run2/llm-driver-entrycheck/fallback/driver.json": '{"kind": "fallback"}',
        "run2/llm-driver-entrycheck/fallback/src/nesy/NesyDriver.java": "class FallbackDriver {}",
        "run2/llm-driver-entrycheck/fallback/src/nesy/Taint.java": "class Taint {}",
    })
    for relative, content in expected.items():
        _write(run_root / relative, content)
    # Build products are unnecessary for inspecting/recompiling the published sources.
    _write(run_root / "run2/llm-driver-entrycheck/classes/nesy/NesyDriver.class", "binary")

    destination = export_artifacts(settings)

    for relative, content in expected.items():
        assert (destination / "subject/fixed" / relative).read_text() == content
    manifest = json.loads((destination / "MANIFEST.json").read_text())
    assert {row["exported"] for row in manifest} == {f"subject/fixed/{p}" for p in expected}
    assert all(row["bytes"] > 0 for row in manifest)


def test_export_preserves_failed_taie_console_and_compresses_large_log(tmp_path):
    settings = SimpleNamespace(work_dir=tmp_path / "work", results_dir=tmp_path / "results")
    source = settings.work_dir / "runs/subject/fixed/taie"
    logs = {"small-failure": "IllegalArgumentException: invalid taint index\n",
            "large-failure": "Stack trace evidence\n" * 60_000}
    for key, log in logs.items():
        _write(source / key / "result.json", '{"returncode": 1}')
        _write(source / key / "console.log", log)

    destination = export_artifacts(settings)

    assert (destination / "subject/fixed/taie/small-failure/console.log").read_text() == logs["small-failure"]
    with gzip.open(destination / "subject/fixed/taie/large-failure/console.log.gz", "rt") as stream:
        assert stream.read() == logs["large-failure"]
    exported = {row["exported"] for row in json.loads((destination / "MANIFEST.json").read_text())}
    assert "subject/fixed/taie/small-failure/console.log" in exported
    assert "subject/fixed/taie/large-failure/console.log.gz" in exported


def test_historical_sampling_audit_rejects_refreshed_frame_before_writing(tmp_path):
    repo = tmp_path / "refreshed-repo"
    _write(repo / "labels/sampling_manifest.json", "{}")
    output = tmp_path / "audit-output"
    script = Path(__file__).resolve().parents[1] / "scripts/audit_label_sampling.py"

    result = subprocess.run([sys.executable, str(script), "--repo", str(repo),
                             "--output-dir", str(output)], capture_output=True, text=True)

    assert result.returncode == 2
    assert "python -m nesy evaluate" in result.stderr
    assert "pre-validator-refresh.tar.gz" in result.stderr
    assert not output.exists()
