---
name: reproduce-study
description: Reproduce the CS6215 Tai-e and neuro-symbolic taint-analysis study, including setup, baseline runs, evaluation and runtime witnesses.
---

# Reproduce the study

Use the repository root and the scope requested. Report failures without inventing results or labels. See `README.md` for dependencies and `docs/evaluation.md` for metric definitions.

## Offline summary and paper regeneration

With the supplied run records, labels and sampling manifest:

```bash
python -m nesy evaluate
python scripts/make_report_assets.py
(cd report && latexmk -pdf main_revised2.tex)
```

This does not require the endpoint, subject builds or a new Tai-e run. It preserves the distinction between provisional labels and runtime checks.

## Full experiment reproduction

1. Create and activate the environment from `environment.yml`, or let `scripts/setup_tools.sh` create `.venv`. Run setup, then `python -m nesy check-env --llm`. JDK 17 runs Tai-e; a full JDK 8 builds subjects and supplies `rt.jar`. Live stages need the NUS network or VPN.
2. Run `python -m pytest -q` and `python -m nesy demo`. Mock demo results are only plumbing checks.
3. Run `python -m nesy fetch all` and `python -m nesy build all`. Inspect build logs for failures.
4. Validate B2 inputs with `python -m nesy check-manual all`, then run `python -m nesy run all --configs B1,B2`.
5. Run `python -m nesy run all --configs v1,v2,v3,v3-noval,v3-noV2,v3-noV3,v4,iris-like --runs 3` for the three repetitions on both versions. Compatible cached answers avoid requests only when all required answers are available.
6. Preserve supplied label CSVs and sampling membership. Use `label-sheet`, `show-flow` and `label-pack` only for the requested evidence workflow; missing labels must remain explicit.
7. Run `python -m nesy evaluate`, then `python -m nesy export`. Regenerate paper assets if requested. Report the summary, case analysis and any recorded analysis failures.

## Runtime checks

- `python scripts/run_witnesses.py` checks the four CVE effects on built buggy/fixed subjects. All four released witnesses reproduce the effect on the buggy version and block it on the fixed version.
- `python scripts/score_witnesses.py` matches saved flows to the witnessed sink families. It does not execute those static routes.
- `results/replay/` records the completed B1/B2 re-execution and its comparison with archived records.
- `python scripts/adjudicate.py` performs a separate LLM judgment pass. `--dry-run` avoids model calls and leaves non-witness cases unresolved. Neither mode updates the original labels automatically.

## Planned held-out evaluation

The released artifact has no held-out scores. Run `bash scripts/run_test.sh prepare` only when that evaluation is requested. Prepare and validate B2 specifications for every test subject before inspecting their results, then commit and tag the frozen inputs as `heldout-freeze`. `bash scripts/run_test.sh run` rejects changes to protected inputs and reports test results under `results/summary/test/`.

## Preservation rules

- Never print or commit `.env`.
- Never report `results/mock/` as experimental evidence.
- Record changes to prompts, configurations, subjects or dependencies as new experimental inputs.
- Preserve original records, failure logs, sample membership and label provenance.
- Fresh hosted responses can differ from the archive; do not promise exact replay from new requests.
