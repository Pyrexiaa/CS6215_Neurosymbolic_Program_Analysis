# Repository guidance

Read `README.md` for supported commands and `docs/design.md` for the pipeline. The maintained report is `report/main_revised2.tex`.

## Preserve the experiment

- Do not change prompts, subjects, specifications or `config/experiment.yaml` to improve reported scores. Record configuration changes as new experiments.
- Keep original run records, labels, sampling probabilities and replay provenance. Never invent missing labels or treat mock output as measured results.
- Distinguish patch-method detection, provisional LLM-judged labels and runtime-witness confirmation.
- Preserve build and Tai-e failure logs; failed runs are part of the results.
- Never print or commit `.env` or credentials.

## Validation

Use a dedicated Python environment and the setup instructions in `README.md`. Run checks appropriate to the change. Documentation-only edits do not require rerunning the study. The full test suite is `python -m pytest -q`; integration tests require the recorded Java/Tai-e dependencies, and live model tests are opt-in.

`python -m nesy evaluate` regenerates summaries from released records without the endpoint. `python scripts/make_report_assets.py` regenerates paper assets; compile with `latexmk -pdf main_revised2.tex` from `report/`. Run experiments or regenerate report assets only when the task calls for them.

Live stages require the configured endpoint and network access. Compatible cached answers may avoid requests, but neither cache availability nor identical fresh responses is guaranteed. Keep held-out results separate from the development study.
