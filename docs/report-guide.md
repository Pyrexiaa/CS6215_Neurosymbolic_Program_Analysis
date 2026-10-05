# Report and artifact guide

The maintained source is [`report/main_revised2.tex`](../report/main_revised2.tex). Its tables and figures come from the released run records and labels; other report drafts are not build entry points.

## Paper structure and supporting material

| Paper section | Supporting material |
| --- | --- |
| Background and Symbolic Baselines | `config/experiment.yaml`, `config/cwe.yaml`, [design.md](design.md) |
| Approach | `src/nesy/`, `prompts/`, [design.md](design.md) |
| Evaluation setup and metrics | [evaluation.md](evaluation.md), `config/subjects.yaml`, `results/summary/subjects.csv` |
| Effectiveness and component comparison | `results/summary/`, [results-explained.md](results-explained.md) |
| Flow judgments and precision | [labelling-guide.md](labelling-guide.md), [precision-estimation.md](precision-estimation.md), `labels/sampling_manifest.json` |
| Runtime witnesses | `witness/`, [witness results](../results/witness/summary.md) |
| Controlled version comparison | [paired replay](../results/extensions/controlled-pair/README.md) |
| Reproducibility | [baseline replay](../results/replay/replay-summary.md), `results/provenance/`, `results/raw/`, `results/history/` |

The development study comprises four subjects, two versions, deterministic B1/B2 runs and three repetitions of each LLM configuration. The held-out experiment remains planned and must be reported separately when executed.

## Rebuild from released data

From the repository root in the project environment:

```bash
python -m nesy evaluate
python scripts/make_report_assets.py
(cd report && latexmk -pdf main_revised2.tex)
```

The first command writes summary CSVs, Markdown and LaTeX under `results/summary/`. The second reads those summaries and the completed paired replay, producing `report/tables/` and `report/figures/`. The final command requires a LaTeX installation with `acmart`, BibTeX and `latexmk`.

This is offline report regeneration, not a new analysis campaign. Keep the result assets generated rather than manually changing numbers. Prose edits should use the existing numerical macros and state whether a number concerns patch overlap, LLM judgments or witness confirmation.

## Interpretation checks

- Detection on any repetition differs from the mean per-run detection rate.
- Alarm counts in the headline table are means per run summed across buggy subjects.
- Patch-method relevance is not proof of exploitability.
- Precision depends on provisional LLM labels and the frozen inclusion probabilities; a second adjudication namespace does not replace those labels automatically.
- Witness checks establish specific CVE effects and support sink-family matching, not every static route.
- Frozen-input comparisons are pre-triage results, not end-to-end v4 scores.
- The v4 rules were developed on the evaluated subjects; their gains are not held-out estimates.
- Logical model calls can reuse responses across configurations and must not be read as fresh request spend.

Check citations, float placement and pagination after compiling. The main-content limit is ten pages, with at most one additional reference page. Page counts are properties of a particular compiled draft, not a fixed repository result.
