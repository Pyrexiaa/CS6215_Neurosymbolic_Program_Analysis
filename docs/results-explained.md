# Interpreting the results

The maintained report source is `report/main_revised2.tex`. Figures and tables use the corrected records in `results/summary/`, the original label sheets and frozen sampling manifest, and the controlled-version comparison. This guide distinguishes three forms of detection evidence that should not be combined into a single score.

## Detection, alarms and precision

The study contains 208 run records on four projects, including eight analysis failures in the deliberate V2-off ablations. On buggy versions, B1 flags one CVE by patch-method overlap. B2 flags all four and reports 1,511 alarms. v4 flags all four in at least one repetition per subject, with an 83% mean per-run detection rate and 289 alarms. Alarm totals are means per run summed across subjects, not totals across all repetitions.

Patch-method detection means that a reported flow touches a method changed by the fix. It does not establish attacker control, path feasibility or exploitability. LLM-judged confirmed detection instead requires a patch-relevant flow labelled TP. Witness-confirmed detection requires a patch-relevant flow matching a subject-specific sink family demonstrated by a runtime witness, with argument matching for zt-zip.

The released witness results in `results/witness/witness-detection.csv` give:

| Configuration | Patch-method detection | LLM-judged confirmed detection | Witness-confirmed detection |
| --- | ---: | ---: | ---: |
| B1 | 1/4 | 0/4 | 0/4 |
| B2 | 4/4 | 4/4 | 4/4 |
| v1 | 4/4 | 3/4 | 3/4 |
| v2 | 4/4 | 2/4 | 3/4 |
| v3 | 2/4 | 1/4 | 2/4 |
| v4 | 4/4 | 3/4 | 4/4 |
| IRIS-style | 3/4 | 2/4 | 2/4 |

These counts credit a subject when at least one run meets the corresponding condition. In particular, v4's 4/4 witness count does not mean every v4 run reaches a witnessed sink. B1's patch overlap targets zt-zip's trusted output-directory argument rather than the vulnerable archive-entry argument. The witness and original judge differ on spark for v2, v3 and v4; the witness establishes a handler-level traversal but does not validate every reported static route.

The automatic FDR and F1 in the headline table use patch-method relevance. The separate `precision_mean` is a Horvitz-Thompson estimate based on the original LLM labels and sampling probabilities. It is 0.51 for B2, 0.33 for v4 and 0.01 for IRIS-style, averaged over nonempty runs and then subjects with nonempty runs. These averages are strongly influenced by the small cron-utils and perfecto-plugin alarm sets. They are provisional estimates, not human-verified precision; see `docs/precision-estimation.md` for unsupported domains, weighting and aggregation.

## What the comparison shows

Specification inference broadens coverage. Generated drivers sharply reduce alarms while changing entry coverage and attacker-control assumptions. Triage removes harmless flows but also loses cron-utils' real vulnerable flow. The added symbolic rules recover detections and retain some false alarms. B2 shows that a good curated specification remains a strong symbolic baseline. Because v4 was developed on the same four subjects, its improvements do not establish transfer to unseen projects.

The independently generated buggy/fixed runs change both the program and its analysis inputs. The 12 controlled comparisons freeze each buggy v4 driver and specification, reuse the cached buggy pre-triage result and run a new fixed-version analysis. zt-zip and spark keep the same patch-relevant alarm counts. Thus the full pipeline's version difference cannot be attributed solely to patch sensitivity in symbolic propagation; changed inputs and triage may contribute. Perfecto-plugin also changes dependencies between versions. See `results/extensions/controlled-pair/README.md`.

## Checks and their limits

Runtime witnesses reproduce the four security effects on buggy versions and show that the corresponding fixes block them. They require no flow labels or LLM calls. They establish those effects under the tested inputs, not the safety of every fixed-version path or the feasibility of every matching static alarm.

A separate clean-environment replay reproduces all 16 archived B1/B2 results: raw, reported and patch-relevant counts, detection flags and reported flow-key sets. This checks reproducibility of the symbolic outputs, not their security accuracy; see `results/replay/replay-summary.md`.

The 436 original labels remain LLM-judged and were not human verified. A completed live adjudication pass in `results/adjudication/` records 13 TP and 423 FP decisions with no UNSURE decisions. It uses the hosted `default` model alias, includes prior label notes in its prompts and keeps decisions separate from `labels/*.csv`. It is an additional model judgement, not a label-free or independent blind check, and does not replace the labels used in the reported metrics. `docs/labelling-guide.md` describes both protocols.
