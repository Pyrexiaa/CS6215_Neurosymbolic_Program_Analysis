# Precision from the frozen original sample

The reported `precision_mean` uses a Horvitz-Thompson (HT) estimate over the frozen original label sample. It is separate from the automatic patch-method precision used to calculate `iris_avg_fdr` and `iris_avg_f1`. The earlier two-stratum descriptive calculation remains available as `precision_descriptive_mean` for comparison, but it does not correct the unequal inclusion probabilities created by overlapping configuration samples.

## Original sampling design

Before corrected run records were generated, `labels/sampling_manifest.json` was frozen from the original 208 run records and eight label sheets. Its 436 selected flow keys exactly reproduce the original fixed-seed samples. It records the source file hashes, selected membership, sampling strata, sample sizes, seeds and inclusion probabilities. The `label_at_freeze` field preserves provenance; scoring reads the current label CSVs. The original sample has 436 labels produced by one LLM judge, without human verification. The original frame contains 6,582 keys; the corrected run records contain 6,523.

For each subject and version, flow keys were pooled across runs of each main configuration: B1, B2, v1, v2, v3, v4 and iris-like. Within each configuration, up to 10 keys were sampled without replacement in each of two strata. A key was in the GT stratum if any original run associated it with a fixed method. The resulting independently seeded samples were combined into one set for labelling.

For flow `i`, let `D(i)` be its eligible configuration/stratum draws, each having original population size `N_d` and sample size `n_d`. Its probability of inclusion in the combined sample is:

```text
pi_i = 1 - product over d in D(i) of (1 - n_d / N_d)
```

The deterministic seeds make the sample reproducible; the statistical interpretation treats the underlying draws as independent simple random samples without replacement. Shared flow keys generally have higher inclusion probabilities. The frozen probabilities must not be reconstructed using corrected alarm sets, because the original labels were not sampled from those new sets.

## Per-run estimate and supported domains

For a current run, let `R` be its distinct reported flow keys, `S` the original selected keys, and `y_i` the current label indicator (TP = 1, FP = 0). Precision is estimated by:

```text
estimated TP total = sum over i in (S intersect R) of y_i / pi_i
precision_HT      = estimated TP total / |R|
```

The denominator is the known current number of reported flows, not an estimated population count. Labels added opportunistically outside `S` do not enter this estimate. They can still supply specific evidence for confirmed detections. Explicitly adopted corrections to originally sampled labels can be used without changing the original inclusion probabilities. Record the reviewer or model, evidence and reason separately; do not present unadopted review suggestions as corrected labels.

The implementation distinguishes these cases:

| Case | Result |
| --- | --- |
| No reported flows | Precision is undefined (`None`); omit this empty run from precision means. |
| Every reported key has positive original inclusion probability, and all selected keys in this domain have TP/FP labels | Compute HT precision. |
| Covered, nonempty reported domain contains no originally sampled key | HT precision is 0, coverage is 0, and status is `no-sampled-reported-flows`. Retain this estimate in means; dropping it would condition the result on having observed a sample member. Zero here is an estimate, not a judgement that unobserved alarms are FP. |
| A reported key is new or had original probability zero | Precision is unknown, even if that key has an opportunistic label. |
| An originally selected, currently reported key has an empty, `?`, `UNSURE`, or other non-TP/FP label | Precision is unknown. No uncertain judgement is silently converted to FP. |
| An unknown sampled label lies outside this run's reported domain | It does not block this domain estimate. |

If a nonempty run has unknown precision, its subject/configuration aggregate remains unknown. If a nonempty subject aggregate is unsupported, the configuration's headline precision also remains unknown. `precision_known_runs`, `precision_nonempty_runs`, `precision_unknown_nonempty_runs`, `precision_subjects`, and `precision_unknown_subjects` make these denominators visible. Means are otherwise computed over nonempty runs per subject and then over subjects with nonempty runs. This makes the reported precision conditional on a run producing alarms and avoids silently discarding unsupported nonempty domains. It is not a pooled ratio over all subjects.

HT estimates are not clipped to `[0,1]`; an individual estimate can exceed one when a rare selected positive represents many flows. Clipping would change the estimator. `precision_sd` measures variation across the available run estimates, not a confidence interval for the label sample.

## Files and regeneration

After run records and any explicitly adopted label corrections are ready:

```bash
python -m nesy evaluate
python scripts/make_report_assets.py
```

Evaluation writes `results/summary/precision_per_run.csv` with reported/sample/known counts, weighted TP totals and statuses. `precision_provenance.json` records the frozen manifest hash, current label-file hashes and interpretation rules. The other summary tables use corrected HT precision. `label-sheet` preserves the frozen sample membership rather than drawing a replacement sample after corrected runs. New flows remain without a sampling priority.

The initial freeze command was:

```bash
python scripts/freeze_label_sampling.py --repo . --manifest labels/sampling_manifest.json
```

Do not run it to replace the released original manifest. It refuses to overwrite an existing manifest. The original manifest's SHA-256 is `64b43477dc7a6cd8e0e30f3c9e3acaec82052560b1abf9c3bdb6e39872de4bc7`. Its source hashes refer to the original artifacts and are expected to differ after documented run corrections. They provide provenance, not a reason to recompute selection probabilities.

## Interpretation limits

Correcting the sampling weights does not independently validate the LLM labels. The original judge saw available N3 verdicts and grouped some decisions by site, allowing anchoring and correlated errors. The judging protocol was not independent of analyzer development; see the report's methodology. Flow keys can merge different driver-source sites and routes, so applying one judgement to multiple configurations assumes the security meaning is shared. Changes to a driver's threat model or a flow's meaning require evidence review even if the string key remains covered. The design also does not establish out-of-sample generalisation when configurations were developed using these subjects or their judgements.

The estimator does not imply human verification or introduce new labels. Additional decisions in `results/adjudication/` remain separate from the label CSVs and are not read by this calculation. No confidence interval is claimed. Automatic method-overlap metrics, label-based precision, confirmed detection and witness-confirmed detection remain separate measures.
