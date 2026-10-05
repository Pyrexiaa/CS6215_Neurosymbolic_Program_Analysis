# Evaluation protocol

This document describes the released comparison and the meaning of its metrics.

## Scope and comparison

The study compares B1, B2, v1 through v4, an IRIS-inspired configuration (`iris-like`), and three validator ablations on four projects from CWE-Bench-Java. Each project has a buggy and a fixed version. B1 and B2 run once per version; the eight LLM configurations run three times, giving 208 records. The corrected records include eight Tai-e failures in V2-off ablations. Those failures remain part of the comparison, with zero reported alarms and explicit failure counts.

All configurations use the same subject builds, Tai-e 0.5.4, JDK 8 analysis library, `1-call` context sensitivity and per-subject settings. The JVM uses a 6 GB heap, a 30-minute pointer-analysis limit and a separate 60-minute wall timeout. Perfecto-plugin alone uses `only_app: true` with generated string-builder chaining transfers. B1, B2, v1 and `iris-like` share the template driver; the others use N1, with template fallback when required.

The analyzer responses identify `qwen3.6:35b`, originally requested through the service's `default` alias. The correction replay explicitly requested `qwen3.6:35b` for its 31 new N3 responses. N1 and N3 use temperature 0; N2 uses one sample at 0 and two at 0.7. Run-derived sample indexes and seeds distinguish repeated requests, but do not guarantee independent draws or identical fresh responses. A mutable service alias also limits reproducibility.

B2 is a curated baseline prepared from candidate APIs and buggy source. The recorded procedure did not consult advisories or fixes, but earlier B1 behaviour had been seen during debugging. It measures a strong curated specification; no comparable human-effort measurement is available. The report documents its preparation and provenance limitations.

The four subjects are the development set. The v4 rules were motivated by failures on these same subjects. Held-out candidates and scripts are prepared, but no held-out results are included.

## Research questions

| RQ | Question | Evidence |
| --- | --- | --- |
| RQ1 Effectiveness | How do configurations compare in CVE detection and alarm volume? | `results/summary/headline.csv`, `cve_detection.csv`, label-based metrics and `results/witness/witness-detection.csv` |
| RQ2 Contribution | What does each LLM stage and validator contribute? | B1 versus v1 (N2), v1 versus v2 (N1), v2 versus v3 (N3), v3 versus `iris-like` (driver choice), v3 versus each validator ablation, and v3 versus v4 (added rules) |
| RQ3 Failures | Why do configurations miss CVEs or report false alarms? | Per-flow records, evidence packets, labels and the failure taxonomy below |
| RQ4 Cost and stability | What resources are needed, how stable are repeated runs, and how does the budget limit the study? | `results/summary/budget.csv`, alarm-set Jaccard, specification vote support, and provenance ledgers |

## Detection and alarm metrics

* **Automatic detection (`detected`).** At least one reported buggy-version flow is GT-relevant: its source or sink method, or a method on its TFG route, matches a method changed by the CVE fix. Route methods must be reachable from the source and able to reach the sink. Matching uses package, class and method name; it does not distinguish overloads or match source lines. Fallback-only route matches are stored separately as weak matches.
* **LLM-judged confirmed detection (`confirmed_detected_rate`).** A reported GT-relevant flow has an explicit TP label. This supports the method-level proxy but is not independent ground truth. If no such flow is TP and some reported GT-relevant flows are unlabelled, the run is unknown and excluded from this rate; `confirmed_known_runs` records the denominator. **TP reported** credits any reported TP-labelled flow, including one outside the patch-method ground truth.
* **Witness-confirmed detection.** A reported GT-relevant buggy-version flow matches the subject-specific sink predicate in `scripts/score_witnesses.py`; zt-zip also requires the vulnerable argument. Runtime witnesses demonstrate the four CVE effects on the buggy versions and their removal on the fixed versions. Sink matching does not execute or validate every static route. Spark's witness exercises the resource handler rather than a full HTTP request dispatch. See `results/witness/witness-results.json` and `witness-detection.csv`.
* **Buggy/fixed differential (`differential_ok`).** The configuration detects the buggy CVE and reports fewer GT-relevant alarms on the fixed version. Drivers and specifications are inferred separately per version, so this does not isolate the patch's effect. The completed frozen-input experiment in `results/extensions/controlled-pair/` holds the buggy v4 driver and specification fixed for 12 fixed-version analyses before triage; perfecto-plugin still differs in dependencies.
* **Automatic IRIS-style precision, FDR and F1.** Precision is the fraction of reported flows that are GT-relevant, recall is 1 when detected and 0 otherwise, FDR is `1 - precision`, and F1 is the harmonic mean. FDR omits empty runs; F1 assigns them zero. Aggregation averages runs within subjects, then subjects. Definitions follow IRIS, but different path extraction and aggregation prevent direct cross-paper score comparisons. These are patch-method proxies, separate from label-based precision.
* **Pooled flow recall (`recall_mean`).** Reported TP-labelled flows divided by all TP-labelled flows for that subject and version, pooled across configurations. This measures recall relative to the labelled pool, not all vulnerable flows in the program.
* **Stability.** Mean pairwise Jaccard similarity of reported flow-key sets across the three runs. Specification vote support records agreement among N2 samples, not semantic correctness.

Accuracy is not reported because the analyzers produce alarms without a population of true negatives. A fixed version is a negative check for its CVE, not proof that every other alarm is false. The fixed revisions, including the cron-utils backport and perfecto-plugin dependency update, are specified in `config/subjects.yaml`.

## Label-based precision

`precision_mean` is a Horvitz-Thompson estimate from the frozen original sample in `labels/sampling_manifest.json`. For each subject and version, flows were pooled across runs of each main configuration (B1, B2, v1, v2, v3, v4 and `iris-like`). Up to 10 flows were sampled from each configuration's GT and non-GT strata, with GT membership defined by the union over original runs. Overlapping draws produced 436 distinct selected keys from the original 6,582-key frame. The corrected records contain 6,523 distinct keys; they do not define a replacement sample.

For flow `i`, with eligible original draws having sample size `n_d` and population size `N_d`, the combined inclusion probability is:

```text
pi_i = 1 - product over eligible draws d of (1 - n_d / N_d)
precision_HT = sum over originally sampled, currently reported TP flows i of (1 / pi_i)
               / number of currently reported flows
```

This corrects unequal sampling probabilities, conditional on the labels. It does not validate their judgments. A two-stratum descriptive estimate is also available as `precision_descriptive_mean`.

Empty runs have undefined precision and are omitted. A covered nonempty run with no selected member contributes zero with coverage zero; this is an estimate, not a claim that every unobserved flow is FP. New or zero-probability reported keys, or missing TP/FP labels for originally selected reported keys, make the estimate unknown. An unsupported nonempty run makes its subject/configuration and headline aggregates unknown. Otherwise, means average nonempty runs within subjects, then subjects with nonempty runs. Estimates are not clipped to `[0,1]`, and `precision_sd` describes run variation rather than a sampling confidence interval.

`results/summary/precision_per_run.csv` records denominators, coverage and status. `precision_provenance.json` records the manifest and label hashes. See `docs/precision-estimation.md` for the complete calculation.

## Label provenance and adjudication

The original 436 labels were produced by one LLM judge, Claude Opus 5.5, without human verification. The judge saw flow evidence and available N3 verdicts and applied shared rules to related sites. The judgments are not independent measurements: shared rules and access to N3 verdicts permit correlated errors and anchoring. The report documents the complete judging protocol and its limitations.

The released evaluation still reads `labels/<subject>-<version>.csv`. Its `priority` values identify the frozen sample: 1 for union-GT membership and 2 for other selected flows. Refreshing sheets preserves this membership and existing labels. New rows have no priority. `TP`, `FP` and `UNSURE` remain distinct; unknown judgments are not silently converted to FP. Any adopted correction needs recorded evidence and provenance without changing the original sampling probabilities.

Two separate checks supplement these labels:

1. Runtime witnesses establish the four CVE effects without LLM judgments. They validate the demonstrated effects and sink families, not the entire labelled sample.
2. `scripts/adjudicate.py` applies the rubric in `prompts/judge.md` to the frozen sample and stores decisions in `results/adjudication/`, without replacing the label CSVs. The released live pass contains 436 decisions: 13 TP, 423 FP and 0 UNSURE (`summary.json`, requested model `default`, `dry_run: false`). It is an LLM-judged pass, not label-free validation. Its prompt includes source and sink text, patch-method metadata, applicable witness evidence and the first 300 characters of existing notes, so it is not independent of the original labels. The separate `--dry-run` mode makes only selected witness-anchored decisions and leaves other cases unsure; it is not the released live pass.

`docs/labelling-guide.md` describes the evidence and rubric. The evaluation code does not automatically use the separate adjudication decisions.

## Failure taxonomy

| Code | Meaning |
| --- | --- |
| `DRV` | Driver taints a value an attacker does not control |
| `SAN` | A check or normalization neutralises the reported flow |
| `IMP` | Analysis imprecision, such as merged contexts or an infeasible route |
| `SPEC-FP` | An incorrect source or sink specification creates a false alarm |
| `SPEC-FN` | A missing specification causes a miss |
| `ENTRY-FN` | The driver does not reach vulnerable code |
| `TRIAGE-FN` | Triage removes a true flow despite valid citations |
| `HALLU` | An LLM claim is unsupported by the code |
| `TOOL` | Build, analyzer or timeout failure |

## Resource accounting and reproducibility

`results/summary/budget.csv` measures logical workload, including responses shared across configurations. Original recorded spend and incremental correction spend are separated in `results/provenance/validator-refresh.json` and `fresh-call-ledger.jsonl`: 4,978 original fresh calls and 31 additional N3 calls. Stored stage timings can mix historical generation time and cached replay time, so they are not a cold-run budget. Fresh-token and latency counters must be interpreted with their recorded provenance.

The released 208 records use the original N1/N2 draws. Preserved records and labels under `results/history/` support provenance checks. A separate B1/B2 replay reproduced all 16 baseline records and flow-key sets (`results/replay/`). Archived answers support replay; fresh hosted calls can differ.

The 200-flow N3 cap leaves additional alarms reported but unjudged. Driver budgets also differ: the template can call up to 300 entries, while N1 sees 60 candidates. These design choices and fallback behaviour limit causal claims about alarm reduction. Other limits include the four-subject scope, development on the evaluated cases, public-CVE leakage, uncertain flow labels and possible changes in the security meaning of a reused flow key.
