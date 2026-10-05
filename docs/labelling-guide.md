# Flow-labelling guide

The 436 original TP/FP labels in `labels/*.csv` were produced by one LLM judge and have not been human verified. Their notes retain the original provenance marker, FP category and reason. The judge saw available N3 verdicts and grouped some decisions by shared sites, so anchoring and correlated errors are possible.

Labels supplement automatic patch-method matching; they do not establish independent ground truth. They support these separate measures:

| Measure | Meaning |
| --- | --- |
| Confirmed detection | At least one reported, patch-relevant flow is labelled TP. A run with unlabelled patch-relevant flows and no known TP is unknown; confirmed rates use known runs. |
| TP reported | At least one reported flow is labelled TP, whether or not patch-method matching credits it. |
| Label-based precision | Horvitz-Thompson estimate over the frozen original probability sample. This is separate from the automatic patch-method FDR in the report. |
| Pooled recall | Fraction of all TP-labelled flows for the subject/version that a run reports. It is relative to the labelled pool, not all vulnerabilities. |

## 1. Preserve the original sample

`labels/sampling_manifest.json` freezes the original sampling frame and selection probabilities. For each subject, version and main configuration (B1, B2, v1, v2, v3, v4 and iris-like), the original procedure pooled reported keys across repetitions and selected up to 10 keys in each of two strata. Small strata were taken completely; overlapping draws were combined.

| Priority | Original sampling stratum |
| --- | --- |
| `1` | The key was associated with a patched method in at least one original run. |
| `2` | Other keys. |

There are 436 selected keys: spark 213, zt-zip 212, cron-utils 5 and perfecto-plugin 6. The original frame contained 6,582 keys; corrected records contain 6,523. Priorities retain original membership even when current routes or patch relevance differ. Ablations reuse labels for shared keys; a newly reported key is not automatically covered by the sample.

To refresh sheet evidence while retaining labels, notes and frozen priorities:

```bash
python -m nesy label-sheet all
```

Do not replace the frozen sample after inspecting corrected outputs. New keys remain without a sampling priority. Labels added outside the original sample may support specific detection evidence, but they do not enter its precision estimate. Keep any explicitly adopted correction's reviewer, evidence and reason separately from the original provenance.

## 2. Inspect a flow

Each row has a `flow_id`, a canonical `flow_key`, a raw source and sink, and the configurations that report it. For example:

```bash
python -m nesy show-flow zt-zip buggy d15307a6a1
```

Review packets are stored in `labels/review/<subject>-<version>.md`. They show the selected raw flow's endpoints, available triage decisions, a TFG route or reachable-method fallback, and bounded source excerpts. A packet is evidence for review, not proof of a feasible execution. The same canonical key can represent different driver sites or routes; inspect the attacker model before reusing one label across configurations.

The following commands regenerate packets for open selected rows, or all selected rows respectively. They overwrite the corresponding review Markdown files; preserve archived evidence when recording a new review.

```bash
python -m nesy label-pack all
python -m nesy label-pack all --all
```

The default excerpts are bounded to six application methods and 60 lines per method. Use `--max-methods` and `--max-lines`, or inspect the source under `work/subjects/<subject>/<version>/`, when evidence is incomplete. A missing TFG route does not by itself make a flow false.

## 3. Apply the four-question rubric

Judge the specific source, sink argument, route and threat model. The first established “no” gives an FP category. If the evidence is insufficient, record `UNSURE` or `?` rather than guessing.

1. **Does an attacker control the source?** Archive content, HTTP input and user-supplied cron text can be attacker-controlled. A caller-selected output directory or trusted server configuration may not be. A synthetic `DRIVER` source is valid only when the corresponding argument models attacker input. Use `DRV` for an incorrect driver model. Jenkins job configuration requires an explicit privilege boundary: permission to configure a job does not necessarily permit arbitrary execution on the controller.
2. **Is this sink argument dangerous for the target CWE?** Path traversal requires a path that can cross the intended boundary; command injection requires command interpretation; code injection requires evaluation. Logging or exception text is not automatically a sink. Use `SPEC-FP` for an incorrect sink specification.
3. **Can this input reach this sink under the stated conditions?** Check object identity, callbacks, branches and any required request state. Shared helpers or an incomplete TFG can leave feasibility unresolved. Use `IMP` when evidence establishes that the reported route is infeasible.
4. **Does the value remain dangerous?** Check whether containment checks, validation, escaping or rejection actually prevent the security effect on this route. Use `SAN` only when neutralisation is effective. A patched version can retain other vulnerabilities, and a recognised check can be bypassable.

Label `TP` only when all four conditions are supported. Record the category, attacker model and a concise reason in `notes`, for example `FP DRV: the caller chooses the trusted extraction directory`.

An unknown label is not silently counted as FP. If an originally selected and currently reported key lacks a TP/FP label, its run's HT precision is unknown, and that unknown propagates to its subject/configuration and headline precision. Unknown labels outside a run's reported set do not block that run's estimate. See `docs/precision-estimation.md`.

## 4. Subject-specific distinctions

- **zt-zip:** file-constructor argument 0 is the parent output directory; argument 1 is the archive-entry name. The former commonly produces driver-modelling false positives. The witness confirms traversal through the latter.
- **spark:** distinguish request input from static-root configuration and inspect the precise handler, request branch and loader. The runtime witness demonstrates a handler-level path escaping the static root; it does not validate every sampled HTTP or resource-loading route.
- **cron-utils:** user text reaching a Bean Validation message template is relevant when the provider and interpolation settings allow expression evaluation. The witness checks the evaluated expression on the recorded buggy build and its absence on the fixed build.
- **perfecto-plugin:** controller command execution and authorised build-step execution have different security meanings. The fixed flow can be an FP under the study's stated job permissions even though the command string is not sanitised. Record the execution location and permission assumption.
- **Fixed versions:** a remaining alarm is not automatically false. Establish that the particular flow is neutralised or harmless under the threat model.

## 5. Regenerate summaries after an adopted correction

```bash
python -m nesy evaluate
python scripts/make_report_assets.py
```

Evaluation reads the current label CSVs and original sampling probabilities. It writes summary metrics and precision diagnostics without rerunning the analyzer or querying an LLM. Asset generation refreshes the report's tables and figures. `python -m nesy export` separately copies stage artifacts; it is not required to recalculate label metrics.

Report the sampling design, judging protocol and model, unknown-label handling and relevant witness evidence. Distinguish the automatic patch-method metrics, original LLM labels and later review decisions.

## 6. Runtime witnesses and additional adjudication

Runtime witnesses in `witness/` check each CVE's security effect on buggy and fixed builds without flow labels or LLM calls. `scripts/run_witnesses.py` runs those checks; `scripts/score_witnesses.py` matches reported patch-relevant flows to the subject-specific witnessed sink family, requiring the vulnerable argument for zt-zip. Witness confirmation does not execute every reported static route.

A separate live adjudication pass is already recorded in `results/adjudication/`: 436 decisions, comprising 13 TP, 423 FP and 0 UNSURE. Its summary records the hosted model alias `default`, not a pinned served-model identity. `scripts/adjudicate.py` uses `prompts/judge.md`, the source and sink fields, prior label notes and available witness evidence. Because it includes prior notes, this pass is not blind or independent of the earlier labels. It also does not supply the full review packet to the model.

These decisions remain separate from `labels/*.csv` and do not change the reported metrics. The script supports `UNSURE`; the archived live pass happened to return none. A new live invocation makes model requests and overwrites its decision files. Its `--dry-run` mode makes no model calls, assigns only its witness-based cases and leaves the rest UNSURE; running it over the live output would replace that completed pass.
