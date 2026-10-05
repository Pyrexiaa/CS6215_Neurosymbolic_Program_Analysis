# Controlled buggy/fixed symbolic replay

Completed 12 fixed-version Tai-e analyses, all successful, after checking that every direct buggy-driver application method signature resolves against the fixed classpath. There were 346 checked invocation references across the 12 drivers, with no unresolved references. Driver class files and assembled taint configurations were copied byte for byte and SHA-256 checked before and after analysis. No new LLM or N3 calls were made. New Tai-e time: 107.84 seconds.

This comparison freezes each buggy v4 driver and assembled specification, reuses its cached buggy **pre-triage** Tai-e result, and runs Tai-e on the fixed subject using the same frozen inputs. Each version keeps its own built dependency classpath. This is a symbolic propagation experiment, not an end-to-end v4 rerun.

| Subject | Mean pre-triage alarms, buggy → fixed | Mean GT-method alarms, buggy → fixed | Runs with fewer GT-method alarms | Same dependency contents/order |
|---|---:|---:|---:|---|
| cron-utils | 2.67 → 2.00 | 0.67 → 0.00 | 2/3 | yes |
| perfecto-plugin | 2.00 → 0.67 | 2.00 → 0.67 | 2/3 | no |
| zt-zip | 156.33 → 156.33 | 54.33 → 54.33 | 0/3 | yes |
| spark | 144.33 → 155.00 | 3.33 → 3.33 | 0/3 | yes |

GT-method relevance means that an endpoint or a method on the graph route was modified by the fix. It does not prove exploitability, correctness of the route, or that the analyzer detected the CVE. Retained alarms on a fixed version are not automatically new vulnerabilities.

The negative result matters: on spark and zt-zip, all three pairs retain exactly the same GT-method alarm counts when the driver and specification are frozen. Spark reports more alarms after the patch. Thus a reduction in the independently generated end-to-end buggy/fixed runs cannot be attributed solely to the patch making symbolic propagation disappear. Driver/specification changes and triage are potential contributors; this experiment does not isolate their individual effects.

Cron-utils removes the GT-method flow in the two runs that originally produced it; the third run had none on either version. Perfecto-plugin reduces counts in two pairs, but its dependency classpath changes between versions, so those differences are not a patch-only causal estimate.

## Reproduce

The repository must already contain its local work/ subject builds, buggy v4 driver class files, assembled configurations, and successful raw buggy Tai-e outputs. The public processed records alone are insufficient. Run the following command from the repository root with the project’s Python environment active and the pinned Tai-e/JDK dependencies available.

```bash
PYTHONDONTWRITEBYTECODE=1 python scripts/run_controlled_pair.py --repo "$PWD" --out /absolute/path/to/new-output-directory
```

Output must be outside the repository and must be fresh. The script refuses to overwrite existing frozen inputs. It runs sequentially, with the configured 6 GB heap, 30-minute pointer-analysis limit and 60-minute wall timeout, and never exceeds 12 new fixed analyses. `--preflight-only` performs compatibility/count checks without launching Tai-e, but use a different output directory for a subsequent full run.

The downloadable `complete_evidence.zip` contains the script, this README, and the `results/` files below, including every fixed-analysis log, graph and frozen input. Extract it to inspect those relative paths. JDK libraries, dependencies and original subject builds are not duplicated in the archive.

## Files inside the evidence archive

The paths below are relative to the extracted archive. The compact CSV, JSON and study manifest are also available beside this README.

- `run_controlled_pair.py`: measurement script, importing the repository’s current class reader, filters and GT-matching implementation.
- `results/controlled_pairs.csv` and `.json`: per-pair results; JSON includes settings and status.
- `results/pairs/<subject>/run<n>/frozen/`: exact buggy driver bytecode and taint-config inputs.
- `results/pairs/<subject>/run<n>/input_manifest.json`: per-file hashes of the frozen inputs and both versions’ app/dependency content, plus signature-resolution evidence.
- `results/pairs/<subject>/run<n>/buggy_symbolic_counts.json` and `fixed_symbolic_counts.json`: full filtered, scored pre-triage flows.
- `results/pairs/<subject>/run<n>/fixed-taie/`: raw Tai-e output, graph and console log, including command/settings.
- `results/study_manifest.json`: run bound, zero neural-call count and limitations.

The signature preflight checks direct calls into application classes, including constructors, rather than proving all JVM linkage or runtime feasibility. The historical buggy raw result is reused; its filtered count is checked against the saved run’s pre-triage flow list. Recorded historical result paths refer to the existing local checkout. Original study files were not edited.
