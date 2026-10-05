# Comparing Symbolic and Neuro-Symbolic Taint Analysis for Java

This CS6215 artifact compares symbolic baselines and neuro-symbolic configurations on four Java CVEs from [CWE-Bench-Java](https://github.com/iris-sast/cwe-bench-java). All configurations use [Tai-e](https://github.com/pascal-lab/Tai-e) for taint propagation. NESY-TAINT, the final configuration (`v4`), adds LLM-generated drivers, inferred specifications, alarm triage and symbolic checks.

The paper is [report/main_revised2.tex](report/main_revised2.tex), with its [PDF](report/main_revised2.pdf). Run all commands below from the repository root.

## Repository organization

| Path | Contents |
| --- | --- |
| `src/nesy/` | Analysis pipeline and command-line interface |
| `config/`, `prompts/` | Experiment settings, subject revisions, taint rules and LLM prompts |
| `scripts/`, `tests/`, `witness/` | Setup and reproduction scripts, tests and runtime CVE witnesses |
| `results/runs/`, `results/summary/` | Released run records and generated result tables |
| `results/artifacts/` | Exported drivers, specifications, graphs and triage evidence |
| `labels/` | Flow labels, frozen sampling manifest and review evidence |
| `results/witness/`, `results/extensions/` | Runtime checks and controlled version comparison |
| `results/raw/`, `results/provenance/` | Archived model responses and request provenance |
| `report/`, `docs/` | Paper sources, figures, tables and supporting documentation |
| `tools/`, `work/` | Downloaded tools, subject builds, intermediate outputs and private cache |
| `AGENTS.md`, `CLAUDE.md`, `skills/reproduce-study/` | Instructions for automated setup and reproduction |

## Environment and dependencies

The setup scripts support macOS and Linux with Bash, Git, `curl` and `tar`. The reported experiments used a MacBook Pro. Install the following dependencies as needed:

| Dependency | Use |
| --- | --- |
| Python 3.9+ | Pipeline and evaluation; `environment.yml` uses Python 3.11 |
| `openai>=1.30`, `PyYAML>=6.0` | Model client and configuration loading |
| `pytest>=7.0`, `matplotlib>=3.7` | Tests and report figures |
| JDK 17+ | Tai-e and driver compilation |
| Full JDK 8, including `javac` and `rt.jar` | Subject builds and the analysed Java library |
| Tai-e 0.5.4 and Maven 3.5.4 | Downloaded and checksum-verified by setup |
| SoCLaaS credentials and NUS network or VPN | Live LLM calls; the reported model is `qwen3.6:35b` |
| LaTeX with `acmart`, BibTeX and `latexmk` | Paper compilation |
| Graphviz (optional) | Viewing taint flow graphs |

Tai-e is configured with a 6 GB Java heap; allow additional memory for the operating system and builds. A full live study takes several hours. Java, Tai-e, Maven and endpoint access are unnecessary when regenerating results from the released records.

## Setup

Create and activate the Python environment, then install the package:

```bash
conda env create -f environment.yml
conda activate nesy
python -m pip install -e ".[test,report]"
```

Alternatively, use `python3 -m venv .venv`, activate it with `source .venv/bin/activate`, and run the same `pip install` command. Dependency installation requires internet access.

For new analysis runs, install both JDKs and download the analysis tools:

```bash
bash scripts/setup_tools.sh
```

Setup creates `.env` from [.env.example](.env.example) if needed. Set `JAVA17_HOME` and `JAVA8_HOME` when automatic detection fails. For live LLM runs, set `SOCLAAS_API_KEY`, use the supplied `SOCLAAS_BASE_URL`, and set `SOCLAAS_MODEL=qwen3.6:35b` to select the reported model. Keep `.env` private.

```bash
python -m nesy check-env
python -m pytest -q
python -m nesy demo
```

The demo uses an offline mock and does not reproduce experimental results. Integration tests require the Java/Tai-e dependencies; live model tests are opt-in.

## Reproduce the reported results

After Python setup, regenerate the summaries, figures, tables and paper from the released data:

```bash
python -m nesy evaluate
python scripts/make_report_assets.py
(cd report && latexmk -pdf main_revised2.tex)
```

The evaluator writes `results/summary/`, including `headline.csv`, `by_config.csv` and `summary.md`. The asset script writes `report/tables/` and `report/figures/`; LaTeX produces `report/main_revised2.pdf`. No model requests or new analyses are made by these commands.

The released study contains 208 run records across four subjects and their buggy/fixed versions, including eight Tai-e failures in validator ablations. Precision uses 436 provisional LLM-judged labels and the frozen sampling manifest. Preserve these inputs to reproduce the reported numbers. See the [report guide](docs/report-guide.md) for the mapping between results and paper sections.

## Run the experiments

Use a separate checkout for new runs to preserve the released records and labels. Fetch and build the four primary subjects (`zt-zip`, `spark`, `cron-utils` and `perfecto-plugin`), then run the symbolic baselines:

```bash
python -m nesy fetch all
python -m nesy build all
python -m nesy check-manual all
python -m nesy run all --configs B1,B2
```

`B1` uses the configured Tai-e specification; `B2` adds the supplied curated rules. Both run once per subject/version and require no LLM access. Subject downloads and Maven dependency resolution require internet access.

To run NESY-TAINT with three repetitions per subject/version:

```bash
python -m nesy check-env --llm
python -m nesy run all --configs v4 --runs 3
python -m nesy evaluate
python -m nesy export
```

The default version selection is `both`. Replace `all` with a subject ID for a smaller run, or add `--version buggy` or `--version fixed`. Records are written to `results/runs/`, intermediate files and logs to `work/`, and exported evidence to `results/artifacts/`.

For the complete configuration comparison, including ablations, use:

```bash
bash scripts/run_all.sh
```

This script checks the endpoint, fetches and builds the subjects, runs all configurations, prepares label sheets and regenerates summaries. It does not create verified flow labels. Run the report-regeneration commands above afterwards to update the figures and paper.

| Configuration | Purpose |
| --- | --- |
| `B1`, `B2` | Symbolic baselines |
| `v1`, `v2`, `v3` | Add specification inference, generated drivers and triage in stages |
| `v4` | Final NESY-TAINT design with the additional checks and rules |
| `iris-like` | IRIS-inspired comparison implemented on Tai-e |
| `v3-noV2`, `v3-noV3`, `v3-noval` | Specification, triage and combined validator ablations |

Configurations, limits and repetition counts are defined in [config/experiment.yaml](config/experiment.yaml); exact subject revisions and build adjustments are in [config/subjects.yaml](config/subjects.yaml). Compatible cached stages and responses may be reused. Fresh responses can differ from the archive, and the archived response file is not automatically a usable cache. Rebuild from the released records when checking the exact reported results.

## Runtime checks and supporting documentation

After building the subjects, reproduce the runtime CVE checks and match saved alarms to their sink families:

```bash
python scripts/run_witnesses.py
python scripts/score_witnesses.py
```

Outputs are written to `results/witness/`. The expected witness result is a reproduced CVE effect on each buggy version and a blocked effect on its fixed version. These checks do not validate every static alarm's route.

See [design](docs/design.md) for the pipeline, [evaluation](docs/evaluation.md) and [results explained](docs/results-explained.md) for metrics, and the [labelling guide](docs/labelling-guide.md) and [precision estimation](docs/precision-estimation.md) for label handling. The [controlled version comparison](results/extensions/controlled-pair/README.md) documents its separate reproduction prerequisites and command.

For Codex or Claude Code, start with [AGENTS.md](AGENTS.md); [CLAUDE.md](CLAUDE.md) points to the same instructions. The [reproduction skill](skills/reproduce-study/SKILL.md) provides the setup, baseline, neuro-symbolic and evaluation workflow. Preserve the supplied experiment settings, labels and failure records when reproducing the study.

## Licences

Project code, prompts and report sources use the [MIT licence](LICENSE). Copied Tai-e specifications retain [LGPL-3.0](config/taint/commonly-used/COPYING.LESSER); benchmark metadata retains its [MIT licence](config/cwe-bench-java/LICENSE-IRIS). Tai-e itself is downloaded by setup and is not redistributed here.
