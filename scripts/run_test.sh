#!/usr/bin/env bash
# Run the frozen analyzer on held-out subjects kept separate from the development study.
# Usage:
#   bash scripts/run_test.sh prepare        # fetch + build the test subjects, write B2 candidate lists
#   (write config/taint/manual/<id>.yml for every test subject, then commit + tag the frozen state)
#   bash scripts/run_test.sh run            # all configurations on all test subjects, then evaluate
# Results: results/summary/test/summary.md (kept separate from the development numbers).
set -euo pipefail
cd "$(dirname "$0")/.."
MODE=${1:-}
if [ -n "${PYTHON:-}" ]; then PY="$PYTHON"
elif [ -n "${VIRTUAL_ENV:-}" ]; then PY=python
elif [ -n "${CONDA_PREFIX:-}" ]; then PY="$CONDA_PREFIX/bin/python"
elif [ -x .venv/bin/python ]; then PY=.venv/bin/python
else PY=python3; fi
TEST_IDS=$("$PY" -c "import yaml;print(' '.join(s['id'] for s in yaml.safe_load(open('config/subjects.yaml'))['subjects'] if s.get('role')=='test'))")

case "$MODE" in
  prepare)
    "$PY" -m nesy fetch test
    "$PY" -m nesy build test
    for s in $TEST_IDS; do "$PY" -m nesy candidates "$s"; done
    echo "Next: write config/taint/manual/<id>.yml for: $TEST_IDS"
    echo "      (same protocol as the development subjects; do not open advisories, fixes or any run output),"
    echo "      check them with: $PY -m nesy check-manual test"
    echo "      then freeze:  git add -A && git commit -m 'Freeze analyzer for held-out test' && git tag heldout-freeze"
    ;;
  run)
    if [ -z "$(git tag -l heldout-freeze)" ]; then
      echo "!! tag 'heldout-freeze' missing: commit and tag the frozen analyzer first (see 'prepare')."; exit 1; fi
    # Freeze subjects, CWE/benchmark data, selection/run scripts and dependency declarations too.
    FREEZE_PATHS=(src prompts config scripts pyproject.toml requirements.txt environment.yml)
    if ! git diff --quiet heldout-freeze -- "${FREEZE_PATHS[@]}"; then
      echo "!! analyzer, subjects, scripts or dependency inputs changed since 'heldout-freeze'; the test run would not be held-out."; exit 1; fi
    # git diff omits untracked inputs. Include ignored files too, except Python bytecode caches.
    UNTRACKED_INPUTS=$(git ls-files --others -- "${FREEZE_PATHS[@]}" ':(exclude)**/__pycache__/**' ':(exclude)**/*.pyc')
    if [ -n "$UNTRACKED_INPUTS" ]; then
      echo "!! untracked analyzer/configuration inputs are not covered by 'heldout-freeze':"
      echo "$UNTRACKED_INPUTS"
      exit 1
    fi
    for s in $TEST_IDS; do
      f="config/taint/manual/$s.yml"
      if [ ! -s "$f" ] || ! grep -qE '^\s*-\s' "$f"; then echo "!! $f is missing or has no entries (write B2 first)."; exit 1; fi
    done
    "$PY" -m nesy check-env --llm
    "$PY" -m nesy check-manual test
    "$PY" -m nesy run test --configs B1,B2
    "$PY" -m nesy run test --configs v1,v2,v3,v4,iris-like
    "$PY" -m nesy evaluate
    "$PY" scripts/make_report_assets.py
    echo "Done. Held-out results: results/summary/test/summary.md, report/tables/heldout.tex, numbers_test.tex"
    ;;
  *) echo "usage: bash scripts/run_test.sh prepare|run"; exit 2;;
esac
