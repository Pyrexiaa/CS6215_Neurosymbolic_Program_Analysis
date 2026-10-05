#!/usr/bin/env bash
# Full study: fetch + build subjects, run every configuration, write label sheets and tables.
# Usage: bash scripts/run_all.sh [subject|all]     (default: all primary subjects)
# Compatible cached runs, drivers, specifications and LLM answers are reused; missing or changed inputs rerun stages.
set -euo pipefail
cd "$(dirname "$0")/.."
SUBJ=${1:-all}
# same environment choice as setup_tools.sh: $PYTHON > active venv > active conda env > .venv
if [ -n "${PYTHON:-}" ]; then PY="$PYTHON"
elif [ -n "${VIRTUAL_ENV:-}" ]; then PY=python
elif [ -n "${CONDA_PREFIX:-}" ]; then PY="$CONDA_PREFIX/bin/python"
elif [ -x .venv/bin/python ]; then PY=.venv/bin/python
else PY=python3; fi

"$PY" -m nesy check-env --llm
"$PY" -m nesy fetch "$SUBJ"
"$PY" -m nesy build "$SUBJ"
# deterministic baselines first (no tokens), then the neuro-symbolic configurations
"$PY" -m nesy run "$SUBJ" --configs B1,B2
"$PY" -m nesy run "$SUBJ" --configs v1,v2,v3,v3-noval,v3-noV2,v3-noV3,v4,iris-like
"$PY" -m nesy label-sheet "$SUBJ"
"$PY" -m nesy evaluate
echo "Done. Summaries are in results/summary/. Preserve the archived labels and frozen sample; see docs/labelling-guide.md for review."
