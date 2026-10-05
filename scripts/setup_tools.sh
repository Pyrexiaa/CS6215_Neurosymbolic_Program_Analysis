#!/usr/bin/env bash
# Download the Tai-e release jar (pinned + checksum) and install Python dependencies.
# Usage: bash scripts/setup_tools.sh        (works on macOS and Linux; bash 3.2 compatible)
set -euo pipefail
cd "$(dirname "$0")/.."

TAIE_VERSION="0.5.4"
TAIE_JAR="tools/tai-e-all-${TAIE_VERSION}.jar"
TAIE_URL="https://github.com/pascal-lab/Tai-e/releases/download/v${TAIE_VERSION}/tai-e-all-${TAIE_VERSION}.jar"
TAIE_SHA256="703d1750b66e8e621d628ac93b07a21315db795b3a1e2224001ad09190c1e4be"

mkdir -p tools
if [ ! -f "$TAIE_JAR" ]; then
  echo "Downloading Tai-e ${TAIE_VERSION} ..."
  curl -fL --retry 3 -o "$TAIE_JAR" "$TAIE_URL"
fi
if command -v shasum >/dev/null 2>&1; then
  got=$(shasum -a 256 "$TAIE_JAR" | awk '{print $1}')
else
  got=$(sha256sum "$TAIE_JAR" | awk '{print $1}')
fi
if [ "$got" != "$TAIE_SHA256" ]; then
  echo "Checksum mismatch for $TAIE_JAR (got $got)"; exit 1
fi
echo "Tai-e jar OK: $TAIE_JAR"

# Pinned Maven (CWE-Bench-Java built these subjects with Maven 3.5.x; Maven 3.9+ rejects some of
# their POMs, e.g. perfecto-plugin declares the same dependency twice). Verified with the .sha512
# file published next to the archive.
MAVEN_VERSION=$(sed -n 's/^ *maven_version: *"\{0,1\}\([0-9.]*\)"\{0,1\}.*/\1/p' config/experiment.yaml | head -1)
MAVEN_VERSION=${MAVEN_VERSION:-3.5.4}
MVN_DIR="tools/apache-maven-${MAVEN_VERSION}"
if [ ! -x "$MVN_DIR/bin/mvn" ]; then
  echo "Downloading Maven ${MAVEN_VERSION} ..."
  MVN_URL="https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz"
  curl -fL --retry 3 -o "tools/maven.tgz" "$MVN_URL"
  curl -fL --retry 3 -o "tools/maven.tgz.sha512" "${MVN_URL}.sha512"
  want=$(awk '{print $1}' tools/maven.tgz.sha512)
  if command -v shasum >/dev/null 2>&1; then got=$(shasum -a 512 tools/maven.tgz | awk '{print $1}');
  else got=$(sha512sum tools/maven.tgz | awk '{print $1}'); fi
  if [ "$want" != "$got" ]; then echo "Maven checksum mismatch"; exit 1; fi
  tar xzf tools/maven.tgz -C tools
  rm -f tools/maven.tgz tools/maven.tgz.sha512
fi
echo "Maven OK: $MVN_DIR"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example - fill in SOCLAAS_API_KEY (and JAVA*_HOME if auto-detection fails)."
fi

# Pick the Python environment to install into, in this order:
#   1. $PYTHON if set explicitly
#   2. an activated virtualenv ($VIRTUAL_ENV)
#   3. an activated conda environment ($CONDA_PREFIX), e.g. `conda activate nesy`
#   4. otherwise a project-local .venv (created here)
# A dedicated environment keeps openai/httpx/h11 from conflicting with other projects.
if [ -n "${PYTHON:-}" ]; then
  PY="$PYTHON"; ENV_KIND="custom ($PYTHON)"
elif [ -n "${VIRTUAL_ENV:-}" ]; then
  PY=python; ENV_KIND="virtualenv $VIRTUAL_ENV"
elif [ -n "${CONDA_PREFIX:-}" ]; then
  PY="$CONDA_PREFIX/bin/python"; ENV_KIND="conda env ${CONDA_DEFAULT_ENV:-$CONDA_PREFIX}"
  if [ "${CONDA_DEFAULT_ENV:-}" = "base" ]; then
    echo "WARNING: installing into the conda *base* environment. Prefer a dedicated one:"
    echo "    conda env create -f environment.yml && conda activate nesy"
  fi
else
  if [ ! -x .venv/bin/python ]; then
    echo "Creating virtual environment .venv ..."
    python3 -m venv .venv
  fi
  PY=.venv/bin/python; ENV_KIND="virtualenv .venv"
fi
echo "Installing into: $ENV_KIND"
"$PY" -m pip install --upgrade pip >/dev/null
"$PY" -m pip install -e ".[test,report]"
echo
"$PY" -m nesy check-env || true
echo
if [ "$PY" = ".venv/bin/python" ]; then
  echo "Activate the environment in every new terminal before using the project:"
  echo "    source .venv/bin/activate"
fi
