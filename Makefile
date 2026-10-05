# Common setup, analysis and reporting commands; see README.md.
PY ?= python3
SUBJECT ?= all

.PHONY: setup check test test-fast demo run evaluate labels

setup:            ## download Tai-e, install Python deps, check environment
	bash scripts/setup_tools.sh

check:            ## check Java, Tai-e, Maven and the LLM endpoint
	$(PY) -m nesy check-env --llm

test:             ## full suite, including Java and Tai-e fixture tests
	$(PY) -m pytest -q

test-fast:        ## exclude marked integration tests; other tests may still need Java or Tai-e
	$(PY) -m pytest -q -m "not integration"

demo:             ## end-to-end on the bundled fixture with the offline mock LLM
	$(PY) -m nesy demo

run:              ## whole study for SUBJECT (default: all primary subjects)
	bash scripts/run_all.sh $(SUBJECT)

labels:
	$(PY) -m nesy label-sheet $(SUBJECT)

evaluate:
	$(PY) -m nesy evaluate
