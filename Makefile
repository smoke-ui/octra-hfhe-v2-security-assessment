SHELL := /usr/bin/env bash
PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: setup verify verify-mobius test run lint clean

setup:
	./scripts/setup.sh

verify:
	./scripts/verify-artifacts.sh

verify-mobius:
	./scripts/verify-mobius.sh

test:
	cd tools/rust-wire-audit && cargo test
	$(PYTHON) -m unittest -v tools/lpn-samples-audit/test_audit.py
	$(PYTHON) -m unittest -v tools/mobius-sequencing/test_mobius.py
	$(PYTHON) -m unittest -v tools/mobius-sequencing/test_lpn_experiment.py
	$(PYTHON) -m unittest -v tools/mobius-sequencing/test_field_experiment.py
	$(PYTHON) -m unittest -v tools/mobius-sequencing/test_hypergraph_experiment.py
	$(PYTHON) -m compileall -q tools scripts
	bash -n scripts/*.sh

run:
	./scripts/run-all.sh

lint:
	cd tools/rust-wire-audit && cargo fmt --check
	git diff --check
	git diff --cached --check
	git show --check --format= HEAD

clean:
	rm -rf build .deps .venv .env.paths results/latest tools/rust-wire-audit/target
