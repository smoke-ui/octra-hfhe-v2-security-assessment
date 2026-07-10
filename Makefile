SHELL := /usr/bin/env bash

.PHONY: setup verify test run lint clean

setup:
	./scripts/setup.sh

verify:
	./scripts/verify-artifacts.sh

test:
	cd tools/rust-wire-audit && cargo test
	python3 -m compileall -q tools scripts
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
