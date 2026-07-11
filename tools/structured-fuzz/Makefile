SHELL := /bin/bash
CXX := clang++-18
ROOT := ../..
INCLUDES := -I$(ROOT)/.deps/pvac_hfhe_cpp/include -I$(ROOT)/.deps/hfhe-challenge/source
COMMON := -std=c++20 -maes -msse4.1 -Wall -Wextra -Werror $(INCLUDES)
.PHONY: all test fuzz-smoke clean
all: build/structured_runner build/seed_generator build/libfuzzer_target
build:
	mkdir -p $@
build/structured_runner: structured_runner.cpp harness.hpp | build
	$(CXX) $(COMMON) -O2 $< -o $@
build/seed_generator: seed_generator.cpp harness.hpp | build
	$(CXX) $(COMMON) -O2 $< -o $@
build/libfuzzer_target: libfuzzer_target.cpp harness.hpp | build
	$(CXX) $(COMMON) -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined $< -o $@
test: all
	python3 test_structured_fuzz.py
	./build/structured_runner > build/classifications.json
fuzz-smoke: test
	@set -o pipefail; ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 ./build/libfuzzer_target -max_total_time=30 -timeout=5 -rss_limit_mb=2048 build/corpus 2>&1 | tee build/fuzz-smoke.log
clean:
	rm -rf build
