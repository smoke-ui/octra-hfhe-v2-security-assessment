CXX ?= g++
PVAC_DIR ?= ../../.deps/pvac_hfhe_cpp
CPPFLAGS := -I$(PVAC_DIR)/include
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra -Wpedantic -pthread -maes -mpclmul
BUILD := build

.PHONY: all tsan test probes clean
all: $(BUILD)/timing_probe $(BUILD)/concurrency_probe

$(BUILD):
	mkdir -p $@

$(BUILD)/timing_probe: timing_probe.cpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< -o $@

$(BUILD)/concurrency_probe: concurrency_probe.cpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< -o $@

$(BUILD)/concurrency_probe_tsan: concurrency_probe.cpp | $(BUILD)
	$(CXX) $(CPPFLAGS) -std=c++17 -O1 -g -pthread -maes -mpclmul -fsanitize=thread -fno-omit-frame-pointer $< -o $@

tsan: $(BUILD)/concurrency_probe_tsan

test:
	python3 test_runtime_probes.py -v

probes: all
	./run_probes.sh

clean:
	rm -rf $(BUILD)
