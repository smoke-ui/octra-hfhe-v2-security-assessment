# §10 Peg Deep-Correlation Audit

Fail-closed analysis of the three pinned HFHE v2 generations. The orchestrator verifies normalized GitHub origins and exact commit objects, extracts artifacts by object ID, and compiles the analyzer **only** against safely extracted immutable `git archive` snapshots: PVAC `include/` at `071b0e909c119de815e284b347c4bd979cb59ef3` and the challenge serializer at `0d08e9622921e5930175a660df0061a65548972f`. Working-tree headers are never used. Output records source blob IDs and artifact SHA-256 digests, not paths or raw objects.

## Run and reproduce

```sh
python3 -m unittest -v test_audit.py
python3 audit.py \
  --challenge-repo ../../.deps/hfhe-challenge \
  --pvac-repo ../../.deps/pvac_hfhe_cpp \
  --output results/s10-pegs.json
python3 audit.py \
  --challenge-repo ../../.deps/hfhe-challenge \
  --pvac-repo ../../.deps/pvac_hfhe_cpp \
  --output results/s10-pegs.json --check-output
```

`--check-output` recompiles the pinned native analyzer, regenerates and validates the complete deterministic document, then requires byte-for-byte equality with the supplied output. The build is always from the audited `deep_corr.cpp`; accepting an externally supplied binary is intentionally unsupported. The output binds SHA-256 digests of both analyzer sources and records compiler executable/identity/target, compile flags, and architecture. Subprocesses use argument lists without a shell. Tar members are rejected if they escape the destination or are links/devices.

## Native validation and alignment

The native parser checks bundle magic, member count and bounds, trailing bytes, `B=337`, `m=8192`, `n=16384` (the H cardinality), H/power/permutation dimensions, H and sigma word sizes, cipher slot/layer rules, PC cardinality, and every edge layer/index/sign/weight. Empty or unequal vectors fail before correlation or summary operations.

For each generation it finds the invertible exponent `d` such that that generation's public `omega_B` equals `peg0.powg_B[d]`. Edge index `idx` is mapped to `(d*idx) mod 337`; all character evaluations use peg0's power table. The document publishes all three maps and the complete `3 generations / 40 ciphertexts / 80 layers / 26,960 character values` scan with six collision counters.

## Evidence and statistics

* Pair evidence gives exact full-object intersections for `(ztag,nonce)` seeds, nonces, PCs, sigma vectors, and weights, plus partial nonce comparisons and ztag mismatch counts. Artifact records include canonical-tag verification summaries, object counts, edge-index chi-square statistics, sign z-scores, hashes, and source blobs. No unsupported p-values are attached to chi-square or z statistics.
* H baselines use realized per-artifact weight histograms. Pair expectation is `mean_i[1-w_i/N-w_j/N+2*w_i*w_j/N²]`; the independent uniform 192/193 model is retained separately as an unconditional reference.
* Nearest-neighbor simulations are compact, deterministic, and explicitly **descriptive only**. There is no arbitrary materiality threshold or significance flag.
* Commitment proximity uses a 50,000-trial Monte Carlo label-permutation test. Labels are shuffled while preserving group sizes; each reported one-sided p-value uses the plus-one estimator `(extreme + 1) / (50,000 + 1)`, whose minimum attainable value and resolution are `1/50,001 ≈ 0.000020`. Three peg pairs are reported; none is below the stated Bonferroni threshold `0.0167`.

The committed result is under 100 KB and contains no raw arrays, artifact names, filesystem paths, or secret-material markers.
