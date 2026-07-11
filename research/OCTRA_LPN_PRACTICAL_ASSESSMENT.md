# OCTRA published-LPN practical assessment (commit `d9d29d5`)

## Evidence and scope

The 44 files at challenge commit `d9d29d505e2840c0028d7a91a2a8ba59e163b9a4` each contain 16,384 equations with `n=4096`, `tau=1/8`. The reproducible audit in `tools/lpn-samples-audit/` verifies all 44 relevant entries in the pinned `SHA256SUMS` manifest. This is 720,896 equations total (176 equations per secret bit).

**The intended construction uses one shared secret `S`, not 44 secrets.** At pinned implementation commit `071b0e909c119de815e284b347c4bd979cb59ef3`, `include/pvac/crypto/keygen.hpp:150-160` allocates and samples exactly one dense, uniform `sk.lpn_s_bits`. `include/pvac/crypto/lpn.hpp:335-373` accepts that `SecKey` and, for every seed/domain, generates fresh rows/noise but computes every label against `sk.lpn_s_bits`. The challenge creates one `SecKey`, and the README uses singular “recover S.” The 44 headers have 44 distinct seed/nonce tuples and 44 distinct `public_T` values, consistent with fresh streams under one key.

Important qualification: the added verifier is **not a cryptographic binding of equation bodies**. `source/tools/verify_lpn_sample_binding.cpp:46-51,103-110,169-180` reads only the first metadata line and matches seed/nonce/`public_T` to a ciphertext target. It never parses or regenerates any `a` or `y` row. SHA256SUMS authenticates the repository files, but the verifier alone would accept arbitrary row bodies under an authentic header. A generator or a verifier that checks every equation is needed to independently establish that the rows implement the pinned secret-key computation. Without recovering `S`, the data alone cannot distinguish “one shared S” from labels made with separate random secrets; the shared-S conclusion is source/publisher evidence, not an independently verified algebraic fact.

## Reproducible structural audit

Commands:

```bash
python3 tools/lpn-samples-audit/test_audit.py
python3 tools/lpn-samples-audit/audit.py \
  --challenge-repo .deps/hfhe-challenge \
  --pvac-repo .deps/pvac_hfhe_cpp \
  --output tools/lpn-samples-audit/results/lpn-samples.json --check-output
```

The committed result validates exact schemas, row indices, lowercase hex widths, filename coordinates, metadata uniqueness, and all 720,896 rows. Every one of the 44 matrices has exact GF(2) `rank(A)=4096` and `rank([A|y])=4097`. Exact complete-row comparison found zero duplicate `A` rows and zero duplicate `(A,y)` rows; this is byte equality over all 512 bytes, not a truncated-hash claim. Across 2,952,790,016 matrix bits, the one fraction is 0.4999853779 (`z=-1.5891` against 1/2); the label fraction is 0.4996892756 (`z=-0.5276`). The archived official verifier passes 44/44 metadata headers, with the equation-body limitation stated above. Timing is intentionally excluded from committed evidence.

A separate deterministic, non-validating exploratory control is reproduced with:

```bash
python3 research/lpn_practical_benchmark.py /path/to/lpn_samples \
  --limit-per-file 16384 --bucket-bits 16 \
  > research/lpn_practical_benchmark.json
```

It fills all 65,536 buckets and records 655,360 first-row bucket cancellations. The first 10,000 residual rows have mean weight 2039.6221 and population standard deviation 32.342642, matching the dense-random expectation of 2040 remaining ones after forcing 16 coordinates to zero. The benchmark's SHA-256 duplicate screen is only a compact corroborating check; the publication's exact duplicate claim comes from the full-byte SQLite comparison in the main audit.

## Practical algorithm assessment

### BKW and coded-BKW

Combining `k` independent equations changes noise to

`q_k = (1-(1-2 tau)^k)/2`, with bias `(1-2 tau)^k = 0.75^k`.

For `k=8,16,32`, noise is respectively 0.44994, 0.494989, 0.4999498; the rough samples needed merely for unit correlation SNR (`bias^-2`) are about 100, 9,955, and 99.1 million. Plain block BKW with block size 16 has 256 blocks/stages; after only 16 original samples per reduced equation its bias is already ~0.0100. The available 720,896 shared-secret rows materially improve over one file, but they do not support hundreds of reduction stages before the signal vanishes.

Coded-BKW/sieving trades imperfect cancellation and decoding work for fewer additions and is the most sensible BKW family to test, but no realistic parameterization is established here. It must be benchmarked with a restricted-sample estimator using exactly `(n,m,tau)=(4096,720896,1/8)`, not an asymptotic/unlimited-sample estimate. Any claimed feasible run must output predicted memory, additions, terminal dimension/bias, and verification cost.

### LF / Walsh-correlation

Direct Walsh recovery is a transform over `2^4096` candidates. Guessing `k` coordinates costs `2^k`, while marginal correlation of a single coordinate is zero for a dense unknown secret because the remaining random parity masks it. LF/FWHT becomes useful only after dimension reduction; BKW reduction sufficient to make (say) a 40–60-bit terminal Walsh search also drives noise toward 1/2. The extra 44-instance sample count helps terminal statistics only if a preceding reduction preserves measurable bias.

### ISD / clean-subset variants

Viewing recovery as syndrome decoding gives a random binary code of length 16,384 with an error of expected weight 2,048 and 4,096 secret variables. A basic “choose 4096 noise-free equations, solve, verify” trial succeeds with

`C(14336,4096)/C(16384,4096) ~= 2^-918.25`.

Modern ISD improves substantially over this naive bound, but this remains a dense random-code decoding instance at large length; no bounded experiment suggests practicality. Reports should use an actual binary-ISD estimator for `(length=16384, redundancy=12288, weight≈2048)` and state conventions, rather than calling `n*H2(tau)=2226.44` a solver cost. That number is only an entropy expression and is not a concrete attack estimate.

### Sparse combinations

Rows are dense and the secret is dense/uniform. Pair collisions conditioned on 16 canceled coordinates left the other 4,080 coordinates statistically dense in the bounded control. Searching pairs/triples for unusually low total Hamming weight faces random-code tails, while XORing more labels rapidly destroys bias. Sparse-LPN algorithms that assume sparse samples or a sparse secret do not apply directly. A useful experiment must include a random-matrix null with identical dimensions and correct for all combinations searched.

### Multi-instance aggregation

Under the source-supported shared-S interpretation, concatenate all 44 files; do **not** solve them independently. Their distinct seed/nonces imply independent-looking row/noise streams, so aggregation raises `m` from 16,384 to 720,896. There is no evidence of repeated rows or stream overlap. Cross-file subtraction has no special cancellation beyond ordinary LPN sample combination. If the files actually used separate secrets, concatenation would produce labels statistically indistinguishable from random and every solver should fail; this makes held-out-file prediction a strong test of any candidate S.

## Realistic conclusion

No evaluated classical route is currently practical on commodity hardware. Aggregation is a real and important improvement (176n samples), but not a demonstrated break at `n=4096,tau=1/8`. The most credible next work is restricted-sample coded-BKW parameter search plus reduced-dimension end-to-end controls—not direct FWHT, naive clean-subset ISD, or uncorrected sparse-combination mining.

## Falsifiable next experiments

1. **Fix equation binding:** publish/build a deterministic checker that parses all 720,896 rows and, with an authorized private fixture or committed generation transcript, regenerates `A,y`; mutation of any body row must fail. The current tool will not.
2. **Shared-S held-out test:** any candidate solver trains on 43 files and reports residual error on the untouched 44th. Shared correct S predicts approximately 1/8 error; separate-S or overfit predicts approximately 1/2. Pre-register the held-out file.
3. **Reduced planted controls:** generate shared-S instances at `n=128,256,512` with fixed `m/n=176,tau=1/8`; run the exact proposed BKW/coded-BKW pipeline and verify recovered S and scaling. Include separate-S negative controls.
4. **Restricted-sample coded-BKW sweep:** enumerate block sizes, code dimensions/radii, stages, retained samples, predicted bias and RAM; reject settings needing more than 720,896 source rows or terminal sample demand exceeding retained rows.
5. **ISD estimate and one bounded control:** run a named/versioned binary syndrome-decoding estimator at the exact parameters, then validate its convention on reduced planted instances. Reject extrapolation if measured exponents do not track predictions.
6. **Sparse-tail control:** search the same bounded pair/triple family on OCTRA and deterministic random matrices; report minimum weights with family-wise correction. A useful anomaly must replicate and yield better label bias than the null.
7. **Candidate verification:** for any alleged S, report per-file residual weights, exact aggregate residual weight, and binomial z-scores. A true shared S should produce 44 consistent near-1/8 rates, not merely a favorable training score.
