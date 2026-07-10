# OCTRA HFHE Challenge v2 — Public-Artifact Security Assessment

**Assessment date:** 2026-07-10

**Challenge repository:** https://github.com/octra-labs/hfhe-challenge

**Challenge commit:** `0d08e9622921e5930175a660df0061a65548972f`

**PVAC implementation:** https://github.com/octra-labs/pvac_hfhe_cpp

**Pinned PVAC commit:** `071b0e909c119de815e284b347c4bd979cb59ef3`
**Assessment status:** No public-only plaintext recovery achieved

## 1. Executive summary

We assessed OCTRA's public HFHE Challenge v2 with the stated winning condition: recover the plaintext of `secret.ct` using only the published files.

The assessment reproduced the official artifact parser and audit, independently parsed and reserialized the artifacts, analyzed the concrete C++ implementation, tested known and novel attack hypotheses, compared historical challenge generations, inspected public forks and pull requests, and reviewed applicable classical and quantum LPN literature.

We did **not** recover the plaintext or private key. No practical public-only confidentiality attack was identified.

The principal conclusion is that Challenge v2 successfully removes the public plaintext-guess oracle that broke v1. The two-layer wrapped text construction uses independent masks and a fresh additive wrapper. Under secure PRFs, secure randomness, and standard Pedersen commitment hiding, the published values do not provide a verifier for candidate plaintext blocks.

Confirmed lower-severity findings are:

1. Ciphertext count leaks a 15-byte interval for plaintext length.
2. `SHA256SUMS` contains a stale checksum for the subsequently edited `README.md`.
3. The supplied deserializer has robustness issues for adversarial malformed inputs.
4. `Layer::R_com` is computed in memory but omitted from v2 serialization, creating provenance and maintenance ambiguity.
5. Independent public reports identify proof/integrity weaknesses in other PVAC paths, but those paths and transcripts are absent from `secret.ct` and could not be composed into plaintext recovery.

## 2. Authorization and scope

This work was performed against an explicitly public cryptographic challenge published by OCTRA Labs.

In scope:

- Public challenge artifacts
- Public source code and Git history
- Public forks, pull requests, issues, releases, and documentation
- Local parsing, fuzzing, sanitizers, statistical analysis, algebraic analysis, and reduced-parameter experiments
- Read-only attempts to inspect public chain state

Out of scope:

- Unrelated wallets or accounts
- Credential theft or social engineering
- OCTRA infrastructure intrusion
- Denial of service or mainnet disruption
- Submission of malformed transactions
- Access to non-public files or systems

No challenge credentials were recovered, and no funds were moved.

## 3. Verified artifacts

The following challenge files matched OCTRA's published SHA-256 values:

| File | SHA-256 status |
|---|---|
| `manifest.json` | Match |
| `params.json` | Match |
| `pk.bin` | Match |
| `pvac_commit.txt` | Match |
| `secret.ct` | Match |
| `source/hfhe_bounty_artifact.cpp` | Match |
| `source/pvac_artifact_serialize.hpp` | Match |

`README.md` did not match the checksum file because the README was edited after the checksum entry was published. Git status was clean before local build artifacts were created.

Important artifact hash:

```text
secret.ct
5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab
```

The pinned implementation commit was independently checked out and confirmed:

```text
071b0e909c119de815e284b347c4bd979cb59ef3
```

## 4. Reproduction baseline

The supplied challenge utility was compiled against the pinned implementation and executed in `public-audit` mode.

Observed output:

```text
compatible = 1
wire_v3 = 1
wrapped = 1
public_nonzero = 1
zero_regression = 1
h_mixed_parity = 1
sigma_mixed_parity = 1
small_h_rank_full = 1
```

This confirms:

- Public key and ciphertext compatibility
- Version 3 wire encoding
- Two-layer wrapped text encoding
- Nonzero public base-layer aggregates
- The wrapped-zero regression defense
- Mixed public-matrix and sigma parity
- Full rank in the supplied small-rank regression

An independent full artifact audit additionally found:

- `secret.ct`: 22 valid length-prefixed ciphertexts
- 44 BASE layers and zero PROD layers
- 1,829 edges
- No trailing bytes
- Canonical byte-for-byte deserialization/reserialization
- `H` rank: 8192/8192
- No duplicate `H` columns
- No repeated base-layer seeds or 128-bit nonces
- No repeated Pedersen commitments
- No repeated weight or sigma vectors
- No out-of-range edge indices
- No invalid tail bits
- All public layer sums distinct

## 5. Scheme model relevant to confidentiality

For each base layer, public edge aggregation reveals a masked field value:

```text
N_l = sum(sign(e) * e.w * g[e.idx]) = R_l * v_l
```

For the wrapped text representation, a plaintext field block `v` is represented by two independently encrypted layers:

```text
N0 = R0 * (v + m)
N1 = R1 * (-m)
```

where:

- `m` is a fresh random field mask
- `R0` and `R1` are independently derived secret masks
- each layer uses a distinct public nonce/seed
- each serialized `PC` is a Pedersen commitment to mask-related secret data with secret-derived blinding

Given `R0` and `R1`, decryption is immediate:

```text
v = N0 / R0 + N1 / R1
```

The public artifact does not reveal either mask and does not expose a public predicate for checking candidate values.

## 6. Confirmed finding: plaintext-length interval leakage

`enc_text` emits:

1. One encrypted plaintext-length value
2. One ciphertext for each 15-byte payload block

The bundle contains 22 ciphertexts, therefore it contains 21 payload blocks.

Confirmed leakage:

```text
301 <= plaintext length <= 315 bytes
```

This is metadata leakage, not plaintext recovery. The exact length remains encrypted, and all 15 candidate lengths remain publicly indistinguishable in our tests.

**Suggested severity:** Informational/Low

**Recommendation:** Pad plaintexts to a fixed public size class, or include dummy blocks so the number of payload blocks does not reveal a narrow length interval.

## 7. v1 oracle regression analysis

Challenge v1 serialized an `R_com` value that allowed structured plaintext guesses to be checked offline:

1. Compute public numerator `N`.
2. Guess plaintext `m'`.
3. Compute candidate mask `R' = N / m'`.
4. Recompute the public commitment/hash.
5. Compare it to serialized `R_com`.

Challenge v2 prevents this attack in two ways:

- `R_com` is omitted from the supplied v2 serializer.
- Text values are wrapped across two independently masked layers.

For any candidate block `v`, there are mask/wrapper assignments consistent with the observed public pair. No candidate-checking oracle was found.

## 8. Attack matrix

| Attack surface | Result |
|---|---|
| v1 `R_com` plaintext-guess oracle | Not available on v2 wire format |
| Public zero oracle | Neutralized by wrapped text encoding |
| Two-layer mask cancellation | Falsified under independent masks |
| Cross-block nonce/mask reuse | No reuse observed |
| Low-entropy encrypted length attack | All 15 candidates publicly indistinguishable |
| Pedersen commitment relation attack | Independent blinding prevents candidate checking |
| Public matrix rank defect | Full rank, 8192/8192 |
| Duplicate matrix columns | None observed |
| Fixed parity invariant | Mixed parity confirmed |
| Edge/sigma structural leakage | No plaintext relation found |
| Serialization trailing data | None |
| Uninitialized memory/padding leak | None found |
| ASan/UBSan on exact public-audit path | No findings |
| Historical key/RNG reuse | None across three v2 generations |
| Sibling artifact secret-key reuse | Not observed |
| Git history plaintext/secret leak | Not found in reachable history |
| Public fork/PR solver | No working v2 recovery found |
| Known native-reset/proof flaws | Relevant transcripts absent; no confidentiality composition found |
| Classical LPN attacks | Required public `(A,y)` samples are not exposed |
| Quantum LPN learning | Requires coherent example-oracle access not supplied by a static artifact |
| Generic Grover search | Still infeasible |

## 9. LPN/PRF assessment

The relevant masking function does not expose a conventional public LPN instance. Dense matrices, noise bits, and Toeplitz extraction are generated inside a secret-keyed AES-derived process. The ciphertext edges do not provide the explicit `(A, y = As + e)` samples required by BKW, coded-BKW, LF/FWHT, covering-code, or ISD-style attacks.

Reduced-parameter statistical tests over 4,096 seeds produced:

```text
Output one-rate:                 0.500150
Single-secret-bit avalanche:    0.500394
Adjacent-output equal-bit rate: 0.499763
```

All measured deviations were below 0.57 standard deviations.

Generic search bounds remain prohibitive:

- 256-bit PRF-key search: approximately `2^256` classically or `2^128` Grover iterations
- Full nominal secret material: 256-bit PRF key plus 4,096-bit LPN secret
- A static ciphertext does not provide coherent quantum oracle access

The implementation's `n * H2(1/8)` entropy expression should not be presented as a concrete solver work factor. It is an entropy quantity, not a complete cryptanalytic cost estimate.

## 10. Historical-generation and RNG assessment

Three distinct v2 generations were inspected:

```text
08bf879dd9e9aff094e4106ee5d86dde9de12742
e4645c97712542c875b7d2d8d53ac9b78b61af3f
88a72b703f4cdd26b5fe6b3249850c2cbcef3b43
```

Across generations, no intersections were found among:

- BASE seeds
- 128-bit nonces
- Pedersen commitments
- sigma vectors
- edge-weight vectors
- canonical tags

The implementation uses Linux `getrandom(2)` with `/dev/urandom` fallback. No timestamp, PID, `rand()`, or Mersenne Twister seed was identified in challenge generation. The challenge generator calls nondeterministic `keygen`, not deterministic `keygen_from_seed`.

Earlier v2 artifacts used different keys and ciphertexts, so they do not create a same-key related-plaintext pair.

## 11. C++ and serialization robustness findings

### 11.1 Pointer-arithmetic robustness

`Reader::need()` evaluates a pointer addition before checking bounds:

```cpp
if (p + n > end) fail("pvac_ser: truncated");
```

For attacker-controlled extreme lengths, `p + n` can itself invoke undefined behavior. A safer check is based on remaining length:

```cpp
if (n > static_cast<size_t>(end - p))
    fail("pvac_ser: truncated");
```

### 11.2 Exact EOF enforcement

Individual deserializers do not always enforce exact end-of-input internally. The outer challenge bundle does enforce framing, and the published artifacts reserialize byte-identically, so this was not exploitable here.

Recommendation: require `remaining() == 0` at the end of every top-level deserializer.

### 11.3 Canonical field encoding

The reader masks the top field bit on input rather than rejecting all noncanonical encodings. This did not affect the canonical published artifacts.

Recommendation: reject noncanonical field encodings explicitly before normalization.

### 11.4 `R_com` lifecycle ambiguity

`Layer::R_com` is computed and consumed by some in-memory/proof paths but omitted from the v2 artifact serializer. Deserialization therefore produces default-zero `R_com` state while retaining serialized `PC` values.

This omission is intentional for v2 confidentiality, but the mixed lifecycle is easy to misuse.

Recommendations:

- Separate wire-layer types from internal proof-layer types.
- Remove `R_com` from confidentiality-sensitive public artifact objects entirely.
- Version serializers around an explicit schema.
- Add regression tests asserting that no secret-checkable mask commitment is emitted.

### 11.5 Independent Rust wire-format differential audit

To avoid reproducing C++ parser assumptions, a dependency-free Rust parser was implemented without including or calling OCTRA's serializer. It independently validates bundle/member framing, exact EOF, layer rules, product parents, canonical 127-bit field encodings, edge references and signs, slot/weight consistency, bit-vector sizes and tail bits, and BASE-layer nonce uniqueness.

The Rust unit tests passed, release compilation succeeded, and the real artifact produced:

```text
wire_audit=PASS
ciphers=22
layers=44 base=44 product=0
edges=1829 commitments=44
unique_nonces=44 duplicate_nonces=0
```

The result matches the C++ parser and structural audit exactly. No endianness, integer-width, canonicalization, framing, or language-specific discrepancy was found.

## 12. Public proof/integrity issues and challenge applicability

Public PVAC discussions report issues involving native-reset digests, proof binding, forged admissions, and noncanonical Ristretto handling. We evaluated whether those weaknesses could be composed into a confidentiality attack against this challenge.

The published bundle contains ordinary `Cipher` records only. It contains no native-reset statements, reset proofs, certificates, openings, evaluation keys, or proof transcripts. Forging or weakening those external proof paths does not create a decryption oracle for the static challenge artifact.

These issues may still warrant remediation in their own affected contexts, but no route to Challenge v2 plaintext was demonstrated.

## 13. Public ecosystem review

We inspected:

- The canonical challenge history
- Four public pull-request refs
- 26 public forks
- Divergent fork commits
- Indexed exact target-address and ciphertext-hash references

No working v2 solver or recovered plaintext was found.

Some repositories use filenames such as `plaintext_recovery.cpp`, but their implementations only parse structures and print statistics. They do not perform key or plaintext recovery.

## 14. Higher-order and automated invariant experiments

To test whether scalar audits missed a joint correlation, we implemented three additional experimental attacks.

### 14.1 Four-dimensional tensor/hypergraph experiment

Each ciphertext was projected into a 2,000-dimensional sketch spanning four coupled axes:

1. Cipher/layer position
2. Subgroup index and sign Fourier mode
3. Field-weight projection
4. Sigma/public-matrix geometry projection

The test used 192 fresh production-parameter encryptions across 16 plaintext-byte classes, with 12 independent repetitions per class. Evaluation used leave-one-repetition-out validation and 300 label permutations.

Results:

```text
Payload prediction:          9/192 = 4.69%
Random-chance baseline:              6.25%
Permutation p-value:                 0.714

Length-control prediction:  13/192 = 6.77%
Permutation p-value:                 0.289
```

A smaller preliminary run produced a borderline result, but it disappeared when the control set was doubled, identifying it as sampling noise. Applying the non-generalizing classifier to the real artifact produced near-uniform confidence: mean maximum softmax 0.0708 versus 0.0625 for a uniform 16-class prediction.

No reproducible tensor or higher-order hypergraph signal predicted plaintext.

### 14.2 Order-337 subgroup and character projections

The field basis uses a multiplicative subgroup of order 337. We tested whether multiplicative-character or quotient projections could remove mask entropy or distinguish plaintext classes.

Tests included:

- Quotient map `Q(x) = x^337`
- All 337 subgroup-character/DFT evaluations for every real layer
- Wrapped-layer ratios
- Normalized character ratios
- Exact cancellations and cross-layer collisions
- Pedersen field-to-scalar reduction interactions

Real-artifact results:

```text
Character values tested:              14,828
Exact cancellations:                       0
Same-coordinate cross-layer collisions:    0
Unique quotient projections:            44/44
Unique wrapped-layer ratios:             22/22
Unique normalized signatures:            44/44
```

An exhaustive toy control correctly detected total leakage when masks were artificially restricted to the small subgroup. With full-field independent masks matching v2, plaintext-class total variation distance was 0.0.

The 127-bit field embeds injectively into the approximately 252-bit Ristretto scalar field, so scalar reduction does not introduce an order-337 collision. No subgroup attack was found.

### 14.3 Automated public-invariant discovery

An automated feature-synthesis pipeline generated and decrypt-verified:

- 480 reduced-parameter encryptions across six independent keys
- 96 production-parameter encryptions across two independent keys

It synthesized 1,104 public expressions, including:

- Bit and residue projections
- Cross-layer sums, differences, ratios, and products
- Degree-two field expressions
- Public edge and layer aggregate combinations

The analysis used key-disjoint train/test splits, permutation p-values, and Benjamini-Hochberg false-discovery-rate correction.

No feature survived FDR 0.05 in either parameter regime. Nominal training correlations failed on unseen keys. The result is a negative finding for the searched expression grammar, not a formal proof against every possible invariant.

Supporting artifacts:

```text
tensor_v2_experiment.cpp
analyze_tensor_v2.py
tensor_v2_results.json
hfhe_subgroup_projection_audit.cpp
hfhe_subgroup_toy.py
hfhe-subgroup-projection-report.md
invariant_discovery/
```

### 14.4 Brute force through OCTRA's own wallet derivation

The public target address provides an exact verifier for candidate wallet mnemonics. OCTRA's official wallet generator uses 128 bits of entropy to produce a 12-word BIP39 mnemonic, then derives the address as:

```text
entropy128 -> BIP39 mnemonic
seed64     = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048)
private32  = HMAC-SHA512("Octra seed", seed64)[0:32]
public32   = Ed25519 public key from private32
address    = "oct" + Base58(SHA256(public32))
```

If the v2 challenge wallet was generated through this path, direct address inversion has a `2^128` entropy search space. This bypasses HFHE conceptually but remains computationally infeasible.

A bounded exact-derivation search tested 1,000 entropy candidates against the real target address:

```text
Candidates:             1,000
Elapsed:                 7.242470228 seconds
Measured rate:           138.074 candidates/second
Match:                   none
```

At the measured single-process rate, expected half-space search time is approximately `3.90e28` years. Even an implementation sustaining `10^15` complete derivations per second would require approximately `5.39e15` years on average. A one-year average search would require approximately `5.39e30` complete derivations per second.

The PBKDF2 cost can be optimized substantially on GPUs or custom hardware, but no plausible classical optimization closes the remaining gap. Generic Grover search reduces a 128-bit search to roughly `2^64` coherent iterations, but requires a fault-tolerant quantum implementation of BIP39 PBKDF2, HMAC-SHA512, Ed25519, SHA-256, and address comparison; no such practical system is available.

Reproduction script:

```text
wallet_entropy_bruteforce.mjs
```

This route becomes practical only if generation entropy was weak, biased, truncated, reused, or human-selected. Historical/source review found OS CSPRNG generation and no evidence of those failures.

## 15. Recommendations

1. Preserve the two-layer independently masked wrapper.
2. Keep all candidate-checkable mask commitments off the public wire format.
3. Add fixed-size or bucketed padding for text payloads.
4. Make every serializer version explicit and canonical.
5. Enforce exact EOF and canonical field encodings.
6. Replace pointer-addition bounds checks with remaining-length checks.
7. Separate proof/reset objects from ordinary ciphertext objects at the type level.
8. Add release CI that regenerates and verifies `SHA256SUMS` after documentation changes.
9. Publish a formal security argument for the wrapper and clearly state its assumptions.
10. Distinguish entropy estimates from concrete LPN attack-cost estimates in documentation.
11. Maintain dedicated tests for:
    - v1 candidate-guess oracle regression
    - wrapped-zero indistinguishability
    - nonce uniqueness
    - serialization omission of mask-checking material
    - canonical parse/serialize round trips
    - malformed length handling

## 16. Conclusion

No public-only plaintext recovery attack was found for OCTRA HFHE Challenge v2 at the assessed commits.

The evidence indicates that v2 materially improves confidentiality over v1. In particular, the combination of omitting `R_com` from the public artifact and wrapping each field block across two independently masked layers removes the previously exploitable offline guess verifier.

This conclusion is conditional on:

- the security of the secret-keyed PRF/AES-derived process
- the independence and quality of operating-system randomness
- standard Pedersen/Ristretto hiding assumptions
- the absence of non-public generation failures

The assessment does not claim a formal proof of the complete PVAC system. It reports that extensive public-artifact analysis found no practical path to the challenge plaintext and documents the tested attack surfaces and residual engineering findings.

## 17. Reproduction artifacts

Local supporting artifacts generated during the assessment:

```text
hfhe_v2_structural_audit.cpp
hfhe_v2_structural_audit
prf_r_audit.cpp
prf_r_audit
HFHE_V2_CIPHERTEXT_ALGEBRA.md
hfhe_ciphertext_algebra_toy.py
length_framing_probe.cpp
length_framing_probe
RNG_HISTORY_REPORT.md
analyze_artifact_history.sh
cross_artifact_rng.cpp
cross_artifact_rng
hfhe-v2-algorithm-assessment.md
```

Before public upload, portable source artifacts should be copied into a clean repository, absolute local paths should be removed, and generated binaries/history blobs should be excluded.

## 18. References

- OCTRA HFHE Challenge v2: https://github.com/octra-labs/hfhe-challenge
- OCTRA `pvac_hfhe_cpp`: https://github.com/octra-labs/pvac_hfhe_cpp
- Public v1 recovery: https://github.com/Iamknownasfesal/octra-hfhe-challenge-recovery
- BKW Meets Fourier: New Algorithms for LPN with Sparse Parities: https://eprint.iacr.org/2021/994
- Algorithms for Sparse LPN and LSPN Against Low-noise: https://arxiv.org/abs/2407.19215
- Solving LPN Using Covering Codes: https://doi.org/10.1007/s00145-019-09338-8
- OCTRA RPC documentation: https://docs.octra.org/developer-docs/rpc-scheme
