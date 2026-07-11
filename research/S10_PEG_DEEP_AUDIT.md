# Section 10 historical-generation peg deep audit

## Scope

This follow-up expands REPORT §10 around the three reachable v2 artifact-generation pegs:

| Peg | UTC commit time | Cipher objects | Public-key SHA-256 | Ciphertext SHA-256 |
|---|---|---:|---|---|
| `08bf879dd9e9aff094e4106ee5d86dde9de12742` | 2026-07-09 18:48:59 | 9 | `ad5f2ecab6d71ffaaf1e363ed3b6aefc7ac1de4156a6189f8ff9ee720305a865` | `8f38ed7706cca15fa5208de905cf3ee4456fafc3c72068d26ea46ac7b6fa3300` |
| `e4645c97712542c875b7d2d8d53ac9b78b61af3f` | 2026-07-09 20:33:45 | 9 | `2ebc2a258a291ad2136926c1b5f5a787a37a4499e6bdad492d9a5c3362cfc003` | `1f48fae52859e3f21011a565f40348e21b4ed3aaa07b1b404d58a4fc6c0456d4` |
| `88a72b703f4cdd26b5fe6b3249850c2cbcef3b43` | 2026-07-09 21:08:01 | 22 | `1e788edff9dea19a782defae053f3757ccf5edd41cd3e24ae44e1496045e9410` | `5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab` |

All three pin PVAC commit `071b0e909c119de815e284b347c4bd979cb59ef3`. The goal was to test whether closely spaced regenerations preserve weak state or algebraic relations missed by exact-intersection checks.

## Historical reconstruction

The pegs form a linear history, not independent forks.

- `08bf879` introduced the v2 challenge. Its generator independently read `/dev/urandom` for a six-digit email suffix and a 32-byte secret, producing a fixed 110-byte template. It then called nondeterministic production `keygen` and `enc_text`.
- `e4645c9` replaced the generated template with a private `plaintext.txt`, regenerated both key and ciphertext, and retained ordinary nondeterministic `keygen`.
- `88a72b7` has generator, serializer, parameters, and manifest blobs identical to `e4645c9`. It regenerated `pk.bin` and `secret.ct`; the bundle grew from 9 to 22 objects. The final plaintext length is therefore 301–315 bytes.
- The apparent `pvac_commit.txt` change at the final peg is newline-only.
- The final key/ciphertext pair remains byte-identical through later reachable history.

No reachable generator uses `keygen_from_seed`. On Linux, production randomness uses `getrandom(2)` with `/dev/urandom` fallback. Commit timestamps are not generator inputs.

## Tests performed

1. Git chronology and source/blob identity across each transition.
2. Artifact hash and object-count reproduction from clean Git archives.
3. Exact cross-generation intersections for BASE seeds, 128-bit nonces, commitments, sigma vectors, and edge-weight vectors.
4. Partial nonce reuse at 64-bit halves and 32-bit prefix/suffix boundaries.
5. Directed nearest-neighbor Hamming distributions for nonces, compressed commitments, 8,192-bit sigma vectors, and 127-bit field weights.
6. Deterministic min-of-m binomial null simulations rather than incorrect pair-distance baselines.
7. 50,000-trial Monte Carlo label-permutation tests for compressed-commitment proximity.
8. UBK permutation positional agreement and value correlation.
9. Public `H` exact-column overlap and aligned-bit agreement under the actual 192/193 mixed-weight generator model.
10. Edge-index chi-square controls, sign balance, aligned-index equality, and aligned correlations.
11. Canonical-tag Hamming relations.
12. Order-337 subgroup-set alignment across public keys.
13. Exhaustive aligned-character collision scan over all 337 coordinates and all 80 historical layers.
14. Cross-key composition review for known-template, related-plaintext, LPN, PRF, commitment, matrix, quotient, and differential attacks.

## Results

### Exact and partial reuse

Across all three pairs:

- full seed intersections: 0;
- full nonce intersections: 0;
- commitment intersections: 0;
- sigma-vector intersections: 0;
- weight-vector intersections: 0;
- repeated 64-bit nonce halves: 0;
- repeated 32-bit nonce prefixes/suffixes: 0.

Every serialized canonical tag was recomputed as `prg_layer_ztag(pk.canon_tag, nonce)`: all 80 matched and zero mismatched. This is public domain-binding evidence, not hidden entropy.

### Nearest-neighbor controls

Observed nearest-neighbor means track the correct independent-bit min-of-m controls:

| Object | Comparison size | Null mean | Representative observed means |
|---|---:|---:|---:|
| 128-bit nonce | 18 candidates | 53.74 | 54.00–54.17 |
| 128-bit nonce | 44 candidates | 51.60 | 51.67–53.84 |
| 8,192-bit sigma | 531 candidates | 3957.72 | 3957.17–3958.23 |
| 8,192-bit sigma | 1,829 candidates | 3941.38 | 3941.90–3942.49 |
| 127-bit field weight | 531 candidates | 46.37 | 46.37–46.47 |
| 127-bit field weight | 1,829 candidates | 44.42 | 44.32–44.49 |

A pair-distance mean such as 64 for a 128-bit nonce is not the correct baseline after choosing the closest of many candidates.

Compressed commitments involving the final peg looked slightly close in the raw table, so a 50,000-trial Monte Carlo label-permutation test was added. Each trial shuffles labels while preserving group sizes. The one-sided p-values use the plus-one estimator `(extreme + 1) / (50,000 + 1)`, giving minimum attainable p-value and resolution `1/50,001 ≈ 0.000020`:

| Pair | Symmetric nearest mean | One-sided permutation p | Closest-pair p |
|---|---:|---:|---:|
| `08bf879` / `e4645c9` | 114.556 | 0.8699 | 0.8846 |
| `08bf879` / `88a72b7` | 109.140 | 0.0621 | 0.6686 |
| `e4645c9` / `88a72b7` | 109.664 | 0.1107 | 0.4178 |

None is significant after three pairwise comparisons. The isolated 96-bit minimum in the first/final comparison is not unusual under relabeling.

### Public-key structure

- UBK positional agreement is exactly 1 for every pair, matching the random-permutation expectation for 8,192 positions.
- UBK value correlations are `-0.002`, `0.015`, and `-0.013`, on the scale expected from independent permutations (`sd ≈ 0.011`).
- Public `H` matrices share zero exact columns.
- Aligned bit agreement is `0.954108760`, `0.954108395`, and `0.954111315`.
- The actual generator mixes column weights 192 and 193. Its independent-column expectation is `0.954107291996479`, so the observed agreement is explained by public sparse-matrix construction rather than state reuse.
- Edge-index chi-square statistics and sign-balance z statistics are retained in the machine-readable artifact as descriptive diagnostics; no p-values are claimed for them.

### Order-337 aligned-character scan

All three `powg_B` tables contain the same 337 field elements. This is expected: the multiplicative subgroup of order 337 in `Fp*` is unique. Different public generators only relabel that public subgroup.

After aligning this shared structure, the scan covered:

```text
generations=3
ciphertexts=40
layers=80
character_values=26,960
exact_zero=0
same_character_coordinate_collisions=0
public_sum_collisions=0
quotient_S1_pow_337_collisions=0
wrapped_ratio_collisions=0
normalized_S0_over_S1_collisions=0
```

Subgroup alignment is mathematically real but does not cancel the independently keyed full-field masks. The collision scan found no repeated quotient mask, character annihilation, or cross-generation cancellation.

## Cryptanalytic interpretation

The historical pegs provide independent-key samples. They do not provide the same-key or same-mask equations required for a related-plaintext or differential attack.

- Knowing the first peg's plaintext template does not reveal its multiplicative masks or create an oracle for another key.
- The public artifacts do not expose the internal LPN `(A,y)` samples needed for a cross-key LPN attack.
- Distinct `canon_tag`, PRF key, LPN secret, nonces, commitment blindings, and field masks block subtraction or ratio cancellation across pegs.
- Public `H`, UBK, and subgroup alignment normalize public coordinates only; no secret coefficient is shared.
- `Q(N)=N^337=Q(R)Q(v)` retains the unknown quotient mask `Q(R)`.

## Finding

**No exploitable historical-generation RNG reuse or cross-key composition was demonstrated.** The deeper tests strengthen §10's negative result: the three pegs are closely timed but behave like independently generated key/ciphertext pairs under the tested exact, partial, statistical, matrix, permutation, subgroup, and algebraic controls.

The only confirmed leakage remains framing metadata: the final 22-object bundle constrains plaintext length to 301–315 bytes. This was already documented and is not plaintext recovery.

## Limitations

- Reachable Git history cannot reveal objects absent from the clone or private publisher process state.
- Statistical non-detection is not proof of ideal randomness or cryptographic security.
- The source establishes the intended OS-CSPRNG path; it cannot retrospectively prove the publisher's host was uncompromised.
- No private plaintext, secret key, generator process memory, or entropy state was accessed.
- No plaintext, key, bounty solution, or fund access was recovered.
