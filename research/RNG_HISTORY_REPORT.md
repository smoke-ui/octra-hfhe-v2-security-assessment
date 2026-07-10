# HFHE v2 artifact/RNG history audit

## Scope and pins

- Challenge reachable history: `900255d..0d08e9622921e5930175a660df0061a65548972f`, tag `v2_fix=08bf879dd9e9aff094e4106ee5d86dde9de12742`.
- Published PVAC pin/current tip: `071b0e909c119de815e284b347c4bd979cb59ef3`.
- `git fsck --full --no-reflogs --unreachable` found no additional unreachable objects in either local full clone.

## Artifact generations

| first commit | pk SHA-256 | secret.ct SHA-256 | count | canon_tag |
|---|---|---|---:|---|
| `08bf879dd9e9aff094e4106ee5d86dde9de12742` | `ad5f2ecab6d71ffaaf1e363ed3b6aefc7ac1de4156a6189f8ff9ee720305a865` | `8f38ed7706cca15fa5208de905cf3ee4456fafc3c72068d26ea46ac7b6fa3300` | 9 | `68d7e3261781444f` |
| `e4645c97712542c875b7d2d8d53ac9b78b61af3f` | `2ebc2a258a291ad2136926c1b5f5a787a37a4499e6bdad492d9a5c3362cfc003` | `1f48fae52859e3f21011a565f40348e21b4ed3aaa07b1b404d58a4fc6c0456d4` | 9 | `93ebe88dbe46d78a` |
| `88a72b703f4cdd26b5fe6b3249850c2cbcef3b43` | `1e788edff9dea19a782defae053f3757ccf5edd41cd3e24ae44e1496045e9410` | `5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab` | 22 | `0760802093a19931` |

The third pair remains byte-identical through `25afde5a`, `841504ab`, `547271bc`, and `0d08e962`.

## Cross-generation statistics

All three pairwise comparisons gave zero intersections for full BASE seeds, 128-bit nonces, 32-byte PCs, sigma vectors, and weight vectors. Tags differ. Within generations:

- 08bf879: 18/18 unique seeds/nonces/PCs; 531/531 unique sigma and weight vectors.
- e4645c9: 18/18 unique seeds/nonces/PCs; 531/531 unique sigma and weight vectors.
- 88a72b7: 44/44 unique seeds/nonces/PCs; 1829/1829 unique sigma and weight vectors.
- Every ztag equals deterministic `prg_layer_ztag(canon_tag, nonce)`; this is domain binding, not hidden entropy or a seed-recovery oracle.

## RNG/source findings

- `include/pvac/core/random.hpp` has used OS CSPRNG from initial PVAC commit `087ff24`: Linux `getrandom(2)` with `/dev/urandom` fallback; Windows `BCryptGenRandom`; BSD/macOS `arc4random_buf`; only the generic fallback uses `std::random_device`.
- Keygen independently draws `canon_tag`, four 64-bit PRF-key words, field generators, and all LPN secret words via `csprng_u64`. Encryption creates each 128-bit nonce with two more `csprng_u64` calls. No `rand`, MT, timestamp, PID, commit time, or user-controlled seed occurs on the production path.
- The v2_fix generator itself drew the email suffix and 256-bit secret directly from `/dev/urandom`; the next generation removed generated plaintext and loaded private `plaintext.txt`. Neither path shares a deterministic PRNG state with keygen/encryption.
- Commit timestamps are only Git metadata and never enter generation.
- `keygen_from_seed` exists at the pin but `git show 08bf879:source/hfhe_bounty_artifact.cpp` and later generator sources call `keygen`, not `keygen_from_seed`.

## Payload leakage

Bundle count and member sizes reveal formatting/length/depth metadata. The first two versions contain 9 ciphertext objects (member edge counts total 531); final contains 22 (1829 edges). This narrows plaintext length/structure but gives no RNG-state relation. Final plaintext is private-file supplied, so earlier known email/secret template does not carry over.

## Conclusion

No cross-version state reuse, predictable seed, nonce collision, tag collision, or reusable per-edge randomness was observed. Under the published Linux path, seed recovery reduces to breaking the OS CSPRNG or the cryptographic derivations; repository history provides no such leverage. Historical artifact comparison therefore does **not** currently enable v2 plaintext recovery.

## Reproduction

```bash
bash analyze_artifact_history.sh
g++ -std=c++17 -O2 -maes -msse4.1 \
  -I${PVAC_DIR}/include \
  cross_artifact_rng.cpp \
  -o cross_artifact_rng
cross_artifact_rng \
  history_artifacts/08bf879 \
  history_artifacts/e4645c9 \
  history_artifacts/88a72b7
```
