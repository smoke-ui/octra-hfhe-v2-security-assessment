# Independent audit contribution — Kubo-cmd/hfhe-v2-solver

Co-author assessment of Octra HFHE v2, contributed per CONTRIBUTING.md
("improve reproducibility / add a controlled attack experiment").

## Pinned inputs (match live `octra-labs/hfhe-challenge` @ `main`)

- challenge: `0d08e9622921e5930175a660df0061a65548972f`
- pvac_hfhe_cpp: `071b0e909c119de815e284b347c4bd979cb59ef3`
- secret.ct SHA-256: `5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab`
- pk.bin SHA-256: `1e788edff9dea19a782defae053f3757ccf5edd41cd3e24ae44e1496045e9410`

## Hypothesis

Public artifacts of OCTRA HFHE v2 expose no practical plaintext-recovery path
under the tested threat model, and the v1 public candidate-verification oracle
(serialized `R_com`) is absent from the v2 wire.

## Controls

- Positive control: inject a deliberately unauthenticated fixture field →
  detected as malformed by `probe2*` deserializer probes.
- Negative control: parse genuine v2 blobs → all structural/statistical checks PASS.

## Result schema (CONTRIBUTING.md)

```json
{
  "hypothesis": "no public-only plaintext recovery; v1 R_com oracle closed",
  "commits": {
    "challenge": "0d08e9622921e5930175a660df0061a65548972f",
    "pvac": "071b0e909c119de815e284b347c4bd979cb59ef3"
  },
  "sample_size": 20000,
  "positive_control": "pass",
  "negative_control": "pass",
  "held_out_result": {},
  "artifact_result": {
    "v1_rcom_oracle": "closed (0 bytes on wire)",
    "lpn_prf_differential_bias": "none (Bonferroni α=0.01, N=20000)"
  },
  "limitations": [
    "No private key / sk.bin available; recovery not attempted",
    "Findings hold for published challenge as audited",
    "Hardness rests on LPN-PRF, Pedersen, secret-key secrecy"
  ]
}
```

## Measured ground truth (live artifacts)

| Parameter | Value |
|-----------|-------|
| secret.ct size | 1,963,107 bytes |
| Bundle magic | `OCTRA-HFHE-BTY02` |
| Cipher count | 22 variable-length PVAC v3 blobs |
| BASE layers | 44 (2 per ciphertext) |
| Unique seeds / PC | 44 / 44 |
| Edges | 1829; mean hamming 63.43; var 32.29 |
| Field q | 2^127 - 1 |
| Pedersen | Ristretto255 |
| R_com on wire | 0 bytes (omitted by `write_layer`) |
| Format | variable-length bundle, not fixed-size layer array |

## Tools added (tools/kubo-audit/)

- `verify_audit.py` — zero-dependency public verification (stdlib Python)
- `test_rcom_closure.cpp` — v1-fix regression: asserts no `R_com` on wire
- `prf_n20k.cpp` — LPN-PRF differential (N=20,000, Bonferroni α=0.01)
- `phase1_trie.cpp` — full N0/N1 branch filters
- `probe2_malformed_struct.cpp` / `probe2b_malformed.cpp` / `probe2c_malformed.cpp`
  — adversarial deserializer robustness probes
- `probe3_wallet_kdf.cpp` — wallet KDF path probe (no secret recovery)
- `probe4_multi_ct.cpp` — multi-ciphertext correlation probe

## Reproduce

```bash
python3 tools/kubo-audit/verify_audit.py
# C++ tools require pvac_hfhe_cpp headers on include path:
clang++ -std=c++17 -O2 -I/path/to/pvac_hfhe_cpp/include \
  tools/kubo-audit/test_rcom_closure.cpp -o test_rcom_closure && ./test_rcom_closure
```

## Claim standard

Negative-result public-artifact audit. No plaintext recovery, no exploitable
bias. Bounty would require a new LPN/HFHE cryptanalytic result or `sk.bin`
access. Full reproducible notes: https://github.com/Kubo-cmd/hfhe-v2-solver
