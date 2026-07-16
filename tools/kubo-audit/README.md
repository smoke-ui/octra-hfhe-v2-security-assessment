# tools/kubo-audit

Independent audit toolkit contributed from Kubo-cmd/hfhe-v2-solver
(co-author assessment of Octra HFHE v2). See
`research/KUBO_AUDIT_SUMMARY.md` for hypothesis, controls, and results.

## Files

| File | Purpose |
|------|---------|
| `verify_audit.py` | Zero-dependency public verification (stdlib Python) |
| `test_rcom_closure.cpp` | v1-fix regression: asserts no `R_com` on wire |
| `prf_n20k.cpp` | LPN-PRF differential (N=20,000, Bonferroni α=0.01) |
| `phase1_triage.cpp` | Full N0/N1 branch filters |
| `probe2_malformed_struct.cpp` | Adversarial deserializer probe (struct) |
| `probe2b_malformed.cpp` | Adversarial deserializer probe (variant b) |
| `probe2c_malformed.cpp` | Adversarial deserializer probe (variant c) |
| `probe3_wallet_kdf.cpp` | Wallet KDF path probe (no secret recovery) |
| `probe4_multi_ct.cpp` | Multi-ciphertext correlation probe |

## Build (C++ tools)

Require `pvac_hfhe_cpp` headers on the include path:

```bash
clang++ -std=c++17 -O2 -I/path/to/pvac_hfhe_cpp/include \
  test_rcom_closure.cpp -o test_rcom_closure && ./test_rcom_closure
```

## Reproduce

```bash
python3 verify_audit.py
```

All tools operate on public artifacts only. No private keys, mnemonics, or
wallet files are committed or required.
