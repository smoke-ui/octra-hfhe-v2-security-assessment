# Wrapped HFHE public invariant discovery

Automated, reproducible search against pinned `pvac_hfhe_cpp` commit `071b0e9`.

## Method

`generate_features.cpp` creates labeled wrapped `enc_value` samples and verifies every decryption. It exports only public fields: per-layer public numerators, limbs, edge-weight XORs, sigma parity, index sums, nonces, layer/edge counts. `discover.py` enumerates 1,104 expressions (bit projections, small-prime residues, and cross-field/cross-layer degree-2 sums/products), ranks by plug-in mutual information, computes permutation p-values, applies Benjamini-Hochberg FDR 0.05, and evaluates on entirely unseen keys.

Commands:

```bash
g++ -std=c++17 -O2 -march=native -pthread -I../pvac_hfhe_cpp/include generate_features.cpp -o generate_features
./generate_features reduced.csv 480 reduced 6
python3 discover.py reduced.csv --perms 200 --out reduced_results.json
./generate_features production.csv 96 production 2
python3 discover.py production.csv --perms 100 --out production_results.json
```

## Results

| regime | samples | keys | train/test | expressions | BH-FDR discoveries |
|---|---:|---:|---:|---:|---:|
| reduced (256x512 H, reduced LPN) | 480 | 6 | 320/160, key-disjoint | 1,104 | **0** |
| production defaults | 96 | 2 | 48/48, key-disjoint | 1,104 | **0** |

The best nominal correlations fail multiplicity correction and have out-of-key classification near/below the 1/16 random baseline. No public plaintext invariant was found in this grammar. High raw MI for high-cardinality residues is finite-sample bias; permutation tests correctly reject it.

The real artifact was independently revalidated with `hfhe_v2_structural_audit` (`artifact_audit.txt`): 22 canonical ciphertexts, 44 BASE layers, 1,829 edges, all nonces/seeds and public layer sums distinct. Since no candidate survived training/FDR/out-of-key testing, there was no candidate plaintext predicate to apply to the unlabeled artifact. Its accessible structures are nevertheless in-family with the production generator (two BASE layers per wrapped value), and there is no collision/reuse exception that would activate a cross-layer candidate.

## Scope / caveats

This is a negative result for the enumerated low-degree grammar, not a proof of semantic security. Production sample size is modest due to cost. Stronger follow-up would increase independent production keys and use exact conditional-randomization tests; SAT/SMT on a toy prime is unlikely to model the full 127-bit field plus PRF/LPN randomness faithfully.
