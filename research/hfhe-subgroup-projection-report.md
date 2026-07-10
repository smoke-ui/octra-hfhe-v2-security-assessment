# OCTRA HFHE v2 subgroup/character projection probe

## Result
No plaintext distinguisher or partial mask cancellation was found.

## Algebra checked
Let `H=<g>` have order `B=337` in `Fp*`, `p=2^127-1`. The quotient/coset label
`Q(x)=x^337` has kernel exactly `H`. Thus it would expose the plaintext coset if a
multiplicative mask were restricted to `H`. In this construction the observable layer
sum is `N=R*v`, with secret PRF-derived `R` not restricted to `H`; consequently
`Q(N)=Q(R)Q(v)` retains a full unknown quotient mask. For wrapped layers,
`N0/N1=(R0/R1)(v+m)/(-m)` has an independent unknown quotient factor.

I also formed all 337 cyclic character evaluations for every real layer:
`S_k = sum_j a_j g^(kj)`, where `a_j` is the signed sum of edge weights at index `j`.
This covers DFT-like subgroup projections, including ordinary public sum `S_1`, trivial
character `S_0`, ratios, and exact cancellation searches.

## Real artifact results
Pinned v2 artifact (`22` ciphertexts, `44` layers):

- 14,828 character values: **0 exact zeros**.
- Same-character-coordinate collisions across layers: **0**.
- `S_1^337` quotient labels: **44/44 unique**.
- Wrapped-layer `S_1(layer0)/S_1(layer1)` ratios: **22/22 unique**.
- `S_0/S_1` normalized signatures: **44/44 unique**.

These are negative controls rather than proofs of pseudorandomness, but reject obvious
shared cosets, repeated quotient masks, character annihilation, and pairwise cancellation.
With only 44 layers, isolated statistical rankings would be false-positive prone; the
probe therefore uses deterministic equalities/collisions and an exhaustive toy control.

## Toy exhaustive control
For `Fp` with `p=29`, subgroup order `B=7`:

- Full-field masks: maximum TV distance between projected plaintext classes = `0.0`.
- Subgroup-restricted masks: TV distance across different plaintext cosets = `1.0`.
- Wrapped construction with independent full-field masks: maximum TV = `0.0`.

This confirms the test detects the intended flaw when present and does not manufacture a
class signal under the masking model used by v2.

## Pedersen scalar path
`sc_from_fp` directly embeds the 127-bit field encoding into the ~252-bit Ristretto scalar
field, so there is no wrap/reduction collision to align with the order-337 quotient.
`pedersen_commit_fp` then uses secret blinding. The serialized `PC` therefore supplies no
public scalar-reduction oracle for `Q(R)` or a character projection.

## Reproduction

```bash
python3 hfhe_subgroup_toy.py
g++ -std=c++17 -O2 -maes -mpclmul -msse4.1 \
  -I${PVAC_DIR}/include \
  hfhe_subgroup_projection_audit.cpp \
  -o hfhe_subgroup_projection_audit
hfhe_subgroup_projection_audit ${CHALLENGE_DIR}
```
