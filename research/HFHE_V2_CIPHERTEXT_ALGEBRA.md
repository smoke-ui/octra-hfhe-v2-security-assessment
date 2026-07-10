# HFHE Challenge v2: ciphertext-algebra attack assessment

## Outcome

No practical ciphertext-algebra equality/guess predicate exists in the published two-BASE-layer wrapper under the stated PRF and Pedersen assumptions. The only information-theoretic predicate found is the event `N0 == 0`; for a nonzero plaintext it occurs with probability about `1/(p-1) = 2^-127`, and for plaintext zero it cannot occur (assuming nonzero masks). The published artifact passes `public_nonzero`, so this event did not occur in any slot.

## Exact public field relations

For layer `i`, sum the public edge terms in slot `j`:

`Ni = c0_i + sum_{e.layer=i} sign(e.ch) * e.w[j] * powg_B[e.idx]` in `F_p`.

`core::synth` constructs all signal and noise edge groups so their sum is exactly `Ri * vi`. Sigma vectors authenticate/decrypt the hidden LPN side but do not alter this publicly computable field sum. Thus the two wrapped layers expose exactly

* `N0 = R0 (v + m)`
* `N1 = R1 (-m)`

with fresh independent nonzero `m`, independently seeded `R0,R1`, and independent edge randomizers. `powg_B` does not add equations: it is merely a public order-337 basis used to form each already-public `Ni`. Decomposing `Ni` into edges provides random shares constrained only by their sum. Sigma is generated from public `H`, seed, index/sign and a fresh 64-bit salt; no equation connects it to `R`, `m`, or `v`.

Eliminating `m` gives

`v = N0/R0 + N1/R1`.

This is one equation in two unknown independently pseudorandom masks. Across blocks, every wrapper mask, layer nonce, `R`, Pedersen blinding, and edge sharing is fresh, so equations do not couple.

## Pedersen commitments cannot cancel the masks

Each BASE layer publishes

`PCi = Com(phi(Ri^-1), rhoi) = phi(Ri^-1) G + rhoi H`,

where `phi = sc_from_fp_signed` maps a field representative to the Ristretto scalar field and `rhoi` is independently PRF-derived from the secret key and layer nonce.

The tempting expression is scalar multiplication by the public numerator:

`[phi(N0)]PC0 + [phi(N1)]PC1`.

Even if `phi` were multiplicative (it is not, because `F_p` and the Ristretto scalar field have different moduli), this would equal

`v G + (phi(N0)rho0 + phi(N1)rho1)H`,

leaving an unknown independent full-width blinding. It is therefore a fresh Pedersen commitment, not `vG`, and cannot test a candidate. Other public linear combinations have the same obstruction. Nonlinear field operations cannot be applied to encoded group exponents in a generic group.

More strongly, because Ristretto's group has prime order and `H` is nonidentity, uniform `rhoi` makes each `PCi` exactly uniform for every fixed `Ri`. Hence `(PC0,PC1)` contains no information-theoretic relation about the inverse masks; replacing uniform blindings by secure PRF outputs gives computational hiding. Multiple blocks do not help because blindings are independent.

`R_com` would have committed by hash directly to `R` and enabled candidate verification. It is zeroed/removed in v2's artifact. `PC` is not a replacement oracle because its unknown Pedersen blinding cannot be recomputed or canceled.

## Complete generic algebra attack map

1. **Field-only combinations of `N0,N1`:** for nonzero `v`, their joint distribution is identical for every value of `v`; for `v=0` it differs only by the negligible `N0=0` event.
2. **Group-only combinations of `PC0,PC1`:** perfectly hidden by independent blindings.
3. **Mixed public-scalar/group combinations:** every nontrivial combination retains at least one unknown independent blinding; additionally the field-to-scalar map breaks the hoped-for multiplication identity.
4. **Edge-level ratios/subsets:** random field shares reveal no additional invariant beyond each layer sum. Fresh independent `R` prevents cross-layer and cross-block ratio cancellation.
5. **Sigma/H linear algebra:** sigma values are independent public-seed-derived vectors and the actual `H` has full row rank; no mask-bearing field coefficient is encoded in them.
6. **Equality/collision tests across blocks:** require reused `R`, nonce, PC/blinding, or wrapper mask. Prior artifact audit found none, and all layer sums are distinct.

## Exact reduced-parameter verification

Script: `hfhe_ciphertext_algebra_toy.py`

It exhaustively enumerates a toy `F_31`, a prime-order commitment group `Z_13`, all nonzero `m,R0,R1`, and all Pedersen blindings. Results:

* PC pairs are exactly uniform for every tested plaintext.
* Full public distributions for two distinct nonzero plaintexts have total variation distance 0.
* Zero versus nonzero plaintext has distance `1/30`, exactly the exceptional `N0=0` event.
* Conditioning on `N0 != 0`, distinct nonzero plaintext distributions remain identical.
* The candidate `N0*PC0 + N1*PC1` has the same distribution for distinct nonzero plaintexts and never becomes an equality oracle.

Reproduction:

```bash
python3 hfhe_ciphertext_algebra_toy.py
cd ${CHALLENGE_DIR}
./build/hfhe_bounty_artifact public-audit
```

The real artifact audit reports `compatible=1`, `wrapped=1`, and `public_nonzero=1`.

## Scope of falsification

This decisively falsifies attacks using algebraic/group operations on the published numerators, PCs, public power basis, edge data, and multiple independent blocks in the generic-group/secure-PRF model. It does not prove the PRFs or Ristretto implementation secure against implementation-specific cryptanalysis; such an attack would have to recover/correlate `R` or `rho`, exploit nonce reuse, or break Pedersen discrete-log hiding rather than exploit the wrapper algebra itself.
