# Cross-generation cryptanalytic composition assessment

## Scope and outcome

This note assesses whether the three reachable v2 generations at `08bf879`, `e4645c9`, and `88a72b7` compose into plaintext or key recovery. **No actionable composition was found.** The strongest new observation is that all order-337 public bases can be aligned across keys (the subgroup of a given order in `F_p*` is unique), but this only normalizes public coordinates; it does not remove the independent full-field PRF masks or Pedersen blindings.

## Concrete model

For generation `k` and wrapped block `b`, the public aggregates are

```text
N[k,b,0] = R[k,b,0] (v[k,b] + m[k,b])
N[k,b,1] = R[k,b,1] (-m[k,b]).
```

Each key generation independently samples `canon_tag`, the 256-bit `prf_k`, field generators, and the 4096-bit LPN secret through the OS CSPRNG (`keygen.hpp:80-155`). `H` is public and deterministically generated from that generation's `canon_tag` (`matrix.hpp:225-283`). Each layer has a fresh 128-bit nonce. Consequently, even an exact relation `v[k,b]=v[k',b']` leaves four unrelated mask unknowns in the two ciphertext pairs.

## Composition opportunities

| Opportunity | Assessment | Decisive blocker / falsifier |
|---|---|---|
| Known template in `08bf879` | Useful as a known-plaintext control only. Its source plaintext was `email = bounty.data%06u@octra.org\nsecret = <64 hex>\n`; unknown suffix/secret do not matter because even exact plaintext knowledge gives no `R` oracle. | Different public key and fresh `R,m,rho`; v2 omits `R_com`. Test whether any candidate-derived public equality holds on the known template and then on fresh keys. Existing generic algebra toy rejects such equalities. |
| Related plaintext across generations | No same-key related-message equations. Repeated headers or formatting do not cancel cross-key masks. | Need reuse/correlation of `R`, wrapper `m`, or commitment blinding; none observed. |
| Same generator source (`e4645c9`/`88a72b7`) | Source identity is not state identity. Byte comparison confirms identical generator source, but each run calls nondeterministic `keygen`; plaintext is loaded from private `plaintext.txt`. | Reproduce under an entropy-call tracer: independent OS draws must differ; deterministic replay would be evidence. Existing entropy/source trace finds `getrandom(2)` with `/dev/urandom` fallback. |
| Generator-state continuity | No user-space PRNG state exists to continue. Plaintext generation in `08bf879` used separate `/dev/urandom` reads; later pegs read a private file. | Would require OS-CSPRNG compromise or captured process state, neither present in public artifacts/history. |
| Cross-key LPN/BKW/ISD | Not constructible. Public ciphertexts expose neither the AES-generated rows `A` nor `y=As+e`; each key also has a distinct `prf_k,s`. | Public `(A,y)` samples are absent. Edge count is not LPN sample count. |
| Cross-key PRF attack | More black-box outputs under independent keys do not aid single-key recovery. Even `R` itself is not public; `PC=phi(R^-1)G+rho H` is independently blinded. | Requires related keys, nonce reuse, stream overlap, or a cross-key distinguisher that generalizes to held-out keys. None is evidenced. |
| Public matrix relations | `H_k` is reproducible from public `canon_tag_k`, so all relations are already public and carry no secret coefficient. Distinct tags produce distinct matrices. | A useful relation must also couple secret `s_k` or `R_k`; independently sampled `s_k` blocks this. Test cross-matrix duplicate columns/low-rank concatenated differences, but interpret any public relation only after showing secret coupling. |
| Differential ciphertext equations | Subtracting aligned public aggregates gives `N-N'`, not a plaintext difference: unrelated multiplicative masks remain. Edge decompositions add random shares constrained only by each `N`. | A known/repeated plaintext does not reduce the number of independent masks. |
| Nonce/tag relation | `ztag=SHA256(domain,canon_tag,nonce)` is deterministic public domain binding, not entropy. Tags differ and nonce intersections are empty. | Any collision in `(canon_tag,nonce)` or full seed would reopen same-input PRF analysis; measured count is zero. |
| Pedersen commitment relation | Cross-key linear combinations retain independent unknown `rho`; uniform blinding makes commitments information-theoretically independent of committed masks in the generic group. | Reused `PC`/blinding or exposed `R_com` would be actionable; neither occurs. |
| Subgroup/character alignment | **Valid normalization, not an attack.** Since `337` is prime and divides `p-1`, all `powg_B` tables generate the same unique subgroup. Find `a_k in [1,336]` with `g_k=g_ref^a_k` and reindex characters by `j -> a_k j mod 337`. | `Q(N)=N^337=Q(R)Q(v)` retains unknown `Q(R)`. Wrapped ratios retain `Q(R0/R1)`. Alignment cannot cancel independently keyed masks. |

## Lightweight reproduction performed

```text
08bf: tag 68d7e3261781444f, 18 seeds/nonces/PCs, 531 sigma/weight vectors
e464: tag 93ebe88dbe46d78a, 18 seeds/nonces/PCs, 531 sigma/weight vectors
88a:  tag 0760802093a19931, 44 seeds/nonces/PCs, 1829 sigma/weight vectors
```

All three pairwise comparisons returned `same_tag=0` and zero intersections for seeds, nonces, PCs, sigma vectors, and weight vectors. SHA-256 confirms all three key/ciphertext pairs are byte-distinct. `cmp` confirms the `e464` and `88a` generator source files are byte-identical.

## Minimal remaining falsifiable experiments

1. **Cross-generation aligned-character collision test (cheap, highest value):** align each order-337 generator to a reference by exhaustive discrete log over 337; compute all aligned `S_k`, `S_0/S_1`, `N^337`, and wrapped ratios for all 80 historical layers. Report exact cross-generation collisions. Positive evidence requires a collision rate incompatible with independent field masks and reproducible on regenerated controls.
2. **Known-template candidate-oracle control:** regenerate the exact `08bf` template under many independent keys, label known blocks, and test only predeclared candidate equations. Hold out whole keys. An expression that works only within one key is rejected.
3. **Public-matrix composition test:** compute pairwise column intersections and GF(2) ranks of `[H_i|H_j]` and `H_i xor P H_j` for simple public permutations. A rank defect is only actionable if a derivation shows it constrains independently sampled `s_i,s_j`; otherwise it is public-generator structure, not leakage.
4. **Entropy-call provenance test:** run the generator under `strace -e getrandom,openat,read` twice in a disposable directory. Any deterministic replay or unexpected shared seed file is positive; independent OS calls reject state-continuity hypotheses.
5. **Cross-key PRF distinguisher:** train on multiple regenerated keys and reserve entire unseen keys. Require multiplicity-corrected significance and held-out generalization. Existing invariant discovery already found no held-out-key signal in 1,104 expressions, making this lower priority.

## Bottom line

The three pegs increase the sample count only for **independent-key** observations. They do not produce the same-key or same-mask relations needed for related-plaintext, differential, LPN, commitment, or character attacks. Cross-key subgroup alignment is mathematically real and worth one deterministic collision scan, but under the source equations it normalizes public basis labels while leaving a fresh unknown quotient mask in every layer. It is therefore a probe, not a current recovery path.
