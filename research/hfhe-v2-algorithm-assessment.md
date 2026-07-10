# HFHE Challenge v2: classical/quantum algorithm assessment

## Bottom line

No known classical or quantum algorithm materially lowers the *applicable* cost of plaintext recovery from the v2 public artifact. Published LPN solvers require explicit classical `(A,y=A s+e)` samples; quantum polynomial-time parity learners require coherent quantum-example-oracle access. V2 provides neither. It publishes 22 wrapped ciphertexts containing 44 independently seeded BASE layers, where the LPN vectors are generated internally and compressed through a secret-keyed AES-derived PRG, a 127-bit Toeplitz extractor, multiplicative combination, ciphertext masking, and commitments. Treating the advertised `(n,t,tau)=(4096,16384,1/8)` as a directly exposed LPN instance is therefore a category error.

## Artifact/source facts

Pinned implementation: `071b0e909c119de815e284b347c4bd979cb59ef3`; challenge: `0d08e9622921e5930175a660df0061a65548972f`.

* `lpn_make_ybits` constructs each row of `A` from AES-CTR keyed by `SHA256(sk.prf_k, public data, layer seed, domain)`, computes `<A_i,s> xor e_i`, and retains `y` only locally (`include/pvac/crypto/lpn.hpp:307-374`). Thus even `A` is not reproducible without `sk.prf_k`.
* `prf_R_core` Toeplitz-compresses the 16,384 hidden `y` bits to one nonzero field element; three independently domain-separated results are multiplied (`lpn.hpp:376-415`). The artifact contains neither rows nor labels.
* The secret consists of an independent 256-bit `prf_k` and dense 4096-bit `lpn_s_bits` (`types.hpp:195-198`); challenge generation calls nondeterministic `keygen`, not the wallet-seeded alternative (`source/hfhe_bounty_artifact.cpp:333-362`; `keygen.hpp:150-161`). Therefore there is no hidden 256-bit master seed to enumerate.
* The public key contains only parameters, deterministic `H`, permutation, digest and field power table (`types.hpp:119-127`), not an LPN sample matrix or labels.
* Prior structural parsing found 22 ciphertexts/44 BASE layers, all layer seeds/nonces/commitments distinct, no PROD layers, and no repeated public aggregate. These are 44 nonlinear, independently blinded images—not 44 LPN equations.

## Classical algorithms

### BKW, coded-BKW, LF/FWHT, covering-code and ISD-style attacks

These methods all start from many explicit noisy linear equations. BKW combines samples to cancel blocks; LF/FWHT and covering-code variants similarly need labels and row vectors; ISD needs a concrete syndrome/code instance. None can be initialized from v2.

Even conditionally granting the attacker one internal instance, only `t=4n=16384` samples exist per domain. Literature repeatedly warns that asymptotic BKW estimates commonly assume effectively unbounded samples; restricted-sample cost can be much worse. The implementation's `n H_2(tau)` estimate is not a solver estimate: for `tau=1/8`, `H_2=0.5435644` and `nH_2=2226.44` bits. It merely counts a typical noise pattern over `n` positions (and is dimensionally unrelated to the actual 16,384-label error vector, whose fixed-weight-2048 set has log2 size about 8899.0). It should not be cited as “~2226-bit concrete LPN security.”

Sparse-secret improvements do not apply: `lpn_s_bits` is sampled uniformly/densely. Ring-LPN/algebraic attacks do not apply: there is no ring/cyclic sample structure. Multiple-layer attacks do not provide repeated samples under one public matrix: each domain/layer derives a fresh secret AES key/stream from `prf_k` and the nonce.

### Generic key/plaintext search

Direct exhaustive secret-key search is nominally `2^(256+4096)=2^4352`, not `2^256`, because challenge generation uses independent randomness. Guessing plaintext is useful only if there is a public guess verifier. V2 intentionally removed the v1 `R_com` offline-check oracle; Pedersen commitments are independently blinded. Text framing and the leaked 301–315-byte length range constrain candidates but do not validate them. Thus dictionary search cannot be converted into a cryptanalytic recovery algorithm unless the plaintext itself has very low entropy or an overlooked public invariant is found.

The outer HFHE structure (`H` rank, sparse edges, sigma vectors) may suggest syndrome decoding, but it does not expose a syndrome whose solution is the plaintext or LPN secret. Solving public `H` relations merely reconstructs public masking relations already represented in the ciphertext and does not reveal the hidden per-layer `R` values.

## Quantum algorithms

### Quantum-example LPN learners

Cross–Smith–Smolin recover parity efficiently in a model with a **quantum example oracle**, i.e. coherent access to a superposition of labeled examples. A static classical file is not that oracle. Piatkowski–Zoufal–Mücke explicitly note that naively encoding classical noisy parity data for the quantum algorithm requires exponential sample complexity. V2 is still weaker: it does not even provide the classical labeled data.

Accordingly, these polynomial-time quantum results give no attack on `secret.ct`. Quantum access to SHA/AES implementations does not synthesize coherent access to the unknown secret-keyed internal sample generator.

### Grover/amplitude amplification and quantum ISD

Grover can at most quadratically accelerate a *defined, efficiently checkable* search. Quantum ISD likewise Groverizes a syndrome-decoding predicate and requires an explicit code/syndrome. There is no v2 LPN syndrome to decode and no public plaintext predicate.

If one hypothetically supplied a verifier and searched only a 256-bit secret, Grover would still require about `2^128 = 3.40e38` sequential oracle iterations. Even an impossible sustained `10^9` full reversible decryptions/s gives about `1.08e22` years, before error correction and the very large reversible HFHE/AES/SHA/field-arithmetic circuit. For the actual independently sampled 4352-bit secret, generic Grover is `2^2176` iterations. Grover over a `k`-bit plaintext dictionary would reduce `2^k` to `2^(k/2)` only if a public verifier existed; v2 supplies none.

Shor, HHL, Simon, hidden-shift and quantum linear-system algorithms do not apply: there is no exposed factoring/discrete-log instance tied to decryption, no coherent periodic oracle, and HHL does not solve noisy Boolean equations or output their full classical secret efficiently. Pedersen commitments have discrete-log security, but opening an independently blinded commitment does not identify plaintext; a future Shor-capable machine could solve the Ristretto discrete logs, yielding commitment linear relations, yet both committed value and blinding are unknown and the map remains underdetermined absent a reused/known blinder.

## Overlooked formulations checked

1. **44 outputs as a small-sample hidden-function problem:** they are independently keyed/seeded, 127-bit extracted and then multiplicatively combined; no known attack inverts them to LPN labels. Forty-four field images are far too little to identify a 4352-bit secret even if they were clean equations, which they are not.
2. **Public `H` as the LPN matrix:** false; `H` is an independent 8192x16384 masking/code matrix. The LPN rows are ephemeral AES outputs inside `lpn_make_ybits`.
3. **Syndrome decoding / quantum ISD on sparse ciphertext edges:** no target syndrome corresponding to secret/plaintext is exposed.
4. **Hidden 256-bit wallet seed:** false for this artifact; generator calls `keygen`, not `keygen_from_seed`.
5. **Known text format as an oracle:** it validates a decrypted key candidate but does not score plaintext guesses directly. Since key search is 4352 bits, this does not create a realistic attack.

## Conclusion

There is no applicable literature speedup that changes the practical recovery outlook. The right security statement is not “LPN at n=4096 costs X”: the attacker is not given an LPN instance. Any meaningful attack must first break the secret-keyed extraction/masking interface, find randomness reuse, recover an offline guess oracle, or expose internal `(A,y)` samples. Absent that missing reduction, classical BKW/LF/ISD estimates and quantum-example polynomial algorithms are irrelevant; generic quantum search remains astronomically infeasible.

## Sources

* A. Blum, A. Kalai, H. Wasserman, “Noise-Tolerant Learning, the Parity Problem, and the Statistical Query Model,” JACM 2003 (BKW): https://doi.org/10.1145/944919.944925
* E. Levieil, P.-A. Fouque, “An Improved LPN Algorithm,” SCN 2006: https://www.di.ens.fr/~fouque/pub/scn06.pdf
* M. Albrecht et al., “On the Concrete Hardness of Learning with Errors,” 2015 (BKW assumptions/concrete estimation): https://eprint.iacr.org/2015/046
* Q. Guo, T. Johansson, P. Stankovski, “Coded-BKW with Sieving,” asymptotic survey/context: https://arxiv.org/abs/1901.06558
* A. W. Cross, G. Smith, J. A. Smolin, “Quantum learning robust against noise,” Phys. Rev. A 92, 012327 (2015), quantum-example oracle model: https://arxiv.org/abs/1407.5088
* N. Piatkowski, C. Zoufal, T. Mücke, “Quantum-classical reinforcement learning for decoding noisy classical parity information,” Quantum Machine Intelligence 2 (2020), classical-data caveat: https://arxiv.org/abs/1910.00781
* G. Kachigar, J.-P. Tillich, “Quantum Information Set Decoding Algorithms,” PQCrypto 2017: https://eprint.iacr.org/2017/213
* S. D., P. C., “On the practical cost of Grover for AES key recovery,” NIST PQC Conference 2024: https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/on-practical-cost-of-grover.pdf
