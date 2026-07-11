# OCTRA Möbius Sequencing Assessment

**Date:** 2026-07-11
**Result:** no demonstrated plaintext, key, or low-weight LPN recovery path

## Scope

This assessment makes the earlier “4D” hypothesis mathematically explicit. The topology is analyst-imposed; the ciphertext does not claim to encode a physical Möbius strip. Three distinct families were tested:

1. non-orientable sequencing of the published `22 × 2` LPN grid;
2. projective Möbius maps over `P¹(F_p)` and twists of the public order-337 character coordinates;
3. Boolean-lattice Möbius inversion and globally parity-constrained cylinder/Möbius incidence cycles.

The original HFHE artifact is pinned to challenge commit `0d08e9622921e5930175a660df0061a65548972f` and PVAC commit `071b0e909c119de815e284b347c4bd979cb59ef3`. The LPN release is pinned to `d9d29d505e2840c0028d7a91a2a8ba59e163b9a4`.

## LPN strip sequencing

The 44 files form 22 ciphertext columns with two layers, 16,384 rows per file, and 720,896 total equations. The cylinder traverses ciphertext/layer/row order directly. The Möbius double cover traverses layer 0 forward and layer 1 in reversed ciphertext-block order while preserving row order inside each file.

The battery used the complete `y` and A-row-weight sequences, periodic and antiperiodic Fourier channels, every ciphertext shift, and every 16,384-position circular seam shift. The seam family therefore contains `22 × 2 × 16,384 = 720,896` alignments, where the factor of two denotes the periodic and antiperiodic channels—not a reversed-row scan. A bounded 256-row control applied four genuine 4,096-bit coordinate maps: identity, global bit reversal, per-byte bit reversal, and their composition. Complement distance was retained as a diagnostic rather than treated as an ordinary LPN symmetry.

Seam positions were scanned exhaustively. Monte Carlo nulls used fixed-seed random ciphertext mappings and layer flips, family maxima, the plus-one estimator, and Holm adjustment across the six reported families.

| family | statistic | raw Monte Carlo p | Holm p |
|---|---:|---:|---:|
| twisted `y` autocorrelation | 0.00004438 | 0.570 | 1.000 |
| twisted row-weight autocorrelation | 0.00004006 | 0.715 | 1.000 |
| antiperiodic spectral concentration | 0.19641366 | 0.120 | 0.720 |
| exhaustive FFT seam scan | 0.01201778 | 0.170 | 0.850 |
| transformed A-row minimum distance | 1903 | 1.000 | 1.000 |
| complement-distance diagnostic | 1908 | 1.000 | 1.000 |

No family survived correction. The nearest bounded transformed pair remained dense rather than producing a useful sparse LPN equation.

## Finite-field projective maps

The pinned C++ extractor computes the complete 337-coordinate character sequence for each public layer:

`S_k = c0 + Σ_j a_j g^(kj)`.

The `c0` accumulator is included at every character evaluation for layer 0, matching evaluation of the full group-algebra polynomial. Inputs are compiled from validated immutable Git archives. Exact repository owner/name, commit objects, clean source repositories, artifact hashes, and extractor hash are checked or recorded.

The experiment applied 224 predeclared normalized matrices with coefficients in `{-2,-1,0,1,2}` as fractional-linear maps on `P¹(F_p)`, where `p = 2^127 - 1`. Denominator zero is retained as projective infinity. Coordinate automorphisms `k → uk mod 337` were tested separately for all 336 nonzero `u`; field-value maps and coordinate twists were not conflated.

Across 44 spectra and 22 wrapped pairs:

- no `k → -k` layer relation;
- no complete multiplicative-coordinate twist relation;
- no complete relation under any of the 224 field-value Möbius maps;
- zero agreements for the identity, negation, inversion, and Cayley core maps;
- zero equality among 88 fixed paired cross-ratio comparisons;
- all 337 seam ratios were unique inside every wrapped pair;
- all 337 `x^337` seam quotient labels were unique inside every wrapped pair;
- no exact zeros, poles, or transformed-value collisions in the tested artifact families.

These are exact equality/collision results, not distributional proof of security.

## Boolean Möbius inversion and non-orientable incidence

Twelve fixed public edge predicates define

`F(S) = number of edges satisfying every predicate in S`.

Boolean-lattice inversion was computed for every nonempty subset of degree at most four: `12 + 66 + 220 + 495 = 793` coefficients. Exact-cell and conjunction transforms round-trip exactly, and a planted degree-three control is recovered at the planted support.

For topology diagnostics, each ciphertext column is a two-state vertex. Adjacent columns admit same-layer (`+1`) or crossed-layer (`-1`) transitions. Dynamic programming minimizes total cycle energy subject to the global transition parity:

- `+1`: orientable cylinder closure;
- `-1`: non-orientable Möbius closure.

This preserves the global orientation sign rather than independently choosing the cheapest edge. The statistic is invariant to local layer gauge and seam rotation. The same function detects deterministic planted cylinder and Möbius controls.

On the public artifact:

- cylinder energy: `0.077993399`;
- Möbius energy: `0.080346359`;
- absolute gap/holonomy diagnostic: `0.002352960`;
- preferred descriptive closure: cylinder;
- family-max Monte Carlo p-values: circulation `0.93`; holonomy, closure gap, and harmonic statistic `1.0`.

No corrected topology signal was found. The model is an analyst-imposed diagnostic over serialization order, not an inferred intrinsic geometry of HFHE.

## Interpretation

The Möbius hypothesis was materially different from the previous four-axis tensor sketch: it tested twisted boundaries, antiperiodic modes, projective-line transformations, order-337 orientation reversal, Boolean-poset inversion, and global non-orientable cycle parity.

The enumerated finite-field equality and collision families returned exact nulls. The LPN and topology statistics returned multiplicity-corrected statistical nulls. Boolean inversion was an exact descriptive transform: its 793 coefficients were not assigned individual leakage p-values. The experiments do not recover the LPN secret `S`, the independent PRF key, the plaintext mask, or the wallet payload. They also do not prove that every possible construction bearing the name “Möbius” is impossible; they reject the explicit, reproducible families above.

## Evidence

- [`../results/lpn-mobius.json`](../results/lpn-mobius.json)
- [`../results/field-mobius.json`](../results/field-mobius.json)
- [`../results/hypergraph-mobius.json`](../results/hypergraph-mobius.json)
- [`../tools/mobius-sequencing/`](../tools/mobius-sequencing/)
