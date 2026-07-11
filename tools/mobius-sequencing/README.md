# Möbius sequencing experiments

Deterministic, public-only diagnostics for the OCTRA HFHE v2 challenge. These tools impose explicit mathematical Möbius constructions; they do not assume that the ciphertext has intrinsic physical topology.

## Setup

From the repository root:

```bash
make setup
```

The setup pins the challenge and PVAC dependencies and installs NumPy in `.venv`.

## Reproduce

LPN sequencing against the publisher's July 11 sample release:

```bash
.venv/bin/python tools/mobius-sequencing/lpn_experiment.py \
  --challenge-repo .deps/hfhe-challenge \
  --trials 199 \
  --output results/lpn-mobius.json
```

The LPN tool validates the exact OCTRA repository identity, archives release commit `d9d29d505e2840c0028d7a91a2a8ba59e163b9a4`, rejects unsafe archive members, checks every published sample against the archived `SHA256SUMS`, and records dataset/analyzer digests.

Finite-field character and projective-map analysis:

```bash
.venv/bin/python tools/mobius-sequencing/field_experiment.py \
  --out results/field-mobius.json
```

The field tool validates exact repository identities and commits, extracts immutable Git archives, compiles the pinned C++ character extractor, and analyzes the original challenge artifact.

Boolean Möbius inversion and global cycle-parity diagnostics:

```bash
.venv/bin/python tools/mobius-sequencing/hypergraph_experiment.py \
  .deps/hfhe-challenge/secret.ct \
  --permutations 999 \
  --seed 20260711 \
  --out results/hypergraph-mobius.json
```

Verify all committed outputs from immutable inputs without overwriting them:

```bash
make verify-mobius
make test
make lint
```

## Scope

- `lpn_experiment.py`: full 720,896-element cylinder/Möbius sequences, periodic/antiperiodic spectra, exhaustive seam shifts, bounded A-coordinate transformations, and family-max Monte Carlo controls.
- `field_extract.cpp` and `field_experiment.py`: exact 337-coordinate character sums, 224 projective maps over `P¹(F_p)`, 336 coordinate twists, seam ratios, quotient labels, and fixed cross-ratios.
- `hypergraph_experiment.py`: 793 degree-≤4 Boolean Möbius coefficients and globally parity-constrained cylinder/Möbius cycle energies with planted controls.

The public artifact has unknown plaintext. Topology results are unlabeled structural diagnostics and cannot establish plaintext leakage without generated, key-disjoint and plaintext-disjoint validation fixtures.
