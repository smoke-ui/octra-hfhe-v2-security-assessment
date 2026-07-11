# Reduced LPN decoder and Construction-A/LLL controls

This is a bounded, deterministic synthetic-control benchmark, **not** an OCTRA key-recovery claim. It writes compact JSON to `results/lpn-lattice-controls.json`; it records neither timings nor secret values.

The companion `bkw_experiment.py` validates all 44 files against the pinned manifest, then parses and uses labels only from the immutable construction split: `ct00-ct17` (36 files, 589,824 rows). Calibration `ct18-ct19` (4 files, 65,536 rows) and final holdout `ct20-ct21` (4 files, 65,536 rows) labels remain unopened because no candidate emerged. Its four executed families use Bonferroni per-family alpha 0.0025 plus a capped global union bound. Random-row tails are conditioned on each family's forced-zero projection: dimension 4,072 after the two disjoint 12-bit bucket blocks, 4,080 for each 16-bit LSH collision, and 4,084 for each 12-bit projected triple/quadruple match. The lower tail is evaluated for every comparison conditioned on its required equality, so a union bound remains valid under dependent comparisons and adaptive finalist retention. LSH comparisons can repeat, so `comparisons_examined` is explicitly the conservative `candidate_evaluations_upper_bound`; an exact unique count is not retained. Computational actionability depends only on explicit residual direct-search and terminal MITM budgets plus terminal dimension; each algorithm's work value and unit remain descriptive, not comparable.

```bash
.venv/bin/python tools/lpn-lattice-sequence/test_lattice_experiment.py
.venv/bin/python tools/lpn-lattice-sequence/lattice_experiment.py --quick \
  --output tools/lpn-lattice-sequence/results/lpn-lattice-controls.json
```

## What is measured

The LPN controls use binary planted values, a **fixed-weight** error vector containing exactly `floor(m/8)` errors, and held-out rows. Five deterministic independent-uniform-label negative seeds guard against a one-seed result. The baseline called `square_gf2_first_n_rows` is exactly that: GF(2) elimination on the first square subsystem, not Gaussian-noise decoding. Exhaustive correlation and information-set sampling report held-out residuals.

Every algorithm reports its own work unit (`candidate_assignments_scored`, `information_sets_sampled`, `rows_in_square_system`, `row_combinations_tested`, or `lovasz_checks`). These units are intentionally not compared across methods. Short-dual output reports observed parity fraction but is explicitly labeled `dependency_enumeration_only`; it is not presented as recovered decoding information.

## Actual lattice experiment

For bounded matrices `A`, the code materializes a full-rank integer basis of the binary Construction-A congruence lattice

`Lambda(A) = {x in Z^m : x A = 0 (mod 2)}`.

It then runs deterministic textbook LLL with exact rational Gram-Schmidt arithmetic and `delta=3/4`; no optional backend is required. The toy positive has a planted weight-two lattice vector (squared norm 2). Five seed-frozen matched negatives have no nonzero binary kernel and therefore shortest squared norm 4. Acceptance requires LLL to recover the planted vector, every lattice negative to remain at squared norm at least 4, and every independent-label decoder negative to exceed a 1/4 held-out error rate.

**Reviewer scope:** 8D duplicate-row/noiseless sanity check; identity negatives are construction-specific; no labels, no noise, no OCTRA rows, no secret decoding, no complexity implication.

Quick decoder controls cover `n=8,12,16`, while the lattice controls remain dimension 8 so basis materialization and exact LLL are auditable and bounded. No large OCTRA lattice or post-hoc real-row projection is attempted.
