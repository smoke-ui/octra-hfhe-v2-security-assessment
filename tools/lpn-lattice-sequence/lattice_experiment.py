#!/usr/bin/env python3
"""Deterministic reduced LPN decoder and Construction-A/LLL controls."""
from __future__ import annotations
import argparse
from fractions import Fraction
import itertools
import json
import pathlib
import numpy as np


def planted_lpn(n, m, tau_num, tau_den, seed, holdout, negative=False):
    if not (0 < n <= m and 0 <= holdout < m and 0 <= tau_num <= tau_den):
        raise ValueError("invalid dimensions or noise rate")
    rng = np.random.default_rng(seed)
    A = rng.integers(0, 2, (m, n), dtype=np.uint8)
    secret = rng.integers(0, 2, n, dtype=np.uint8)
    e = np.zeros(m, dtype=np.uint8)
    count = (m * tau_num) // tau_den
    if count:
        e[rng.choice(m, count, replace=False)] = 1
    b = ((A @ secret) + e) & 1
    if negative:
        b = rng.integers(0, 2, m, dtype=np.uint8)
    cut = m - holdout
    return {"A": A, "b": b, "e": e, "secret": secret, "seed": seed,
            "A_train": A[:cut], "b_train": b[:cut], "A_holdout": A[cut:], "b_holdout": b[cut:]}


def gf2_solve(A, b):
    M = np.column_stack((np.asarray(A, dtype=np.uint8), np.asarray(b, dtype=np.uint8))).copy()
    rows, n1 = M.shape; n = n1 - 1; pivot_row = 0; pivots = []
    for col in range(n):
        choices = np.flatnonzero(M[pivot_row:, col])
        if not len(choices): continue
        p = pivot_row + int(choices[0]); M[[pivot_row, p]] = M[[p, pivot_row]]
        for r in range(rows):
            if r != pivot_row and M[r, col]: M[r] ^= M[pivot_row]
        pivots.append(col); pivot_row += 1
        if pivot_row == rows: break
    if np.any((M[:, :n].sum(axis=1) == 0) & (M[:, n] == 1)) or len(pivots) < n: return None
    x = np.zeros(n, dtype=np.uint8)
    for r, col in enumerate(pivots): x[col] = M[r, n]
    return x


def residual_weight(A, b, secret):
    return int(np.count_nonzero(((A @ secret) & 1) ^ b))


def correlation_decode(A, b, max_candidates):
    n = A.shape[1]; total = 1 << n
    if total > max_candidates: raise ValueError(f"2^{n} candidates exceeds limit {max_candidates}")
    best_score, best = A.shape[0] + 1, None
    for start in range(0, total, 4096):
        vals = np.arange(start, min(start + 4096, total), dtype=np.uint64)
        bits = ((vals[:, None] >> np.arange(n, dtype=np.uint64)) & 1).astype(np.uint8)
        scores = np.count_nonzero(((bits @ A.T) & 1) ^ b, axis=1); i = int(np.argmin(scores))
        if int(scores[i]) < best_score: best_score, best = int(scores[i]), bits[i].copy()
    return {"secret": best, "train_residual": best_score, "work": total}


def isd_decode(A, b, iterations, seed):
    rng = np.random.default_rng(seed); best, score = None, A.shape[0] + 1
    for _ in range(iterations):
        rows = rng.choice(A.shape[0], A.shape[1], replace=False); candidate = gf2_solve(A[rows], b[rows])
        if candidate is not None:
            value = residual_weight(A, b, candidate)
            if value < score: best, score = candidate, value
    return {"secret": best, "train_residual": None if best is None else score, "work": iterations}


def short_dual_search(A, b, max_weight=3, max_combinations=10000):
    vectors, work = [], 0
    for weight in range(1, max_weight + 1):
        for rows in itertools.combinations(range(A.shape[0]), weight):
            if work >= max_combinations: return {"vectors": vectors, "work": work, "truncated": True}
            work += 1
            if not np.any(A[list(rows)].sum(axis=0) & 1):
                vectors.append({"rows": list(rows), "parity": int(np.bitwise_xor.reduce(b[list(rows)]))})
    return {"vectors": vectors, "work": work, "truncated": False}


def dual_parity_summary(result):
    count = len(result["vectors"]); zeros = sum(v["parity"] == 0 for v in result["vectors"])
    return {"dependencies_found": count, "zero_parity_fraction": None if not count else zeros / count,
            "truncated": result["truncated"], "interpretation": "dependency_enumeration_only",
            "work": {"value": result["work"], "unit": "row_combinations_tested"}}


def construction_a_basis(A, max_dimension=64):
    """Basis of {x in Z^m: x A = 0 mod 2}, from GF(2) RREF."""
    A = np.asarray(A, dtype=np.uint8); m = A.shape[0]
    if m > max_dimension: raise ValueError(f"lattice dimension {m} exceeds bound {max_dimension}")
    R = A.T.copy(); row = 0; pivots = []
    for col in range(m):
        choices = np.flatnonzero(R[row:, col])
        if not len(choices): continue
        p = row + int(choices[0]); R[[row, p]] = R[[p, row]]
        for r in range(R.shape[0]):
            if r != row and R[r, col]: R[r] ^= R[row]
        pivots.append(col); row += 1
        if row == R.shape[0]: break
    free = [c for c in range(m) if c not in pivots]; basis = []
    for f in free:
        v = np.zeros(m, dtype=np.int64); v[f] = 1
        for r, p in enumerate(pivots): v[p] = int(R[r, f])
        basis.append(v)
    for p in pivots:
        v = np.zeros(m, dtype=np.int64); v[p] = 2; basis.append(v)
    return np.asarray(basis, dtype=np.int64)


def lll_reduce(basis, delta=Fraction(3, 4)):
    """Exact-arithmetic, deterministic textbook LLL; work is Lovasz checks."""
    B = [list(map(int, row)) for row in np.asarray(basis)]
    def gs():
        stars, mu, norms = [], [[Fraction(0) for _ in B] for _ in B], []
        for i, v in enumerate(B):
            u = list(map(Fraction, v))
            for j in range(i):
                mu[i][j] = sum(Fraction(v[t]) * stars[j][t] for t in range(len(v))) / norms[j]
                u = [u[t] - mu[i][j] * stars[j][t] for t in range(len(v))]
            stars.append(u); norms.append(sum(x*x for x in u))
        return mu, norms
    k, checks = 1, 0; mu, norms = gs()
    while k < len(B):
        for j in range(k - 1, -1, -1):
            q = int(mu[k][j] + Fraction(1, 2)) if mu[k][j] >= 0 else int(mu[k][j] - Fraction(1, 2))
            if q: B[k] = [x - q*y for x, y in zip(B[k], B[j])]; mu, norms = gs()
        checks += 1
        if norms[k] >= (delta - mu[k][k-1]**2) * norms[k-1]: k += 1
        else: B[k], B[k-1] = B[k-1], B[k]; k = max(k-1, 1); mu, norms = gs()
    return np.asarray(B, dtype=np.int64), checks


def _lattice_result(A, planted=None):
    reduced, checks = lll_reduce(construction_a_basis(A, 16)); norms = np.sum(reduced*reduced, axis=1); shortest = reduced[int(np.argmin(norms))]
    recovered = False if planted is None else any(np.array_equal(shortest, s*planted) for s in (1, -1))
    return {"dimension": int(A.shape[0]), "basis_materialized": True, "algorithm": "exact_fraction_textbook_lll_delta_3/4",
            "shortest_squared_l2": int(np.min(norms)), "planted_vector_recovered": recovered,
            "work": {"value": checks, "unit": "lovasz_checks"}}


def toy_lattice_controls(positive_seed, negative_seeds):
    # Seeds are recorded; row permutations make independently seeded, isometric controls.
    rng = np.random.default_rng(positive_seed); P = np.eye(7, dtype=np.uint8); A = np.vstack((P, P[0]))
    perm = rng.permutation(8); A = A[perm]; planted = np.zeros(8, dtype=np.int64); planted[np.flatnonzero(perm == 0)[0]] = 1; planted[np.flatnonzero(perm == 7)[0]] = 1
    positive = {"seed": positive_seed, **_lattice_result(A, planted)}
    negatives = []
    for seed in negative_seeds:
        rng = np.random.default_rng(seed); N = np.eye(8, dtype=np.uint8)[rng.permutation(8)]
        negatives.append({"seed": seed, **_lattice_result(N)})
    return positive, negatives


def _record(method, c, result, unit):
    candidate = result.get("secret")
    return {"method": method, "work": {"value": result["work"], "unit": unit}, "candidate_found": candidate is not None,
            "train_residual": None if candidate is None else residual_weight(c["A_train"], c["b_train"], candidate),
            "holdout_residual": None if candidate is None else residual_weight(c["A_holdout"], c["b_holdout"], candidate),
            "exact_recovery": False if candidate is None else bool(np.array_equal(candidate, c["secret"]))}


def run_benchmarks(quick=True):
    positive = []
    for i, n in enumerate([8, 12, 16] if quick else [8, 12, 16, 18]):
        c = planted_lpn(n, 8*n, 1, 8, 4100+i, 2*n); methods = []
        s = gf2_solve(c["A_train"][:n], c["b_train"][:n]); methods.append(_record("square_gf2_first_n_rows", c, {"secret": s, "work": n}, "rows_in_square_system"))
        methods.append(_record("exhaustive_correlation", c, correlation_decode(c["A_train"], c["b_train"], 1 << 18), "candidate_assignments_scored"))
        methods.append(_record("information_set_sampling", c, isd_decode(c["A_train"], c["b_train"], 2000, 5100+i), "information_sets_sampled"))
        methods.append({"method": "short_dual", **dual_parity_summary(short_dual_search(c["A_train"], c["b_train"], 3, 20000))})
        positive.append({"n": n, "m": 8*n, "train": 6*n, "holdout": 2*n, "seed": 4100+i, "methods": methods})
    lattice_positive, lattice_negative = toy_lattice_controls(6200, [6201, 6202, 6203, 6204, 6205])
    negative = []
    for seed in [4999, 5000, 5001, 5002, 5003]:
        c = planted_lpn(12, 96, 1, 8, seed, 24, negative=True)
        negative.append({"seed": seed, "labels": "independent_uniform", "result": _record("exhaustive_correlation", c, correlation_decode(c["A_train"], c["b_train"], 1 << 12), "candidate_assignments_scored")})
    passed = lattice_positive["planted_vector_recovered"] and lattice_positive["shortest_squared_l2"] < 4 and all(x["shortest_squared_l2"] >= 4 for x in lattice_negative) and all(x["result"]["holdout_residual"] / 24 > .25 for x in negative)
    return {"schema_version": 2, "parameters": {"noise_model": "fixed_weight_floor_m_over_8", "noise_rate": "1/8", "m_over_n": 8, "frozen_seeds": True},
            "controls": {"positive": positive, "negative": negative, "construction_a_lll": {"positive": lattice_positive, "matched_negative": lattice_negative}},
            "acceptance": {"criterion": "planted norm^2<4 recovered; every lattice negative norm^2>=4; every label negative holdout error rate>1/4", "passed": passed},
            "limitations": {"no_full_octra_recovery_claim": True, "scope": "reduced deterministic controls only; work units are algorithm-specific and not cross-method comparisons",
            "lattice_reviewer_scope": "8D duplicate-row/noiseless sanity check; identity negatives are construction-specific; no labels, no noise, no OCTRA rows, no secret decoding, no complexity implication."}}


def main():
    p = argparse.ArgumentParser(); p.add_argument("--quick", action="store_true"); p.add_argument("--output", type=pathlib.Path, default=pathlib.Path(__file__).parent / "results/lpn-lattice-controls.json"); args = p.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(run_benchmarks(args.quick), separators=(",", ":"), sort_keys=True) + "\n"); print(args.output)


if __name__ == "__main__": main()
