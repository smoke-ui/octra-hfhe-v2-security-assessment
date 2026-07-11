#!/usr/bin/env python3
"""Deterministic subset-lattice and non-orientable public-incidence diagnostics."""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import random
import struct
from pathlib import Path
from typing import Iterable

PREDICATE_NAMES = (
    "layer_1", "negative_sign", "idx_bit_0", "idx_bit_1", "idx_bit_2", "idx_bit_3",
    "idx_mod_3_zero", "idx_mod_5_zero", "weight_lo_odd", "weight_hi_odd",
    "support_popcount_odd", "support_first_bit",
)
PINNED_CIPHERTEXTS = 22
PINNED_SLOTS = 1
PINNED_LAYERS = 2
PINNED_SUPPORT_BITS = 8192
PINNED_EDGE_INDEX_BOUND = 337


def degree_terms(variables: int, degree: int) -> list[tuple[int, ...]]:
    return [term for k in range(1, degree + 1) for term in itertools.combinations(range(variables), k)]


def subset_zeta(values: list[int]) -> list[int]:
    out = values.copy()
    bits = _power_bits(len(out))
    for bit in range(bits):
        for mask in range(len(out)):
            if mask & (1 << bit):
                out[mask] += out[mask ^ (1 << bit)]
    return out


def subset_mobius(values: list[int]) -> list[int]:
    out = values.copy()
    bits = _power_bits(len(out))
    for bit in range(bits):
        for mask in range(len(out)):
            if mask & (1 << bit):
                out[mask] -= out[mask ^ (1 << bit)]
    return out


def subset_zeta_supersets(cells: list[int]) -> list[int]:
    out = cells.copy()
    bits = _power_bits(len(out))
    for bit in range(bits):
        for mask in range(len(out)):
            if not mask & (1 << bit):
                out[mask] += out[mask | (1 << bit)]
    return out


def subset_mobius_supersets(values: list[int]) -> list[int]:
    out = values.copy()
    bits = _power_bits(len(out))
    for bit in range(bits):
        for mask in range(len(out)):
            if not mask & (1 << bit):
                out[mask] -= out[mask | (1 << bit)]
    return out


def boolean_coefficients(conjunction_counts: list[int]) -> list[int]:
    """Invert F(S), the count satisfying every predicate in S, on the Boolean lattice."""
    return subset_mobius(conjunction_counts)


def _power_bits(n: int) -> int:
    if n < 1 or n & (n - 1):
        raise ValueError("length must be a power of two")
    return n.bit_length() - 1


def planted_inversion_fixture(variables: int = 6, degree: int = 3) -> dict:
    if not 1 <= degree <= variables:
        raise ValueError("invalid planted degree")
    planted = tuple(range(degree))
    coefficients = [0] * (1 << variables)
    coefficients[sum(1 << i for i in planted)] = 7
    evaluations = subset_zeta(coefficients)
    recovered = subset_mobius(evaluations)
    support = tuple(i for i, value in enumerate(recovered) if value)
    return {
        "exact": recovered == coefficients,
        "max_error": max(abs(a - b) for a, b in zip(recovered, coefficients)),
        "planted_degree": degree,
        "planted_support": [sum(1 << i for i in planted)],
        "recovered_support": list(support),
    }


def orientation_product(transitions: Iterable[int]) -> int:
    product = 1
    for transition in transitions:
        if transition not in (-1, 1):
            raise ValueError("orientation transition must be +/-1")
        product *= transition
    return product


def orientability_check(width: int = 22) -> dict[str, bool]:
    if width < 2:
        raise ValueError("width must be at least two")
    return {
        "cylinder": orientation_product([1] * width) == 1,
        "mobius": orientation_product([1] * (width - 1) + [-1]) == 1,
    }


def fixture_grid(twisted: bool, width: int = 8) -> list[list[list[float]]]:
    if width < 2:
        raise ValueError("width must be at least two")
    grid = []
    for column in range(width):
        x = column / (width - 1)
        turns = math.pi * x if twisted else 2 * math.pi * x
        first = [0.5 + 0.5 * math.cos(turns + 2 * math.pi * p / 12) for p in range(12)]
        other = [0.5 + 0.5 * math.cos(turns + math.pi + 2 * math.pi * p / 12) for p in range(12)]
        grid.append([first, other])
    return grid


def _bounded_wave(x: float, predicate: int) -> float:
    return x if predicate % 3 == 0 else (x * x if predicate % 3 == 1 else math.sqrt(x))


def _distance(a: list[float], b: list[float]) -> float:
    if len(a) != len(b) or not a:
        raise ValueError("incompatible feature vectors")
    return sum(abs(x - y) for x, y in zip(a, b)) / len(a)


def closure_errors(grid: list[list[list[float]]], shift: int = 0) -> tuple[float, float]:
    width = len(grid)
    target = shift % width
    cylinder = sum(_distance(grid[-1][layer], grid[target][layer]) for layer in range(2)) / 2
    mobius = sum(_distance(grid[-1][layer], grid[target][1 - layer]) for layer in range(2)) / 2
    return min(1.0, cylinder), min(1.0, mobius)


def cycle_parity_energies(grid: list[list[list[float]]]) -> dict[str, float]:
    """Minimum adjacent-cycle matching energy for each global transition parity."""
    _validate_grid(grid)
    width = len(grid)
    energy = {1: 0.0, -1: math.inf}
    for column in range(width):
        following = (column + 1) % width
        costs = {
            1: sum(_distance(grid[column][l], grid[following][l]) for l in range(2)) / 2,
            -1: sum(_distance(grid[column][l], grid[following][1 - l]) for l in range(2)) / 2,
        }
        energy = {parity: min(energy[parity * transition] + costs[transition]
                              for transition in (-1, 1))
                  for parity in (-1, 1)}
    return {"cylinder": round(min(1.0, energy[1] / width), 9),
            "mobius": round(min(1.0, energy[-1] / width), 9)}


def incidence_summary(grid: list[list[list[float]]]) -> dict:
    _validate_grid(grid)
    width = len(grid)
    energies = cycle_parity_energies(grid)
    preferred = "cylinder" if energies["cylinder"] <= energies["mobius"] else "mobius"
    gap = abs(energies["cylinder"] - energies["mobius"])
    alternating = []
    for predicate in range(12):
        numerator = abs(sum(((-1) ** c) * abs(grid[c][0][predicate] - grid[c][1][predicate])
                            for c in range(width)))
        denominator = sum(abs(grid[c][0][predicate]) + abs(grid[c][1][predicate]) for c in range(width)) or 1.0
        alternating.append(numerator / denominator)
    return {
        "circulation": min(energies.values()),
        "holonomy": round(gap, 9),
        "harmonic": round(min(1.0, sum(alternating) / len(alternating)), 9),
        "preferred_closure": preferred,
        "closure_gap": round(gap, 9),
    }


def planted_holonomy_fixture(twisted: bool, width: int = 8) -> dict:
    summary = incidence_summary(fixture_grid(twisted, width))
    expected = "mobius" if twisted else "cylinder"
    preferred = summary["preferred_closure"]
    return {"detected": preferred == expected and summary["closure_gap"] > 0,
            "preferred": preferred, "closure_gap": summary["closure_gap"]}


def control_grids(grid: list[list[list[float]]], seed: int) -> dict[str, list[list[list[float]]]]:
    _validate_grid(grid)
    gauge = [[row[1][:], row[0][:]] if c % 2 else [row[0][:], row[1][:]] for c, row in enumerate(grid)]
    reversal = [[row[0][:], row[1][:]] for row in reversed(grid)]
    order = list(range(len(grid)))
    random.Random(seed).shuffle(order)
    columns = [[[v for v in grid[c][l]] for l in range(2)] for c in order]
    return {"layer_gauge": gauge, "layer_reversal": reversal, "random_columns": columns}


def _validate_grid(grid: list[list[list[float]]]) -> None:
    if len(grid) < 2 or any(len(column) != 2 for column in grid):
        raise ValueError("expected width x 2 grid")
    if any(len(layer) != 12 for column in grid for layer in column):
        raise ValueError("expected 12 public predicates")


def family_max_pvalues(observed: list[float], null: list[list[float]]) -> list[float]:
    if not null or any(len(row) != len(observed) for row in null):
        raise ValueError("invalid permutation family")
    maxima = [max(row) for row in null]
    return [(1 + sum(value >= score for value in maxima)) / (len(null) + 1) for score in observed]


def holm_adjust(pvalues: list[float]) -> list[float]:
    order = sorted(range(len(pvalues)), key=pvalues.__getitem__)
    adjusted = [1.0] * len(pvalues)
    running = 0.0
    for rank, index in enumerate(order):
        running = max(running, min(1.0, (len(pvalues) - rank) * pvalues[index]))
        adjusted[index] = running
    return adjusted


class _Reader:
    def __init__(self, data: bytes): self.data, self.pos = data, 0
    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data): raise ValueError("truncated artifact")
        value = self.data[self.pos:self.pos + n]; self.pos += n; return value
    def integer(self, n: int) -> int: return int.from_bytes(self.take(n), "little")
    def u8(self) -> int: return self.integer(1)
    def u16(self) -> int: return self.integer(2)
    def u32(self) -> int: return self.integer(4)
    def u64(self) -> int: return self.integer(8)


def _read_bitvec(reader: _Reader, expected_nbits: int) -> tuple[int, list[int]]:
    nbits, words = reader.u64(), reader.u64()
    if words != (nbits + 63) // 64 or words > 1 << 20: raise ValueError("invalid bit vector")
    values = [reader.u64() for _ in range(words)]
    if nbits % 64 and values and values[-1] >> (nbits % 64):
        raise ValueError("nonzero support tail bits")
    if nbits != expected_nbits: raise ValueError("support dimension mismatch")
    return nbits, values


def parse_bundle(path: str | Path) -> list[list[dict]]:
    reader = _Reader(Path(path).read_bytes())
    if reader.take(16) != b"OCTRA-HFHE-BTY02": raise ValueError("bad bundle magic")
    count = reader.u64()
    if count != PINNED_CIPHERTEXTS: raise ValueError("cipher count does not match pinned dimension")
    ciphers = []
    for _ in range(count):
        member = _Reader(reader.take(reader.u64()))
        if member.take(6) != b"PVAC\x03\x00": raise ValueError("bad cipher header")
        slots, layers = member.u64(), member.u64()
        if (slots, layers) != (PINNED_SLOTS, PINNED_LAYERS):
            raise ValueError("cipher shape does not match pinned dimensions")
        for _layer in range(layers):
            rule = member.u8()
            if rule not in (0, 1): raise ValueError("invalid layer rule")
            member.take(24 if rule == 0 else 8)
            member.take(member.u64() * 32)
        member.take(member.u64() * 16)
        edges = []
        for _edge in range(member.u64()):
            layer, idx, sign, nw = member.u32(), member.u16(), member.u8(), member.u64()
            if layer >= layers: raise ValueError("edge layer out of range")
            if idx >= PINNED_EDGE_INDEX_BOUND: raise ValueError("edge index out of range")
            if sign not in (0, 1): raise ValueError("edge sign out of range")
            if nw != slots: raise ValueError("edge weight/slot mismatch")
            weights = [(member.u64(), member.u64()) for _ in range(nw)]
            _, words = _read_bitvec(member, PINNED_SUPPORT_BITS)
            edges.append({"layer": layer, "idx": idx, "sign": sign, "weights": weights, "support": words})
        if member.pos != len(member.data): raise ValueError("trailing cipher bytes")
        ciphers.append(edges)
    if reader.pos != len(reader.data): raise ValueError("trailing bundle bytes")
    return ciphers


def edge_mask(edge: dict) -> int:
    lo, hi = edge["weights"][0]
    words = edge["support"]
    values = (edge["layer"] == 1, edge["sign"] != 0,
              *((edge["idx"] >> bit) & 1 for bit in range(4)), edge["idx"] % 3 == 0,
              edge["idx"] % 5 == 0, lo & 1, hi & 1,
              sum(word.bit_count() for word in words) & 1, bool(words and words[0] & 1))
    return sum((1 << i) for i, value in enumerate(values) if value)


def artifact_statistics(ciphers: list[list[dict]]) -> tuple[list[int], list[list[list[float]]]]:
    if len(ciphers) != 22: raise ValueError("experiment requires 22 ciphertext columns")
    cells = [0] * (1 << 12)
    grid = [[[0.0] * 12 for _ in range(2)] for _ in range(22)]
    totals = [[0, 0] for _ in range(22)]
    for column, edges in enumerate(ciphers):
        for edge in edges:
            layer = edge["layer"]
            if layer not in (0, 1): raise ValueError("invalid edge layer")
            mask = edge_mask(edge); cells[mask] += 1; totals[column][layer] += 1
            for predicate in range(12): grid[column][layer][predicate] += bool(mask & (1 << predicate))
        if any(total == 0 for total in totals[column]):
            raise ValueError("each ciphertext must contain edges in both layers")
    for c in range(22):
        for layer in range(2):
            if totals[c][layer]: grid[c][layer] = [value / totals[c][layer] for value in grid[c][layer]]
    return cells, grid


def write_fixture_bundle(path: str | Path, width: int = 22) -> None:
    members = []
    for column in range(width):
        member = bytearray(b"PVAC\x03\x00" + struct.pack("<QQ", 1, 2))
        for layer in range(2): member += bytes([0]) + struct.pack("<QQQQ", column, layer, 0, 0)
        member += struct.pack("<Q", 0)
        edges = []
        for layer in range(2):
            idx = column if layer == 0 else width - 1 - column
            edge = struct.pack("<IHBQ", layer, idx, layer, 1) + struct.pack("<QQ", idx + 1, layer)
            support = [0] * (PINNED_SUPPORT_BITS // 64)
            support[layer] = 1
            edge += struct.pack("<QQ", PINNED_SUPPORT_BITS, len(support))
            edge += b"".join(struct.pack("<Q", word) for word in support)
            edges.append(edge)
        member += struct.pack("<Q", len(edges)) + b"".join(edges)
        members.append(bytes(member))
    bundle = bytearray(b"OCTRA-HFHE-BTY02" + struct.pack("<Q", width))
    for member in members: bundle += struct.pack("<Q", len(member)) + member
    Path(path).write_bytes(bundle)


def run_experiment(path: str | Path, permutations: int = 999, seed: int = 20260711) -> dict:
    cells, grid = artifact_statistics(parse_bundle(path))
    inclusive = subset_zeta_supersets(cells)
    recovered = subset_mobius_supersets(inclusive)
    terms = degree_terms(12, 4)
    polynomial = boolean_coefficients(inclusive)
    coefficient_rows = [[sum(1 << i for i in term), polynomial[sum(1 << i for i in term)]] for term in terms]
    degree_counts = {str(k): sum(1 for term in terms if len(term) == k) for k in range(1, 5)}
    observed_summary = incidence_summary(grid)
    controls = {name: incidence_summary(value) for name, value in control_grids(grid, seed).items()}
    rng = random.Random(seed)
    statistic_names = ("circulation", "holonomy", "harmonic", "closure_gap")
    observed = [observed_summary[k] for k in statistic_names]
    null = []
    for _ in range(permutations):
        order = list(range(22)); rng.shuffle(order)
        shuffled = [grid[i] for i in order]
        summary = incidence_summary(shuffled)
        null.append([summary[k] for k in statistic_names])
    max_p = family_max_pvalues(observed, null)
    artifact_path = Path(path)
    return {
        "schema": 1,
        "artifact": {"ciphertexts": 22, "layers_per_ciphertext": 2, "label_use": "unlabeled_descriptive_only",
                     "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest()},
        "analyzer": {"sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        "subset_lattice": {"predicates": list(PREDICATE_NAMES), "degree_limit": 4,
                           "function_definition": "F(S)=edge_count_satisfying_all_predicates_in_S",
                           "inversion": "boolean_subset_mobius_of_F",
                           "degree_counts": degree_counts, "reported_nonconstant_coefficients": len(terms),
                           "coefficients_degree_le_4": coefficient_rows,
                           "exact_round_trip": recovered == cells,
                           "nonzero_exact_cells": sum(value != 0 for value in recovered)},
        "geometry": {"shape": [22, 2], "topology_status": "analyst_imposed_hypothetical_unlabeled",
                     "orientability": {"status": "analyst_imposed_hypothetical_complex",
                                       "artifact_inferred": False,
                                       "models": orientability_check(22)},
                     "artifact_summary": observed_summary,
                     "controls": controls},
        "inference": {"permutations": permutations, "permutation_seed": seed,
                      "family_max_p": dict(zip(statistic_names, max_p))},
        "fixtures": {"inversion_positive": planted_inversion_fixture(),
                     "holonomy_positive": planted_holonomy_fixture(True),
                     "holonomy_negative": planted_holonomy_fixture(False)},
        "claims": {"plaintext_leakage": False, "scope": "public_incidence_diagnostics_only"},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--permutations", type=int, default=999)
    parser.add_argument("--seed", type=int, default=20260711)
    args = parser.parse_args()
    report = run_experiment(args.artifact, args.permutations, args.seed)
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    if args.out: args.out.write_text(text)
    else: print(text, end="")


if __name__ == "__main__": main()
