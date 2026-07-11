#!/usr/bin/env python3
"""Exact toy controls for the HFHE wrapped-layer quotient relation.

For public layer numerators N0 and N1 and unknown nonzero inverse masks
q0=R0^-1 and q1=R1^-1, a candidate plaintext relation is

    N0*q0 + N1*q1 = coefficient*candidate + constant (mod p).

Independent mode gives each observation fresh q0,q1, matching independent layer
masks. Shared and disclosed modes are deliberately weak positive controls.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
import json


@dataclass(frozen=True)
class WrappedObservation:
    numerator_0: int
    numerator_1: int
    coefficient: int
    constant: int = 0


def _is_prime(value: int) -> bool:
    return value >= 2 and all(value % divisor for divisor in range(2, int(value**0.5) + 1))


def _matches(
    prime: int,
    candidate: int,
    observation: WrappedObservation,
    q0: int,
    q1: int,
) -> bool:
    public_side = (observation.numerator_0 * q0 + observation.numerator_1 * q1) % prime
    candidate_side = (observation.coefficient * candidate + observation.constant) % prime
    return public_side == candidate_side


def enumerate_candidate_counts(
    prime: int,
    observations: tuple[WrappedObservation, ...],
    mode: str,
    *,
    disclosed_masks: tuple[int, int] | None = None,
) -> dict[int, int]:
    """Count compatible nonzero inverse-mask assignments for each candidate."""
    if not _is_prime(prime):
        raise ValueError("prime must be a toy prime")
    if not observations:
        raise ValueError("at least one observation is required")
    if mode not in {"independent", "shared", "disclosed"}:
        raise ValueError("mode must be independent, shared, or disclosed")
    if any(item.numerator_0 % prime == 0 or item.numerator_1 % prime == 0 for item in observations):
        raise ValueError("public numerators must be nonzero in this control")
    if mode == "disclosed":
        if disclosed_masks is None:
            raise ValueError("disclosed mode requires inverse masks")
        if any(mask <= 0 or mask >= prime for mask in disclosed_masks):
            raise ValueError("disclosed inverse masks must be nonzero field elements")

    masks = tuple(product(range(1, prime), repeat=2))
    counts: dict[int, int] = {}
    for candidate in range(prime):
        if mode == "independent":
            count = 1
            for observation in observations:
                count *= sum(
                    _matches(prime, candidate, observation, q0, q1) for q0, q1 in masks
                )
        elif mode == "shared":
            count = sum(
                all(_matches(prime, candidate, observation, q0, q1) for observation in observations)
                for q0, q1 in masks
            )
        else:
            q0, q1 = disclosed_masks  # type: ignore[misc]
            count = int(
                all(_matches(prime, candidate, observation, q0, q1) for observation in observations)
            )
        counts[candidate] = count
    return counts


def _result(counts: dict[int, int]) -> dict[str, object]:
    values = list(counts.values())
    return {
        "candidate_counts": {str(candidate): count for candidate, count in counts.items()},
        "all_satisfiable": all(count > 0 for count in values),
        "distinguishes_candidates": len(set(values)) > 1,
        "surviving_candidates": [candidate for candidate, count in counts.items() if count],
    }


def main() -> None:
    observations = (
        WrappedObservation(1, 2, 1, 0),
        WrappedObservation(1, 3, 2, 1),
    )
    results = {
        "independent": _result(enumerate_candidate_counts(7, observations, "independent")),
        "shared": _result(enumerate_candidate_counts(7, observations, "shared")),
        "disclosed": _result(
            enumerate_candidate_counts(7, observations, "disclosed", disclosed_masks=(2, 4))
        ),
    }
    document = {
        "model_scope": "exact exhaustive toy-prime N0*q0 + N1*q1 wrapped-layer relation",
        "non_extrapolation_warning": (
            "This reduced finite-field control must not be extrapolated to production "
            "parameters, cryptographic security, or the full HFHE construction."
        ),
        "prime": 7,
        "inverse_masks_are_nonzero": True,
        "results": results,
    }
    print(json.dumps(document, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
