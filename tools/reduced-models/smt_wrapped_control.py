#!/usr/bin/env python3
"""SMT-LIB cross-check for the exact toy HFHE wrapped-layer relation."""

from __future__ import annotations

import json
import shutil
import subprocess

from finite_field_controls import WrappedObservation, enumerate_candidate_counts


def _equation(
    prime: int,
    candidate: int,
    observation: WrappedObservation,
    q0: str,
    q1: str,
) -> str:
    rhs = (observation.coefficient * candidate + observation.constant) % prime
    return (
        f"(assert (= (mod (+ (* {observation.numerator_0} {q0}) "
        f"(* {observation.numerator_1} {q1})) {prime}) {rhs}))"
    )


def _program(
    prime: int,
    observations: tuple[WrappedObservation, ...],
    mode: str,
    candidate: int,
    disclosed_masks: tuple[int, int] | None,
) -> str:
    lines = ["(set-logic QF_NIA)"]
    if mode == "independent":
        names = [(f"q0_{i}", f"q1_{i}") for i in range(len(observations))]
    elif mode == "shared":
        names = [("q0", "q1")] * len(observations)
    else:
        assert disclosed_masks is not None
        names = [(str(disclosed_masks[0]), str(disclosed_masks[1]))] * len(observations)

    for name in sorted({name for pair in names for name in pair if not name.isdigit()}):
        lines.extend(
            (
                f"(declare-const {name} Int)",
                f"(assert (and (>= {name} 1) (< {name} {prime})))",
            )
        )
    lines.extend(
        _equation(prime, candidate, observation, q0, q1)
        for observation, (q0, q1) in zip(observations, names, strict=True)
    )
    lines.extend(("(check-sat)", "(exit)"))
    return "\n".join(lines) + "\n"


def solver_satisfiability(
    prime: int,
    observations: tuple[WrappedObservation, ...],
    mode: str,
    *,
    disclosed_masks: tuple[int, int] | None = None,
) -> dict[int, bool]:
    """Return per-candidate SAT results from the Z3 CLI."""
    if shutil.which("z3") is None:
        raise RuntimeError("z3 CLI unavailable")
    enumerate_candidate_counts(
        prime, observations, mode, disclosed_masks=disclosed_masks
    )  # shared validation with the exhaustive control
    solved = {}
    for candidate in range(prime):
        process = subprocess.run(
            ["z3", "-in"],
            input=_program(prime, observations, mode, candidate, disclosed_masks),
            text=True,
            capture_output=True,
            check=True,
        )
        answer = process.stdout.strip()
        if answer not in {"sat", "unsat"}:
            raise RuntimeError(f"unexpected z3 output: {answer!r}")
        solved[candidate] = answer == "sat"
    return solved


def main() -> None:
    observations = (
        WrappedObservation(1, 2, 1, 0),
        WrappedObservation(1, 3, 2, 1),
    )
    result = {
        mode: solver_satisfiability(
            7,
            observations,
            mode,
            disclosed_masks=(2, 4) if mode == "disclosed" else None,
        )
        for mode in ("independent", "shared", "disclosed")
    }
    print(
        json.dumps(
            {
                "solver": "z3-cli",
                "model_scope": "toy-prime HFHE wrapped-layer relation",
                "non_extrapolation_warning": "SAT controls must not be extrapolated to full HFHE security.",
                "satisfiable": result,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
