import shutil
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from finite_field_controls import WrappedObservation, enumerate_candidate_counts  # noqa: E402
from smt_wrapped_control import solver_satisfiability  # noqa: E402


@unittest.skipUnless(shutil.which("z3"), "z3 CLI unavailable")
class SmtWrappedControlTests(unittest.TestCase):
    def test_z3_matches_exhaustive_enumeration(self):
        observations = (
            WrappedObservation(1, 2, 1, 0),
            WrappedObservation(1, 3, 2, 1),
        )
        for mode, masks in (
            ("independent", None),
            ("shared", None),
            ("disclosed", (2, 4)),
        ):
            exhaustive = enumerate_candidate_counts(
                7, observations, mode, disclosed_masks=masks
            )
            solved = solver_satisfiability(
                7, observations, mode, disclosed_masks=masks
            )
            self.assertEqual(
                solved,
                {candidate: count > 0 for candidate, count in exhaustive.items()},
            )


if __name__ == "__main__":
    unittest.main()
