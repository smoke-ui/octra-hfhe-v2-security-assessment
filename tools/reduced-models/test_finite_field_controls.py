import json
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from finite_field_controls import (  # noqa: E402
    WrappedObservation,
    enumerate_candidate_counts,
)


class FiniteFieldControlTests(unittest.TestCase):
    def setUp(self):
        self.observations = (
            WrappedObservation(numerator_0=1, numerator_1=2, coefficient=1, constant=0),
            WrappedObservation(numerator_0=1, numerator_1=3, coefficient=2, constant=1),
        )

    def test_independent_inverse_masks_leave_every_candidate_satisfiable(self):
        counts = enumerate_candidate_counts(7, self.observations, "independent")
        self.assertEqual(set(counts), set(range(7)))
        self.assertTrue(all(count > 0 for count in counts.values()))

    def test_shared_inverse_masks_are_a_positive_control(self):
        counts = enumerate_candidate_counts(7, self.observations, "shared")
        self.assertGreater(len(set(counts.values())), 1)
        self.assertGreater(counts[3], 0)

    def test_disclosed_inverse_masks_identify_the_true_candidate(self):
        counts = enumerate_candidate_counts(
            7, self.observations, "disclosed", disclosed_masks=(2, 4)
        )
        surviving = [candidate for candidate, count in counts.items() if count]
        self.assertEqual(surviving, [3])

    def test_zero_public_numerator_is_rejected_as_outside_control_scope(self):
        bad = (WrappedObservation(0, 2, 1, 0),)
        with self.assertRaisesRegex(ValueError, "nonzero"):
            enumerate_candidate_counts(7, bad, "independent")

    def test_cli_emits_deterministic_scoped_json_warning_against_extrapolation(self):
        command = [sys.executable, str(HERE / "finite_field_controls.py")]
        first = subprocess.run(command, check=True, capture_output=True, text=True).stdout
        second = subprocess.run(command, check=True, capture_output=True, text=True).stdout
        self.assertEqual(first, second)
        document = json.loads(first)
        self.assertIn("N0", document["model_scope"])
        self.assertIn("must not be extrapolated", document["non_extrapolation_warning"])
        self.assertEqual(document["results"]["independent"]["all_satisfiable"], True)
        self.assertEqual(document["results"]["shared"]["distinguishes_candidates"], True)
        self.assertEqual(document["results"]["disclosed"]["surviving_candidates"], [3])


if __name__ == "__main__":
    unittest.main()
