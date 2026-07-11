import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

HERE = pathlib.Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("lattice_experiment", HERE / "lattice_experiment.py")
le = importlib.util.module_from_spec(SPEC)
try:
    SPEC.loader.exec_module(le)
except FileNotFoundError:
    le = None


class LatticeExperimentTests(unittest.TestCase):
    def test_planted_control_is_frozen_tau_and_split(self):
        c = le.planted_lpn(n=8, m=64, tau_num=1, tau_den=8, seed=1729, holdout=16)
        self.assertEqual(c["A_train"].shape, (48, 8))
        self.assertEqual(c["A_holdout"].shape, (16, 8))
        self.assertEqual(int(c["e"].sum()), 8)
        self.assertEqual(c["seed"], 1729)
        self.assertTrue(((c["A"] @ c["secret"] + c["e"]) % 2 == c["b"]).all())

    def test_gaussian_elimination_exact_on_noiseless_control(self):
        c = le.planted_lpn(10, 40, 0, 8, 1730, 10)
        s = le.gf2_solve(c["A_train"], c["b_train"])
        self.assertIsNotNone(s)
        self.assertTrue((s == c["secret"]).all())
        self.assertEqual(le.residual_weight(c["A_holdout"], c["b_holdout"], s), 0)

    def test_correlation_decoder_recovers_small_noisy_control_and_validates_holdout(self):
        c = le.planted_lpn(12, 96, 1, 8, 1731, 24)
        result = le.correlation_decode(c["A_train"], c["b_train"], max_candidates=1 << 12)
        self.assertTrue((result["secret"] == c["secret"]).all())
        self.assertEqual(result["work"], 1 << 12)
        self.assertLessEqual(le.residual_weight(c["A_holdout"], c["b_holdout"], result["secret"]), 6)

    def test_negative_random_labels_do_not_pass_tau_holdout_threshold(self):
        c = le.planted_lpn(10, 80, 1, 8, 1732, 24, negative=True)
        result = le.correlation_decode(c["A_train"], c["b_train"], 1 << 10)
        rate = le.residual_weight(c["A_holdout"], c["b_holdout"], result["secret"]) / 24
        self.assertGreater(rate, 0.25)

    def test_short_dual_search_returns_only_valid_bounded_dependencies(self):
        c = le.planted_lpn(8, 32, 1, 8, 1733, 8)
        out = le.short_dual_search(c["A_train"], c["b_train"], max_weight=3, max_combinations=5000)
        self.assertLessEqual(out["work"], 5000)
        for d in out["vectors"]:
            self.assertLessEqual(len(d["rows"]), 3)
            self.assertTrue((c["A_train"][d["rows"]].sum(axis=0) % 2 == 0).all())

    def test_construction_a_materializes_a_valid_full_rank_integer_basis(self):
        c = le.planted_lpn(6, 16, 1, 8, 1734, 4)
        basis = le.construction_a_basis(c["A_train"], max_dimension=16)
        self.assertEqual(basis.shape, (12, 12))
        self.assertNotEqual(round(__import__("numpy").linalg.det(basis)), 0)
        self.assertTrue(((basis @ c["A_train"]) % 2 == 0).all())
        with self.assertRaises(ValueError):
            le.construction_a_basis(c["A"], max_dimension=12)

    def test_pure_python_lll_exposes_work_units_and_finds_planted_short_vector(self):
        positive, negatives = le.toy_lattice_controls(6200, [6201, 6202, 6203])
        self.assertLess(positive["shortest_squared_l2"], 4)
        self.assertTrue(positive["planted_vector_recovered"])
        self.assertTrue(all(x["shortest_squared_l2"] >= 4 for x in negatives))
        self.assertEqual(positive["work"]["unit"], "lovasz_checks")
        self.assertGreater(positive["work"]["value"], 0)

    def test_short_dual_reports_parity_bias_not_decoder_recovery(self):
        c = le.planted_lpn(8, 32, 1, 8, 1733, 8)
        out = le.short_dual_search(c["A_train"], c["b_train"], 3, 5000)
        summary = le.dual_parity_summary(out)
        self.assertEqual(summary["interpretation"], "dependency_enumeration_only")
        self.assertIn("zero_parity_fraction", summary)
        self.assertEqual(summary["work"]["unit"], "row_combinations_tested")

    def test_cli_writes_compact_reproducible_json_with_no_full_recovery_claim(self):
        out = HERE / "results" / "test-output.json"
        out.parent.mkdir(exist_ok=True)
        subprocess.run([sys.executable, str(HERE / "lattice_experiment.py"), "--quick", "--output", str(out)], check=True)
        data = json.loads(out.read_text())
        self.assertEqual(data["schema_version"], 2)
        self.assertEqual(data["parameters"]["noise_model"], "fixed_weight_floor_m_over_8")
        self.assertTrue(data["limitations"]["no_full_octra_recovery_claim"])
        self.assertIn("positive", data["controls"])
        self.assertGreaterEqual(len(data["controls"]["negative"]), 3)
        self.assertTrue(data["acceptance"]["passed"])
        wording = data["limitations"]["lattice_reviewer_scope"]
        self.assertIn("8D duplicate-row/noiseless sanity check", wording)
        self.assertIn("identity negatives are construction-specific", wording)
        for phrase in ("no labels", "no noise", "no OCTRA rows", "no secret decoding", "no complexity implication"):
            self.assertIn(phrase, wording)
        encoded = json.dumps(data).lower()
        self.assertNotIn('"secret":', encoded)
        self.assertNotIn("seconds", encoded)
        self.assertNotIn("gaussian", encoded)
        out.unlink()


if __name__ == "__main__":
    unittest.main()
