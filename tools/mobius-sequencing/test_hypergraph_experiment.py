#!/usr/bin/env python3
import importlib.util
import hashlib
import json
import pathlib
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("hypergraph_experiment", HERE / "hypergraph_experiment.py")
h = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(h)


class SubsetLatticeTests(unittest.TestCase):
    def test_predicate_family_is_fixed_and_degree_four_has_793_nonconstant_terms(self):
        self.assertEqual(len(h.PREDICATE_NAMES), 12)
        terms = h.degree_terms(12, 4)
        self.assertEqual(len(terms), 793)
        self.assertEqual(len(set(terms)), 793)
        self.assertTrue(all(1 <= len(t) <= 4 for t in terms))

    def test_exact_subset_inversion_recovers_every_cell(self):
        cells = [((i * 37) ^ (i >> 3)) % 101 for i in range(1 << 12)]
        inclusive = h.subset_zeta_supersets(cells)
        self.assertEqual(h.subset_mobius_supersets(inclusive), cells)

    def test_planted_degree_k_fixture_is_recovered_exactly(self):
        fixture = h.planted_inversion_fixture(6, 3)
        self.assertTrue(fixture["exact"])
        self.assertEqual(fixture["planted_degree"], 3)
        self.assertEqual(fixture["recovered_support"], fixture["planted_support"])
        self.assertEqual(fixture["max_error"], 0)

    def test_boolean_coefficients_are_inverted_from_conjunction_counts_not_exact_cells(self):
        cells = [0, 0, 0, 1]
        conjunctions = h.subset_zeta_supersets(cells)
        self.assertEqual(conjunctions, [1, 1, 1, 1])
        self.assertEqual(h.boolean_coefficients(conjunctions), [1, 0, 0, 0])


class IncidenceTests(unittest.TestCase):
    def test_orientability_algebra_distinguishes_cylinder_and_mobius(self):
        self.assertEqual(h.orientation_product([1] * 22), 1)
        self.assertEqual(h.orientation_product([1] * 21 + [-1]), -1)
        self.assertTrue(h.orientability_check(22)["cylinder"])
        self.assertFalse(h.orientability_check(22)["mobius"])

    def test_global_cycle_optimization_preserves_transition_parity(self):
        grid = h.fixture_grid(True, 8)
        energies = h.cycle_parity_energies(grid)
        self.assertLess(energies["mobius"], energies["cylinder"])
        gauged = [[[v for v in row[1]], [v for v in row[0]]] if c in (1, 4, 6)
                   else [[v for v in row[0]], [v for v in row[1]]]
                   for c, row in enumerate(grid)]
        self.assertEqual(energies, h.cycle_parity_energies(gauged))

    def test_reduced_twisted_fixture_uses_artifact_summary_holonomy(self):
        for twisted, expected in ((True, "mobius"), (False, "cylinder")):
            fixture = h.planted_holonomy_fixture(twisted, 8)
            summary = h.incidence_summary(h.fixture_grid(twisted, 8))
            self.assertTrue(fixture["detected"])
            self.assertEqual(fixture["preferred"], expected)
            self.assertEqual(fixture["closure_gap"], summary["closure_gap"])

    def test_controls_preserve_shape_and_are_deterministic(self):
        grid = [[[c + 10 * l + p for p in range(12)] for l in range(2)] for c in range(22)]
        a = h.control_grids(grid, 913)
        b = h.control_grids(grid, 913)
        self.assertEqual(a, b)
        self.assertEqual(set(a), {"layer_gauge", "layer_reversal", "random_columns"})
        self.assertTrue(all(len(v) == 22 and len(v[0]) == 2 and len(v[0][0]) == 12 for v in a.values()))

    def test_bounded_summary_omits_uncomputed_seam_shift_scan(self):
        grid = h.fixture_grid(True, 22)
        result = h.incidence_summary(grid)
        self.assertNotIn("seam_shifts", result)
        for family in ("circulation", "holonomy", "harmonic"):
            self.assertGreaterEqual(result[family], 0)
            self.assertLessEqual(result[family], 1)

    def test_closure_diagnostics_are_invariant_to_local_layer_gauge_and_seam_rotation(self):
        grid = h.fixture_grid(True, 22)
        gauged = h.control_grids(grid, 913)["layer_gauge"]
        rotated = grid[7:] + grid[:7]
        keys = ("circulation", "holonomy", "harmonic", "closure_gap")
        baseline = h.incidence_summary(grid)
        self.assertEqual([baseline[k] for k in keys], [h.incidence_summary(gauged)[k] for k in keys])
        self.assertEqual([baseline[k] for k in keys], [h.incidence_summary(rotated)[k] for k in keys])

    def test_invalid_layer_or_missing_layer_fails_closed(self):
        valid = [[{"layer": layer, "idx": 0, "sign": 0, "weights": [(0, 0)], "support": [0]}
                  for layer in (0, 1)] for _ in range(22)]
        h.artifact_statistics(valid)
        missing = [list(edges) for edges in valid]
        missing[3] = [missing[3][0]]
        with self.assertRaisesRegex(ValueError, "both layers"):
            h.artifact_statistics(missing)
        invalid = [list(edges) for edges in valid]
        invalid[4] = invalid[4] + [dict(invalid[4][0], layer=2)]
        with self.assertRaisesRegex(ValueError, "invalid edge layer"):
            h.artifact_statistics(invalid)


class ParserValidationTests(unittest.TestCase):
    def _bundle(self):
        td = tempfile.TemporaryDirectory()
        path = pathlib.Path(td.name) / "fixture.ct"
        h.write_fixture_bundle(path, 22)
        return td, path, bytearray(path.read_bytes())

    def test_parser_rejects_unknown_layer_rule(self):
        td, path, data = self._bundle()
        with td:
            data[32 + 22] = 2
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "invalid layer rule"):
                h.parse_bundle(path)

    def test_parser_rejects_edge_index_and_sign_out_of_range(self):
        for offset, value, message in ((32 + 104 + 4, (337).to_bytes(2, "little"), "edge index"),
                                        (32 + 104 + 6, b"\x02", "edge sign")):
            td, path, data = self._bundle()
            with td:
                data[offset:offset + len(value)] = value
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, message):
                    h.parse_bundle(path)

    def test_parser_rejects_support_dimension_and_noncanonical_tail(self):
        support = 32 + 104 + 15 + 16
        td, path, data = self._bundle()
        with td:
            data[support:support + 8] = (8191).to_bytes(8, "little")
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "support dimension"):
                h.parse_bundle(path)
        malformed = h._Reader((3).to_bytes(8, "little") + (1).to_bytes(8, "little")
                              + (8).to_bytes(8, "little"))
        with self.assertRaisesRegex(ValueError, "tail bits"):
            h._read_bitvec(malformed, 3)


class StatisticsAndOutputTests(unittest.TestCase):
    def test_family_max_permutation_uses_plus_one_and_holm_is_family_level(self):
        observed = [0.8, 0.2]
        null = [[0.1, 0.3], [0.7, 0.1], [0.9, 0.4]]
        self.assertEqual(h.family_max_pvalues(observed, null), [0.5, 1.0])
        corrected = h.holm_adjust([0.01, 0.04, 0.5])
        self.assertEqual(corrected, [0.03, 0.08, 0.5])

    def test_report_is_compact_deterministic_and_contains_no_paths_raw_or_timing(self):
        with tempfile.TemporaryDirectory() as td:
            artifact = pathlib.Path(td) / "secret.ct"
            h.write_fixture_bundle(artifact, 22)
            artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
            one = h.run_experiment(artifact, permutations=31, seed=20260711)
            two = h.run_experiment(artifact, permutations=31, seed=20260711)
        self.assertEqual(one, two)
        encoded = json.dumps(one, sort_keys=True, separators=(",", ":"))
        self.assertNotIn(str(artifact), encoded)
        self.assertNotIn('"raw"', encoded)
        self.assertNotIn("timing", encoded)
        self.assertNotIn("seam_shifts", encoded)
        self.assertEqual(one["artifact"]["label_use"], "unlabeled_descriptive_only")
        self.assertEqual(one["subset_lattice"]["reported_nonconstant_coefficients"], 793)
        self.assertEqual(one["subset_lattice"]["function_definition"],
                         "F(S)=edge_count_satisfying_all_predicates_in_S")
        self.assertEqual(one["subset_lattice"]["inversion"], "boolean_subset_mobius_of_F")
        self.assertEqual(len(one["subset_lattice"]["coefficients_degree_le_4"]), 793)
        self.assertEqual(one["geometry"]["shape"], [22, 2])
        self.assertEqual(one["claims"]["plaintext_leakage"], False)
        self.assertEqual(one["artifact"]["sha256"], artifact_sha)
        self.assertEqual(one["analyzer"]["sha256"], hashlib.sha256((HERE / "hypergraph_experiment.py").read_bytes()).hexdigest())
        self.assertNotIn("holm_family_p", one["inference"])
        self.assertNotIn("p", one["geometry"]["controls"])
        self.assertEqual(one["geometry"]["topology_status"],
                         "analyst_imposed_hypothetical_unlabeled")
        self.assertEqual(one["geometry"]["orientability"]["status"], "analyst_imposed_hypothetical_complex")
        self.assertEqual(one["geometry"]["orientability"]["models"]["mobius"], False)
        self.assertEqual(one["inference"]["permutation_seed"], 20260711)
        self.assertEqual(set(one["inference"]["family_max_p"]),
                         {"circulation", "holonomy", "harmonic", "closure_gap"})


if __name__ == "__main__":
    unittest.main()
