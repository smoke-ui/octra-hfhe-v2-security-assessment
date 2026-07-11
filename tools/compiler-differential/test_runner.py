#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("runner", HERE / "runner.py")
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def test_dependency_defaults_are_repository_relative(self):
        self.assertEqual(runner.DEFAULT_PVAC, runner.REPOSITORY / ".deps" / "pvac_hfhe_cpp")
        self.assertNotIn("/home/jackm", (HERE / "runner.py").read_text())

    def test_origin_normalization_and_validation_fail_closed(self):
        expected = "github.com/octra-labs/pvac_hfhe_cpp"
        for value in (
            "git@github.com:octra-labs/pvac_hfhe_cpp.git",
            "ssh://git@github.com/octra-labs/pvac_hfhe_cpp.git",
            "https://github.com/octra-labs/pvac_hfhe_cpp.git",
        ):
            self.assertEqual(runner.normalized_origin(value), expected)
        with mock.patch.object(runner, "git_head", return_value="wrong"):
            with self.assertRaises(SystemExit):
                runner.validate_dependency(pathlib.Path("dep"), "pin", expected)
        with mock.patch.object(runner, "git_head", return_value="pin"), \
             mock.patch.object(runner.subprocess, "check_output", return_value="https://github.com/other/repo.git\n"):
            with self.assertRaises(SystemExit):
                runner.validate_dependency(pathlib.Path("dep"), "pin", expected)

    def test_matrix_contains_required_optimizations_and_feature_variants(self):
        variants = runner.build_matrix({"gcc": "/usr/bin/g++", "clang": "/usr/bin/clang++"})
        for family in ("gcc", "clang"):
            flags = [v.flags for v in variants if v.family == family]
            for opt in ("-O0", "-O1", "-O2", "-O3", "-Ofast"):
                self.assertTrue(any(opt in row for row in flags), (family, opt))
            self.assertTrue(any("-flto" in row for row in flags))
            self.assertTrue(any("-march=native" in row for row in flags))
            self.assertTrue(any("-march=x86-64" in row and "-maes" in row for row in flags))
            self.assertTrue(any("-mno-aes" in row for row in flags))

    def test_comparison_distinguishes_expected_build_failure(self):
        rows = [
            {"id": "base", "status": "ok", "semantic": {"x": 1}},
            {"id": "same", "status": "ok", "semantic": {"x": 1}},
            {"id": "minimum", "status": "build-failed", "expected_build_failure": True},
        ]
        summary = runner.compare(rows)
        self.assertEqual(summary["observed_fact_differentials"], [])
        self.assertEqual(summary["expected_build_failures"], ["minimum"])
        self.assertTrue(summary["pass"])

    def test_comparison_fails_on_semantic_difference(self):
        rows = [
            {"id": "base", "status": "ok", "semantic": {"x": 1}},
            {"id": "bad", "status": "ok", "semantic": {"x": 2}},
        ]
        summary = runner.compare(rows)
        self.assertEqual(summary["observed_fact_differentials"], ["bad"])
        self.assertFalse(summary["pass"])

    def test_comparison_fails_on_serialization_difference_but_preserves_semantics(self):
        rows = [
            {"id": "base", "status": "ok", "semantic": {"pubkey": {"sha256": "a"}, "ciphertexts": [{"sha256": "x", "fact": {"dec": [[7, 0]]}}]}},
            {"id": "other", "status": "ok", "semantic": {"pubkey": {"sha256": "a"}, "ciphertexts": [{"sha256": "y", "fact": {"dec": [[7, 0]]}}]}},
        ]
        summary = runner.compare(rows)
        self.assertEqual(summary["observed_fact_differentials"], [])
        self.assertEqual(summary["serialization_differentials"], ["other"])
        self.assertFalse(summary["pass"])

    def test_repeatability_detects_same_binary_drift(self):
        self.assertTrue(runner.repeat_equal({"x": 1}, {"x": 1}))
        self.assertFalse(runner.repeat_equal({"x": 1}, {"x": 2}))

    def test_fixture_uses_seeded_apis_pinned_serializer_and_no_secret_output(self):
        source = (HERE / "fixture.cpp").read_text()
        for token in ("keygen_from_seed", "enc_value_seeded", "enc_value_depth_seeded",
                      "enc_values_seeded", "ct_add", "ct_sub", "ct_mul_seeded",
                      "serialize_pubkey", "serialize_cipher"):
            self.assertIn(token, source)
        self.assertNotIn("serialize_seckey", source)
        self.assertNotIn("sizeof(PubKey)", source)
        self.assertNotIn("sizeof(Cipher)", source)

    def test_parse_semantic_requires_one_json_object(self):
        self.assertEqual(runner.parse_semantic('{"schema":1}\n'), {"schema": 1})
        with self.assertRaises(ValueError):
            runner.parse_semantic("debug\n{\"schema\":1}\n")


if __name__ == "__main__":
    unittest.main()
