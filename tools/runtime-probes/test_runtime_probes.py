#!/usr/bin/env python3
import json
import pathlib
import subprocess
import unittest

HERE = pathlib.Path(__file__).resolve().parent


class RuntimeProbeTests(unittest.TestCase):
    def test_sources_enforce_bounded_inputs_and_json_contract(self):
        timing = (HERE / "timing_probe.cpp").read_text()
        conc = (HERE / "concurrency_probe.cpp").read_text()
        self.assertIn("kMaxSamples", timing)
        self.assertIn("welch_t", timing)
        self.assertIn("volatile", timing)
        self.assertIn("first_use_toeplitz", conc)
        self.assertIn("shared_encrypt_decrypt", conc)

    def test_smoke_outputs_are_machine_readable_and_secret_free(self):
        subprocess.run(["make", "all"], cwd=HERE, check=True)
        timing = subprocess.run(
            [str(HERE / "build/timing_probe"), "--samples", "8", "--warmup", "1", "--batch", "1"],
            cwd=HERE, check=True, text=True, capture_output=True, timeout=120,
        )
        obj = json.loads(timing.stdout)
        self.assertEqual(obj["probe"], "prf_R_core_welch_t")
        self.assertEqual(obj["samples_per_class"], 8)
        self.assertIn(obj["status"], {"ok", "investigate"})
        self.assertNotIn("key", timing.stdout.lower())

        stress = subprocess.run(
            [str(HERE / "build/concurrency_probe"), "--threads", "2", "--iterations", "1"],
            cwd=HERE, check=True, text=True, capture_output=True, timeout=180,
        )
        obj = json.loads(stress.stdout)
        self.assertEqual(obj["probe"], "pvac_concurrency")
        self.assertEqual(obj["failures"], 0)
        self.assertNotIn("key", stress.stdout.lower())


if __name__ == "__main__":
    unittest.main()
