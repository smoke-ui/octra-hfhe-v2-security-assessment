#!/usr/bin/env python3
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
EXPECTED_SEEDS = {"direct", "bundle", "fp-bit127", "payload-bit", "edge-sign",
                  "edge-index", "layer-count", "bundle-suffix"}


class StructuredFaultTests(unittest.TestCase):
    def test_runner_emits_required_classifications(self):
        proc = subprocess.run([str(ROOT / "build" / "structured_runner")], text=True,
                              capture_output=True, check=True)
        doc = json.loads(proc.stdout)
        required = {"baseline", "fp_bit127", "payload_bit", "edge_sign", "edge_index",
                    "edge_layer", "layer_count", "c0_count", "edge_count",
                    "direct_object_suffix", "bundle_suffix", "sigma_tail"}
        self.assertEqual(required, {x["name"] for x in doc["cases"]})
        self.assertEqual("generated-reduced-deterministic", doc["fixture"])
        self.assertTrue(doc["all_expectations_met"])

    def test_seed_corpus_is_generated_without_secret_material(self):
        subprocess.run([str(ROOT / "build" / "seed_generator")], cwd=ROOT, check=True)
        seeds = sorted((ROOT / "build" / "corpus").iterdir())
        self.assertEqual({path.name for path in seeds}, EXPECTED_SEEDS)
        self.assertTrue(all(path.is_file() and not path.is_symlink() for path in seeds))
        self.assertTrue(all(0 < path.stat().st_size <= 4096 for path in seeds))

    def test_seed_generator_never_deletes_caller_relative_corpus(self):
        with tempfile.TemporaryDirectory() as temporary:
            sentinel = pathlib.Path(temporary) / "build" / "corpus" / "sentinel"
            sentinel.parent.mkdir(parents=True)
            sentinel.write_text("preserve")
            subprocess.run([str(ROOT / "build" / "seed_generator")], cwd=temporary, check=True)
            self.assertEqual(sentinel.read_text(), "preserve")

    def test_seed_generator_replaces_corpus_symlink_without_following_it(self):
        corpus = ROOT / "build" / "corpus"
        if corpus.is_symlink() or corpus.is_file():
            corpus.unlink()
        elif corpus.exists():
            shutil.rmtree(corpus)
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary)
            sentinel = target / "sentinel"
            sentinel.write_text("preserve")
            corpus.symlink_to(target, target_is_directory=True)
            subprocess.run([str(ROOT / "build" / "seed_generator")], cwd=ROOT, check=True)
            self.assertEqual(sentinel.read_text(), "preserve")
            self.assertFalse(corpus.is_symlink())
            self.assertEqual({path.name for path in corpus.iterdir()}, EXPECTED_SEEDS)

    def test_seed_generator_replaces_seed_symlink_without_following_it(self):
        corpus = ROOT / "build" / "corpus"
        if corpus.exists():
            shutil.rmtree(corpus)
        corpus.mkdir()
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "target"
            target.write_text("preserve")
            (corpus / "direct").symlink_to(target)
            subprocess.run([str(ROOT / "build" / "seed_generator")], cwd=ROOT, check=True)
            self.assertEqual(target.read_text(), "preserve")
            self.assertFalse((corpus / "direct").is_symlink())
            self.assertEqual({path.name for path in corpus.iterdir()}, EXPECTED_SEEDS)


if __name__ == "__main__":
    unittest.main()
