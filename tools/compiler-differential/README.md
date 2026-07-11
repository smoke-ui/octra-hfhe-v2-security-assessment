# Deterministic compiler differential

Builds a canonical, seeded PVAC fixture against the pinned challenge serializer and compares canonical public-key/ciphertext SHA-256 values plus public shape and decryption facts. It never serializes a secret key or hashes raw C++ objects.

```bash
python3 -m unittest test_runner.py -v
python3 runner.py
```

The matrix capability-gates installed GCC/Clang and exercises `-O0/-O1/-O2/-O3/-Ofast`, LTO, baseline x86-64 AES, native ISA, and a minimum no-AES negative build. The runner refuses source trees not at the two pinned commits. A no-AES intrinsic compilation failure is recorded separately as expected; any other build/run failure or output differential fails the run. Full evidence is written to `matrix-results.json`; binaries stay under this directory's `build/`.
