# HFHE Phase II Deep-Testing Plan

## Scope and safety

Authorized local testing of OCTRA's public HFHE Challenge v2 artifacts and pinned public source only. No production services, wallets, malformed network traffic, or claims of plaintext recovery without deterministic verification.

Pinned inputs:

- `octra-labs/hfhe-challenge@0d08e9622921e5930175a660df0061a65548972f`
- `octra-labs/pvac_hfhe_cpp@071b0e909c119de815e284b347c4bd979cb59ef3`

## Workstreams

### 1. Deterministic fixture and bit-fault atlas

- Generate local known-key/known-plaintext fixtures outside published artifacts.
- Independently map wire offsets to semantic fields.
- Flip every bit and classify native parser, Rust parser, exact reserialization, public audit, proof/integrity result, decryption result, and runtime.
- Emit JSONL/CSV summaries and a field-aware heatmap.
- Positive control: inject a deliberately unauthenticated fixture field and require detection.

### 2. Structure-aware differential fuzzing

- Seed with valid public and generated fixtures.
- Mutate counts, lengths, layer types, parents, field values, edge metadata, bit-vectors, nonces, commitments, and trailing data while repairing framing where intended.
- Differentially compare native C++ and independent Rust parsers.
- Run available sanitizers; capability-gate AFL++, libFuzzer, MSan, and TSan.

### 3. Compiler and architecture differential

- Compare GCC/Clang and O0/O1/O2/O3/LTO where available.
- Compare semantic outputs, serialized bytes for deterministic fixtures, and audit/decryption results.
- Capability-gate ARM64/QEMU and 32-bit builds.

### 4. Integrity and API properties

- Test `decrypt(encrypt(m))`, probabilistic ciphertext uniqueness, wrong-key behavior, proof binding, wrapped-share swaps, reorderings, boundary field values, and exact serialization.
- Classify accepted semantic mutation as a security-significant candidate requiring independent reproduction.

### 5. Runtime security

- Constant-time experiments with whole-key train/holdout separation.
- Dynamic secret-dependency/taint analysis where toolchain permits.
- Entropy syscall tracing and fail-closed injection.
- Concurrent keygen/encryption and fork-state tests under TSan/Helgrind where available.

### 6. Reduced symbolic/algebraic models

- Encode reduced wrapped-layer, PRF/noise, and parser arithmetic models in SMT/SAT.
- Include intentionally weak positive controls and full-mask negative controls.
- Record solver time, conflicts, memory, model count, and scaling slope.
- Trace Boolean/taint influence from secret inputs to serialized outputs.

### 7. Binary/source correspondence

- Inventory whether publisher binaries exist; do not invent correspondence claims when only source is published.
- Compare reproducible local builds across toolchains and inspect metadata/sections.
- Use diffoscope/Ghidra/BinDiff only when an upstream binary exists.

## Fail-closed interpretation

- Crash or sanitizer finding: robustness candidate, not confidentiality break.
- Parser disagreement: serialization finding pending source-level adjudication.
- Accepted mutation: classify semantic effect and proof binding before severity.
- Timing signal: require multiplicity correction and held-out-key replication.
- Reduced-model solve: not a full-parameter break without defensible scaling.
- Statistical correlation: not leakage without independent-key generalization.
- Plaintext recovery: require clean-room deterministic rerun and target-address validation.

## Verification gates

- Preserve and reverify upstream hashes before every artifact run.
- Keep generated private fixtures ignored and permission-restricted.
- Unit-test every parser/mutator/classifier with malformed and positive-control fixtures.
- Run canonical `make test`, `make lint`, secret scan, and full safe harness.
- Independently review every security claim before publication.
