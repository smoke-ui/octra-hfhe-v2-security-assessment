# Independent Rust wire audit

Dependency-free Rust parser for OCTRA HFHE Challenge v2 `secret.ct` bundles.

Unlike the C++ probes, this tool does not include or call OCTRA's serializer. It independently validates:

- Bundle and PVAC framing
- Version and type tags
- Exact member lengths and EOF
- Layer rules and product parents
- Canonical 127-bit field encodings
- Edge-to-layer references and signs
- Slot/weight consistency
- Bit-vector sizes and unused tail bits
- BASE-layer nonce uniqueness

## Run

```bash
cargo run --release -- /path/to/hfhe-challenge/secret.ct
```

Expected result for the published v2 artifact:

```text
wire_audit=PASS
ciphers=22
layers=44 base=44 product=0
edges=1829 commitments=44
unique_nonces=44 duplicate_nonces=0
```
