# OCTRA LPN samples audit

A dependency-light, fail-closed audit of the 44 JSONL files published at challenge commit `d9d29d505e2840c0028d7a91a2a8ba59e163b9a4`.

## Guarantees and limits

The tool validates exact GitHub origins and exact commit objects, then consumes only safely extracted `git archive` members. It verifies all 44 relevant pinned `SHA256SUMS` entries; exact metadata/row schemas, coordinates, counts, indices and lowercase hex; metadata uniqueness; aggregate bit/label balance; exact full-byte duplicate `A` and `(A,y)` rows; and exact GF(2) ranks of `A` and `[A|y]` in every file. It compiles the publisher's verifier from the archived release source against archived PVAC headers and runs it on all files.

The native verifier reads only each file's first metadata line and performs set membership. **It cannot authenticate equation bodies.** Repository checksums authenticate the published bodies; the native binding result does not independently regenerate or bind them.

No sample rows, absolute paths, temporary locations, or timing measurements enter the deterministic result. The exact-row database is disposable and stores complete 512-byte rows, so duplicate claims do not rely on a truncated hash.

## Reproduce

From the assessment repository:

```bash
python3 tools/lpn-samples-audit/test_audit.py
python3 tools/lpn-samples-audit/audit.py \
  --challenge-repo .deps/hfhe-challenge \
  --pvac-repo .deps/pvac_hfhe_cpp \
  --output tools/lpn-samples-audit/results/lpn-samples.json
python3 tools/lpn-samples-audit/audit.py \
  --challenge-repo .deps/hfhe-challenge \
  --pvac-repo .deps/pvac_hfhe_cpp \
  --output tools/lpn-samples-audit/results/lpn-samples.json --check-output
```

Requirements: Python 3.12+, Git, a C++17 compiler, and the two local Git object databases with the pinned commits. The build flags and compiler identity, target, executable hash, and architecture are recorded in the result. Expect a disposable SQLite database somewhat larger than the raw `A` payload while the audit runs.

`--check-output` regenerates all evidence and byte-compares canonical pretty-printed, sorted-key JSON. Any origin, object, checksum, schema, count, coordinate, duplicate, rank, native-binding, provenance, or output mismatch fails closed with exit status 2.
