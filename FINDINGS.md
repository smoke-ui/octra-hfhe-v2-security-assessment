# Standardized findings

These findings concern OCTRA's pinned upstream challenge package and source, not files authored by this assessment repository. Each entry identifies its upstream provenance.

## OCTRA-HFHE-INFO-001 — Ciphertext count leaks a narrow plaintext-length interval

- **Severity:** Informational
- **Upstream provenance:** `octra-labs/hfhe-challenge@0d08e9622921e5930175a660df0061a65548972f` and `octra-labs/pvac_hfhe_cpp@071b0e909c119de815e284b347c4bd979cb59ef3`
- **Affected artifact:** `secret.ct`
- **Evidence:** 22 ciphertexts = one encrypted length plus 21 15-byte payload blocks
- **Impact:** Public observer learns `301 <= length <= 315`
- **Remediation:** Fixed-size or bucketed padding with dummy blocks
- **Regression:** Assert identical public block counts for messages in the same privacy class

## OCTRA-RELEASE-LOW-002 — Stale documentation checksum

- **Severity:** Low
- **Upstream provenance:** `octra-labs/hfhe-challenge@0d08e9622921e5930175a660df0061a65548972f`
- **Affected file:** `SHA256SUMS`
- **Evidence:** Cryptographic artifacts match; edited README does not
- **Impact:** Confusing release verification and reduced trust in package integrity
- **Remediation:** Generate checksums after all release content is finalized in CI
- **Regression:** CI verifies the committed checksum manifest

## OCTRA-PVAC-LOW-003 — Pointer-addition bounds check can be hardened

- **Severity:** Low
- **Upstream provenance:** `octra-labs/hfhe-challenge@0d08e9622921e5930175a660df0061a65548972f`, published serializer source
- **Affected component:** `Reader::need()`
- **Evidence:** Checks `p + n > end`, where extreme attacker-controlled `n` can make pointer addition undefined
- **Impact:** Parser robustness risk for malformed input; not triggered by the challenge artifact
- **Remediation:** Compare `n` against remaining length before pointer arithmetic
- **Regression:** Truncated and maximum-length fuzz corpus under ASan/UBSan

## OCTRA-PVAC-LOW-004 — Noncanonical field encodings are normalized

- **Severity:** Low
- **Upstream provenance:** `octra-labs/hfhe-challenge@0d08e9622921e5930175a660df0061a65548972f`, published serializer source
- **Affected component:** Field deserialization
- **Evidence:** Top field bit is masked rather than rejected
- **Impact:** Multiple encodings may map to one internal value in permissive paths
- **Remediation:** Reject noncanonical encodings before normalization
- **Regression:** Rust and C++ parsers reject a top-bit-set field fixture

## OCTRA-PVAC-INFO-005 — Ambiguous `R_com` internal/wire lifecycle

- **Severity:** Informational
- **Upstream provenance:** pinned challenge serializer and `octra-labs/pvac_hfhe_cpp@071b0e909c119de815e284b347c4bd979cb59ef3`
- **Affected component:** Layer schema
- **Evidence:** `R_com` exists in internal objects but is intentionally omitted from v2 serialization
- **Impact:** Maintenance risk; future code may assume deserialized state retains internal proof metadata
- **Remediation:** Separate wire and proof-layer types with explicit schema versions
- **Regression:** Assert public serializers never emit candidate-checkable mask commitments
