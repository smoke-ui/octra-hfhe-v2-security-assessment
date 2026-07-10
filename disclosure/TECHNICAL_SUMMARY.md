# Vendor technical summary

## Versions

- Challenge: `0d08e9622921e5930175a660df0061a65548972f`
- PVAC: `071b0e909c119de815e284b347c4bd979cb59ef3`
- Ciphertext: `5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab`

## Assessment result

No public-only plaintext recovery was achieved. V2 appears to close the v1 public candidate-verification oracle under the documented assumptions.

## Confirmed engineering findings

See [../FINDINGS.md](../FINDINGS.md) and [../results/findings.json](../results/findings.json).

## Requested vendor actions

- Confirm generation source/commit provenance.
- Confirm independence of wrapper and PRF masks.
- Review canonicalization and bounds checks.
- Add padding policy for text payloads.
- Separate proof-layer and wire-layer schemas.
- Automate release checksum verification.

## Sensitive evidence

Do not attach live credentials to public issues. Exchange encrypted artifacts through a vendor-approved private channel.
