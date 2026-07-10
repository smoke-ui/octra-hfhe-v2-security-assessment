# Limitations and falsification criteria

This assessment is not a formal proof of the complete PVAC system.

## Assumptions

- Published source matches the challenge-generation path.
- OS CSPRNG output was independent and unpredictable.
- Wrapper values `m`, `R0`, and `R1` were independently sampled/derived.
- AES/HMAC/SHA primitives behave as assumed.
- Pedersen/Ristretto blindings remain secret and binding assumptions hold.
- No non-public side channel or generator compromise occurred.

## Coverage limitations

- Automated expression synthesis covered a finite grammar and sample set.
- Production tensor datasets were constrained by compute cost.
- Sanitizers cover executed paths, not every possible path.
- Public-history review cannot establish absence from inaccessible systems.
- Quantum estimates are resource assessments, not formal lower bounds.

## Evidence that would overturn the conclusion

Any of the following warrants immediate reassessment:

1. Reused or predictable challenge-generation entropy.
2. A serialized or derivable opening for `R0`, `R1`, or their blindings.
3. A public predicate that verifies a plaintext candidate.
4. Exposed conventional LPN samples linked to the mask secret.
5. Dependence or reuse between wrapper masks.
6. Same-key related-plaintext artifacts.
7. A production path different from the pinned source.
8. A cross-language parser disagreement on canonical bytes.
9. A fresh-key, held-out distinguisher with corrected significance.
10. Independent partial plaintext recovery.

## Reporting new evidence

Open a private vendor disclosure first if the evidence includes live credentials or an immediately exploitable path. Public issues must contain only redacted, reproducible evidence.
