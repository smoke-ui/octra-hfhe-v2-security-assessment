# Experiment methodology

## Principle

A claimed break must survive fresh keys, fresh randomness, held-out evaluation, and an independent verifier. Interesting-looking output is not evidence by itself.

## Required controls

1. **Positive control:** deliberately introduce the hypothesized weakness and verify the detector finds it.
2. **Negative control:** use independent full-field masks matching v2 and verify the detector stays at chance.
3. **Fresh-key control:** train and test on disjoint keys.
4. **Fresh-randomness control:** never reuse encryption randomness between labels.
5. **Production check:** repeat promising reduced-parameter results at production parameters.
6. **Artifact check:** apply only validated predicates to the real artifact.

## Statistical gates

- Predeclare the tested feature family where practical.
- Report sample size and class balance.
- Use held-out or cross-validation results, never training accuracy alone.
- Use permutation tests for unusual statistics.
- Correct broad feature searches with Benjamini–Hochberg FDR.
- Treat borderline results as hypotheses requiring a larger replication.
- Report null and contradictory results.

## Cryptographic evidence ladder

| Level | Evidence | Interpretation |
|---|---|---|
| 0 | Suspicious code or statistic | Hypothesis only |
| 1 | Toy positive control | Detector can work somewhere |
| 2 | Fresh-key distinguisher | Potential leakage |
| 3 | Candidate verifier on production construction | Exploitable primitive |
| 4 | Partial plaintext/key recovery | Confirmed confidentiality impact |
| 5 | Independent reproduction and target verification | Bounty-grade result |

## Reproducibility

Every experiment should record:

- Challenge and PVAC commits
- Input artifact hashes
- Compiler/runtime versions
- Command line
- Hardware assumptions
- Random seeds when deterministic controls are intended
- Output in text or JSON
- Known limitations

## Safe handling

Never commit recovered mnemonics, private keys, wallet files, or proof-of-control material. A successful recovery should be validated offline, redacted in public reports, and disclosed through the official channel.
