# Contributing

Contributions that improve reproducibility, falsify an assumption, or add a controlled attack experiment are welcome.

## Ground rules

- Work only with public challenge artifacts and authorized targets.
- Never commit private keys, mnemonics, wallet files, access tokens, or live credentials.
- Do not claim plaintext recovery without reproducible evidence.
- Preserve negative results and failed hypotheses.
- Keep experiments deterministic where possible and document random controls.

## Workflow

1. Fork or create a branch.
2. State the attack hypothesis and expected observable.
3. Add a positive control that intentionally contains the weakness.
4. Add a negative control matching v2 assumptions.
5. Run `make test` and `make lint`.
6. For artifact-facing changes, run `make setup verify run`.
7. Submit a pull request using the template.

## Result schema

Experiment reports should include:

```json
{
  "hypothesis": "...",
  "commits": {"challenge": "...", "pvac": "..."},
  "sample_size": 0,
  "positive_control": "pass|fail",
  "negative_control": "pass|fail",
  "held_out_result": {},
  "artifact_result": {},
  "limitations": []
}
```

## Claim standard

A bounty-grade claim requires candidate verification or recovered material, independent reproduction, and a source-level root cause. Statistical anomalies alone are hypotheses.

## Licensing

By contributing, you agree that your original contribution is available under this repository's MIT License. Do not copy upstream code under incompatible terms.
