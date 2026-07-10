# Security policy

## Supported scope

This repository analyzes OCTRA's explicitly public HFHE Challenge v2 artifacts and pinned public source. It does not authorize testing unrelated wallets, accounts, infrastructure, or users.

## Reporting a vulnerability

Do not open a public issue containing:

- private keys or mnemonics
- live wallet credentials
- unredacted proof-of-control material
- an immediately exploitable path before vendor notification

Report sensitive findings to OCTRA Labs through its published security/contact channel, currently `dev@octra.org`, and reference this repository's assessed commits.

For non-sensitive methodology errors or reproducibility defects, open a normal GitHub issue.

## Evidence expected

A confidentiality claim should include:

- exact affected commits and hashes
- deterministic reproduction commands
- fresh-key controls
- recovered bytes or a redacted proof of recovery
- independent verification against public data
- explanation of why the result is not sampling noise

## Coordinated disclosure

Allow the vendor a reasonable remediation window before publishing operational exploit details. Public reports should preserve the technical root cause while redacting credentials.
