# OCTRA HFHE Challenge v2 Security Assessment

Independent public-artifact cryptanalysis of [OCTRA Labs' HFHE Challenge v2](https://github.com/octra-labs/hfhe-challenge).

## Result

No public-only plaintext recovery was achieved. The assessment found no practical confidentiality break at the pinned challenge and PVAC commits. It confirms that v2 closes the public plaintext-guess oracle that broke v1, while documenting metadata leakage and implementation-hardening opportunities.

Start with the **[executive summary](EXECUTIVE_SUMMARY.md)** or read the complete **[technical report](REPORT.md)**.

Supporting guidance:

- [Threat model](THREAT_MODEL.md)
- [Standardized findings](FINDINGS.md)
- [Experiment methodology](METHODOLOGY.md)
- [How to evaluate cryptographic claims](CRYPTOGRAPHIC_CLAIMS_GUIDE.md)
- [Limitations and falsification criteria](LIMITATIONS.md)
- [Contributing](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Security and disclosure policy](SECURITY.md)

## Scope

This repository covers only OCTRA's explicitly public cryptographic challenge and published artifacts. It does not target unrelated wallets, accounts, infrastructure, or users.

Assessed versions:

- Challenge: `0d08e9622921e5930175a660df0061a65548972f`
- PVAC: `071b0e909c119de815e284b347c4bd979cb59ef3`
- `secret.ct`: `5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab`

## Confirmed findings

- Ciphertext count constrains plaintext length to 301–315 bytes.
- `SHA256SUMS` contains a stale checksum for the subsequently edited README.
- Deserialization bounds and canonicalization can be hardened.
- `R_com` has an ambiguous internal-versus-wire lifecycle.

## Reviewed non-findings

- Publicly reported proof/integrity issues in other PVAC paths were reviewed, but the required proof/reset objects are absent from `secret.ct`; no composition into challenge plaintext recovery was demonstrated.

## Attack classes tested

- v1 commitment oracle regression
- Wrapped-layer algebra and mask cancellation
- Low-entropy encrypted-length attacks
- LPN/PRF statistical and implementation analysis
- Historical RNG and cross-artifact correlation
- C++ memory and serialization leakage
- Independent Rust wire-format differential audit
- Pedersen/Ristretto relations
- Order-337 subgroup and character projections
- Four-dimensional tensor/hypergraph analysis
- Automated public-invariant synthesis
- Direct BIP39 wallet-entropy brute force
- Classical and quantum algorithm applicability
- Public Git history, forks, issues, and pull requests

## Repository layout

```text
EXECUTIVE_SUMMARY.md  Short decision-maker overview
REPORT.md             Consolidated technical assessment
FINDINGS.md           Standardized finding cards
THREAT_MODEL.md       Trust boundaries and attack blockers
research/             Detailed algebra, RNG, subgroup, and algorithm notes
tools/                Reproducible C++, Rust, Python, shell, and JavaScript probes
scripts/              Setup, integrity verification, safe execution, and secret scan
results/              Machine-readable findings and experiment summaries
disclosure/           Vendor communication templates
docs/                 Renderable diagrams
```

## Reproduction prerequisites

- Linux x86-64 with AES/PCLMUL support recommended
- C++17 compiler
- Stable Rust toolchain for the independent wire audit
- Python 3
- NumPy for tensor/invariant analysis
- Bun or Node-compatible packages for the wallet benchmark
- Local clones of the challenge and pinned PVAC implementation

```bash
git clone https://github.com/octra-labs/hfhe-challenge.git
git clone https://github.com/octra-labs/pvac_hfhe_cpp.git
git -C pvac_hfhe_cpp checkout 071b0e909c119de815e284b347c4bd979cb59ef3
```

Individual tools contain their own expected paths/arguments. Generated binaries, virtual environments, challenge wallet data, and challenge binary artifacts are intentionally excluded.

## One-command reproduction

```bash
make setup
make verify
make test
make run
```

`make setup` pins both upstream repositories and creates an isolated Python environment. `make verify` checks the challenge commit and artifact hashes. `make run` compiles native/Rust tools and writes safe outputs to `results/latest/`.

Production tensor and broad invariant-discovery datasets are intentionally not regenerated in default CI because of their compute cost. Their checked result summaries remain under `results/`.

## Machine-readable output

- [`results/findings.json`](results/findings.json)
- [`results/findings.sarif`](results/findings.sarif)
- Experiment result JSON under [`results/`](results/)

## Disclosure posture

This is a negative-result security assessment, not a successful bounty claim. No challenge credentials were recovered and no funds were moved.

## License

Original assessment prose and newly authored analysis tooling in this repository are released under the MIT License. OCTRA/PVAC source and challenge artifacts remain governed by their respective upstream licenses; they are referenced rather than redistributed here.
