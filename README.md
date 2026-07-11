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
- [Phase II deep-testing plan](research/PHASE2_DEEP_TESTING_PLAN.md)
- [Phase II lab log](research/PHASE2_LAB_LOG.md)
- [Section 10 historical-peg deep audit](research/S10_PEG_DEEP_AUDIT.md)
- [Cross-generation composition assessment](research/CROSS_GENERATION_COMPOSITION_ASSESSMENT.md)
- [July 11 published-LPN practical assessment](research/OCTRA_LPN_PRACTICAL_ASSESSMENT.md)
- [Möbius sequencing and projective-map assessment](research/OCTRA_MOBIUS_SEQUENCING_ASSESSMENT.md)
- [Contributing](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Security and disclosure policy](SECURITY.md)

## Scope

This repository covers only OCTRA's explicitly public cryptographic challenge and published artifacts. It does not target unrelated wallets, accounts, infrastructure, or users.

Assessed versions:

- Challenge: `0d08e9622921e5930175a660df0061a65548972f`
- LPN sample release: `d9d29d505e2840c0028d7a91a2a8ba59e163b9a4`
- LPN scope clarification: `019380c97543620091409b0fbf73a8a773a9a0da`
- PVAC: `071b0e909c119de815e284b347c4bd979cb59ef3`
- `secret.ct`: `5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab`

## Confirmed findings

- Ciphertext count constrains plaintext length to 301–315 bytes.
- `SHA256SUMS` contains a stale checksum for the subsequently edited README.
- Deserialization bounds and canonicalization can be hardened.
- `R_com` has an ambiguous internal-versus-wire lifecycle.
- Concurrent first use races on lazy Toeplitz dispatch (`pvac::g_toep`).

## Reviewed non-findings

- Publicly reported proof/integrity issues in other PVAC paths were reviewed, but the required proof/reset objects are absent from `secret.ct`; no composition into challenge plaintext recovery was demonstrated.
- OCTRA's 44 added LPN files expose 720,896 equations against the source-supported shared 4096-bit `S`. No duplicate rows, rank shortcut, anomalous bias, or practical commodity-hardware recovery route was found. Recovering `S` would still leave the independent 256-bit `prf_k` and does not directly decrypt the payload.

## Publication caveat

- OCTRA's supplied LPN verifier proves only that each file's first-line seed/nonce/public-aggregate metadata matches a base layer in `secret.ct`. It does not parse or authenticate the 720,896 equation bodies. The repository checksum manifest commits OCTRA to the published bytes, but no public generator independently proves those bodies came from the pinned private-key computation.

## Attack classes tested

- v1 commitment oracle regression
- Wrapped-layer algebra and mask cancellation
- Low-entropy encrypted-length attacks
- LPN/PRF statistical and implementation analysis
- Historical RNG, generation-peg correlation, and cross-key composition
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
- [`tools/lpn-samples-audit/results/lpn-samples.json`](tools/lpn-samples-audit/results/lpn-samples.json)
- [`results/lpn-mobius.json`](results/lpn-mobius.json)
- [`results/lpn-bkw.json`](results/lpn-bkw.json) — deterministic exact bucket cancellation, all-construction-row LSH, and bounded disjoint-shard MITM on 589,824 pinned construction equations. Exact bucket cancellation retains 293,889 then 145,936 equations and reaches residual weight 1,896 (matched random control: 1,894). LSH reaches 1,868 after 10,615,133 comparison evaluations with repeats (used as a conservative candidate-count upper bound; exact unique count was not retained; control: 1,877). MITM reaches 1,918 for triples (3,964 projected matches) and 1,898 for quadruples (1,048,508 projected matches); controls are 1,939 and 1,893. All four executed families are `bounded_null` under Bonferroni alpha 0.0025 and the capped global union bound is 1; none is computationally actionable.
- [`results/field-mobius.json`](results/field-mobius.json)
- [`results/hypergraph-mobius.json`](results/hypergraph-mobius.json)
- Experiment result JSON under [`results/`](results/)

## Disclosure posture

This is a negative-result security assessment, not a successful bounty claim. No challenge credentials were recovered and no funds were moved.

## License

Original assessment prose and newly authored analysis tooling in this repository are released under the MIT License. OCTRA/PVAC source and challenge artifacts remain governed by their respective upstream licenses; they are referenced rather than redistributed here.
