# How to evaluate cryptographic security claims

## Entropy is not an attack estimate

`n × H₂(tau)` measures combinatorial entropy under a model. It does not automatically include sample availability, memory, preprocessing, verification cost, or the best concrete algorithm.

## Compatibility is not confidentiality

A parser accepting a ciphertext proves only that the bytes fit a schema. It does not prove the scheme hides plaintext.

## Anomaly is not exploit

A biased statistic matters only if it generalizes across fresh keys and yields a useful predicate or key-space reduction.

## Training accuracy is not a distinguisher

Feature searches must use key-disjoint held-out data and multiple-testing correction. Otherwise they discover noise.

## Proof forgery is not automatic decryption

An integrity failure may admit false statements without revealing a secret witness. Confidentiality impact needs a demonstrated data path.

## Quantum speedup is not practical quantum access

Many quantum learning algorithms assume coherent oracle access. A static ciphertext file does not provide that oracle. Grover search still requires a reversible implementation and feasible fault-tolerant resources.

## A filename is not evidence

A tool named `plaintext_recovery` may only print metadata. Require recovered bytes, independent target verification, and reproducible commands.

## Negative results can be valuable

A strong negative result:

- states assumptions and limitations
- uses positive controls
- tests the real artifact
- publishes commands and data
- avoids claiming a formal proof
- identifies what future evidence would falsify it
