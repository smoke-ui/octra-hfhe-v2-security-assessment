# PVAC runtime probes

Bounded, investigative probes against pinned `pvac_hfhe_cpp@071b0e909c119de815e284b347c4bd979cb59ef3`.

- `timing_probe`: dudect-style randomized measurement ordering, fixed public key/seed/domain, randomized secret pools split by one secret-bit class, warmup, batching, volatile sink, and Welch's t statistic. `|t| >= 4.5` means **investigate**, never “leak proven.”
- `concurrency_probe`: races first-use Toeplitz dispatch, then stresses encrypt/decrypt with shared immutable key objects and thread-local ciphertexts.
- `run_probes.sh`: runs bounded timing/non-TSan stress and TSan. It retries TSan under `setarch -R`; known WSL address-space/personality limitations produce a machine-readable capability skip.

No key or secret material is printed.

```sh
make test
./run_probes.sh
# bounds: samples<=20000, batch<=64, threads<=32, iterations<=100
```

Timing data is sensitive to scheduling, frequency scaling, virtualization, and system load. Repeat on pinned bare metal before drawing conclusions.
