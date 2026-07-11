# HFHE Phase II Lab Log

## 2026-07-10 — Baselines

Pinned challenge and PVAC provenance was reverified by the existing fail-closed harness before Phase II.

### Mutation-space sizing

- `secret.ct`: 1,963,107 bytes / 15,704,856 bits
- `pk.bin`: 3,042,901 bytes / 24,343,208 bits
- Combined single-bit space: 40,048,064 mutations
- Independent Rust parse baseline: <0.01 s for `secret.ct`
- Native public-audit baseline: approximately 1.06 s

Interpretation: exhaustive mutation scheduling must run in-process. Native audit, compatibility, proof, and generated-fixture decryption are escalation stages for accepted or anomalous cases, not one fresh process per bit.

### Installed analysis toolchain

- Clang/LLVM 18.1.3
- AFL++ 4.09c
- Valgrind 3.22.0
- strace 6.8
- Z3 4.8.12
- CVC5 1.1.2
- MiniSat 2.2.1
- CaDiCaL 1.7.3
- CBMC 5.95.1

### Clang ASan/UBSan

The exact pinned `hfhe_bounty_artifact.cpp public-audit` path compiled under Clang 18 with AddressSanitizer and UndefinedBehaviorSanitizer and passed all eight public invariants. No sanitizer diagnostic was emitted.

### Valgrind Memcheck

The exact native public-audit path passed Memcheck with origin tracking, full leak checking, and a fail-on-error exit code. No memory or definite/indirect leak error was emitted.

### Entropy syscall baseline

`hfhe_bounty_artifact selftest` under `strace` observed:

- `getrandom`: 1,677 calls
- `openat`: 5 calls
- `read`: 4 calls
- `close`: 5 calls
- `/dev/urandom` fallback: not used

The counts include process/library activity selected by the syscall filter; the key security observation is that the normal run completed through `getrandom` without the fallback path.

### Entropy fault injection

A controlled `LD_PRELOAD` shim exercised `csprng_bytes` at lengths `0, 1, 7, 8, 31, 32, 4097` and under eight concurrent callers. All 11 scenarios matched fail-closed expectations:

- short `getrandom`: completes
- `getrandom` EINTR: retries
- ENOSYS/zero: falls back
- fallback open failure: aborts
- short fallback read: completes
- fallback read EINTR: retries
- fallback EOF/EIO: aborts
- close failure after complete read: succeeds (close result is ignored)
- concurrent chunked requests: complete without corrupted output

### Exact reduced wrapped-layer control

The accepted model directly encodes `N0*q0 + N1*q1 = a*v + b (mod p)` with nonzero inverse masks. At toy prime 7:

- independent masks: every candidate remained satisfiable
- deliberately shared masks: candidate set was restricted
- disclosed masks: only the planted candidate survived

The exact enumeration was independently cross-checked with generated SMT-LIB through the Z3 CLI at toy primes 7 and 31. Z3 matched exhaustive satisfiability for every candidate and mode. At prime 31, independent masks left 31/31 candidates satisfiable, shared-mask misuse left 29/31, and disclosed masks left only the planted candidate. Solver timings were approximately 2.64 s, 2.77 s, and 0.21 s respectively on this host.

This is a positive/negative control, not a production-security estimate.

### Confirmed real-artifact Fp bit-127 differential

The atlas flipped absolute bit `1663` (file byte 207, bit 7), the top bit of member 0 `c0[0]`:

- Independent strict parser: rejected `non-canonical Fp`
- Native parser: accepted and masked the bit
- Native public audit: all eight invariants passed
- Canonical deserialize/reserialize: byte mismatch (`ct_wire_canonical=0`)

Classification: confirmed noncanonical wire alias/parser differential. This is not plaintext recovery; semantic equivalence is expected because native `Reader::fp()` clears the bit.

### Compiler/optimization public-audit differential

Four supported variants produced byte-identical public-audit output with SHA-256 `ce838254f0c82cabbabc2cee66cbb376c96f9be27114b7a68290915a603804af`:

- GCC `-O0 -march=x86-64 -maes -msse2`
- GCC `-O3 -march=native`
- Clang `-O0 -march=x86-64 -maes -msse2`
- Clang `-O3 -march=native`

A cross-compiled `armv8-a+crypto` build run under `qemu-aarch64` with the Ubuntu ARM64 sysroot produced the same byte-identical public-audit output as native x86-64. The official generated selftest also passed all nine semantic/round-trip controls under AArch64. This verifies audit and generated-operation parity across the two hardware-AES implementations; deterministic generated serialization remains separately tested.

A baseline without `-maes` failed at compile time by design because the pinned source requires hardware AES support. This is a supported-platform constraint, not a behavioral differential.

### MemorySanitizer boundary blocker

Clang MemorySanitizer stopped in libstdc++ `std::filesystem::path` destruction at `hfhe_bounty_artifact.cpp:44`, before cryptographic parsing. The standard library was not MSan-instrumented, so this result is classified as an instrumentation-boundary false positive, not an HFHE finding. A minimized harness avoiding `std::filesystem` and other uninstrumented C++ library paths is required before drawing target conclusions.

### Structured generated-fixture mutation and fuzzing

The deterministic reduced fixture classified targeted mutations as follows:

- Fp bit 127: accepted, noncanonical reserialization, compatible, decryption unchanged
- payload bit: accepted and canonical, but decryption changed
- edge sign and layer: rejected
- edge index: parsed and canonical, then failed public-key compatibility
- layer/c0/edge counts: rejected
- direct object suffix: accepted, noncanonical reserialization, decryption unchanged
- bundle suffix: rejected
- sigma tail: not applicable because sigma is not serialized in the cipher/bundle formats

A 31-second Clang libFuzzer ASan/UBSan smoke completed 675,636 executions with no sanitizer crash. Final coverage was 1,482 counters and 4,581 features over a 213-input, 27 KiB corpus. This is bounded negative evidence only.

### Deterministic compiler serialization differential

The full GCC/Clang matrix completed 14 supported variants plus two expected no-AES build failures. The harness's limited observed facts—ciphertext byte lengths, slot/layer/edge counts, compatibility booleans, and decrypted values under each variant's own generated keypair—were stable across successful variants. It does not compare public-key semantics independently and therefore does not establish broader semantic equivalence. However:

- every Clang variant produced canonical serialized hashes different from the GCC baseline
- `clang-O2-aes` and `clang-O2-lto-aes` were not repeatable across two executions of the same binary

The strict reproducibility result is therefore fail. This does not show a plaintext error, but it invalidates cross-compiler deterministic-byte assumptions and warrants root-cause analysis of seeded generation and uninitialized/order-dependent state.

### Timing and concurrency probes

The bounded `prf_R_core` Welch test used 500 samples per class, batch size 2, and 20 warmups. It returned `t=0.826`, below the investigative threshold `|t|=4.5`. This is not proof of constant-time behavior and must be repeated on pinned bare metal.

The ordinary four-thread stress probe completed without functional failures. ThreadSanitizer independently reported a read/write data race on global `pvac::g_toep` during concurrent first use:

- writer: `pvac::select_toeplitz()`, `toeplitz.hpp:249`
- reader: `pvac::toep_127()`, `toeplitz.hpp:265`
- TSan exit code: 66

Classification: confirmed unsynchronized lazy-dispatch race under the C++ memory model. The observed stress run did not miscompute, but undefined behavior is present and initialization should use `std::call_once`, a function-local static, or an atomic publication scheme.
