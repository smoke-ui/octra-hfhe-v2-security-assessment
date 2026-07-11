# Generated-fixture structured fuzzing

This harness creates a tiny deterministic `B=3, m=n=1` fixture in memory. It does not read challenge artifacts or contain published/private key material. `structured_runner` records parse, canonical reserialization, compatibility, and decryption comparisons. `sigma_tail` is explicitly `not_applicable`: the pinned cipher/bundle formats contain no serialized sigma field, so inventing such a mutation would not be valid.

Run `make test` for deterministic classifications and `make fuzz-smoke` for a bounded 30-second Clang libFuzzer ASan/UBSan smoke. Results are written below `build/`.
