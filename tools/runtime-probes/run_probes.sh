#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
make all tsan >/dev/null
./build/timing_probe --samples "${SAMPLES:-500}" --warmup "${WARMUP:-20}" --batch "${BATCH:-2}"
./build/concurrency_probe --threads "${THREADS:-4}" --iterations "${ITERATIONS:-3}"

run_tsan() { TSAN_OPTIONS=halt_on_error=1:exitcode=66 "$@" --threads "${TSAN_THREADS:-4}" --iterations "${TSAN_ITERATIONS:-1}"; }
set +e
out=$(run_tsan ./build/concurrency_probe_tsan 2>&1); rc=$?
if (( rc != 0 )) && grep -Eq 'unexpected memory mapping|FATAL: ThreadSanitizer' <<<"$out" && command -v setarch >/dev/null; then
  arch=$(uname -m)
  out=$(run_tsan setarch "$arch" -R ./build/concurrency_probe_tsan 2>&1); rc=$?
fi
set -e
if (( rc == 0 )); then
  printf '%s\n' "$out"
elif grep -Eq 'unexpected memory mapping|Operation not permitted|personality' <<<"$out"; then
  printf '{"probe":"pvac_concurrency_tsan","status":"capability_skip","reason":"tsan_address_space_or_setarch_unavailable_on_wsl","exit_code":%d}\n' "$rc"
else
  printf '%s\n' "$out" >&2
  printf '{"probe":"pvac_concurrency_tsan","status":"fail","exit_code":%d}\n' "$rc"
  exit "$rc"
fi
