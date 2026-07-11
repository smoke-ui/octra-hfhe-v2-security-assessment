#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$ROOT/../.." && pwd)
BUILD=$(mktemp -d /tmp/pvac-entropy-fault.XXXXXX)
trap 'rm -rf "$BUILD"' EXIT

CXX=${CXX:-c++}
CC=${CC:-cc}
"$CXX" -std=c++17 -O0 -Wall -Wextra -Werror -pthread -I"$REPO/.deps/pvac_hfhe_cpp/include" \
  "$ROOT/csprng-driver.cpp" -o "$BUILD/csprng-driver"
"$CC" -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared \
  "$ROOT/entropy-fault.c" -o "$BUILD/entropy-fault.so" -ldl

baseline=$(DRIVER_REPORT=1 ENTROPY_FAULT_SCENARIO=enosys_fallback \
  LD_PRELOAD="$BUILD/entropy-fault.so" "$BUILD/csprng-driver")
grep -q '^lengths_tested=7$' <<<"$baseline"

scenarios=(short_getrandom getrandom_eintr enosys_fallback zero_fallback open_fail short_read read_eintr read_eof read_eio close_fail concurrent)
expected=(0 0 0 0 134 0 0 134 134 0 0)
passed=0
results=()

for i in "${!scenarios[@]}"; do
  scenario=${scenarios[$i]}
  want=${expected[$i]}
  got=$(python3 "$ROOT/status-runner.py" "$scenario" \
    "$BUILD/entropy-fault.so" "$BUILD/csprng-driver")
  if [[ $got -eq $want ]]; then
    ok=true
    passed=$((passed + 1))
  else
    ok=false
  fi
  results+=("{\"scenario\":\"$scenario\",\"expected_status\":$want,\"actual_status\":$got,\"passed\":$ok}")
done

printf '{"suite":"entropy-fail-closed","passed":%d,"total":%d,"results":[' "$passed" "${#scenarios[@]}"
printf '%s' "${results[0]}"
for ((i=1; i<${#results[@]}; i++)); do printf ',%s' "${results[$i]}"; done
printf ']}\n'
[[ $passed -eq ${#scenarios[@]} ]]
