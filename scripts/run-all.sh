#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PVAC=${PVAC_DIR:-"$ROOT/.deps/pvac_hfhe_cpp"}
CHALLENGE=${CHALLENGE_DIR:-"$ROOT/.deps/hfhe-challenge"}
BUILD="$ROOT/build"
RESULTS="$ROOT/results/latest"
mkdir -p "$BUILD" "$RESULTS"

"$ROOT/scripts/verify-artifacts.sh"

compile() {
  local src=$1 name
  name=$(basename "${src%.cpp}")
  g++ -std=c++17 -O2 -march=native -Wall -Wextra -pthread \
    -I"$PVAC/include" -I"$CHALLENGE/source" "$src" -o "$BUILD/$name"
}

for src in "$ROOT"/tools/*.cpp; do compile "$src"; done

g++ -std=c++17 -O2 -march=native -Wall -Wextra -pthread \
  -I"$PVAC/include" -I"$CHALLENGE/source" \
  "$CHALLENGE/source/hfhe_bounty_artifact.cpp" -o "$BUILD/hfhe_bounty_artifact"
(
  cd "$CHALLENGE"
  "$BUILD/hfhe_bounty_artifact" public-audit
) | tee "$RESULTS/official-public-audit.txt"

"$BUILD/hfhe_v2_structural_audit" "$CHALLENGE" | tee "$RESULTS/structural-audit.txt"
"$BUILD/prf_r_audit" "$CHALLENGE" | tee "$RESULTS/prf-audit.txt"
"$BUILD/hfhe_subgroup_projection_audit" "$CHALLENGE" | tee "$RESULTS/subgroup-audit.txt"

(
  cd "$ROOT/tools/rust-wire-audit"
  cargo test --quiet
  cargo run --release --quiet -- "$CHALLENGE/secret.ct"
) | tee "$RESULTS/rust-wire-audit.txt"

python3 "$ROOT/tools/hfhe_ciphertext_algebra_toy.py" | tee "$RESULTS/algebra-toy.txt"
python3 "$ROOT/tools/hfhe_subgroup_toy.py" | tee "$RESULTS/subgroup-toy.txt"

python3 - <<'PY' "$RESULTS"
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
summary = {"status": "pass", "outputs": sorted(p.name for p in root.glob("*.txt"))}
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
PY

echo "safe_experiments=PASS results=$RESULTS"
