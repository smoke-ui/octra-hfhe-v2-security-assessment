#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEPS=${OCTRA_DEPS_DIR:-"$ROOT/.deps"}
PVAC="$DEPS/pvac_hfhe_cpp"
CHALLENGE="$DEPS/hfhe-challenge"
PVAC_COMMIT=071b0e909c119de815e284b347c4bd979cb59ef3
CHALLENGE_COMMIT=0d08e9622921e5930175a660df0061a65548972f

mkdir -p "$DEPS"
clone_or_update() {
  local url=$1 dir=$2 commit=$3
  if [[ -d "$dir/.git" ]]; then git -C "$dir" fetch --quiet origin; else git clone --quiet "$url" "$dir"; fi
  git -C "$dir" checkout --quiet --detach "$commit"
  test "$(git -C "$dir" rev-parse HEAD)" = "$commit"
}

clone_or_update https://github.com/octra-labs/pvac_hfhe_cpp.git "$PVAC" "$PVAC_COMMIT"
clone_or_update https://github.com/octra-labs/hfhe-challenge.git "$CHALLENGE" "$CHALLENGE_COMMIT"

python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --quiet --upgrade pip
"$ROOT/.venv/bin/python" -m pip install --quiet -r "$ROOT/requirements.txt"

printf 'PVAC_DIR=%s\nCHALLENGE_DIR=%s\n' "$PVAC" "$CHALLENGE" > "$ROOT/.env.paths"
echo "setup=PASS deps=$DEPS"
