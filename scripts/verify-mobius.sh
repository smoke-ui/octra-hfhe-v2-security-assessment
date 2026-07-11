#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY="$ROOT/.venv/bin/python"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

[[ -x "$PY" ]] || { echo "missing .venv; run make setup" >&2; exit 1; }

"$PY" "$ROOT/tools/mobius-sequencing/lpn_experiment.py" \
  --challenge-repo "$ROOT/.deps/hfhe-challenge" \
  --trials 199 \
  --output "$TMP/lpn-mobius.json"

"$PY" "$ROOT/tools/mobius-sequencing/field_experiment.py" \
  --root "$ROOT" \
  --out "$TMP/field-mobius.json"

"$PY" "$ROOT/tools/mobius-sequencing/hypergraph_experiment.py" \
  "$ROOT/.deps/hfhe-challenge/secret.ct" \
  --permutations 999 \
  --seed 20260711 \
  --out "$TMP/hypergraph-mobius.json"

for name in lpn-mobius field-mobius hypergraph-mobius; do
  cmp "$ROOT/results/$name.json" "$TMP/$name.json"
done

printf 'mobius_reproducibility=PASS\n'
