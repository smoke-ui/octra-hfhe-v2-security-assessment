#!/usr/bin/env bash
set -euo pipefail
repo=${1:?usage: analyze_artifact_history.sh /path/to/hfhe-challenge}
out=history_artifacts
mkdir -p "$out"
for c in 08bf879 e4645c9 88a72b7 25afde5 841504a 547271b 0d08e96; do
  d="$out/$c"
  mkdir -p "$d"
  git -C "$repo" archive "$c" | tar -x -C "$d"
  printf 'COMMIT %s %s\n' "$c" "$(git -C "$repo" rev-parse "$c")"
  sha256sum "$d"/pk.bin "$d"/secret.ct 2>/dev/null || true
  echo "AUDIT $c"
  hfhe_v2_structural_audit "$d" 2>&1 | grep -E 'bundle.count|layers.total|edges.total|^ct\[' || true
done
