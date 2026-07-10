#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHALLENGE=${CHALLENGE_DIR:-"$ROOT/.deps/hfhe-challenge"}
PVAC=${PVAC_DIR:-"$ROOT/.deps/pvac_hfhe_cpp"}
expected_commit=0d08e9622921e5930175a660df0061a65548972f
expected_pvac_commit=071b0e909c119de815e284b347c4bd979cb59ef3

[[ -d "$CHALLENGE/.git" ]] || { echo "missing challenge clone: run scripts/setup.sh" >&2; exit 1; }
[[ -d "$PVAC/.git" ]] || { echo "missing PVAC clone: run scripts/setup.sh" >&2; exit 1; }
test "$(git -C "$CHALLENGE" rev-parse HEAD)" = "$expected_commit"
test "$(git -C "$PVAC" rev-parse HEAD)" = "$expected_pvac_commit"

case "$(git -C "$CHALLENGE" remote get-url origin)" in
  https://github.com/octra-labs/hfhe-challenge|https://github.com/octra-labs/hfhe-challenge.git|git@github.com:octra-labs/hfhe-challenge|git@github.com:octra-labs/hfhe-challenge.git) ;;
  *) echo "unexpected challenge origin" >&2; exit 1 ;;
esac
case "$(git -C "$PVAC" remote get-url origin)" in
  https://github.com/octra-labs/pvac_hfhe_cpp|https://github.com/octra-labs/pvac_hfhe_cpp.git|git@github.com:octra-labs/pvac_hfhe_cpp|git@github.com:octra-labs/pvac_hfhe_cpp.git) ;;
  *) echo "unexpected PVAC origin" >&2; exit 1 ;;
esac

check() {
  local expected=$1 file=$2 actual
  actual=$(sha256sum "$CHALLENGE/$file" | cut -d' ' -f1)
  test "$actual" = "$expected" || { echo "checksum mismatch: $file" >&2; exit 1; }
  printf 'OK  %s\n' "$file"
}

check 97d76005f0f8ffbcc4f04244da43fecfef53811cb24a2bea2d423cd77e594a42 manifest.json
check 28ea07666fa34935cfa4f46efe96548ee6c9879dcea2c4b10a57b6da95b8c559 params.json
check 1e788edff9dea19a782defae053f3757ccf5edd41cd3e24ae44e1496045e9410 pk.bin
check b1852a5f7803a5561cbb8cea175e68c73bbdbf68e57cdb9a6e7f8f741e030a08 pvac_commit.txt
check 5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab secret.ct
check 3ad3bf592a294c0124688aedd60263955e1241d49c873dbee809cee49431e4fa source/hfhe_bounty_artifact.cpp
check 87115033ab8a248c6c0067916a562c4922703197d220416985da24b2d646c5a5 source/pvac_artifact_serialize.hpp

echo "artifact_verification=PASS challenge_commit=$expected_commit pvac_commit=$expected_pvac_commit"
