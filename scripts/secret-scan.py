#!/usr/bin/env python3
"""Fail if tracked or publishable candidate files contain credential markers."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATTERNS = [
    re.compile("gh" + r"p_[A-Za-z0-9]{20,}"),
    re.compile("github" + r"_pat_[A-Za-z0-9_]{20,}"),
    re.compile("AK" + r"IA[0-9A-Z]{16}"),
    re.compile("xo" + r"x[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile("s" + r"k-[A-Za-z0-9_-]{20,}"),
    re.compile("BEGIN " + r"(?:(?:OPENSSH|RSA|EC) )?PRIVATE KEY"),
    re.compile("private" + "_key_b64", re.IGNORECASE),
    re.compile("Mnemonic" + ":", re.IGNORECASE),
]

listed = subprocess.run(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    cwd=ROOT,
    check=True,
    capture_output=True,
).stdout
paths = [ROOT / raw.decode() for raw in listed.split(b"\0") if raw]

findings: list[str] = []
for path in paths:
    if not path.is_file():
        continue
    text = path.read_bytes().decode("utf-8", errors="ignore")
    for line_no, line in enumerate(text.splitlines(), 1):
        if any(pattern.search(line) for pattern in PATTERNS):
            findings.append(f"{path.relative_to(ROOT)}:{line_no}")

if findings:
    print("potential secret markers:", file=sys.stderr)
    print("\n".join(findings), file=sys.stderr)
    raise SystemExit(1)
print(f"secret_scan=PASS files={len(paths)}")
