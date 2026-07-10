#!/usr/bin/env python3
"""Fail if publishable files contain common credential or wallet-secret markers."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".deps", ".venv", ".tensor-venv", "target", "build", "node_modules"}
PATTERNS = [
    re.compile("gh" + r"p_[A-Za-z0-9]{20,}"),
    re.compile("github" + r"_pat_[A-Za-z0-9_]{20,}"),
    re.compile("BEGIN " + r"(?:OPENSSH|RSA|EC) PRIVATE KEY"),
    re.compile("private" + "_key_b64", re.IGNORECASE),
    re.compile("Mnemonic" + ":", re.IGNORECASE),
]

findings: list[str] = []
for path in ROOT.rglob("*"):
    if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    for line_no, line in enumerate(text.splitlines(), 1):
        if any(pattern.search(line) for pattern in PATTERNS):
            findings.append(f"{path.relative_to(ROOT)}:{line_no}")

if findings:
    print("potential secret markers:", file=sys.stderr)
    print("\n".join(findings), file=sys.stderr)
    raise SystemExit(1)
print("secret_scan=PASS")
