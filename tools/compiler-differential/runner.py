#!/usr/bin/env python3
"""Capability-gated compiler/optimization differential runner for a canonical PVAC fixture."""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
DEFAULT_PVAC = REPOSITORY / ".deps" / "pvac_hfhe_cpp"
DEFAULT_CHALLENGE = REPOSITORY / ".deps" / "hfhe-challenge"
PVAC_PIN = "071b0e909c119de815e284b347c4bd979cb59ef3"
CHALLENGE_PIN = "0d08e9622921e5930175a660df0061a65548972f"
PVAC_ORIGIN = "github.com/octra-labs/pvac_hfhe_cpp"
CHALLENGE_ORIGIN = "github.com/octra-labs/hfhe-challenge"


@dataclasses.dataclass(frozen=True)
class Variant:
    id: str
    family: str
    compiler: str
    flags: tuple[str, ...]
    expected_build_failure: bool = False


def build_matrix(compilers: dict[str, str]) -> list[Variant]:
    common = ("-std=c++17", "-pthread", "-march=x86-64", "-maes", "-msse2")
    rows: list[Variant] = []
    for family, compiler in compilers.items():
        for opt in ("-O0", "-O1", "-O2", "-O3", "-Ofast"):
            rows.append(Variant(f"{family}-{opt[1:]}-aes", family, compiler, common + (opt,)))
        rows.append(Variant(f"{family}-O2-lto-aes", family, compiler, common + ("-O2", "-flto")))
        rows.append(Variant(f"{family}-O3-native", family, compiler,
                            ("-std=c++17", "-pthread", "-O3", "-march=native")))
        rows.append(Variant(f"{family}-O2-minimum-noaes", family, compiler,
                            ("-std=c++17", "-pthread", "-O2", "-march=x86-64", "-mno-aes", "-msse2"), True))
    return rows


def parse_semantic(stdout: str) -> dict[str, Any]:
    lines = stdout.splitlines()
    if len(lines) != 1:
        raise ValueError("fixture must emit exactly one JSON line")
    value = json.loads(lines[0])
    if not isinstance(value, dict):
        raise ValueError("fixture output is not an object")
    return value


def repeat_equal(first: dict[str, Any], second: dict[str, Any]) -> bool:
    return first == second


def compare(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [r for r in rows if r["status"] == "ok"]
    baseline = ok[0]["semantic"] if ok else None

    def facts(value: dict[str, Any]) -> Any:
        ciphers = value.get("ciphertexts")
        if not isinstance(ciphers, list):
            return value
        return [{"fact": c.get("fact"), "bytes": c.get("bytes")} for c in ciphers]

    def serializations(value: dict[str, Any]) -> Any:
        ciphers = value.get("ciphertexts")
        if not isinstance(ciphers, list):
            return value
        return {"pubkey": value.get("pubkey"),
                "ciphertexts": [{"sha256": c.get("sha256"), "bytes": c.get("bytes")} for c in ciphers]}

    observed_fact_diffs = [r["id"] for r in ok if facts(r["semantic"]) != facts(baseline)] if baseline else []
    serialization_diffs = [r["id"] for r in ok if serializations(r["semantic"]) != serializations(baseline)] if baseline else []
    expected = [r["id"] for r in rows if r["status"] == "build-failed" and r.get("expected_build_failure")]
    unexpected = [r["id"] for r in rows if r["status"] in ("build-failed", "run-failed", "invalid-output")
                  and not (r["status"] == "build-failed" and r.get("expected_build_failure"))]
    nondeterministic = [r["id"] for r in ok if r.get("repeatable") is False]
    return {"pass": bool(ok) and not observed_fact_diffs and not serialization_diffs and not unexpected and not nondeterministic,
            "successful_variants": len(ok), "observed_fact_differentials": observed_fact_diffs,
            "serialization_differentials": serialization_diffs,
            "nondeterministic_variants": nondeterministic,
            "expected_build_failures": expected, "unexpected_failures": unexpected,
            "baseline_sha256": hashlib.sha256(json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()).hexdigest() if baseline else None}


def git_head(path: pathlib.Path) -> str:
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


def normalized_origin(value: str) -> str:
    value = value.strip().removesuffix(".git")
    if value.startswith("git@github.com:"):
        value = "github.com/" + value.removeprefix("git@github.com:")
    elif value.startswith("ssh://git@github.com/"):
        value = "github.com/" + value.removeprefix("ssh://git@github.com/")
    elif value.startswith("https://github.com/"):
        value = "github.com/" + value.removeprefix("https://github.com/")
    return value.lower()


def validate_dependency(path: pathlib.Path, commit: str, origin: str) -> None:
    if git_head(path) != commit:
        raise SystemExit(f"refusing unpinned dependency commit: {path}")
    actual = subprocess.check_output(
        ["git", "-C", str(path), "remote", "get-url", "origin"], text=True
    )
    if normalized_origin(actual) != origin:
        raise SystemExit(f"refusing unexpected dependency origin: {path}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pvac", type=pathlib.Path, default=DEFAULT_PVAC)
    ap.add_argument("--challenge", type=pathlib.Path, default=DEFAULT_CHALLENGE)
    ap.add_argument("--output", type=pathlib.Path, default=HERE / "matrix-results.json")
    args = ap.parse_args()
    validate_dependency(args.pvac, PVAC_PIN, PVAC_ORIGIN)
    validate_dependency(args.challenge, CHALLENGE_PIN, CHALLENGE_ORIGIN)
    compilers = {k: v for k, name in (("gcc", "g++"), ("clang", "clang++")) if (v := shutil.which(name))}
    if not compilers:
        raise SystemExit("no supported C++ compiler")
    outdir = HERE / "build"
    outdir.mkdir(exist_ok=True)
    rows: list[dict[str, Any]] = []
    for variant in build_matrix(compilers):
        binary = outdir / variant.id
        cmd = [variant.compiler, *variant.flags, "-I", str(args.pvac / "include"),
               "-I", str(args.challenge / "source"), str(HERE / "fixture.cpp"), "-o", str(binary)]
        built = subprocess.run(cmd, text=True, capture_output=True)
        row: dict[str, Any] = {"id": variant.id, "family": variant.family,
                               "flags": list(variant.flags), "expected_build_failure": variant.expected_build_failure}
        if built.returncode:
            row.update(status="build-failed", returncode=built.returncode,
                       diagnostic=built.stderr[-2000:])
        else:
            run = subprocess.run([str(binary)], text=True, capture_output=True, timeout=300)
            if run.returncode:
                row.update(status="run-failed", returncode=run.returncode, diagnostic=run.stderr[-2000:])
            else:
                try:
                    semantic = parse_semantic(run.stdout)
                    repeat = subprocess.run([str(binary)], text=True, capture_output=True, timeout=300)
                    repeat_semantic = parse_semantic(repeat.stdout) if repeat.returncode == 0 else None
                    row.update(status="ok", semantic=semantic,
                               repeatable=repeat_semantic is not None and repeat_equal(semantic, repeat_semantic))
                except (ValueError, json.JSONDecodeError) as exc:
                    row.update(status="invalid-output", diagnostic=str(exc), stdout=run.stdout[-2000:])
        rows.append(row)
        print(f"{variant.id}: {row['status']}", file=sys.stderr)
    report = {"schema": 1, "architecture": platform.machine(), "pins": {"pvac": PVAC_PIN, "challenge": CHALLENGE_PIN},
              "rows": rows, "summary": compare(rows)}
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report["summary"], sort_keys=True))
    return 0 if report["summary"]["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
