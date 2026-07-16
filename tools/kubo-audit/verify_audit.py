#!/usr/bin/env python3
"""
Octra HFHE v2 public audit verification (no C++ toolchain required).

Parses the real v2 wire format:
  secret.ct = OCTRA-HFHE-BTY02 bundle of PVAC v3 ciphers
  (pvac_artifact_serialize.hpp @ pvac_hfhe_cpp 071b0e9)

Checks (public-artifact scope only):
  1. Bundle / cipher structure + wrap encoding (2 BASE layers)
  2. Commitment uniqueness (rho-reuse filter via PC)
  3. BASE seed uniqueness
  4. Edge-weight noise statistics (deterministic-noise filter)
  5. R_com not present on the wire (v1 oracle closure)

Full N0/N1 field algebra (requires pk.powg_B) is optional via
compiled phase1_triage if present next to this script.
"""
from __future__ import print_function

import argparse
import os
import struct
import subprocess
import sys
from collections import defaultdict

BUNDLE_MAGIC = b"OCTRA-HFHE-BTY02"
PVAC_MAGIC = b"PVAC"
PVAC_VERSION = 0x03
TAG_CIPHER = 0
RULE_BASE = 0
RULE_PROD = 1
SGN_P = 0
SGN_M = 1
MASK63 = (1 << 63) - 1

# Relative to this script so any clone can run: python3 verify_audit.py
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CT = os.path.normpath(os.path.join(_SCRIPT_DIR, "public_artifacts", "secret.ct"))
DEFAULT_PK = os.path.normpath(os.path.join(_SCRIPT_DIR, "public_artifacts", "pk.bin"))


class ParseError(Exception):
    pass


class Reader(object):
    def __init__(self, data, pos=0, end=None):
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end

    def remaining(self):
        return self.end - self.pos

    def need(self, n):
        if self.pos + n > self.end:
            raise ParseError("truncated at offset %d (need %d)" % (self.pos, n))

    def raw(self, n):
        self.need(n)
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        self.need(1)
        v = self.data[self.pos]
        if not isinstance(v, int):
            v = ord(v)
        self.pos += 1
        return v

    def u16(self):
        self.need(2)
        v = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return v

    def u32(self):
        self.need(4)
        v = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return v

    def u64(self):
        self.need(8)
        v = struct.unpack_from("<Q", self.data, self.pos)[0]
        self.pos += 8
        return v

    def fp(self):
        lo = self.u64()
        hi = self.u64() & MASK63
        return lo, hi

    def bitvec(self):
        nbits = self.u64()
        nw = self.u64()
        expected = (nbits + 63) // 64
        if nbits > (1 << 20):
            raise ParseError("bitvec too large: %d" % nbits)
        if nw != expected:
            raise ParseError("bitvec word count mismatch %d != %d" % (nw, expected))
        words = [self.u64() for _ in range(nw)]
        return nbits, words


def popcount64(x):
    n = 0
    x = int(x) & ((1 << 64) - 1)
    while x:
        x &= x - 1
        n += 1
    return n


def variance(xs):
    n = len(xs)
    if n < 2:
        return 0.0
    m = sum(xs) / float(n)
    return sum((x - m) * (x - m) for x in xs) / float(n - 1)


def pc_hex(pc):
    if hasattr(pc, "hex"):
        return pc.hex()
    return "".join("%02x" % (ord(c) if not isinstance(c, int) else c) for c in pc)


def parse_layer(r):
    rule = r.u8()
    layer = {"rule": rule, "pc": [], "seed": None, "pa": None, "pb": None,
             "wire_has_rcom_slot": False}
    if rule == RULE_BASE:
        ztag = r.u64()
        nlo = r.u64()
        nhi = r.u64()
        layer["seed"] = (ztag, nlo, nhi)
        # Wire format: seed fields then PC[] — no R_com field between them.
    elif rule == RULE_PROD:
        layer["pa"] = r.u32()
        layer["pb"] = r.u32()
    else:
        raise ParseError("invalid layer rule %d" % rule)
    npc = r.u64()
    if npc > (1 << 20):
        raise ParseError("PC count too large")
    for _ in range(npc):
        layer["pc"].append(r.raw(32))
    return layer


def parse_edge(r):
    lid = r.u32()
    idx = r.u16()
    ch = r.u8()
    if ch not in (SGN_P, SGN_M):
        raise ParseError("invalid edge sign %d" % ch)
    nw = r.u64()
    if nw > (1 << 20):
        raise ParseError("edge weight count too large")
    weights = [r.fp() for _ in range(nw)]
    nbits, words = r.bitvec()
    return {
        "layer_id": lid,
        "idx": idx,
        "ch": ch,
        "w": weights,
        "sigma_nbits": nbits,
        "sigma_words": words,
    }


def parse_cipher(blob):
    r = Reader(blob)
    magic = r.raw(4)
    if magic != PVAC_MAGIC:
        raise ParseError("bad PVAC magic %r" % magic)
    ver = r.u8()
    if ver != PVAC_VERSION:
        raise ParseError("bad PVAC version %d (expected %d)" % (ver, PVAC_VERSION))
    tag = r.u8()
    if tag != TAG_CIPHER:
        raise ParseError("not a cipher tag: %d" % tag)
    slots = r.u64()
    nL = r.u64()
    layers = [parse_layer(r) for _ in range(nL)]
    nc0 = r.u64()
    c0 = [r.fp() for _ in range(nc0)]
    nE = r.u64()
    edges = [parse_edge(r) for _ in range(nE)]
    if r.remaining() != 0:
        raise ParseError("trailing bytes in cipher (%d left)" % r.remaining())
    return {
        "slots": slots,
        "layers": layers,
        "c0": c0,
        "edges": edges,
    }


def parse_bundle(data):
    if len(data) < 16 + 8:
        raise ParseError("secret.ct too short")
    if data[:16] != BUNDLE_MAGIC:
        raise ParseError("bad bundle magic %r" % data[:16])
    count = struct.unpack_from("<Q", data, 16)[0]
    if count == 0 or count > 1024:
        raise ParseError("invalid cipher count %d" % count)
    pos = 24
    cts = []
    for i in range(count):
        if pos + 8 > len(data):
            raise ParseError("truncated length for cipher %d" % i)
        n = struct.unpack_from("<Q", data, pos)[0]
        pos += 8
        if n == 0 or pos + n > len(data):
            raise ParseError("invalid cipher length %d at %d" % (n, i))
        cts.append(parse_cipher(data[pos:pos + n]))
        pos += n
    if pos != len(data):
        raise ParseError("trailing bytes in secret.ct (%d)" % (len(data) - pos))
    return cts


def test_structure(cts):
    msgs = []
    ok = True
    if len(cts) < 1:
        return False, "no ciphertexts"
    two_base = 0
    for i, ct in enumerate(cts):
        bases = [L for L in ct["layers"] if L["rule"] == RULE_BASE]
        if len(bases) == 2:
            two_base += 1
        else:
            ok = False
            msgs.append("ct[%d] BASE layers=%d (want 2)" % (i, len(bases)))
        for L in bases:
            if not L["pc"]:
                ok = False
                msgs.append("ct[%d] BASE missing PC" % i)
    msgs.insert(0, "cts=%d wrap_2BASE=%d/%d" % (len(cts), two_base, len(cts)))
    return ok and two_base == len(cts), "; ".join(msgs)


def test_commitment_uniqueness(cts):
    pc_by_tau = defaultdict(list)
    all_pc = []
    for ct in cts:
        for L in ct["layers"]:
            if L["rule"] != RULE_BASE:
                continue
            tau = L["seed"]
            for pc in L["pc"]:
                hx = pc_hex(pc)
                pc_by_tau[tau].append(hx)
                all_pc.append(hx)
    if not all_pc:
        return False, "no PC values found"
    full_dup_groups = 0
    dup_ratios = []
    for tau, pcs in pc_by_tau.items():
        uniq = len(set(pcs))
        ratio = 1.0 - (uniq / float(len(pcs)))
        dup_ratios.append(ratio)
        if len(pcs) > 1 and ratio == 1.0:
            full_dup_groups += 1
    mean_dup = sum(dup_ratios) / float(len(dup_ratios))
    global_dup = 1.0 - (len(set(all_pc)) / float(len(all_pc)))
    ok = mean_dup < 0.01 and global_dup < 0.01 and full_dup_groups == 0
    msg = ("base_pc=%d unique_pc=%d unique_tau=%d mean_dup=%.4f global_dup=%.4f"
           % (len(all_pc), len(set(all_pc)), len(pc_by_tau), mean_dup, global_dup))
    if not ok:
        msg += " FAIL (rho reuse signal)"
    return ok, msg


def test_noise_edge_weights(cts):
    """Deterministic-noise branch filter using public edge weights (no pk needed)."""
    global_ham = []
    per_layer_vars = []
    for ct in cts:
        by_layer = defaultdict(list)
        for e in ct["edges"]:
            if not e["w"]:
                continue
            lo, hi = e["w"][0]
            ham = popcount64(lo) + popcount64(hi & MASK63)
            by_layer[e["layer_id"]].append(float(ham))
            global_ham.append(float(ham))
        for lid, hs in by_layer.items():
            if len(hs) >= 2:
                per_layer_vars.append(variance(hs))
    if len(global_ham) < 8:
        return False, "insufficient edges for noise test"
    gvar = variance(global_ham)
    gmean = sum(global_ham) / float(len(global_ham))
    if not per_layer_vars:
        return False, "no multi-edge layers"
    per_layer_vars.sort()
    med = per_layer_vars[len(per_layer_vars) // 2]
    # Healthy random Fp* weight hamming ~ Bin(127,0.5) mean~63.5 var~31.75
    healthy_mean = 55.0 <= gmean <= 72.0
    healthy_var = gvar >= 10.0
    not_collapsed = med >= 5.0
    ok = healthy_mean and healthy_var and not_collapsed
    msg = ("edges=%d mean_ham=%.2f global_var=%.2f median_within_layer_var=%.2f"
           % (len(global_ham), gmean, gvar, med))
    return ok, msg


def test_rcom_wire_closure(cts, raw):
    """
    v1 public oracle used serialized R_com (32B per BASE layer).
    v2 write_layer: rule + seed(3*u64) + nPC + PC[] — no R_com field.
    """
    structural_ok = all(
        (L["rule"] != RULE_BASE) or (L.get("wire_has_rcom_slot") is False)
        for ct in cts for L in ct["layers"]
    )
    domain_hit = b"pvac.dom.r_com" in raw
    marker_hit = b"RCOM" in raw[:4096]
    ok = structural_ok and not domain_hit
    msg = ("wire_layout_no_rcom=%s domain_string_in_ct=%s marker_RCOM_in_header=%s"
           % (structural_ok, domain_hit, marker_hit))
    if not ok:
        msg += " (v1-style leakage signal)"
    return ok, msg


def test_seed_uniqueness(cts):
    seeds = []
    for ct in cts:
        for L in ct["layers"]:
            if L["rule"] == RULE_BASE:
                seeds.append(L["seed"])
    uniq = len(set(seeds))
    ok = uniq == len(seeds) and len(seeds) > 0
    return ok, "base_seeds=%d unique=%d" % (len(seeds), uniq)


def try_phase1_binary(script_dir):
    bin_path = os.path.join(script_dir, "phase1_triage")
    if not os.path.isfile(bin_path) or not os.access(bin_path, os.X_OK):
        return None
    try:
        p = subprocess.run(
            [bin_path],
            cwd=script_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            universal_newlines=True,
        )
        out = p.stdout or ""
        passed = ("Test1 verdict: PASS" in out
                  and "Test2 verdict: PASS" in out
                  and "Test3 verdict: PASS" in out
                  and p.returncode == 0)
        return passed, out
    except Exception as e:
        return False, "phase1_triage exec failed: %s" % e


def main():
    ap = argparse.ArgumentParser(description="Octra HFHE v2 public audit verification")
    ap.add_argument("secret_ct", nargs="?", default=DEFAULT_CT,
                    help="path to secret.ct (default: public_artifacts/secret.ct)")
    ap.add_argument("--skip-phase1-bin", action="store_true",
                    help="do not invoke compiled phase1_triage even if present")
    args = ap.parse_args()

    path = os.path.abspath(args.secret_ct)
    print("=== Octra HFHE v2 Public Audit Verification ===")
    print("artifact: %s" % path)
    print("format:   OCTRA-HFHE-BTY02 / PVAC v3 length-prefixed bundle")
    print("scope:    public artifacts only (see THREAT_MODEL.md)\n")

    if not os.path.isfile(path):
        print("FAIL | cannot open %s" % path)
        return 2

    raw = open(path, "rb").read()
    try:
        cts = parse_bundle(raw)
    except ParseError as e:
        print("FAIL | parse error: %s" % e)
        return 1

    print("Loaded %d ciphertexts (parse OK)\n" % len(cts))

    tests = [
        ("Structure / wrap encoding (2 BASE)", lambda: test_structure(cts)),
        ("Commitment uniqueness (rho reuse filter)", lambda: test_commitment_uniqueness(cts)),
        ("BASE seed uniqueness", lambda: test_seed_uniqueness(cts)),
        ("Noise via edge-weight hamming", lambda: test_noise_edge_weights(cts)),
        ("v1 R_com oracle wire closure", lambda: test_rcom_wire_closure(cts, raw)),
    ]

    all_pass = True
    for name, fn in tests:
        passed, msg = fn()
        status = "PASS" if passed else "FAIL"
        mark = "[OK]" if passed else "[!!]"
        print("%s %s | %s: %s" % (mark, status, name, msg))
        if not passed:
            all_pass = False

    script_dir = os.path.dirname(os.path.abspath(__file__))
    if not args.skip_phase1_bin:
        res = try_phase1_binary(script_dir)
        if res is None:
            print("[--] SKIP | compiled phase1_triage not found (N0/N1 field algebra optional)")
        else:
            passed, out = res
            status = "PASS" if passed else "FAIL"
            mark = "[OK]" if passed else "[!!]"
            print("%s %s | Full phase1_triage (N0/N1 algebra)" % (mark, status))
            for line in out.strip().splitlines():
                if "verdict" in line or "PHASE 1 SUMMARY" in line or line.startswith("Test"):
                    print("       %s" % line)
            if not passed:
                all_pass = False

    print("\n=== Final Result ===")
    if all_pass:
        print("All public checks pass: no obvious public dependency flaws detected")
        print("Not a formal security proof. See LIMITATIONS.md / THREAT_MODEL.md.")
        return 0
    print("One or more checks failed: investigate before proceeding")
    return 1


if __name__ == "__main__":
    sys.exit(main())
