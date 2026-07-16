// Regression: v1 R_com must not reappear on the public wire; wrap uses PC only.
// Build (from this directory):
//   clang++ -std=c++17 -O2 -I../pvac_hfhe_cpp/include \
//     test_rcom_closure.cpp -o test_rcom_closure && ./test_rcom_closure
#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include "public_artifacts/source/pvac_artifact_serialize.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <set>
#include <string>

using namespace pvac;

static constexpr std::array<uint8_t,16> BUNDLE_MAGIC = {
    'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'
};

static std::vector<uint8_t> readf(const char* p) {
    std::ifstream i(p, std::ios::binary);
    i.seekg(0, std::ios::end);
    auto n = i.tellg(); i.seekg(0);
    std::vector<uint8_t> d((size_t)n);
    if (!d.empty()) i.read((char*)d.data(), n);
    return d;
}

int main() {
    std::cout << "=== test_rcom_closure (v2 regression) ===\n";

    // 1) Live public artifact: R_com not on wire (serializer omits it)
    auto ctb = readf("public_artifacts/secret.ct");
    assert(ctb.size() >= BUNDLE_MAGIC.size());
    assert(std::equal(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end(), ctb.begin()));
    // Domain string for R_com hashing must not appear in ciphertext blob
    std::string raw(ctb.begin(), ctb.end());
    assert(raw.find("pvac.dom.r_com") == std::string::npos);

    // 2) Round-trip serialize of a fresh wrap: still no R_com field after deser zeros
    Params prm; prm.noise_entropy_bits = 128.0;
    PubKey pk; SecKey sk; keygen(prm, pk, sk);
    Cipher wrap = enc_fp_wrapped_depth(pk, sk, fp_from_u64(42), 2);
    assert(wrap.L.size() == 2);
    // In-memory R_com may be set during encrypt; public blob must not carry it as a field.
    auto blob = pvac_ser::serialize_cipher(wrap);
    auto back = pvac_ser::deserialize_cipher(blob.data(), blob.size());
    // After public deser, R_com array is default-zero (not present on wire)
    for (auto& L : back.L) {
        bool allz = true;
        for (auto b : L.R_com) if (b) allz = false;
        assert(allz && "R_com survived public deserialize — v1-style regression");
        if (L.rule == RRule::BASE) {
            assert(!L.PC.empty() && "BASE layer missing PC on public wire");
        }
    }
    std::cout << "OK public wire: R_com zero after deser, PC present on BASE\n";

    // 3) PC uniqueness across independent encrypts (same plaintext)
    std::set<std::string> pcs;
    for (int i = 0; i < 32; ++i) {
        Cipher c = enc_fp_wrapped_depth(pk, sk, fp_from_u64(7), 2);
        for (auto& L : c.L) {
            if (L.rule != RRule::BASE || L.PC.empty()) continue;
            pcs.insert(std::string(L.PC[0].begin(), L.PC[0].end()));
        }
    }
    assert(pcs.size() == 64 && "PC collision among 64 independent BASE layers");
    std::cout << "OK PC uniqueness: 64/64 unique across 32 wraps\n";

    // 4) Mask is not fixed: two wraps of same v yield different edge-weight sets
    Cipher a = enc_fp_wrapped_depth(pk, sk, fp_from_u64(99), 2);
    Cipher b = enc_fp_wrapped_depth(pk, sk, fp_from_u64(99), 2);
    assert(a.E.size() > 0 && b.E.size() > 0);
    bool same = a.E.size() == b.E.size();
    if (same) {
        same = true;
        for (size_t i = 0; i < a.E.size() && same; ++i) {
            if (a.E[i].w.empty() || b.E[i].w.empty()) { same = false; break; }
            if (a.E[i].w[0].lo != b.E[i].w[0].lo || a.E[i].w[0].hi != b.E[i].w[0].hi)
                same = false;
        }
    }
    assert(!same && "identical edge weights across independent wraps — entropy collapse");
    std::cout << "OK wrap entropy: independent encrypts differ\n";

    std::cout << "ALL regression tests pass: v1 R_com oracle closed; no public entropy reuse signal\n";
    return 0;
}
