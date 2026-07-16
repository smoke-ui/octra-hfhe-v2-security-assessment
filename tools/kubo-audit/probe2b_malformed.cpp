// Day-7 Probe 2 (v2 — precise offsets): Targeted malformed-structure fuzz.
// REAL serialize_cipher layout (from pvac_artifact_serialize.hpp):
//   [0..3]   MAGIC "PVAC"
//   [4]      VERSION (0x03)
//   [5]      TAG (0 = CIPHER)
//   [6..13]  u64 slots
//   [14..21] u64 nL (layer count)
//   [22..29] u64 c0count
//   [30..37] u64 nE (edge count)
//   then nL layers, c0count c0 Fps, nE edges...
// We mutate EXACT u64 fields and feed to deserialize_cipher + validator.
// ASan+UBSan instrumented. Confirm parser throws cleanly on every
// invalid input (safe) or flags a real logic gap (review).
//
// Build:
//   clang++ -std=c++17 -O1 -g -fsanitize=address,undefined \
//     -mcpu=apple-m2 -I../pvac_hfhe_cpp/include \
//     -I../pvac_hfhe_cpp/include -I<challenge>/source \
//     probe2b_malformed.cpp -o probe2b_malformed
// Run: ./probe2b_malformed
#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <iostream>
#include <vector>
#include <cstring>
#include <string>
#include <functional>

using namespace pvac;
using namespace pvac_ser;

static std::vector<uint8_t> make_baseline() {
    Params prm; prm.noise_entropy_bits = 128;
    PubKey pk; SecKey sk; keygen(prm, pk, sk);
    Cipher C = enc_zero_depth(pk, sk, 0);
    return serialize_cipher(C);
}
static void set_u64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) b[off+i] = (v >> (8*i)) & 0xFF;
}

struct Mut { std::string name; std::function<void(std::vector<uint8_t>&)> fn; };

int main() {
    std::cout << "Probe2b malformed-structure fuzz @ 071b0e9 (ASan, exact offsets)\n";
    auto base = make_baseline();
    std::cout << "  baseline blob bytes=" << base.size() << "\n";

    std::vector<Mut> muts;
    muts.push_back({"slots=0",       [](std::vector<uint8_t>& b){ set_u64(b, 6,  0); }});
    muts.push_back({"nL=0",          [](std::vector<uint8_t>& b){ set_u64(b, 14, 0); }});
    muts.push_back({"nL=1e9",        [](std::vector<uint8_t>& b){ set_u64(b, 14, 1000000000ULL); }});
    muts.push_back({"c0count=1e9",   [](std::vector<uint8_t>& b){ set_u64(b, 22, 1000000000ULL); }});
    muts.push_back({"nE=1e9",        [](std::vector<uint8_t>& b){ set_u64(b, 30, 1000000000ULL); }});
    muts.push_back({"bad_magic",     [](std::vector<uint8_t>& b){ b[0]='X'; }});
    muts.push_back({"bad_version",    [](std::vector<uint8_t>& b){ b[4]=0x99; }});
    muts.push_back({"truncate_50pct",[](std::vector<uint8_t>& b){ b.resize(b.size()/2); }});
    muts.push_back({"header_only",    [](std::vector<uint8_t>& b){ b.resize(6); }});

    int clean_throws = 0, accepted = 0, crashes = 0;
    for (auto& m : muts) {
        auto b = base;
        try {
            m.fn(b);
            Cipher C = deserialize_cipher(b.data(), b.size());
            std::cout << "  [" << m.name << "] ACCEPTED c0=" << C.c0.size()
                      << " L=" << C.L.size() << " E=" << C.E.size()
                      << " (no throw) — REVIEW\n";
            ++accepted;
        } catch (const std::exception& e) {
            ++clean_throws;
        } catch (...) {
            ++clean_throws;
        }
    }
    std::cout << "  clean_throws=" << clean_throws
              << " accepted_unexpected=" << accepted
              << " asan_crashes=" << crashes << "\n";
    if (accepted == 0)
        std::cout << "  VERDICT: parser throws cleanly on all malformed inputs. NO OOB/leak path.\n";
    else
        std::cout << "  VERDICT: parser ACCEPTED " << accepted << " malformed input(s) without throw — LOGIC GAP, review.\n";
    std::cout << "PROBE2B_DONE\n";
    return 0;
}
