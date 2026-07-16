// Day-7 Probe 2c (correct offsets): Targeted malformed-structure fuzz.
// REAL serialize_cipher layout:
//   [0..5]   header (MAGIC+VER+TAG)
//   [6..13]  u64 slots
//   [14..21] u64 nL
//   then nL layers (write_layer):
//      u8 rule
//      if BASE: u64 ztag, u64 nonce.lo, u64 nonce.hi   (24)
//      else:    u32 pa, u32 pb                      (8)
//      u64 PC.size ; then PC.size*32 bytes
//   u64 c0count ; then c0count * 16 bytes (each fp = 2*u64)
//   u64 nE     ; then nE edges
// We WALK the blob exactly like deserialize_cipher to find the true
// byte offsets of c0count and nE, then corrupt THOSE fields.
// ASan+UBSan instrumented. Confirm parser throws cleanly on every
// invalid input (safe) or flags a real logic gap.
//
// Build:
//   clang++ -std=c++17 -O1 -g -fsanitize=address,undefined \
//     -mcpu=apple-m2 -I../pvac_hfhe_cpp/include \
//     -I../pvac_hfhe_cpp/include -I<challenge>/source \
//     probe2c_malformed.cpp -o probe2c_malformed
// Run: ./probe2c_malformed
#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <iostream>
#include <vector>
#include <cstring>
#include <string>
#include <functional>
#include <cstdint>

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

// Walk to locate the true c0count / nE byte offsets.
static void find_offsets(const std::vector<uint8_t>& b, size_t& c0off, size_t& nEoff) {
    size_t p = 6; // past header
    uint64_t slots = *(const uint64_t*)(b.data()+p); p += 8;
    uint64_t nL    = *(const uint64_t*)(b.data()+p); p += 8;
    (void)slots;
    for (uint64_t i = 0; i < nL; ++i) {
        uint8_t rule = b[p]; p += 1;
        if (rule == (uint8_t)RRule::BASE) {
            p += 24; // ztag + nonce.lo + nonce.hi
        } else {
            p += 8;  // pa + pb
        }
        uint64_t nPC = *(const uint64_t*)(b.data()+p); p += 8;
        p += (size_t)nPC * 32;
    }
    c0off = p;
    uint64_t c0count = *(const uint64_t*)(b.data()+p); p += 8;
    p += (size_t)c0count * 16; // each fp = 2*u64
    nEoff = p;
}

struct Mut { std::string name; std::function<void(std::vector<uint8_t>&, size_t, size_t)> fn; };

int main() {
    std::cout << "Probe2c malformed-structure fuzz @ 071b0e9 (ASan, WALKED offsets)\n";
    auto base = make_baseline();
    size_t c0off, nEoff;
    find_offsets(base, c0off, nEoff);
    std::cout << "  baseline bytes=" << base.size()
              << " c0count_off=" << c0off << " nE_off=" << nEoff << "\n";

    std::vector<Mut> muts;
    muts.push_back({"c0count=1e9", [](std::vector<uint8_t>& b, size_t c, size_t e){
        (void)e; set_u64(b, c, 1000000000ULL); }});
    muts.push_back({"nE=1e9",     [](std::vector<uint8_t>& b, size_t c, size_t e){
        (void)c; set_u64(b, e, 1000000000ULL); }});
    muts.push_back({"c0count=0",   [](std::vector<uint8_t>& b, size_t c, size_t e){
        (void)e; set_u64(b, c, 0); }});
    muts.push_back({"nE=0",        [](std::vector<uint8_t>& b, size_t c, size_t e){
        (void)c; set_u64(b, e, 0); }});
    muts.push_back({"bad_magic",   [](std::vector<uint8_t>& b, size_t c, size_t e){
        (void)c;(void)e; b[0]='X'; }});
    muts.push_back({"bad_version", [](std::vector<uint8_t>& b, size_t c, size_t e){
        (void)c;(void)e; b[4]=0x99; }});
    muts.push_back({"truncate_50pct",[](std::vector<uint8_t>& b, size_t c, size_t e){
        (void)c;(void)e; b.resize(b.size()/2); }});
    muts.push_back({"header_only", [](std::vector<uint8_t>& b, size_t c, size_t e){
        (void)c;(void)e; b.resize(6); }});

    int clean_throws = 0, accepted = 0, crashes = 0;
    for (auto& m : muts) {
        auto b = base;
        try {
            m.fn(b, c0off, nEoff);
            Cipher C = deserialize_cipher(b.data(), b.size());
            std::cout << "  [" << m.name << "] ACCEPTED c0=" << C.c0.size()
                      << " L=" << C.L.size() << " E=" << C.E.size()
                      << " (no throw) -- REVIEW\n";
            ++accepted;
        } catch (const std::exception& e) {
            (void)e; ++clean_throws;
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
        std::cout << "  VERDICT: parser ACCEPTED " << accepted << " malformed input(s) -- LOGIC GAP, review.\n";
    std::cout << "PROBE2C_DONE\n";
    return 0;
}
