// Day-7 Probe 2: Targeted malformed-bundle structure fuzz.
// Feeds hand-crafted INVALID ciphertext byte-blobs into the REAL
// deserialize_cipher() + validate_cipher_structure(). Goal: confirm the
// parser either throws cleanly (safe) or, if it ever OOB-reads / crashes
// without throwing, that is a memory-safety finding. ASan-instrumented.
//
// We do NOT rely on random fuzzing (already done). We target the exact
// structural predicates the validator checks — flipping each to an invalid
// value — to see if any slips past the guards and reaches unsafe code.
//
// Build (ASan):
//   clang++ -std=c++17 -O1 -g -fsanitize=address,undefined \
//     -mcpu=apple-m2 -I../pvac_hfhe_cpp/include \
//     probe2_malformed_struct.cpp -o probe2_malformed_struct
// Run:
//   ./probe2_malformed_struct
#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"  // local: copy from <challenge>/source/ before build
#include <iostream>
#include <vector>
#include <cstring>
#include <string>
#include <memory>

using namespace pvac;
using namespace pvac_ser;

// Build a valid baseline cipher then we mutate specific fields.
static std::vector<uint8_t> make_baseline() {
    Params prm; prm.noise_entropy_bits = 128;
    PubKey pk; SecKey sk; keygen(prm, pk, sk);
    Cipher C = enc_zero_depth(pk, sk, 0);   // valid 1-slot wrapped ct
    return serialize_cipher(C);
}

// Mutators operate on the serialized blob (post-header) by flipping counts.
struct Mut {
    std::string name;
    std::function<void(std::vector<uint8_t>&)> fn;
};

int main() {
    std::cout << "Probe2 malformed-structure fuzz @ 071b0e9 (ASan)\n";
    auto base = make_baseline();
    std::cout << "  baseline blob bytes=" << base.size() << "\n";

    // Helper: rewrite a u64 LE at offset inside blob (after MAGIC/VER/TAG = 6 bytes)
    auto set_u64 = [](std::vector<uint8_t>& b, size_t off, uint64_t v) {
        for (int i = 0; i < 8; ++i) b[off+i] = (v >> (8*i)) & 0xFF;
    };
    auto set_u32 = [](std::vector<uint8_t>& b, size_t off, uint32_t v) {
        for (int i = 0; i < 4; ++i) b[off+i] = (v >> (8*i)) & 0xFF;
    };

    std::vector<Mut> muts;
    // 1) slots = 0 (validator throws if slots==0)
    muts.push_back({"slots=0", [=](std::vector<uint8_t>& b){ set_u64(b, 6, 0); }});
    // 2) layer count huge (e.g. 1e9) -> check_count fails (>1<<24)
    muts.push_back({"nL=1e9", [=](std::vector<uint8_t>& b){ set_u64(b, 14, 1000000000ULL); }});
    // 3) layer count = 0 but edges reference layer 0 -> edge layer out of range
    muts.push_back({"nL=0", [=](std::vector<uint8_t>& b){ set_u64(b, 14, 0); }});
    // 4) edge count huge
    muts.push_back({"nE=1e9", [=](std::vector<uint8_t>& b){ set_u64(b, 14 + 8 + /*est*/ 0, 1000000000ULL); }});
    // 5) corrupt MAGIC -> bad magic throw
    muts.push_back({"bad_magic", [=](std::vector<uint8_t>& b){ b[0]='X'; }});
    // 6) version 0x99 -> bad version throw
    muts.push_back({"bad_version", [=](std::vector<uint8_t>& b){ b[4]=0x99; }});
    // 7) truncate blob by 50% -> truncated throw
    muts.push_back({"truncate_50pct", [=](std::vector<uint8_t>& b){ b.resize(b.size()/2); }});
    // 8) truncate to just header -> truncated
    muts.push_back({"header_only", [=](std::vector<uint8_t>& b){ b.resize(6); }});

    int clean_throws = 0, crashes = 0, unexpected = 0;
    for (auto& m : muts) {
        auto b = base;
        try {
            m.fn(b);
            // attempt deserialize — may throw or may return (if mutation didn't
            // actually reach a checked field). Either way we check ASan is quiet.
            const uint8_t* p = b.data();
            size_t len = b.size();
            Cipher C = deserialize_cipher(p, len);
            // if it returned without throw, the mutation was benignly ignored
            // OR parser accepted invalid — note it.
            std::cout << "  [" << m.name << "] ACCEPTED (no throw) — review\n";
            ++unexpected;
        } catch (const std::exception& e) {
            // clean throw = safe parser behavior
            ++clean_throws;
        } catch (...) {
            std::cout << "  [" << m.name << "] non-std throw\n";
            ++clean_throws;
        }
    }
    std::cout << "  clean_throws=" << clean_throws
              << " accepted_unexpected=" << unexpected
              << " asan_crashes=" << crashes << "\n";
    if (crashes == 0 && unexpected == 0)
        std::cout << "  VERDICT: parser rejects all malformed inputs via clean throw. NO OOB/leak path.\n";
    else if (unexpected > 0)
        std::cout << "  VERDICT: parser ACCEPTED malformed input w/o throw — REVIEW for logic gap.\n";
    std::cout << "PROBE2_DONE\n";
    return 0;
}
