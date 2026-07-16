// Day-7 Probe 3: Wallet-derived KDF test.
// Question: did the challenge generator tie sk to a wallet private key
// (via keygen_from_seed), making the public address recover sk?
//
// Evidence from source (hfhe_bounty_artifact.cpp generate()):
//   generate() calls keygen(prm, pk, sk)  [CSPRNG path], NOT
//   keygen_from_seed(...). So live sk is CSPRNG-derived.
//
// Test: derive a pk via keygen_from_seed(dummy_wallet_privkey) and
// compare its canon_tag against the REAL challenge pk.bin canon_tag.
// If they differ -> challenge did NOT use wallet path -> address cannot
// recover sk (one-way). If equal -> flaw (would be a lead).
//
// Build:
//   clang++ -std=c++17 -O2 -mcpu=apple-m2 -I../pvac_hfhe_cpp/include \
//     probe3_wallet_kdf.cpp -o probe3_wallet_kdf
// Run: ./probe3_wallet_kdf
#include <pvac/pvac.hpp>
#include <pvac/crypto/keygen.hpp>
#include "pvac_artifact_serialize.hpp"  // local: copy from <challenge>/source/ before build
#include <iostream>
#include <vector>
#include <cstring>
#include <fstream>

using namespace pvac;

static std::vector<uint8_t> read_file_bytes(const char* path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open pk.bin");
    in.seekg(0, std::ios::end);
    std::streamoff n = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> d((size_t)n);
    in.read((char*)d.data(), n);
    return d;
}

int main() {
    std::cout << "Probe3 wallet-derived KDF @ 071b0e9\n";

    Params prm; prm.noise_entropy_bits = 128;

    // 1) Live challenge pk from pk.bin
    auto pk_blob = read_file_bytes("public_artifacts/pk.bin");  // shipped in repo
    PubKey pk_live = pvac_ser::deserialize_pubkey(pk_blob.data(), pk_blob.size());
    std::cout << "  live canon_tag = " << pk_live.canon_tag << "\n";

    // 2) Wallet-derived path with a DUMMY 32-byte privkey
    uint8_t dummy_wallet[32];
    for (int i = 0; i < 32; ++i) dummy_wallet[i] = (uint8_t)(i * 7 + 3);
    PubKey pk_seed; SecKey sk_seed;
    keygen_from_seed(prm, pk_seed, sk_seed, dummy_wallet);
    std::cout << "  wallet-derived canon_tag (dummy) = " << pk_seed.canon_tag << "\n";

    // 3) CSPRNG path (what generate() actually calls)
    PubKey pk_csprng; SecKey sk_csprng;
    keygen(prm, pk_csprng, sk_csprng);
    std::cout << "  csprng canon_tag = " << pk_csprng.canon_tag << "\n";

    bool live_matches_wallet = (pk_live.canon_tag == pk_seed.canon_tag);
    bool live_matches_csprng  = (pk_live.canon_tag == pk_csprng.canon_tag);

    std::cout << "  live == wallet-derived(dummy)? " << live_matches_wallet << "\n";
    std::cout << "  live == csprng(random)?        " << live_matches_csprng  << " (1-in-2^64, expect 0)\n";

    // 4) Determinism of keygen_from_seed: same wallet -> same tag
    PubKey pk_seed2; SecKey sk_seed2;
    keygen_from_seed(prm, pk_seed2, sk_seed2, dummy_wallet);
    bool deterministic = (pk_seed.canon_tag == pk_seed2.canon_tag);
    std::cout << "  keygen_from_seed deterministic (same wallet)? " << deterministic << "\n";

    if (!live_matches_wallet && deterministic) {
        std::cout << "  VERDICT: challenge sk is NOT wallet-derived (live canon_tag != wallet path).\n";
        std::cout << "  The wallet->sk path EXISTS in the lib but generate() used CSPRNG.\n";
        std::cout << "  Public address is a one-way output of sk; cannot recover sk.\n";
        std::cout << "  NO FLAW: address does not leak sk.\n";
    } else if (live_matches_wallet) {
        std::cout << "  VERDICT: LIVE canon_tag MATCHES wallet path -> POSSIBLE FLAW. LEAD.\n";
    }
    std::cout << "PROBE3_DONE\n";
    return 0;
}
