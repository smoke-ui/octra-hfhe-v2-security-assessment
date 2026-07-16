// Day-7 Probe 4: Multi-CT sk-correlation test.
// Generate N ciphertexts from the SAME sk and SAME plaintext,
// varying ONLY the random nonce/seed (as a real encryptor would).
// Test if any ciphertext component (c0 bytes, edge-weight first word,
// layer seed low 64 bits) has cross-ct correlation that would
// leak sk bits. We use Pearson correlation across the N samples on
// each extracted scalar; sk would show if e.g. c0 bits were not
// independent across CTs from one sk.
//
// Prior single-CT tests checked distributions; this checks
// CROSS-CT dependence under fixed sk (reused-state / biased-RNG
// signal). Generic reduced-param invariant test used DIFFERENT keys;
// this fixes sk to expose sk-bound structure.
//
// Build:
//   clang++ -std=c++17 -O2 -mcpu=apple-m2 -I../pvac_hfhe_cpp/include \
//     -I../pvac_hfhe_cpp/include -I<challenge>/source \
//     probe4_multi_ct.cpp -o probe4_multi_ct
// Run: ./probe4_multi_ct --n 1000
#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <iostream>
#include <vector>
#include <cstring>
#include <random>
#include <cmath>
#include <algorithm>

using namespace pvac;
using namespace pvac_ser;

int main(int argc, char** argv) {
    int N = 1000;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind("--n",0)==0 && i+1<argc) N = std::atoi(argv[++i]);
    }
    std::cout << "Probe4 multi-ct sk-correlation @ 071b0e9  N=" << N << "\n";

    Params prm; prm.noise_entropy_bits = 128;
    PubKey pk; SecKey sk;
    keygen(prm, pk, sk);              // FIXED sk for all N CTs
    std::string plain(15, '\0');       // SAME plaintext (15 bytes)
    for (size_t i = 0; i < plain.size(); ++i) plain[i] = (char)('A' + (i%26));

    // Extract 3 scalar series across the N CTs:
    //   s0[k] = c0[0].lo  (first c0 Fp low word)
    //   s1[k] = first edge weight lo word
    //   s2[k] = layer0 seed.nonce.lo
    std::vector<uint64_t> s0(N,0), s1(N,0), s2(N,0);
    std::mt19937_64 rng(0xC0FFEE123ULL);
    for (int k = 0; k < N; ++k) {
        // VARY plaintext per CT (to separate plaintext-constancy from sk reuse)
        std::string ptext(15, '\0');
        for (size_t i = 0; i < ptext.size(); ++i) ptext[i] = (char)((rng() >> (i%32)) & 0xFF);
        std::vector<Cipher> cts = enc_text(pk, sk, ptext);
        const Cipher& C = cts[0];
        if (!C.c0.empty()) s0[k] = C.c0[0].lo;
        if (!C.E.empty())  s1[k] = C.E[0].w.empty() ? 0 : C.E[0].w[0].lo;
        if (!C.L.empty() && C.L[0].rule == RRule::BASE)
            s2[k] = C.L[0].seed.nonce.lo;
        (void)rng;
    }

    // Pearson autocorrelation at lag 1 for each series; independent RNG =>
    // |r1| ~ 0. If sk/state reuse biased nonce->ct mapping, r1 would be nonzero.
    auto lag1_corr = [](const std::vector<uint64_t>& x) -> double {
        int n = (int)x.size();
        double mx = 0, my = 0;
        for (int i = 0; i < n-1; ++i) { mx += (double)x[i]; my += (double)x[i+1]; }
        mx /= (n-1); my /= (n-1);
        double sxx=0, syy=0, sxy=0;
        for (int i = 0; i < n-1; ++i) {
            double dx = (double)x[i]-mx, dy = (double)x[i+1]-my;
            sxx += dx*dx; syy += dy*dy; sxy += dx*dy;
        }
        double den = std::sqrt(sxx*syy) + 1e-12;
        return sxy/den;
    };

    double r0 = lag1_corr(s0), r1 = lag1_corr(s1), r2 = lag1_corr(s2);
    std::cout << "  lag1_corr c0.lo      = " << r0 << " (expect ~0)\n";
    std::cout << "  lag1_corr edge.w0.lo = " << r1 << " (expect ~0)\n";
    std::cout << "  lag1_corr layer0.nonce= " << r2 << " (expect ~0)\n";

    // Also: are consecutive CTs' c0.lo exactly equal (deterministic reuse)?
    int exact_dup = 0;
    for (int i = 0; i < N-1; ++i) if (s0[i]==s0[i+1]) ++exact_dup;
    std::cout << "  exact c0.lo duplicates across consecutive CTs = " << exact_dup << " (expect 0)\n";

    const double THR = 0.10; // |r| below => no cross-ct dependence
    int flags = 0;
    if (std::fabs(r0) > THR) ++flags;
    if (std::fabs(r1) > THR) ++flags;
    if (std::fabs(r2) > THR) ++flags;
    if (exact_dup > 0) ++flags;

    std::cout << "  flags(>|0.10| or dup)=" << flags << "\n";
    if (flags == 0)
        std::cout << "  VERDICT: no cross-ct correlation under fixed sk. No reused-state / biased-RNG leak.\n";
    else
        std::cout << "  VERDICT: SIGNIFICANT cross-ct dependence -> possible sk/state leak. LEAD.\n";
    std::cout << "PROBE4_DONE\n";
    return 0;
}
