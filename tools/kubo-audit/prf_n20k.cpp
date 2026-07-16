// Definitive N=20000 full-param prf_R bias test
// clang++ -std=c++17 -O2 -mcpu=apple-m2 -I../pvac_hfhe_cpp/include prf_n20k.cpp -o prf_n20k
#include <pvac/pvac.hpp>
#include <iostream>
#include <cmath>
#include <array>
#include <chrono>
using namespace pvac;

static int ham(const Fp& a, const Fp& b) {
    return __builtin_popcountll(a.lo ^ b.lo)
         + __builtin_popcountll((a.hi ^ b.hi) & MASK63);
}

static double bit_pvalue(uint64_t ones, uint64_t N) {
    double p = (double)ones / (double)N;
    double se = std::sqrt(0.25 / (double)N);
    double z = std::fabs(p - 0.5) / se;
    return std::erfc(z / std::sqrt(2.0));
}

int main() {
    const int N = 20000;
    Params prm;
    prm.noise_entropy_bits = 128;
    PubKey pk;
    SecKey sk;
    auto t0 = std::chrono::steady_clock::now();
    keygen(prm, pk, sk);
    auto t1 = std::chrono::steady_clock::now();

    std::array<uint64_t, 127> ones{};
    std::array<uint64_t, 256> hist{};
    double sum_hd = 0;

    for (int i = 0; i < N; i++) {
        RSeed s;
        s.nonce = make_nonce128();
        s.ztag = prg_layer_ztag(pk.canon_tag, s.nonce);
        Fp r = prf_R(pk, sk, s);
        for (int b = 0; b < 64; b++)
            if ((r.lo >> b) & 1) ones[b]++;
        for (int b = 0; b < 63; b++)
            if ((r.hi >> b) & 1) ones[64 + b]++;
        hist[r.lo & 0xFF]++;

        RSeed s2 = s;
        s2.nonce.lo ^= 1ull << (i % 64);
        s2.ztag = prg_layer_ztag(pk.canon_tag, s2.nonce);
        sum_hd += ham(r, prf_R(pk, sk, s2));
    }
    auto t2 = std::chrono::steady_clock::now();
    auto keygen_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    auto prf_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

    const double alpha = 0.01 / 127.0;
    int flags_bonf = 0;
    double max_dev = 0;
    int max_bit = -1;
    double min_p = 1.0;
    int min_p_bit = -1;
    for (int b = 0; b < 127; b++) {
        double p = (double)ones[b] / N;
        double d = std::fabs(p - 0.5);
        if (d > max_dev) {
            max_dev = d;
            max_bit = b;
        }
        double pv = bit_pvalue(ones[b], N);
        if (pv < min_p) {
            min_p = pv;
            min_p_bit = b;
        }
        if (pv < alpha) flags_bonf++;
    }

    double exp = (double)N / 256.0, chi = 0;
    for (int i = 0; i < 256; i++) {
        double d = hist[i] - exp;
        chi += d * d / exp;
    }

    std::cout << "=== N=20000 full-param prf_R definitive bias test ===\n";
    std::cout << "keygen_ms=" << keygen_ms << " prf_loop_ms=" << prf_ms << "\n";
    std::cout << "mean_avalanche_HD=" << (sum_hd / N) << " (expect ~63.5)\n";
    std::cout << "max_bit_dev=" << max_dev << " at_bit=" << max_bit << "\n";
    std::cout << "min_bit_pvalue=" << min_p << " at_bit=" << min_p_bit << "\n";
    std::cout << "bonferroni_alpha=" << alpha << " flags_fail=" << flags_bonf << "\n";
    std::cout << "chi2_lo_byte=" << chi << " (df=255, E=255)\n";
    if (flags_bonf == 0)
        std::cout << "VERDICT: NO significant bit bias at family-wise alpha=0.01\n";
    else
        std::cout << "VERDICT: BIAS FLAGS — investigate for key recovery\n";
    return flags_bonf == 0 ? 0 : 2;
}
