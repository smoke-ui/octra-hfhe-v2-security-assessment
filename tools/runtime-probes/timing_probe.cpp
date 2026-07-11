#include <pvac/pvac.hpp>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <vector>

using namespace pvac;
using Clock = std::chrono::steady_clock;
static constexpr std::size_t kMaxSamples = 20000;
static constexpr std::size_t kMaxBatch = 64;
static volatile std::uint64_t g_sink = 0;

static std::size_t arg(std::vector<std::string> const& a, char const* name, std::size_t d, std::size_t max) {
    for (std::size_t i = 0; i + 1 < a.size(); ++i) if (a[i] == name) {
        auto v = std::stoull(a[i + 1]);
        if (!v || v > max) throw std::runtime_error(std::string(name) + " out of bounds");
        return static_cast<std::size_t>(v);
    }
    return d;
}

static double mean(std::vector<double> const& x) {
    return std::accumulate(x.begin(), x.end(), 0.0) / x.size();
}
static double variance(std::vector<double> const& x, double m) {
    double s = 0; for (double v : x) { double d = v - m; s += d * d; }
    return s / static_cast<double>(x.size() - 1);
}
static double welch_t(std::vector<double> const& a, std::vector<double> const& b) {
    double ma = mean(a), mb = mean(b);
    return (ma - mb) / std::sqrt(variance(a, ma) / a.size() + variance(b, mb) / b.size());
}

int main(int argc, char** argv) try {
    std::vector<std::string> args(argv + 1, argv + argc);
    std::size_t samples = arg(args, "--samples", 500, kMaxSamples);
    std::size_t warmup = arg(args, "--warmup", 20, 1000);
    std::size_t batch = arg(args, "--batch", 2, kMaxBatch);
    if (samples < 2) throw std::runtime_error("--samples must be at least 2");

    Params prm; PubKey pk; SecKey base; keygen(prm, pk, base);
    RSeed seed{0x9e3779b97f4a7c15ULL, {0x243f6a8885a308d3ULL, 0x13198a2e03707344ULL}};
    constexpr std::size_t pool_size = 64;
    std::vector<SecKey> secrets[2];
    for (int c = 0; c < 2; ++c) for (std::size_t j = 0; j < pool_size; ++j) {
        SecKey sk = base;
        for (auto& w : sk.prf_k) w = csprng_u64();
        for (auto& w : sk.lpn_s_bits) w = csprng_u64();
        sk.lpn_s_bits[0] = (sk.lpn_s_bits[0] & ~1ULL) | static_cast<std::uint64_t>(c);
        secrets[c].push_back(std::move(sk));
    }
    for (std::size_t i = 0; i < warmup; ++i) {
        Fp r = prf_R_core(pk, secrets[i & 1][i % pool_size], seed, Dom::PRF_R1);
        g_sink ^= r.lo;
    }

    std::vector<int> labels(2 * samples);
    std::fill(labels.begin(), labels.begin() + samples, 0);
    std::fill(labels.begin() + samples, labels.end(), 1);
    std::mt19937_64 shuffle_rng(csprng_u64());
    std::shuffle(labels.begin(), labels.end(), shuffle_rng);
    std::vector<double> times[2]; times[0].reserve(samples); times[1].reserve(samples);
    std::size_t pick[2] = {0, 0};
    for (int c : labels) {
        SecKey const& sk = secrets[c][pick[c]++ % pool_size];
        auto t0 = Clock::now();
        std::uint64_t local = 0;
        for (std::size_t b = 0; b < batch; ++b) {
            Fp r = prf_R_core(pk, sk, seed, Dom::PRF_R1); local ^= r.lo ^ r.hi;
        }
        auto t1 = Clock::now(); g_sink ^= local;
        times[c].push_back(std::chrono::duration<double, std::nano>(t1 - t0).count() / batch);
    }
    double m0 = mean(times[0]), m1 = mean(times[1]), t = welch_t(times[0], times[1]);
    double threshold = 4.5;
    std::cout << std::setprecision(10)
      << "{\"probe\":\"prf_R_core_welch_t\",\"status\":\"" << (std::abs(t) >= threshold ? "investigate" : "ok")
      << "\",\"interpretation\":\"threshold_for_investigation_not_proof\",\"samples_per_class\":" << samples
      << ",\"batch\":" << batch << ",\"warmup\":" << warmup << ",\"class0_mean_ns\":" << m0
      << ",\"class1_mean_ns\":" << m1 << ",\"welch_t\":" << t << ",\"threshold_abs_t\":" << threshold << "}\n";
    return 0;
} catch (std::exception const& e) { std::cerr << "timing_probe: " << e.what() << '\n'; return 2; }
