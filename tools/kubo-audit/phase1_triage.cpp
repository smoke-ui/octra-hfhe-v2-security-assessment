// Phase 1 artifact triage (branch filters) for Octra HFHE v2 secret.ct
// Maps plan terms to PVAC structure:
//   tau        = BASE layer seed (ztag, nonce.lo, nonce.hi)
//   commitment = layer.PC[0] (32-byte Pedersen)
//   c0/c1      = public layer sums N0/N1 of the two wrap BASE layers
//   m          = fused mask (not public; only statistical fingerprints)
#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include "public_artifacts/source/pvac_artifact_serialize.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <sstream>

using namespace pvac;

static constexpr std::array<uint8_t,16> MAGIC = {
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
static uint64_t take_u64(const std::vector<uint8_t>& in, size_t& pos) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)in[pos++] << (8 * i);
    return v;
}
static std::vector<Cipher> load_cts(const std::vector<uint8_t>& in) {
    size_t pos = MAGIC.size();
    uint64_t count = take_u64(in, pos);
    std::vector<Cipher> cts;
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t n = take_u64(in, pos);
        cts.push_back(pvac_ser::deserialize_cipher(in.data() + pos, (size_t)n));
        pos += (size_t)n;
    }
    return cts;
}

struct Tau {
    uint64_t z, lo, hi;
    bool operator<(const Tau& o) const {
        if (z != o.z) return z < o.z;
        if (lo != o.lo) return lo < o.lo;
        return hi < o.hi;
    }
    std::string key() const {
        std::ostringstream os;
        os << std::hex << z << ":" << lo << ":" << hi;
        return os.str();
    }
};

static Tau tau_of(const Layer& L) {
    return { L.seed.ztag, L.seed.nonce.lo, L.seed.nonce.hi };
}

static std::string pc_hex(const std::array<uint8_t,32>& pc) {
    std::ostringstream os;
    for (int i = 0; i < 32; ++i)
        os << std::hex << std::setw(2) << std::setfill('0') << (int)pc[i];
    return os.str();
}

// Public linear form N for layer (slot 0): c0 + sum_e ± w[0]*g[idx]
static Fp public_N(const PubKey& pk, const Cipher& c, uint32_t lid) {
    Fp acc = (lid == 0 && !c.c0.empty()) ? c.c0[0] : fp_from_u64(0);
    for (const auto& e : c.E) {
        if (e.layer_id != lid || e.w.empty()) continue;
        Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
        acc = sgn_val(e.ch) > 0 ? fp_add(acc, term) : fp_sub(acc, term);
    }
    return acc;
}

// Map Fp -> double for crude variance (use low 53 bits of lo)
static double fp_as_double(const Fp& x) {
    return (double)(x.lo & ((1ULL << 53) - 1));
}

static double variance(const std::vector<double>& xs) {
    if (xs.size() < 2) return 0.0;
    double m = std::accumulate(xs.begin(), xs.end(), 0.0) / xs.size();
    double v = 0;
    for (double x : xs) v += (x - m) * (x - m);
    return v / (xs.size() - 1);
}

int main() {
    auto pkb = readf("public_artifacts/pk.bin");
    auto ctb = readf("public_artifacts/secret.ct");
    auto pk = pvac_ser::deserialize_pubkey(pkb.data(), pkb.size());
    auto cts = load_cts(ctb);

    std::cout << "=== PHASE 1 ARTIFACT TRIAGE (branch filters) ===\n";
    std::cout << "cts=" << cts.size() << " B=" << pk.prm.B
              << " noise_entropy_bits=" << pk.prm.noise_entropy_bits << "\n";

    // Collect (tau, PC) for all BASE layers
    std::map<Tau, std::vector<std::string>> pc_by_tau;
    std::vector<std::string> all_pc;
    int base_layers = 0, missing_pc = 0;
    for (const auto& ct : cts) {
        for (const auto& L : ct.L) {
            if (L.rule != RRule::BASE) continue;
            ++base_layers;
            if (L.PC.empty()) { ++missing_pc; continue; }
            auto t = tau_of(L);
            auto hx = pc_hex(L.PC[0]);
            pc_by_tau[t].push_back(hx);
            all_pc.push_back(hx);
        }
    }
    std::cout << "base_layers=" << base_layers << " missing_pc=" << missing_pc
              << " unique_tau=" << pc_by_tau.size() << "\n";

    // ---- Test 1: Commitment grouping ----
    std::cout << "\n--- Test 1: Commitment Grouping (rho reuse filter) ---\n";
    int tau_groups = 0, max_count = 0, full_dup_groups = 0;
    double sum_dup_ratio = 0;
    for (auto& [t, pcs] : pc_by_tau) {
        ++tau_groups;
        std::set<std::string> u(pcs.begin(), pcs.end());
        size_t count = pcs.size();
        size_t uniq = u.size();
        double dup = 1.0 - (double)uniq / (double)count;
        sum_dup_ratio += dup;
        if ((int)count > max_count) max_count = (int)count;
        if (dup == 1.0 && count > 1) ++full_dup_groups;
        if (count > 1) {
            std::cout << "  multi-layer tau " << t.key()
                      << " count=" << count << " uniq=" << uniq
                      << " dup_ratio=" << dup << "\n";
        }
    }
    std::set<std::string> global_unique(all_pc.begin(), all_pc.end());
    double global_dup = all_pc.empty() ? 0.0
        : 1.0 - (double)global_unique.size() / (double)all_pc.size();
    double mean_dup = tau_groups ? sum_dup_ratio / tau_groups : 0.0;

    std::cout << "tau_groups=" << tau_groups
              << " mean_dup_ratio=" << mean_dup
              << " full_dup_groups=" << full_dup_groups
              << " max_count_per_tau=" << max_count << "\n";
    std::cout << "global_pc_count=" << all_pc.size()
              << " unique_pc=" << global_unique.size()
              << " global_dup_ratio=" << global_dup << "\n";

    std::string t1;
    if (global_dup == 1.0 && all_pc.size() > 1)
        t1 = "CRITICAL: global identical commitments (static rho)";
    else if (full_dup_groups > 0)
        t1 = "SUSPICIOUS: all commitments identical per some tau (rho fixed per tau)";
    else if (mean_dup < 0.01)
        t1 = "PASS: near-unique commitments per tau (rules out trivial rho reuse)";
    else
        t1 = "NOTE: intermediate duplicate ratio; inspect further";
    std::cout << "Test1 verdict: " << t1 << "\n";

    // ---- Test 2: Ciphertext fingerprinting via N0/N1 ----
    // For wrap: L0 encrypts v+m, L1 encrypts -m. Without plaintext we cannot
    // group by v. We still measure variance of Δ = N0-N1 and of N0,N1 across
    // all wrap blocks, and check if Δ is constant (would indicate fixed m*R
    // structure collapse). Also generate local known-plaintext control.
    std::cout << "\n--- Test 2: Ciphertext Fingerprinting (fixed-m filter) ---\n";
    std::vector<double> deltas, n0s, n1s, sums;
    int wrap_ok = 0, non_wrap = 0;
    for (const auto& ct : cts) {
        int bases = 0;
        for (auto& L : ct.L) if (L.rule == RRule::BASE) ++bases;
        if (bases != 2) { ++non_wrap; continue; }
        // assume first two layers are BASE 0,1 for wrap fuse
        if (ct.L.size() < 2 || ct.L[0].rule != RRule::BASE || ct.L[1].rule != RRule::BASE) {
            ++non_wrap; continue;
        }
        ++wrap_ok;
        Fp N0 = public_N(pk, ct, 0);
        Fp N1 = public_N(pk, ct, 1);
        Fp D = fp_sub(N0, N1);
        Fp S = fp_add(N0, N1);
        n0s.push_back(fp_as_double(N0));
        n1s.push_back(fp_as_double(N1));
        deltas.push_back(fp_as_double(D));
        sums.push_back(fp_as_double(S));
    }
    double var_d = variance(deltas);
    double var_n0 = variance(n0s);
    double var_n1 = variance(n1s);
    double var_s = variance(sums);
    std::cout << "wrap_cts=" << wrap_ok << " non_wrap=" << non_wrap << "\n";
    std::cout << "var(Δ=N0-N1)=" << var_d
              << " var(N0)=" << var_n0
              << " var(N1)=" << var_n1
              << " var(N0+N1)=" << var_s << "\n";
    // uniqueness of (N0,N1) pairs at full precision
    std::set<std::string> n_pairs;
    for (const auto& ct : cts) {
        if (ct.L.size() < 2 || ct.L[0].rule != RRule::BASE || ct.L[1].rule != RRule::BASE) continue;
        Fp N0 = public_N(pk, ct, 0);
        Fp N1 = public_N(pk, ct, 1);
        std::ostringstream os;
        os << std::hex << N0.lo << N0.hi << ":" << N1.lo << N1.hi;
        n_pairs.insert(os.str());
    }
    std::cout << "unique_(N0,N1)_pairs=" << n_pairs.size() << "/" << wrap_ok << "\n";

    // Local control with known plaintexts: same v encrypted many times
    {
        Params prm; prm.noise_entropy_bits = 128;
        PubKey pk2; SecKey sk2; keygen(prm, pk2, sk2);
        Fp v = pack_15_bytes_to_fp((const uint8_t*)"AAAAAAAAAAAAAAA", 15);
        std::vector<double> d_same;
        for (int i = 0; i < 16; ++i) {
            Cipher c = enc_fp_wrapped_depth(pk2, sk2, v, 2);
            Fp N0 = public_N(pk2, c, 0);
            Fp N1 = public_N(pk2, c, 1);
            d_same.push_back(fp_as_double(fp_sub(N0, N1)));
        }
        std::cout << "control same-v var(Δ)=" << variance(d_same)
                  << " (expect large if m/R independent each encrypt)\n";
    }

    std::string t2;
    if (var_d < 2.0 && wrap_ok > 2)
        t2 = "SUSPICIOUS: near-constant Δ across wrap blocks";
    else if (var_d == 0.0 && wrap_ok > 1)
        t2 = "CRITICAL: Δ identical for all blocks (m/R collapse)";
    else if (var_d >= 10.0)
        t2 = "PASS: high Δ variance (rules out obvious fixed m)";
    else
        t2 = "NOTE: moderate variance; not a trivial fixed-m signal";
    std::cout << "Test2 verdict: " << t2 << "\n";

    // ---- Test 3: Noise relative variance ----
    // Compare var(N) among "same tau" (should be singleton here) vs global.
    // Also compare edge-weight hamming variance within-layer vs across.
    std::cout << "\n--- Test 3: Noise Relative Variance ---\n";
    // Use per-layer public N variance across layers sharing nothing (all unique tau)
    // Set A: all N values (one per base layer) — if deterministic noise, structure collapses
    std::vector<double> all_N;
    for (const auto& ct : cts) {
        for (uint32_t li = 0; li < ct.L.size(); ++li) {
            if (ct.L[li].rule != RRule::BASE) continue;
            all_N.push_back(fp_as_double(public_N(pk, ct, li)));
        }
    }
    std::cout << "var(all public N)=" << variance(all_N) << " n=" << all_N.size() << "\n";

    // Edge weight hamming popcnt variance per layer vs global
    std::vector<double> global_ham;
    std::vector<double> per_layer_vars;
    for (const auto& ct : cts) {
        for (uint32_t li = 0; li < ct.L.size(); ++li) {
            if (ct.L[li].rule != RRule::BASE) continue;
            std::vector<double> ham;
            for (const auto& e : ct.E) {
                if (e.layer_id != li || e.w.empty()) continue;
                double h = __builtin_popcountll(e.w[0].lo)
                         + __builtin_popcountll(e.w[0].hi & MASK63);
                ham.push_back(h);
                global_ham.push_back(h);
            }
            if (ham.size() >= 2) per_layer_vars.push_back(variance(ham));
        }
    }
    double med_layer = 0;
    if (!per_layer_vars.empty()) {
        std::sort(per_layer_vars.begin(), per_layer_vars.end());
        med_layer = per_layer_vars[per_layer_vars.size()/2];
    }
    double var_global_ham = variance(global_ham);
    std::cout << "median_within_layer_ham_var=" << med_layer
              << " global_ham_var=" << var_global_ham
              << " global_ham_mean="
              << (global_ham.empty()?0:std::accumulate(global_ham.begin(),global_ham.end(),0.0)/global_ham.size())
              << "\n";

    std::string t3;
    if (med_layer == 0.0 && var_global_ham > 0)
        t3 = "CRITICAL: zero within-layer noise variance";
    else if (med_layer < 5.0 && var_global_ham >= 10.0)
        t3 = "SUSPICIOUS: low within-layer vs high global noise variance";
    else
        t3 = "PASS: within-layer noise variance comparable to healthy random Fp weights";
    std::cout << "Test3 verdict: " << t3 << "\n";

    // Structural wrap check
    std::cout << "\n--- Structural ---\n";
    int two_base = 0;
    for (const auto& ct : cts) {
        int b = 0; for (auto& L : ct.L) if (L.rule == RRule::BASE) ++b;
        if (b == 2) ++two_base;
    }
    std::cout << "cts_with_exactly_2_BASE=" << two_base << "/" << cts.size()
              << " (wrapped encoding expected)\n";
    std::cout << "R_com serialized in public artifact: NO (v2 serializer omits R_com)\n";
    std::cout << "PC present on BASE layers: " << (missing_pc == 0 ? "YES" : "PARTIAL") << "\n";

    std::cout << "\n=== PHASE 1 SUMMARY ===\n";
    std::cout << "T1 " << t1 << "\n";
    std::cout << "T2 " << t2 << "\n";
    std::cout << "T3 " << t3 << "\n";
    std::cout << "Action: proceed to Phase 2 source audit (m / rho / noise).\n";
    return 0;
}
