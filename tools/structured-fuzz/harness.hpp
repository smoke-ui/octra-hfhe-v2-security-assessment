#pragma once
#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace structured_fuzz {
using Bytes = std::vector<uint8_t>;
inline constexpr std::array<uint8_t,16> kBundleMagic = {'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};

inline void put64(Bytes& b, uint64_t v) { for (int i=0;i<8;++i) b.push_back(uint8_t(v>>(8*i))); }
inline void set64(Bytes& b, size_t p, uint64_t v) { for(int i=0;i<8;++i)b.at(p+i)=uint8_t(v>>(8*i)); }
inline uint64_t get64(const Bytes& b,size_t& p){if(p+8>b.size())throw std::runtime_error("bundle truncated");uint64_t v=0;for(int i=0;i<8;++i)v|=uint64_t(b[p++])<<(8*i);return v;}

struct Fixture { pvac::PubKey pk; pvac::SecKey sk; pvac::Cipher ct; Bytes direct; Bytes bundle; };
inline Fixture make_fixture() {
  Fixture f{};
  f.pk.prm.B=3; f.pk.prm.m_bits=1; f.pk.prm.n_bits=1;
  f.pk.prm.h_col_wt=0; f.pk.prm.x_col_wt=0; f.pk.prm.err_wt=0;
  f.pk.prm.lpn_n=1; f.pk.prm.lpn_t=1; f.pk.prm.lpn_tau_num=0; f.pk.prm.lpn_tau_den=1;
  f.pk.canon_tag=0x46555a5a46495854ULL;
  f.pk.H={pvac::BitVec::make(1)}; f.pk.ubk.perm={0}; f.pk.ubk.inv={0};
  f.pk.omega_B=pvac::fp_from_u64(1); f.pk.powg_B={pvac::fp_from_u64(1),pvac::fp_from_u64(2),pvac::fp_from_u64(4)};
  f.sk.prf_k={1,2,3,4}; f.sk.lpn_s_bits={0};
  pvac::Layer layer{}; layer.rule=pvac::RRule::BASE; layer.seed={0x1111,{0x2222,0x3333}};
  pvac::Edge edge{}; edge.layer_id=0; edge.idx=1; edge.ch=pvac::SGN_P; edge.w={pvac::fp_from_u64(7)}; edge.s=pvac::BitVec::make(1);
  f.ct.slots=1; f.ct.L={layer}; f.ct.c0={pvac::fp_from_u64(42)}; f.ct.E={edge};
  f.direct=pvac_ser::serialize_cipher(f.ct);
  f.bundle.assign(kBundleMagic.begin(),kBundleMagic.end()); put64(f.bundle,1); put64(f.bundle,f.direct.size()); f.bundle.insert(f.bundle.end(),f.direct.begin(),f.direct.end());
  return f;
}
inline Bytes parse_bundle_one(const Bytes& b) {
  if (b.size() < 16 || !std::equal(kBundleMagic.begin(), kBundleMagic.end(), b.begin()))
    throw std::runtime_error("bad bundle magic");
  size_t p = 16;
  auto count = get64(b, p);
  if (count != 1) throw std::runtime_error("invalid cipher count");
  auto n = get64(b, p);
  if (n == 0 || n > b.size() - p) throw std::runtime_error("invalid cipher length");
  Bytes out(b.begin() + p, b.begin() + p + n);
  p += n;
  if (p != b.size()) throw std::runtime_error("bundle trailing bytes");
  return out;
}
inline bool same_fp(const pvac::Fp&a,const pvac::Fp&b){return a.lo==b.lo&&a.hi==b.hi;}
inline bool decrypt_same(const Fixture& f,const pvac::Cipher& c){auto a=pvac::dec_value(f.pk,f.sk,f.ct);auto b=pvac::dec_value(f.pk,f.sk,c);return same_fp(a,b);}

inline void exercise_direct(const uint8_t* data,size_t size) {
  try {
    auto c = pvac_ser::deserialize_cipher(data, size);
    auto canon = pvac_ser::serialize_cipher(c);
    (void)canon;
    auto f = make_fixture();
    if (c.slots <= 64 && c.L.size() <= 64 && c.E.size() <= 256 &&
        pvac::is_cipher_compatible_with_pubkey(f.pk, c)) {
      auto d = pvac::dec_values(f.pk, f.sk, c);
      (void)d;
    }
  } catch (const std::exception&) {}
}
inline void exercise_bundle(const uint8_t* data,size_t size) { try { Bytes b(data,data+size); auto x=parse_bundle_one(b); exercise_direct(x.data(),x.size()); } catch(const std::exception&) {} }
}
