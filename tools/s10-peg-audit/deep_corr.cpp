#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <algorithm>
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace pvac;
struct Blob { std::vector<uint64_t> w; size_t bits; };
struct Artifact { PubKey pk; std::vector<Cipher> ciphers; std::vector<Nonce128> nonce; std::vector<uint64_t> ztag; std::vector<Blob> pc, sigma, weight; std::vector<uint16_t> idx; std::vector<uint8_t> sign; size_t ztag_verified = 0, ztag_mismatches = 0; };
static std::vector<uint8_t> load(const std::string &p) { std::ifstream f(p, std::ios::binary); if (!f) throw std::runtime_error("input open failed"); return {std::istreambuf_iterator<char>(f), {}}; }
static uint64_t rd64(const std::vector<uint8_t>& b, size_t& p) { if (p + 8 > b.size()) throw std::runtime_error("truncated framing"); uint64_t x=0; for(int i=0;i<8;i++) x |= uint64_t(b[p++]) << (8*i); return x; }
static Blob blob(const void* p,size_t n) { Blob b; b.bits=n*8; b.w.assign((n+7)/8,0); std::memcpy(b.w.data(),p,n); return b; }
static void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

static Artifact parse(const std::string& root) {
  Artifact a;
  const auto pb = load(root + "/pk.bin");
  const auto cb = load(root + "/secret.ct");
  static const uint8_t bundle_magic[16] = {'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
  require(cb.size() >= 24, "truncated bundle header");
  require(std::equal(bundle_magic, bundle_magic + 16, cb.begin()), "bad bundle magic");
  a.pk = pvac_ser::deserialize_pubkey(pb.data(), pb.size());
  require(a.pk.prm.B == 337 && a.pk.prm.m_bits == 8192, "unexpected public parameters");
  require(a.pk.H.size() == 16384 && a.pk.powg_B.size() == 337 && a.pk.ubk.perm.size() == 8192, "unexpected public-key vector size");
  for (const auto& h : a.pk.H) require(h.nbits == 8192 && h.w.size() == 128, "invalid H column word length");

  size_t p = 16;
  const uint64_t count = rd64(cb, p);
  require(count >= 1 && count <= 1024, "invalid bundle member count");
  for (uint64_t i = 0; i < count; ++i) {
    const uint64_t bytes = rd64(cb, p);
    require(bytes > 0 && bytes <= cb.size() - p, "invalid member length");
    auto cipher = pvac_ser::deserialize_cipher(cb.data() + p, static_cast<size_t>(bytes));
    p += static_cast<size_t>(bytes);
    require(cipher.slots == 1 && cipher.L.size() == 2, "unexpected cipher slots/layers");
    for (const auto& layer : cipher.L) {
      require(layer.rule == RRule::BASE && layer.PC.size() == 1, "unexpected layer rule/PC cardinality");
      a.nonce.push_back(layer.seed.nonce);
      a.ztag.push_back(layer.seed.ztag);
      const uint64_t expected_ztag = prg_layer_ztag(a.pk.canon_tag, layer.seed.nonce);
      if (expected_ztag == layer.seed.ztag) ++a.ztag_verified; else ++a.ztag_mismatches;
      for (const auto& q : layer.PC) a.pc.push_back(blob(q.data(), q.size()));
    }
    for (const auto& edge : cipher.E) {
      require(edge.layer_id < cipher.L.size() && edge.idx < 337, "edge layer/index out of range");
      require(edge.ch == SGN_P || edge.ch == SGN_M, "invalid edge sign");
      require(!edge.w.empty() && edge.w.size() == cipher.slots, "edge weight slots invalid");
      require(edge.s.nbits == 8192 && edge.s.w.size() == 128, "sigma word size invalid");
      a.sigma.push_back({edge.s.w, static_cast<size_t>(edge.s.nbits)});
      a.weight.push_back(blob(edge.w.data(), edge.w.size() * sizeof(Fp)));
      a.idx.push_back(edge.idx);
      a.sign.push_back(edge.ch);
    }
    a.ciphers.push_back(std::move(cipher));
  }
  require(p == cb.size(), "trailing bundle bytes");
  require(!a.nonce.empty() && a.nonce.size() == a.pc.size(), "nonce/PC vectors invalid");
  require(!a.idx.empty() && a.idx.size() == a.sign.size() && a.idx.size() == a.sigma.size() && a.idx.size() == a.weight.size(), "edge vectors invalid");
  return a;
}
static int hd(const Blob&a,const Blob&b) { if(a.bits!=b.bits)return -1; int d=0; for(size_t i=0;i<a.w.size();i++)d+=__builtin_popcountll(a.w[i]^b.w[i]); return d; }
static Blob nonceblob(Nonce128 n){return {{n.lo,n.hi},128};}
static std::vector<int> nearest(const std::vector<Blob>&a,const std::vector<Blob>&b){std::vector<int> out;for(auto&x:a){int m=INT_MAX;for(auto&y:b){int d=hd(x,y);if(d>=0)m=std::min(m,d);}if(m!=INT_MAX)out.push_back(m);}return out;}
static double correlation(const std::vector<double>&x,const std::vector<double>&y){double ax=std::accumulate(x.begin(),x.end(),0.0)/x.size(),ay=std::accumulate(y.begin(),y.end(),0.0)/y.size(),xy=0,xx=0,yy=0;for(size_t i=0;i<x.size();i++){double a=x[i]-ax,b=y[i]-ay;xy+=a*b;xx+=a*a;yy+=b*b;}return xx&&yy?xy/std::sqrt(xx*yy):0;}
static void summary(const std::vector<int>&v){auto x=v;std::sort(x.begin(),x.end());auto q=[&](double p){return x[(size_t)std::floor(p*(x.size()-1))];};double mean=std::accumulate(x.begin(),x.end(),0.0)/x.size();std::cout<<"{\"min\":"<<x.front()<<",\"q05\":"<<q(.05)<<",\"median\":"<<q(.5)<<",\"q95\":"<<q(.95)<<",\"max\":"<<x.back()<<",\"mean\":"<<mean<<"}";}
static void nn(const char*kind,const char*direction,const std::vector<Blob>&a,const std::vector<Blob>&b,bool& comma){require(!a.empty()&&!b.empty(),"nearest vectors empty");auto d=nearest(a,b);require(d.size()==a.size(),"nearest vector incompatible");if(comma)std::cout<<",";comma=true;std::cout<<"{\"kind\":\""<<kind<<"\",\"direction\":\""<<direction<<"\",\"bits\":"<<a[0].bits<<",\"targets_m\":"<<b.size()<<",\"query_count\":"<<d.size()<<",\"observed_summary\":";summary(d);std::cout<<"}";}
static void artifact_json(const Artifact& a) {
  std::map<int,int> weight_bits, h_weights;
  for (const auto& w : a.weight) ++weight_bits[static_cast<int>(w.bits)];
  for (const auto& h : a.pk.H) {
    int weight = 0; for (uint64_t word : h.w) weight += __builtin_popcountll(word);
    ++h_weights[weight];
  }
  std::set<std::pair<uint64_t,uint64_t>> nonces;
  for (auto nonce : a.nonce) nonces.insert({nonce.lo, nonce.hi});
  std::map<int,int> idx_hist; size_t positives = 0;
  for (size_t i = 0; i < a.idx.size(); ++i) { ++idx_hist[a.idx[i]]; positives += a.sign[i] == SGN_P; }
  const double expected = static_cast<double>(a.idx.size()) / 337.0;
  double chi = 0.0; for (int i = 0; i < 337; ++i) { double delta = idx_hist[i] - expected; chi += delta * delta / expected; }
  const double sign_z = (static_cast<double>(positives) - a.sign.size() / 2.0) / std::sqrt(a.sign.size() / 4.0);
  std::cout << "{\"counts\":{\"base_nonces\":" << a.nonce.size() << ",\"pcs\":" << a.pc.size() << ",\"edges\":" << a.idx.size()
            << ",\"h_columns\":" << a.pk.H.size() << ",\"ubk_permutation\":" << a.pk.ubk.perm.size() << "},\"uniqueness\":{\"nonce_unique\":" << nonces.size()
            << "},\"parameters\":{\"B\":337,\"m_bits\":8192,\"n\":16384},\"edge_statistics\":{\"index_chi_square\":" << chi << ",\"degrees_of_freedom\":336,\"sign_z\":" << sign_z
            << "},\"canonical_tags\":{\"recomputed\":" << a.ztag.size() << ",\"verified\":" << a.ztag_verified << ",\"mismatches\":" << a.ztag_mismatches << "},\"h_weight_histogram\":{";
  bool comma = false; for (auto [key,value] : h_weights) { if (comma) std::cout << ','; comma = true; std::cout << '\"' << key << "\":" << value; }
  std::cout << "},\"edge_weight_bit_lengths\":{"; comma = false; for (auto [key,value] : weight_bits) { if (comma) std::cout << ','; comma = true; std::cout << '\"' << key << "\":" << value; }
  std::cout << "}}";
}
static std::string fpkey(Fp x){std::ostringstream s;s<<std::hex<<std::setw(16)<<std::setfill('0')<<x.hi<<std::setw(16)<<x.lo;return s.str();}
static bool fpzero(Fp x){return !(x.lo|x.hi);}
static Fp fppow(Fp x,unsigned __int128 e){Fp r=fp_from_u64(1);while(e){if(e&1)r=fp_mul(r,x);x=fp_mul(x,x);e>>=1;}return r;}
static void pc_hex_json(const Artifact&a){std::cout<<"[";for(size_t i=0;i<a.pc.size();i++){if(i)std::cout<<",";std::cout<<"\"";for(auto w:a.pc[i].w)std::cout<<std::hex<<std::setw(16)<<std::setfill('0')<<w;std::cout<<std::dec<<"\"";}std::cout<<"]";}
static int basis_map(const Artifact& artifact, const Artifact& reference) {
  for (int d = 1; d < 337; ++d) {
    const Fp value = reference.pk.powg_B[static_cast<size_t>(d)];
    if (value.lo == artifact.pk.omega_B.lo && value.hi == artifact.pk.omega_B.hi) {
      require(std::gcd(d, 337) == 1, "basis map is not invertible");
      return d;
    }
  }
  throw std::runtime_error("omega generator absent from reference basis");
}

static void character_scan_json(const std::vector<Artifact>& as) {
  constexpr int B = 337;
  require(as.size() == 3, "character scan requires three generations");
  const Artifact& reference = as.front();
  std::vector<int> maps;
  for (const auto& artifact : as) maps.push_back(basis_map(artifact, reference));
  std::vector<std::set<std::string>> coords(B);
  std::set<std::string> sums, quotients, ratios, norms;
  size_t ciphers = 0, layers = 0, zeros = 0, coord_coll = 0, sum_coll = 0, q_coll = 0, ratio_coll = 0, norm_coll = 0;
  for (size_t generation = 0; generation < as.size(); ++generation) {
    const auto& artifact = as[generation];
    ciphers += artifact.ciphers.size();
    for (const auto& cipher : artifact.ciphers) {
      std::vector<Fp> s1;
      for (size_t lid = 0; lid < cipher.L.size(); ++lid) {
        ++layers;
        std::vector<Fp> coeff(B, fp_from_u64(0));
        for (const auto& edge : cipher.E) if (edge.layer_id == lid) {
          Fp weight = edge.w[0];
          if (edge.ch != SGN_P) weight = fp_sub(fp_from_u64(0), weight);
          const size_t aligned = (static_cast<size_t>(maps[generation]) * edge.idx) % B;
          coeff[aligned] = fp_add(coeff[aligned], weight);
        }
        std::vector<Fp> spectrum(B, fp_from_u64(0));
        for (int k = 0; k < B; ++k) for (int j = 0; j < B; ++j)
          spectrum[k] = fp_add(spectrum[k], fp_mul(coeff[j], reference.pk.powg_B[(k * j) % B]));
        for (int k = 0; k < B; ++k) { zeros += fpzero(spectrum[k]); coord_coll += !coords[k].insert(fpkey(spectrum[k])).second; }
        sum_coll += !sums.insert(fpkey(spectrum[1])).second;
        q_coll += !quotients.insert(fpkey(fppow(spectrum[1], B))).second;
        if (!fpzero(spectrum[1])) norm_coll += !norms.insert(fpkey(fp_mul(spectrum[0], fp_inv(spectrum[1])))).second;
        s1.push_back(spectrum[1]);
      }
      if (s1.size() == 2 && !fpzero(s1[1])) ratio_coll += !ratios.insert(fpkey(fp_mul(s1[0], fp_inv(s1[1])))).second;
    }
  }
  std::cout << "{\"generations\":" << as.size() << ",\"ciphertexts\":" << ciphers << ",\"layers\":" << layers
            << ",\"character_values\":" << layers * B << ",\"basis_maps\":[";
  for (size_t i = 0; i < maps.size(); ++i) { if (i) std::cout << ','; std::cout << maps[i]; }
  std::cout << "],\"exact_zero\":" << zeros << ",\"same_coordinate_collisions\":" << coord_coll
            << ",\"public_sum_collisions\":" << sum_coll << ",\"quotient_collisions\":" << q_coll
            << ",\"wrapped_ratio_collisions\":" << ratio_coll << ",\"normalized_collisions\":" << norm_coll << "}";
}
static std::string blob_key(const Blob& value) { return std::string(reinterpret_cast<const char*>(value.w.data()), value.w.size() * sizeof(uint64_t)); }
static size_t blob_intersection(const std::vector<Blob>& a, const std::vector<Blob>& b) {
  require(!a.empty() && !b.empty(), "intersection vectors empty");
  std::set<std::string> left; for (const auto& x : a) left.insert(blob_key(x));
  size_t count = 0; for (const auto& x : b) count += left.count(blob_key(x)); return count;
}
static size_t nonce_intersection(const Artifact& a, const Artifact& b, bool include_tag) {
  std::set<std::string> left;
  for (size_t i = 0; i < a.nonce.size(); ++i) left.insert(std::to_string(a.nonce[i].lo) + ":" + std::to_string(a.nonce[i].hi) + (include_tag ? ":" + std::to_string(a.ztag[i]) : ""));
  size_t count = 0;
  for (size_t i = 0; i < b.nonce.size(); ++i) count += left.count(std::to_string(b.nonce[i].lo) + ":" + std::to_string(b.nonce[i].hi) + (include_tag ? ":" + std::to_string(b.ztag[i]) : ""));
  return count;
}
static void pair_json(const Artifact&a,const Artifact&b,size_t ai,size_t bi){
 int lo=0,hi=0,pre=0,suf=0;for(auto x:a.nonce)for(auto y:b.nonce){lo+=x.lo==y.lo;hi+=x.hi==y.hi;pre+=uint32_t(x.hi>>32)==uint32_t(y.hi>>32);suf+=uint32_t(x.lo)==uint32_t(y.lo);}
 std::vector<Blob> an,bn,at,bt;for(size_t i=0;i<a.nonce.size();++i){an.push_back(nonceblob(a.nonce[i]));at.push_back({{a.ztag[i]},64});}for(size_t i=0;i<b.nonce.size();++i){bn.push_back(nonceblob(b.nonce[i]));bt.push_back({{b.ztag[i]},64});}
 size_t n=std::min(a.pk.ubk.perm.size(),b.pk.ubk.perm.size()),pa=0;std::vector<double>px(n),py(n);for(size_t i=0;i<n;i++){pa+=a.pk.ubk.perm[i]==b.pk.ubk.perm[i];px[i]=a.pk.ubk.perm[i];py[i]=b.pk.ubk.perm[i];}
 size_t cols=std::min(a.pk.H.size(),b.pk.H.size()),same=0,exact=0,total=0;uint64_t weight_cross_product_sum=0;std::vector<int> wa,wb;wa.reserve(cols);wb.reserve(cols);std::set<std::string> hs;for(auto&v:a.pk.H)hs.insert(std::string((char*)v.w.data(),v.w.size()*8));size_t overlap=0;for(auto&v:b.pk.H)overlap+=hs.count(std::string((char*)v.w.data(),v.w.size()*8));for(size_t i=0;i<cols;i++){int d=0,xw=0,yw=0;for(size_t j=0;j<a.pk.H[i].w.size();j++){d+=__builtin_popcountll(a.pk.H[i].w[j]^b.pk.H[i].w[j]);xw+=__builtin_popcountll(a.pk.H[i].w[j]);yw+=__builtin_popcountll(b.pk.H[i].w[j]);}wa.push_back(xw);wb.push_back(yw);weight_cross_product_sum+=static_cast<uint64_t>(xw)*static_cast<uint64_t>(yw);same+=a.pk.prm.m_bits-d;total+=a.pk.prm.m_bits;exact+=d==0;}
 std::set<std::pair<uint64_t,uint64_t>> pg;for(auto&v:a.pk.powg_B)pg.insert({v.lo,v.hi});size_t ov=0;for(auto&v:b.pk.powg_B)ov+=pg.count({v.lo,v.hi});int omega=-1;for(size_t k=0;k<b.pk.powg_B.size();k++)if(a.pk.omega_B.lo==b.pk.powg_B[k].lo&&a.pk.omega_B.hi==b.pk.powg_B[k].hi)omega=k;
 size_t en=std::min(a.idx.size(),b.idx.size()),ie=0,se=0;std::vector<double>ix(en),iy(en);for(size_t i=0;i<en;i++){ie+=a.idx[i]==b.idx[i];se+=a.sign[i]==b.sign[i];ix[i]=a.idx[i];iy[i]=b.idx[i];}
 std::cout<<"{\"peg_indices\":["<<ai<<","<<bi<<"],\"exact_intersections\":{\"seed\":"<<nonce_intersection(a,b,true)<<",\"nonce\":"<<nonce_intersection(a,b,false)<<",\"pc\":"<<blob_intersection(a.pc,b.pc)<<",\"sigma\":"<<blob_intersection(a.sigma,b.sigma)<<",\"weight\":"<<blob_intersection(a.weight,b.weight)<<"},\"ztag_mismatches\":"<<(a.ztag_mismatches+b.ztag_mismatches)<<",\"partial_nonce_reuse\":{\"lo64\":"<<lo<<",\"hi64\":"<<hi<<",\"prefix32\":"<<pre<<",\"suffix32\":"<<suf<<",\"comparisons\":"<<a.nonce.size()*b.nonce.size()<<",\"detected\":"<<((lo||hi||pre||suf)?"true":"false")<<"},\"ubk\":{\"positions\":"<<n<<",\"position_agreement\":"<<pa<<",\"expected_agreement\":1.0,\"value_correlation\":"<<correlation(px,py)<<"},\"h_columns\":{\"columns\":"<<cols<<",\"aligned_bit_agreement\":"<<double(same)/total<<",\"aligned_exact_columns\":"<<exact<<",\"set_overlap\":"<<overlap<<",\"realized_weight_cross_product_sum\":"<<weight_cross_product_sum<<"},\"subgroup\":{\"order\":337,\"powg_set_overlap\":"<<ov<<",\"expected_overlap\":337,\"omega_a_index_in_b\":"<<omega<<"},\"edges\":{\"aligned_count\":"<<en<<",\"index_equal\":"<<ie<<",\"index_expected\":"<<double(en)/a.pk.prm.B<<",\"index_correlation\":"<<correlation(ix,iy)<<",\"sign_equal\":"<<se<<",\"sign_expected\":"<<en*.5<<"},\"nearest\":[";bool comma=false;nn("nonce","a_to_b",an,bn,comma);nn("nonce","b_to_a",bn,an,comma);nn("canonical_tag","a_to_b",at,bt,comma);nn("canonical_tag","b_to_a",bt,at,comma);nn("pc","a_to_b",a.pc,b.pc,comma);nn("pc","b_to_a",b.pc,a.pc,comma);nn("sigma","a_to_b",a.sigma,b.sigma,comma);nn("sigma","b_to_a",b.sigma,a.sigma,comma);nn("edge_weight","a_to_b",a.weight,b.weight,comma);nn("edge_weight","b_to_a",b.weight,a.weight,comma);std::cout<<"]}";
}
int main(int ac,char**av){try{if(ac!=4)throw std::runtime_error("expected exactly three extracted peg directories");std::cout<<std::setprecision(15);std::vector<Artifact>a;for(int i=1;i<ac;i++)a.push_back(parse(av[i]));std::cout<<"{\"artifacts\":[";for(size_t i=0;i<a.size();i++){if(i)std::cout<<",";artifact_json(a[i]);}std::cout<<"],\"pc_hex\":[";for(size_t i=0;i<a.size();i++){if(i)std::cout<<",";pc_hex_json(a[i]);}std::cout<<"],\"aligned_character_scan\":";character_scan_json(a);std::cout<<",\"pairs\":[";bool c=false;for(size_t i=0;i<a.size();i++)for(size_t j=i+1;j<a.size();j++){if(c)std::cout<<",";c=true;pair_json(a[i],a[j],i,j);}std::cout<<"]}\n";}catch(const std::exception&e){std::cerr<<"analysis failed: "<<e.what()<<"\n";return 1;}return 0;}
