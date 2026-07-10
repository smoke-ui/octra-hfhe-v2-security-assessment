#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>
using namespace pvac;

static std::vector<uint8_t> load(const std::string& p){std::ifstream f(p,std::ios::binary); if(!f) throw std::runtime_error("open "+p); return {std::istreambuf_iterator<char>(f),{}};}
static uint64_t u64(const std::vector<uint8_t>& b,size_t& p){if(p+8>b.size())throw std::runtime_error("truncated bundle");uint64_t x=0;for(int i=0;i<8;i++)x|=(uint64_t)b[p++]<<(8*i);return x;}
static std::string hx(uint64_t x){std::ostringstream s;s<<std::hex<<std::setw(16)<<std::setfill('0')<<x;return s.str();}
static std::string seedkey(const RSeed&s){return hx(s.ztag)+hx(s.nonce.lo)+hx(s.nonce.hi);}
static std::string byteskey(const uint8_t*p,size_t n){return std::string((const char*)p,n);}
static int parity(const BitVec&v){int p=0;for(auto x:v.w)p^=__builtin_popcountll(x)&1;return p;}
static int top(const BitVec&v){for(int i=(int)v.w.size()-1;i>=0;i--)if(v.w[i])return i*64+63-__builtin_clzll(v.w[i]);return -1;}
static int rank(std::vector<BitVec> cols,size_t bits){std::vector<BitVec> base(bits);std::vector<char> used(bits);int r=0;for(auto&x:cols)for(;;){int p=top(x);if(p<0)break;if(!used[p]){base[p]=std::move(x);used[p]=1;r++;break;}x.xor_with(base[p]);}return r;}
static bool eq(Fp a,Fp b){return a.lo==b.lo&&a.hi==b.hi;}
static Fp powu(Fp a,uint64_t e){Fp r=fp_from_u64(1);while(e){if(e&1)r=fp_mul(r,a);a=fp_mul(a,a);e>>=1;}return r;}

int main(int argc,char**argv){try{
 std::string root=argc>1?argv[1]:".";
 auto pb=load(root+"/pk.bin"), cb=load(root+"/secret.ct");
 auto pk=pvac_ser::deserialize_pubkey(pb.data(),pb.size());
 auto pkraw=pvac::compress::unpack(pb.data(),pb.size());
 auto pkcanon=pvac_ser::serialize_pubkey_raw(pk);
 bool pk_wire_canonical=(pkraw==pkcanon);
 PubKey regen; regen.prm=pk.prm; regen.canon_tag=pk.canon_tag; gen_H(regen);
 bool h_regenerated=(regen.H_digest==pk.H_digest && regen.H.size()==pk.H.size());
 if(h_regenerated) for(size_t i=0;i<pk.H.size();i++) if(regen.H[i].w!=pk.H[i].w) {h_regenerated=false;break;}
 const std::array<uint8_t,16> magic={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
 if(cb.size()<24||!std::equal(magic.begin(),magic.end(),cb.begin()))throw std::runtime_error("bad bundle magic");
 size_t pos=16;uint64_t count=u64(cb,pos);std::vector<Cipher> cts;std::vector<uint64_t> lens;bool ct_wire_canonical=true;
 for(uint64_t i=0;i<count;i++){uint64_t n=u64(cb,pos);if(!n||n>cb.size()-pos)throw std::runtime_error("bad member length");lens.push_back(n);cts.push_back(pvac_ser::deserialize_cipher(cb.data()+pos,n));auto canon=pvac_ser::serialize_cipher(cts.back());if(canon.size()!=n||std::memcmp(canon.data(),cb.data()+pos,n))ct_wire_canonical=false;pos+=n;}if(pos!=cb.size())throw std::runtime_error("trailing bundle bytes");
 std::cout<<"bundle.count="<<count<<" trailing_bytes="<<(cb.size()-pos)<<" ct_wire_canonical="<<ct_wire_canonical<<" pk_wire_canonical="<<pk_wire_canonical<<" H_reproducible_and_digest_ok="<<h_regenerated<<"\n";
 std::cout<<"pk.params B="<<pk.prm.B<<" m="<<pk.prm.m_bits<<" n="<<pk.prm.n_bits<<" hwt="<<pk.prm.h_col_wt<<" xwt="<<pk.prm.x_col_wt<<" errwt="<<pk.prm.err_wt<<" entropy="<<pk.prm.noise_entropy_bits<<"\n";
 std::map<size_t,size_t> hw;size_t he=0,ho=0,hdup=0;std::set<std::string> hseen;bool tailbad=false;
 for(auto&c:pk.H){size_t w=c.popcnt();hw[w]++;(parity(c)?ho:he)++;if(!hseen.insert(byteskey((uint8_t*)c.w.data(),c.w.size()*8)).second)hdup++;if(c.nbits%64 && (c.w.back()>>(c.nbits%64)))tailbad=true;}
 std::cout<<"H.weight_hist=";for(auto [w,n]:hw)std::cout<<w<<":"<<n<<",";std::cout<<" parity_even="<<he<<" parity_odd="<<ho<<" duplicate_columns="<<hdup<<" tail_bits_nonzero="<<tailbad<<"\n";
 int hr=rank(pk.H,pk.prm.m_bits);std::cout<<"H.gf2_rank="<<hr<<" deficiency="<<(pk.prm.m_bits-hr)<<"\n";
 bool permok=true;for(size_t i=0;i<pk.ubk.perm.size();i++){int x=pk.ubk.perm[i];if(x<0||x>=(int)pk.ubk.inv.size()||pk.ubk.inv[x]!=(int)i)permok=false;}
 bool powers=true;for(int i=1;i<pk.prm.B;i++)if(!eq(fp_mul(pk.powg_B[i-1],pk.powg_B[1]),pk.powg_B[i]))powers=false;
 bool order=eq(powu(pk.powg_B[1],pk.prm.B),fp_from_u64(1))&&!eq(pk.powg_B[1],fp_from_u64(1));
 std::cout<<"pk.permutation_inverse_ok="<<permok<<" pow_table_geometric="<<powers<<" generator_order_divides_B_nontrivial="<<order<<"\n";
 std::set<std::string> seeds,nonces,pcs,sigmas,weights;size_t seeddup=0,noncedup=0,ztagbad=0,pcdup=0,sigdup=0,wdup=0,totalL=0,totalE=0,baseL=0,prodL=0,emptyPC=0,zeroW=0,zeroS=0,idxbad=0,s_tailbad=0;
 std::map<size_t,size_t> edgehist,sighist;std::set<std::string> publicsum;
 for(size_t ci=0;ci<cts.size();ci++){auto&c=cts[ci];totalL+=c.L.size();totalE+=c.E.size();edgehist[c.E.size()]++;
  std::cout<<"ct["<<ci<<"].bytes="<<lens[ci]<<" slots="<<c.slots<<" layers="<<c.L.size()<<" edges="<<c.E.size()<<" c0="<<c.c0.size()<<"\n";
  for(auto&L:c.L){if(L.rule==RRule::BASE){baseL++;auto sk=seedkey(L.seed);if(!seeds.insert(sk).second)seeddup++;auto nk=hx(L.seed.nonce.lo)+hx(L.seed.nonce.hi);if(!nonces.insert(nk).second)noncedup++;if(L.seed.ztag!=prg_layer_ztag(pk.canon_tag,L.seed.nonce))ztagbad++;}else prodL++;if(L.PC.empty())emptyPC++;for(auto&p:L.PC)if(!pcs.insert(byteskey(p.data(),32)).second)pcdup++;}
  std::vector<Fp> sums(c.L.size(),fp_from_u64(0));if(!c.c0.empty())sums[0]=c.c0[0];
  for(auto&e:c.E){if(e.idx>=pk.powg_B.size())idxbad++;bool wz=true;for(auto x:e.w)if(x.lo||x.hi)wz=false;if(wz)zeroW++;if(e.s.popcnt()==0)zeroS++;sighist[e.s.popcnt()]++;if(e.s.nbits%64&&(e.s.w.back()>>(e.s.nbits%64)))s_tailbad++;auto ss=byteskey((uint8_t*)e.s.w.data(),e.s.w.size()*8);if(!sigmas.insert(ss).second)sigdup++;auto ws=byteskey((uint8_t*)e.w.data(),e.w.size()*sizeof(Fp));if(!weights.insert(ws).second)wdup++;Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);sums[e.layer_id]=(e.ch==SGN_P)?fp_add(sums[e.layer_id],t):fp_sub(sums[e.layer_id],t);}
  for(auto x:sums)publicsum.insert(hx(x.lo)+hx(x.hi));
 }
 std::cout<<"layers.total="<<totalL<<" base="<<baseL<<" prod="<<prodL<<" empty_PC="<<emptyPC<<" repeated_seed="<<seeddup<<" repeated_nonce="<<noncedup<<" ztag_mismatch="<<ztagbad<<" repeated_PC="<<pcdup<<"\n";
 std::cout<<"edges.total="<<totalE<<" idx_oob="<<idxbad<<" zero_weight_vectors="<<zeroW<<" zero_sigma="<<zeroS<<" repeated_weight_vectors="<<wdup<<" repeated_sigma_vectors="<<sigdup<<" sigma_tail_bits_nonzero="<<s_tailbad<<"\n";
 std::cout<<"sigma.popcount_range="<<sighist.begin()->first<<".."<<sighist.rbegin()->first<<" distinct_popcounts="<<sighist.size()<<" public_layer_sums_distinct="<<publicsum.size()<<"/"<<totalL<<"\n";
 return 0;}catch(const std::exception&e){std::cerr<<"error="<<e.what()<<"\n";return 1;}}
