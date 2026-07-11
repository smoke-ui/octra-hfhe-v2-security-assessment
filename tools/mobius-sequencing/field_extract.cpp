// Fail-closed extractor for the pinned PVAC v3 public artifact. C++17, NDJSON stdout.
#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace pvac;
namespace {
constexpr size_t ORDER=337;
constexpr std::array<uint8_t,16> MAGIC={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
std::vector<uint8_t> read_bounded(const char* p,uint64_t cap){
 std::ifstream f(p,std::ios::binary); if(!f)throw std::runtime_error("input unavailable");
 f.seekg(0,std::ios::end);auto n=f.tellg();if(n<=0||(uint64_t)n>cap)throw std::runtime_error("invalid input size");
 f.seekg(0);std::vector<uint8_t>b((size_t)n);f.read((char*)b.data(),n);if(!f)throw std::runtime_error("input read failed");return b;
}
uint64_t u64(const std::vector<uint8_t>&b,size_t& p){if(p+8>b.size())throw std::runtime_error("truncated bundle");uint64_t x=0;for(int i=0;i<8;i++)x|=(uint64_t)b[p++]<<(8*i);return x;}
std::vector<Cipher> bundle(const std::vector<uint8_t>&b){
 if(b.size()<MAGIC.size()||!std::equal(MAGIC.begin(),MAGIC.end(),b.begin()))throw std::runtime_error("bad bundle magic");
 size_t p=MAGIC.size();auto n=u64(b,p);if(!n||n>1024)throw std::runtime_error("bad cipher count");std::vector<Cipher> out;out.reserve(n);
 for(uint64_t i=0;i<n;i++){auto z=u64(b,p);if(!z||z>b.size()-p)throw std::runtime_error("bad cipher extent");out.push_back(pvac_ser::deserialize_cipher(b.data()+p,z));p+=(size_t)z;}
 if(p!=b.size())throw std::runtime_error("trailing bundle bytes");return out;
}
std::string hex(const Fp&x){std::ostringstream o;o<<std::hex<<std::setfill('0');if(x.hi)o<<x.hi<<std::setw(16)<<x.lo;else o<<x.lo;return o.str();}
void emit_layer(size_t ci,size_t li,size_t slot,const char* rule,const std::array<Fp,ORDER>&v){
 std::cout<<"{\"type\":\"layer\",\"cipher\":"<<ci<<",\"layer\":"<<li<<",\"slot\":"<<slot<<",\"rule\":\""<<rule<<"\",\"spectrum\":[";
 for(size_t k=0;k<ORDER;k++){if(k)std::cout<<',';std::cout<<'"'<<hex(v[k])<<'"';}std::cout<<"]}\n";
}
}
int main(int argc,char**argv){try{
 if(argc!=3)throw std::runtime_error("usage: field_extract pk.bin secret.ct");
 auto pb=read_bounded(argv[1],1ull<<32),cb=read_bounded(argv[2],1ull<<32);
 auto pk=pvac_ser::deserialize_pubkey(pb.data(),pb.size());auto cs=bundle(cb);
 if(pk.prm.B!=(int)ORDER||pk.powg_B.size()!=ORDER)throw std::runtime_error("order is not 337");
 std::cout<<"{\"type\":\"meta\",\"schema\":\"pvac-character-spectrum-v2\",\"order\":337,\"field\":\"2^127-1\",\"c0_convention\":\"added_to_every_character_sum\",\"ciphers\":"<<cs.size()<<"}\n";
 size_t records=0;
 for(size_t ci=0;ci<cs.size();ci++){
  const auto&C=cs[ci];if(!is_cipher_compatible_with_pubkey(pk,C))throw std::runtime_error("incompatible cipher");
  if(!C.slots||C.slots>4096||C.L.empty()||C.L.size()>4096)throw std::runtime_error("unsafe dimensions");
  size_t bases=0;for(auto&L:C.L)if(L.rule==RRule::BASE)bases++;if(bases!=2)throw std::runtime_error("cipher is not wrapped pair");
  for(size_t li=0;li<C.L.size();li++)for(size_t s=0;s<C.slots;s++){
   std::array<Fp,ORDER> v;
   const Fp c0=(li==0&&!C.c0.empty())?C.c0[s]:fp_from_u64(0);
   v.fill(c0);
   for(const auto&e:C.E)if(e.layer_id==li){
    if(e.idx>=ORDER||e.w.size()!=C.slots)throw std::runtime_error("invalid edge spectrum");
    for(size_t k=0;k<ORDER;k++){
     const Fp term=fp_mul(e.w[s],pk.powg_B[(e.idx*k)%ORDER]);
     v[k]=sgn_val(e.ch)>0?fp_add(v[k],term):fp_sub(v[k],term);
    }
   }
   emit_layer(ci,li,s,C.L[li].rule==RRule::BASE?"base":"prod",v);records++;
  }
 }
 std::cout<<"{\"type\":\"end\",\"records\":"<<records<<"}\n";return 0;
}catch(const std::exception&e){std::cerr<<"extractor error: "<<e.what()<<"\n";return 1;}}
