#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace pvac;

// Small self-contained SHA-256: hashes only canonical serializer output, never raw objects.
namespace sha256 {
constexpr uint32_t K[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
uint32_t r(uint32_t x,int n){return(x>>n)|(x<<(32-n));}
std::string hash(const std::vector<uint8_t>& in){
 std::vector<uint8_t> m=in; uint64_t bits=uint64_t(m.size())*8; m.push_back(0x80); while(m.size()%64!=56)m.push_back(0); for(int i=7;i>=0;--i)m.push_back(uint8_t(bits>>(8*i)));
 uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 for(size_t p=0;p<m.size();p+=64){uint32_t w[64];for(int i=0;i<16;i++)w[i]=(uint32_t(m[p+4*i])<<24)|(uint32_t(m[p+4*i+1])<<16)|(uint32_t(m[p+4*i+2])<<8)|m[p+4*i+3];for(int i=16;i<64;i++){uint32_t a=r(w[i-15],7)^r(w[i-15],18)^(w[i-15]>>3),b=r(w[i-2],17)^r(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+a+w[i-7]+b;}uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],z=h[7];for(int i=0;i<64;i++){uint32_t s1=r(e,6)^r(e,11)^r(e,25),ch=(e&f)^(~e&g),t1=z+s1+ch+K[i]+w[i],s0=r(a,2)^r(a,13)^r(a,22),maj=(a&b)^(a&c)^(b&c),t2=s0+maj;z=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z;}
 std::ostringstream o;o<<std::hex<<std::setfill('0');for(auto x:h)o<<std::setw(8)<<x;return o.str();}
}

std::array<uint8_t,32> seed(uint8_t domain){std::array<uint8_t,32>s{};for(size_t i=0;i<s.size();++i)s[i]=uint8_t(domain+i*17);return s;}
std::string fact(const PubKey& pk,const SecKey& sk,const Cipher& c){auto d=dec_values(pk,sk,c);std::ostringstream o;o<<"{\"slots\":"<<c.slots<<",\"layers\":"<<c.L.size()<<",\"edges\":"<<c.E.size()<<",\"compatible\":"<<(is_cipher_compatible_with_pubkey(pk,c)?"true":"false")<<",\"dec\":[";for(size_t i=0;i<d.size();++i){if(i)o<<',';o<<"["<<d[i].lo<<","<<d[i].hi<<"]";}return o<<"]}",o.str();}
int main(){
 Params prm; PubKey pk; SecKey sk; auto ks=seed(1); keygen_from_seed(prm,pk,sk,ks.data());
 auto s1=seed(2),s2=seed(3),s3=seed(4),sm=seed(5);
 auto a=enc_value_seeded(pk,sk,7,s1.data());
 auto b=enc_value_depth_seeded(pk,sk,5,1,s2.data());
 auto v=enc_values_seeded(pk,sk,std::vector<uint64_t>{2,3,11},s3.data());
 auto add=ct_add(pk,a,b), sub=ct_sub(pk,a,b), mul=ct_mul_seeded(pk,a,b,sm.data());
 auto pkb=pvac_ser::serialize_pubkey(pk,true); std::vector<Cipher> cs={a,b,v,add,sub,mul};
 std::cout<<"{\"schema\":1,\"pubkey\":{\"bytes\":"<<pkb.size()<<",\"sha256\":\""<<sha256::hash(pkb)<<"\"},\"ciphertexts\":[";
 for(size_t i=0;i<cs.size();++i){if(i)std::cout<<',';auto blob=pvac_ser::serialize_cipher(cs[i]);std::cout<<"{\"bytes\":"<<blob.size()<<",\"sha256\":\""<<sha256::hash(blob)<<"\",\"fact\":"<<fact(pk,sk,cs[i])<<"}";}
 std::cout<<"]}\n";
}
