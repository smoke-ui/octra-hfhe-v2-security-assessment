#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include "pvac_artifact_serialize.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>
using namespace pvac;

static uint64_t mix(uint64_t x){x+=0x9e3779b97f4a7c15ULL;x=(x^(x>>30))*0xbf58476d1ce4e5b9ULL;x=(x^(x>>27))*0x94d049bb133111ebULL;return x^(x>>31);}
static double rsign(uint64_t seed,uint64_t x){return (mix(seed^x)&1)?1.0:-1.0;}
static std::vector<uint8_t> rf(const std::string&p){std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("open "+p);return {(std::istreambuf_iterator<char>(f)),{}};}
static uint64_t take(const std::vector<uint8_t>&b,size_t&p){if(p+8>b.size())throw std::runtime_error("truncated");uint64_t x=0;for(int i=0;i<8;i++)x|=(uint64_t)b[p++]<<(8*i);return x;}
static std::vector<Cipher> bundle(const std::string&p){auto b=rf(p);const std::string m="OCTRA-HFHE-BTY02";if(b.size()<24||!std::equal(m.begin(),m.end(),b.begin()))throw std::runtime_error("magic");size_t q=16,n=take(b,q);std::vector<Cipher>v;for(size_t i=0;i<n;i++){size_t z=take(b,q);v.push_back(pvac_ser::deserialize_cipher(b.data()+q,z));q+=z;}return v;}
static int bit(const BitVec&s,size_t i){return (s.w[i>>6]>>(i&63))&1;}

// A genuine 4-way sketch: layer x subgroup-index/sign Fourier mode x field-weight
// projection x sigma/H geometry projection. No component is reported as a marginal.
static std::vector<double> sketch(const PubKey&pk,const Cipher&c){
 const int A=2,I=10,W=10,G=10; std::vector<double>t(A*I*W*G,0.0); std::array<int,2>cnt{};
 for(const auto&e:c.E){int a=(int)e.layer_id;if(a<0||a>=A||e.w.empty())continue;cnt[a]++;double theta=2*M_PI*(double)e.idx/pk.prm.B;double ix[I];
  for(int i=0;i<I;i++){int k=i/2+1;ix[i]=(i&1)?sin(k*theta):cos(k*theta);if(e.ch==SGN_M)ix[i]=-ix[i];}
  double wx[W];uint64_t lo=e.w[0].lo,hi=e.w[0].hi;for(int w=0;w<W;w++){uint64_t h=mix(lo^mix(hi+w*0x123456789ULL));wx[w]=((int)(h&0xffff)-32767.5)/32767.5;}
  double gx[G];for(int g=0;g<G;g++){double z=0;for(int q=0;q<64;q++){size_t pos=mix(0x5349474d41000000ULL+g*131+q)%pk.prm.m_bits;int sb=bit(e.s,pos);int hb=bit(pk.H[(e.idx+g)%pk.H.size()],pos);z+=rsign(0x4847454f4dULL+g,pos)*(sb?1:-1)*(hb?1:-1);}gx[g]=z/8.0;}
  for(int i=0;i<I;i++)for(int w=0;w<W;w++)for(int g=0;g<G;g++)t[((a*I+i)*W+w)*G+g]+=ix[i]*wx[w]*gx[g];
 }
 for(int a=0;a<A;a++){
  if(cnt[a])for(int j=0;j<I*W*G;j++)t[a*I*W*G+j]/=sqrt((double)cnt[a]);
 }
 return t;
}
static void row(std::ofstream&o,const std::string&src,int sample,int block,int label,const std::vector<double>&x){o<<src<<','<<sample<<','<<block<<','<<label;for(double v:x)o<<','<<v;o<<'\n';}
int main(int ac,char**av){try{if(ac!=4){std::cerr<<"usage: extractor pk.bin secret.ct out.csv\n";return 2;}auto pb=rf(av[1]);auto pk=pvac_ser::deserialize_pubkey(pb.data(),pb.size());std::ofstream o(av[3]);o<<"source,sample,block,label";for(int i=0;i<2000;i++)o<<",x"<<i;o<<'\n';auto real=bundle(av[2]);for(size_t i=0;i<real.size();i++)row(o,"artifact",i,i,-1,sketch(pk,real[i]));
 // Known-plaintext controls use production defaults and a fresh key. Labels are 16
 // byte classes; each payload is exactly one 15-byte block. The length ciphertext
 // is retained as block 0 to detect accidental metadata classification.
 Params p;p.noise_entropy_bits=128.0;PubKey cp;SecKey sk;keygen(p,cp,sk);std::mt19937_64 rg(0x54454e534f523444ULL);int sid=0;
 for(int rep=0;rep<12;rep++)for(int y=0;y<16;y++){std::string s(15,(char)y);for(int j=1;j<15;j++)s[j]=(char)(rg()&255);auto cs=enc_text(cp,sk,s);for(size_t b=0;b<cs.size();b++)row(o,"control",sid,b,y,sketch(cp,cs[b]));sid++;}
 std::cerr<<"artifact="<<real.size()<<" controls="<<sid<<" dims=2000\n";return 0;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
