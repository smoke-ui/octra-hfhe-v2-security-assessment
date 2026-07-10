#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <fstream>
#include <iostream>
#include <set>
#include <vector>
#include <cmath>
using namespace pvac;

static uint64_t u64(const std::vector<uint8_t>& b,size_t& p){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)b.at(p++)<<(8*i);return v;}
static std::vector<Cipher> bundle(const char* path){std::ifstream f(path,std::ios::binary);std::vector<uint8_t>b((std::istreambuf_iterator<char>(f)),{});size_t p=16,n=u64(b,p);std::vector<Cipher> o;for(size_t i=0;i<n;i++){size_t z=u64(b,p);o.push_back(pvac_ser::deserialize_cipher(b.data()+p,z));p+=z;}if(p!=b.size())throw std::runtime_error("trailing bytes");return o;}
static unsigned pc128(uint64_t x){return __builtin_popcountll(x);}
int main(int argc, char** argv){
 if(argc != 2){std::cerr<<"usage: prf_r_audit CHALLENGE_DIR\n";return 2;}
 std::string path=std::string(argv[1])+"/secret.ct";
 auto c=bundle(path.c_str()); size_t L=0,E=0,B=0,P=0; std::set<std::pair<uint64_t,uint64_t>> nonces; bool dup=false;
 for(auto&x:c){L+=x.L.size();E+=x.E.size();for(auto&l:x.L)if(l.rule==RRule::BASE){B++;P+=l.PC.size();auto q=std::make_pair(l.seed.nonce.lo,l.seed.nonce.hi);if(!nonces.insert(q).second)dup=true;}}
 std::cout<<"artifact ciphers="<<c.size()<<" layers="<<L<<" base="<<B<<" edges="<<E<<" PCs="<<P<<" duplicate_base_nonce="<<dup<<"\n";
 Params p;p.m_bits=256;p.n_bits=512;p.h_col_wt=32;p.x_col_wt=16;p.err_wt=16;p.lpn_n=64;p.lpn_t=256;PubKey pk;SecKey sk;keygen(p,pk,sk);SecKey sk2=sk;sk2.lpn_s_bits[0]^=1;
 const int N=4096; long ones=0,total=(long)N*127,hd=0; long eqadj=0,adjtot=0; Fp prev{};
 for(int i=0;i<N;i++){RSeed s; s.nonce={(uint64_t)i,0x123456789abcdef0ULL^(uint64_t)i};s.ztag=prg_layer_ztag(pk.canon_tag,s.nonce);Fp a=prf_R(pk,sk,s),b=prf_R(pk,sk2,s);ones+=pc128(a.lo)+pc128(a.hi&((1ULL<<63)-1));hd+=pc128(a.lo^b.lo)+pc128((a.hi^b.hi)&((1ULL<<63)-1));if(i){eqadj+=127-(pc128(a.lo^prev.lo)+pc128((a.hi^prev.hi)&((1ULL<<63)-1)));adjtot+=127;}prev=a;}
 double ph=(double)ones/total, pav=(double)hd/total, padj=(double)eqadj/adjtot;
 std::cout<<"reduced N="<<N<<" output_one_rate="<<ph<<" secret_flip_rate="<<pav<<" adjacent_equal_rate="<<padj<<"\n";
 double se=std::sqrt(.25/total);std::cout<<"z_one="<<(ph-.5)/se<<" z_secret_flip="<<(pav-.5)/se<<" z_adjacent="<<(padj-.5)/std::sqrt(.25/adjtot)<<"\n";
}
