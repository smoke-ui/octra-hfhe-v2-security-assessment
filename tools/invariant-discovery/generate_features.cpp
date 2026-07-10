#include <pvac/pvac.hpp>
#include <iostream>
#include <fstream>
#include <numeric>
#include <string>
using namespace pvac;

static Fp layer_num(const PubKey& pk,const Cipher& c,size_t lid){
 Fp a=(lid==0&&!c.c0.empty())?c.c0[0]:fp_from_u64(0);
 for(const auto&e:c.E) if(e.layer_id==lid){Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);a=sgn_val(e.ch)>0?fp_add(a,t):fp_sub(a,t);} return a;
}
static uint64_t parity(const BitVec&b){uint64_t x=0;for(auto w:b.w)x^=__builtin_parityll(w);return x;}
static void emit(std::ostream&o,const PubKey&pk,const Cipher&c,uint64_t y,uint64_t keyid,uint64_t id){
 Fp n0=layer_num(pk,c,0),n1=layer_num(pk,c,1); uint64_t wp0=0,wp1=0,sp0=0,sp1=0,idx0=0,idx1=0;
 for(const auto&e:c.E){uint64_t *wp=e.layer_id?&wp1:&wp0,*sp=e.layer_id?&sp1:&sp0,*ix=e.layer_id?&idx1:&idx0;*wp^=e.w[0].lo;*sp^=parity(e.s);*ix+=e.idx;}
 o<<id<<','<<keyid<<','<<y<<','<<c.L.size()<<','<<c.E.size()<<','<<n0.lo<<','<<n0.hi<<','<<n1.lo<<','<<n1.hi<<','<<wp0<<','<<wp1<<','<<sp0<<','<<sp1<<','<<idx0<<','<<idx1<<','<<c.L[0].seed.nonce.lo<<','<<c.L[1].seed.nonce.lo<<'\n';
}
int main(int ac,char**av){
 if(ac<4){std::cerr<<"usage: generate_features OUT.csv SAMPLES reduced|production [KEYS]\n";return 2;} size_t N=std::stoull(av[2]),K=ac>4?std::stoull(av[4]):4; bool prod=std::string(av[3])=="production";
 std::ofstream o(av[1]);o<<"id,key_id,y,layers,edges,n0_lo,n0_hi,n1_lo,n1_hi,wxor0,wxor1,spar0,spar1,idxsum0,idxsum1,nonce0,nonce1\n";
 for(size_t k=0,id=0;k<K;k++){Params p;if(!prod){p.m_bits=256;p.n_bits=512;p.h_col_wt=32;p.x_col_wt=32;p.err_wt=32;p.lpn_n=64;p.lpn_t=256;p.noise_entropy_bits=64;} PubKey pk;SecKey sk;keygen(p,pk,sk);for(size_t i=0;i<N/K;i++,id++){uint64_t y=(i*13+k*7)%16;Cipher c=enc_value(pk,sk,y);if(dec_value(pk,sk,c).lo!=y)return 3;emit(o,pk,c,y,k,id);}}
}
