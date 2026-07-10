#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include "pvac_artifact_serialize.hpp"
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#include <vector>
using namespace pvac;

static std::vector<uint8_t> readb(const char* p){std::ifstream f(p,std::ios::binary); if(!f)throw std::runtime_error(p); return {std::istreambuf_iterator<char>(f),{}};}
static uint64_t u64(const std::vector<uint8_t>&b,size_t&p){if(p+8>b.size())throw std::runtime_error("truncated");uint64_t x=0;for(int i=0;i<8;i++)x|=uint64_t(b[p++])<<(8*i);return x;}
static std::vector<Cipher> bundle(const std::vector<uint8_t>&b){const char m[16]={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};if(b.size()<24||!std::equal(m,m+16,b.begin()))throw std::runtime_error("magic");size_t p=16,n=u64(b,p);std::vector<Cipher>v;for(size_t i=0;i<n;i++){size_t z=u64(b,p);v.push_back(pvac_ser::deserialize_cipher(b.data()+p,z));p+=z;}if(p!=b.size())throw std::runtime_error("tail");return v;}
static Fp pubnum(const PubKey&pk,const Cipher&c,size_t lid){Fp a=(lid==0&&!c.c0.empty())?c.c0[0]:fp_from_u64(0);for(auto&e:c.E)if(e.layer_id==lid){Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);a=sgn_val(e.ch)>0?fp_add(a,t):fp_sub(a,t);}return a;}
static bool z(Fp x){return x.lo==0&&x.hi==0;}
static bool digest_accepts_any_r(const PubKey&pk,const Layer&L,Fp r){return compute_R_com_base(pk.canon_tag,L.seed.ztag,L.seed.nonce.lo,L.seed.nonce.hi,{r})==L.R_com;}
static std::pair<uint64_t,uint64_t> nk(const Layer&l){return {l.seed.nonce.lo,l.seed.nonce.hi};}
int main(int ac,char**av){if(ac!=3){std::cerr<<"pk secret.ct\n";return 2;}auto pb=readb(av[1]);auto pk=pvac_ser::deserialize_pubkey(pb.data(),pb.size());auto cs=bundle(readb(av[2]));auto&len=cs[0];
 size_t accepts=0,compat=0,pubzero=0;std::set<std::pair<uint64_t,uint64_t>> nonces;size_t layers=0;for(auto&c:cs)for(auto&L:c.L){layers++;nonces.insert(nk(L));}
 for(uint64_t k=301;k<=315;k++){Fp cand=fp_from_u64(k);Fp n=pubnum(pk,len,0);Fp r=fp_mul(n,fp_inv(cand));if(digest_accepts_any_r(pk,len.L[0],r))accepts++;auto t=ct_sub_const(pk,len,k);if(is_cipher_compatible_with_pubkey(pk,t))compat++;if(z(pubnum(pk,t,0)))pubzero++;}
 std::cout<<"real_blocks="<<cs.size()<<" candidate_range=15\n"<<"candidate_commit_accepts="<<accepts<<"/15\n"<<"transformed_compatible="<<compat<<"/15 public_slot0_zero="<<pubzero<<"/15\n"<<"layers="<<layers<<" unique_nonces="<<nonces.size()<<"\n";
 Params p;p.m_bits=256;p.n_bits=512;p.h_col_wt=32;p.x_col_wt=32;p.err_wt=32;p.lpn_n=256;p.lpn_t=512;p.lpn_tau_num=1;p.lpn_tau_den=8;p.B=337;p.noise_entropy_bits=32;PubKey q;SecKey s;keygen(p,q,s);auto g=enc_text(q,s,std::string(307,'A'));auto&gl=g[0];size_t gok=0,gzero=0,gcommit=0;for(uint64_t k=301;k<=315;k++){auto t=ct_sub_const(q,gl,k);Fp d=dec_value(q,s,t);Fp expect=fp_sub(fp_from_u64(307),fp_from_u64(k));if(d.lo==expect.lo&&d.hi==expect.hi)gok++;if(z(pubnum(q,t,0)))gzero++;Fp r=fp_mul(pubnum(q,gl,0),fp_inv(fp_from_u64(k)));if(digest_accepts_any_r(q,gl.L[0],r))gcommit++;}
 std::cout<<"generated_true_len=307 transformed_decrypt_relations="<<gok<<"/15\n"<<"generated_candidate_commit_accepts="<<gcommit<<"/15 public_slot0_zero="<<gzero<<"/15\n";
 auto zz=enc_value(q,s,0);std::cout<<"fresh_enc_zero_public_slot0_zero="<<z(pubnum(q,zz,0))<<" decrypt_zero="<<z(dec_value(q,s,zz))<<"\n";
 return 0;}
