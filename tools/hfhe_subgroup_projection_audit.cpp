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
#include <vector>
using namespace pvac;
static std::vector<uint8_t> load(const std::string&p){std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("open "+p);return {std::istreambuf_iterator<char>(f),{}};}
static uint64_t rd64(const std::vector<uint8_t>&b,size_t&p){uint64_t x=0;if(p+8>b.size())throw std::runtime_error("truncated");for(int i=0;i<8;i++)x|=(uint64_t)b[p++]<<(8*i);return x;}
static std::string key(Fp x){std::ostringstream s;s<<std::hex<<std::setw(16)<<std::setfill('0')<<x.hi<<std::setw(16)<<x.lo;return s.str();}
static bool zero(Fp x){return !(x.lo|x.hi);} static bool eq(Fp a,Fp b){return a.lo==b.lo&&a.hi==b.hi;}
static Fp pw(Fp a,unsigned __int128 e){Fp r=fp_from_u64(1);while(e){if(e&1)r=fp_mul(r,a);a=fp_mul(a,a);e>>=1;}return r;}
int main(int argc,char**argv){try{std::string root=argc>1?argv[1]:".";auto pb=load(root+"/pk.bin"),cb=load(root+"/secret.ct");auto pk=pvac_ser::deserialize_pubkey(pb.data(),pb.size());size_t pos=16;uint64_t n=rd64(cb,pos);std::vector<Cipher> cs;for(uint64_t i=0;i<n;i++){auto z=rd64(cb,pos);cs.push_back(pvac_ser::deserialize_cipher(cb.data()+pos,z));pos+=z;}
std::vector<std::vector<Fp>> spectra;std::vector<Fp> base,cosets,pairrat;size_t spectral_zero=0,coset_coll=0,ratio_coll=0;std::set<std::string> cosseen,ratseen,normseen;unsigned __int128 E=337;
for(auto&C:cs){std::vector<std::vector<Fp>> a(C.L.size(),std::vector<Fp>(337,fp_from_u64(0)));for(auto&e:C.E){Fp w=e.w[0];if(e.ch!=SGN_P)w=fp_sub(fp_from_u64(0),w);a[e.layer_id][e.idx]=fp_add(a[e.layer_id][e.idx],w);}std::vector<Fp> vals(C.L.size());for(size_t l=0;l<a.size();l++){std::vector<Fp> sp(337,fp_from_u64(0));for(int k=0;k<337;k++)for(int j=0;j<337;j++)sp[k]=fp_add(sp[k],fp_mul(a[l][j],pk.powg_B[(k*j)%337]));for(auto x:sp)if(zero(x))spectral_zero++;vals[l]=sp[1];Fp q=pw(vals[l],E);if(!cosseen.insert(key(q)).second)coset_coll++;cosets.push_back(q);if(!zero(vals[l])){Fp norm=fp_mul(sp[0],fp_inv(vals[l]));normseen.insert(key(norm));}spectra.push_back(std::move(sp));}
if(vals.size()==2&&!zero(vals[1])){Fp r=fp_mul(vals[0],fp_inv(vals[1]));pairrat.push_back(r);if(!ratseen.insert(key(r)).second)ratio_coll++;}}
size_t coord_coll=0;for(int k=0;k<337;k++){std::set<std::string>s;for(auto&v:spectra)if(!s.insert(key(v[k])).second)coord_coll++;}
std::cout<<"ciphertexts="<<cs.size()<<" layers="<<spectra.size()<<" B="<<pk.prm.B<<"\n";
std::cout<<"dft_values="<<spectra.size()*337<<" exact_zero="<<spectral_zero<<" same_character_coordinate_collisions="<<coord_coll<<"\n";
std::cout<<"coset_projection=x^337 unique="<<cosseen.size()<<" collisions="<<coset_coll<<"\n";
std::cout<<"wrapped_pair_ratios unique="<<ratseen.size()<<" collisions="<<ratio_coll<<" normalized_S0_over_S1_unique="<<normseen.size()<<"\n";
std::cout<<"interpretation=no exact cancellations or repeated quotient/ratio signatures observed\n";
}catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}}
