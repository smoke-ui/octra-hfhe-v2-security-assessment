#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>
using namespace pvac;
static std::vector<uint8_t> load(const std::string&p){std::ifstream f(p,std::ios::binary);return {std::istreambuf_iterator<char>(f),{}};}
static uint64_t u64(const std::vector<uint8_t>&b,size_t&p){uint64_t x=0;for(int i=0;i<8;i++)x|=(uint64_t)b[p++]<<(8*i);return x;}
static std::string hex64(uint64_t x){std::ostringstream s;s<<std::hex<<std::setw(16)<<std::setfill('0')<<x;return s.str();}
struct A{std::string n;uint64_t tag;std::set<std::string> seeds,nonces,pcs,sigmas,weights;};
static A parse(std::string root){A a;a.n=root;auto pb=load(root+"/pk.bin"),cb=load(root+"/secret.ct");auto pk=pvac_ser::deserialize_pubkey(pb.data(),pb.size());a.tag=pk.canon_tag;size_t p=16,n=u64(cb,p);for(size_t i=0;i<n;i++){size_t z=u64(cb,p);auto c=pvac_ser::deserialize_cipher(cb.data()+p,z);p+=z;for(auto&L:c.L){if(L.rule==RRule::BASE){a.seeds.insert(hex64(L.seed.ztag)+hex64(L.seed.nonce.lo)+hex64(L.seed.nonce.hi));a.nonces.insert(hex64(L.seed.nonce.lo)+hex64(L.seed.nonce.hi));}for(auto&q:L.PC)a.pcs.insert(std::string((char*)q.data(),32));}for(auto&e:c.E){a.sigmas.insert(std::string((char*)e.s.w.data(),e.s.w.size()*8));a.weights.insert(std::string((char*)e.w.data(),e.w.size()*sizeof(Fp)));}}return a;}
template<class S>static size_t inter(const S&a,const S&b){size_t n=0;for(auto&x:a)if(b.count(x))n++;return n;}
int main(int ac,char**av){std::vector<A> v;for(int i=1;i<ac;i++){v.push_back(parse(av[i]));auto&a=v.back();std::cout<<a.n<<" canon_tag=0x"<<hex64(a.tag)<<" seeds="<<a.seeds.size()<<" nonces="<<a.nonces.size()<<" PCs="<<a.pcs.size()<<" sigmas="<<a.sigmas.size()<<" weights="<<a.weights.size()<<"\n";}for(size_t i=0;i<v.size();i++)for(size_t j=i+1;j<v.size();j++)std::cout<<v[i].n<<" vs "<<v[j].n<<" same_tag="<<(v[i].tag==v[j].tag)<<" seed_inter="<<inter(v[i].seeds,v[j].seeds)<<" nonce_inter="<<inter(v[i].nonces,v[j].nonces)<<" PC_inter="<<inter(v[i].pcs,v[j].pcs)<<" sigma_inter="<<inter(v[i].sigmas,v[j].sigmas)<<" weight_inter="<<inter(v[i].weights,v[j].weights)<<"\n";
}
