#include "harness.hpp"
#include <iostream>
#include <string>

using namespace structured_fuzz;
struct Result { std::string name, classification; bool parsed=false, canonical=false, compatible=false, decrypt_equal=false, expected=true; };

static Result direct_case(const Fixture& f,std::string name,Bytes b,bool expect_parse,bool expect_canonical,bool expect_compat,bool expect_decrypt){
 Result r{name,"rejected"}; try{auto c=pvac_ser::deserialize_cipher(b.data(),b.size());r.parsed=true;r.classification="accepted";auto s=pvac_ser::serialize_cipher(c);r.canonical=(s==b);r.compatible=pvac::is_cipher_compatible_with_pubkey(f.pk,c);if(r.compatible)r.decrypt_equal=decrypt_same(f,c);}catch(const std::exception&){}
 r.expected=r.parsed==expect_parse&&r.canonical==expect_canonical&&r.compatible==expect_compat&&r.decrypt_equal==expect_decrypt;return r;
}
static Result bundle_case(const Fixture& f,std::string name,Bytes b,bool expect_parse){Result r{name,"rejected"};try{auto d=parse_bundle_one(b);auto c=pvac_ser::deserialize_cipher(d.data(),d.size());r.parsed=true;r.classification="accepted";r.canonical=pvac_ser::serialize_cipher(c)==d;r.compatible=pvac::is_cipher_compatible_with_pubkey(f.pk,c);if(r.compatible)r.decrypt_equal=decrypt_same(f,c);}catch(const std::exception&){}r.expected=r.parsed==expect_parse;return r;}
int main(){
 auto f=make_fixture(); std::vector<Result> rs;
 rs.push_back(direct_case(f,"baseline",f.direct,true,true,true,true));
 auto b=f.direct;b[78]^=0x80;rs.push_back(direct_case(f,"fp_bit127",b,true,false,true,true));
 b=f.direct;b[63]^=1;rs.push_back(direct_case(f,"payload_bit",b,true,true,true,false));
 b=f.direct;b[93]=2;rs.push_back(direct_case(f,"edge_sign",b,false,false,false,false));
 b=f.direct;b[91]=0xff;b[92]=0xff;rs.push_back(direct_case(f,"edge_index",b,true,true,false,false));
 b=f.direct;b[87]=1;rs.push_back(direct_case(f,"edge_layer",b,false,false,false,false));
 b=f.direct;set64(b,14,2);rs.push_back(direct_case(f,"layer_count",b,false,false,false,false));
 b=f.direct;set64(b,55,2);rs.push_back(direct_case(f,"c0_count",b,false,false,false,false));
 b=f.direct;set64(b,79,2);rs.push_back(direct_case(f,"edge_count",b,false,false,false,false));
 b=f.direct;b.push_back(0xa5);rs.push_back(direct_case(f,"direct_object_suffix",b,true,false,true,true));
 b=f.bundle;b.push_back(0xa5);rs.push_back(bundle_case(f,"bundle_suffix",b,false));
 Result sigma{"sigma_tail","not_applicable"}; sigma.expected=true; rs.push_back(sigma);
 bool all=true;for(auto&r:rs)all&=r.expected;
 std::cout<<"{\"fixture\":\"generated-reduced-deterministic\",\"contains_published_secret\":false,\"cases\":[";
 for(size_t i=0;i<rs.size();++i){auto&r=rs[i];if(i)std::cout<<',';std::cout<<"{\"name\":\""<<r.name<<"\",\"classification\":\""<<r.classification<<"\",\"parsed\":"<<(r.parsed?"true":"false")<<",\"canonical_reserialize_equal\":"<<(r.canonical?"true":"false")<<",\"compatible\":"<<(r.compatible?"true":"false")<<",\"decrypt_equal\":"<<(r.decrypt_equal?"true":"false")<<",\"expectation_met\":"<<(r.expected?"true":"false")<<'}';}
 std::cout<<"],\"all_expectations_met\":"<<(all?"true":"false")<<"}\n";return all?0:1;
}
