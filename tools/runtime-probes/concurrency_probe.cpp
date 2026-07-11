#include <pvac/pvac.hpp>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace pvac;
static constexpr std::size_t kMaxThreads = 32, kMaxIterations = 100;

static std::size_t arg(std::vector<std::string> const& a, char const* n, std::size_t d, std::size_t max) {
    for (std::size_t i=0; i+1<a.size(); ++i) if (a[i]==n) { auto v=std::stoull(a[i+1]); if (!v||v>max) throw std::runtime_error(std::string(n)+" out of bounds"); return v; }
    return d;
}

template<class F> static void parallel(std::size_t n, F f) {
    std::atomic<std::size_t> ready{0}; std::atomic<bool> go{false}; std::vector<std::thread> ts;
    for (std::size_t i=0;i<n;++i) ts.emplace_back([&,i]{ready.fetch_add(1); while(!go.load(std::memory_order_acquire)) std::this_thread::yield(); f(i);});
    while (ready.load() != n) {
        std::this_thread::yield();
    }
    go.store(true, std::memory_order_release);
    for(auto& t:ts)t.join();
}

int main(int argc,char** argv) try {
    std::vector<std::string> a(argv+1,argv+argc); auto threads=arg(a,"--threads",4,kMaxThreads), iterations=arg(a,"--iterations",3,kMaxIterations);
    std::atomic<std::size_t> failures{0};
    // first_use_toeplitz: intentionally exercise the unsynchronised lazy dispatch.
    g_toep=nullptr; g_toep_id=0;
    std::vector<uint64_t> top(260,0x123456789abcdef0ULL), y(256,0xfedcba9876543210ULL);
    parallel(threads,[&](std::size_t){uint64_t lo=0,hi=0; toep_127(top,y,lo,hi); if(!(lo|hi)) failures.fetch_add(1);});

    // shared_encrypt_decrypt: pk/sk are shared immutable inputs; ciphertexts remain thread-local.
    Params prm; PubKey pk; SecKey sk; keygen(prm,pk,sk);
    parallel(threads,[&](std::size_t tid){
        for(std::size_t i=0;i<iterations;++i){
            uint64_t value=1+tid*iterations+i; Cipher c=enc_value(pk,sk,value); Fp got=dec_value(pk,sk,c);
            if(!ct::fp_eq(got,fp_from_u64(value))) failures.fetch_add(1);
        }
    });
    auto f=failures.load();
    std::cout << "{\"probe\":\"pvac_concurrency\",\"status\":\""<<(f?"fail":"ok")<<"\",\"subprobes\":[\"first_use_toeplitz\",\"shared_encrypt_decrypt\"],\"threads\":"<<threads<<",\"iterations\":"<<iterations<<",\"failures\":"<<f<<"}\n";
    return f?1:0;
} catch(std::exception const& e){std::cerr<<"concurrency_probe: "<<e.what()<<'\n';return 2;}
