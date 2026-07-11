#include <pvac/core/random.hpp>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

namespace {

constexpr std::array<std::size_t, 7> LENGTHS = {0, 1, 7, 8, 31, 32, 4097};

void exercise_lengths() {
    for (std::size_t length : LENGTHS) {
        std::vector<std::uint8_t> bytes(length, 0);
        pvac::csprng_bytes(bytes.data(), bytes.size());
        for (std::uint8_t byte : bytes) {
            if (byte != UINT8_C(0xa5)) {
                std::abort();
            }
        }
    }
}

}  // namespace

int main() {
    const char* scenario = std::getenv("ENTROPY_FAULT_SCENARIO");
    if (scenario != nullptr && std::string(scenario) == "concurrent") {
        std::vector<std::thread> workers;
        for (int i = 0; i < 8; ++i) {
            workers.emplace_back(exercise_lengths);
        }
        for (auto& worker : workers) {
            worker.join();
        }
    } else {
        exercise_lengths();
    }
    if (std::getenv("DRIVER_REPORT") != nullptr) {
        std::cout << "lengths_tested=" << LENGTHS.size() << '\n';
    }
    return 0;
}
