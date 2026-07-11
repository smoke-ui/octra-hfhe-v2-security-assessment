#include "harness.hpp"

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>

using namespace structured_fuzz;

static void save(const std::filesystem::path& path, uint8_t selector, const Bytes& bytes) {
    std::ofstream output(path, std::ios::binary);
    output.put(char(selector));
    output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    if (!output) throw std::runtime_error("seed write failed");
}

static std::filesystem::path temporary_directory(const std::filesystem::path& parent,
                                                 const char* prefix) {
    std::string pattern = (parent / (std::string(prefix) + "-XXXXXX")).string();
    std::vector<char> writable(pattern.begin(), pattern.end());
    writable.push_back('\0');
    char* created = mkdtemp(writable.data());
    if (created == nullptr) throw std::runtime_error("mkdtemp failed");
    return created;
}

static void publish(const std::filesystem::path& fresh,
                    const std::filesystem::path& corpus) {
    const auto status = std::filesystem::symlink_status(corpus);
    if (status.type() != std::filesystem::file_type::not_found) {
        auto backup = temporary_directory(corpus.parent_path(), ".corpus-old");
        if (rmdir(backup.c_str()) != 0 || std::rename(corpus.c_str(), backup.c_str()) != 0) {
            throw std::runtime_error("cannot quarantine existing corpus");
        }
        if (std::rename(fresh.c_str(), corpus.c_str()) != 0) {
            std::rename(backup.c_str(), corpus.c_str());
            throw std::runtime_error("cannot publish fresh corpus");
        }
        return;
    }
    if (std::rename(fresh.c_str(), corpus.c_str()) != 0) {
        throw std::runtime_error("cannot publish fresh corpus");
    }
}

int main(int argc, char** argv) try {
    if (argc != 1) return 2;
    const auto executable = std::filesystem::canonical(argv[0]);
    const auto build = executable.parent_path();
    const auto corpus = build / "corpus";
    const auto fresh = temporary_directory(build, ".corpus-new");

    auto fixture = make_fixture();
    save(fresh / "direct", 0, fixture.direct);
    save(fresh / "bundle", 1, fixture.bundle);
    auto bytes = fixture.direct;
    bytes[78] ^= 0x80;
    save(fresh / "fp-bit127", 0, bytes);
    bytes = fixture.direct;
    bytes[63] ^= 1;
    save(fresh / "payload-bit", 0, bytes);
    bytes = fixture.direct;
    bytes[93] = 2;
    save(fresh / "edge-sign", 0, bytes);
    bytes = fixture.direct;
    bytes[91] = 0xff;
    bytes[92] = 0xff;
    save(fresh / "edge-index", 0, bytes);
    bytes = fixture.direct;
    set64(bytes, 14, 2);
    save(fresh / "layer-count", 0, bytes);
    bytes = fixture.bundle;
    bytes.push_back(0xa5);
    save(fresh / "bundle-suffix", 1, bytes);

    publish(fresh, corpus);
    std::cout << "generated 8 deterministic reduced seeds\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << "seed_generator: " << error.what() << '\n';
    return 1;
}
