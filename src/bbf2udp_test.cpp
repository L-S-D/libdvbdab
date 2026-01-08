#include "bbf2udp.hpp"
#include "udp2edi.hpp"
#include <iostream>
#include <iomanip>
#include <map>
#include <fstream>

int main(int argc, char* argv[]) {
    std::map<std::pair<std::uint32_t, std::uint16_t>, std::size_t> udp_counts;
    std::map<std::pair<std::uint32_t, std::uint16_t>, std::size_t> eti_counts;
    std::size_t total_udp = 0;
    std::size_t total_eti = 0;

    // Optional: output ETI to files per stream
    std::map<std::pair<std::uint32_t, std::uint16_t>, std::unique_ptr<std::ofstream>> eti_files;
    bool write_files = (argc > 1 && std::string(argv[1]) == "-o");

    // Create UDP->EDI handler that produces ETI frames
    Udp2Edi udp_handler([&](std::uint32_t ip, std::uint16_t port,
                            const std::uint8_t* data, std::size_t len,
                            std::uint16_t /*dflc*/) {
        auto key = std::make_pair(ip, port);
        eti_counts[key]++;
        total_eti++;

        // Write ETI to file if requested
        if (write_files) {
            auto it = eti_files.find(key);
            if (it == eti_files.end()) {
                std::string filename = "eti_" + Udp2Edi::ipToString(ip) + "_" +
                                       std::to_string(port) + ".eti";
                auto file = std::make_unique<std::ofstream>(filename, std::ios::binary);
                it = eti_files.emplace(key, std::move(file)).first;
                std::cerr << "Writing to " << filename << "\n";
            }
            it->second->write(reinterpret_cast<const char*>(data), len);
        }
    });

    // Create BBF parser that extracts UDP and feeds to EDI parser
    Bbf2Udp bbf_parser([&](std::uint32_t ip, std::uint16_t port,
                           const std::uint8_t* data, std::size_t len) {
        auto key = std::make_pair(ip, port);
        udp_counts[key]++;
        total_udp++;

        udp_handler.feed(ip, port, data, len);
    });

    // Read from stdin (piped from pts2bbf)
    std::array<std::uint8_t, 65536> buffer;

    while (std::cin.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) ||
           std::cin.gcount() > 0) {
        bbf_parser.feed(buffer.data(), static_cast<std::size_t>(std::cin.gcount()));
    }

    // Print results
    std::cerr << "\n=== Stream Summary ===\n";
    std::cerr << "Total UDP packets: " << total_udp << "\n";
    std::cerr << "Total ETI frames:  " << total_eti << "\n\n";

    for (const auto& [key, count] : udp_counts) {
        std::cerr << "  " << Udp2Edi::ipToString(key.first)
                  << ":" << key.second
                  << " -> " << count << " UDP packets, "
                  << eti_counts[key] << " ETI frames\n";
    }

    return 0;
}
