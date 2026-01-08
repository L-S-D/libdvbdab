// Test GSE parser with live_gse_capture.bin
// This file contains GSE-in-TS format: 188-byte TS packets with GSE at byte 4

#include "../src/sources/gse_ts_source.hpp"
#include "../src/parsers/udp_extractor.hpp"
#include <iostream>
#include <fstream>
#include <map>
#include <set>

int main(int argc, char* argv[]) {
    const char* filename = "/usr/src/libdvbdab/live_gse_capture.bin";
    if (argc > 1) {
        filename = argv[1];
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open: " << filename << std::endl;
        return 1;
    }

    // Track unique streams by IP:port
    std::map<dvbdab::StreamKey, size_t> streams;
    size_t total_udp = 0;
    size_t total_ip = 0;

    // Create UDP extractor
    dvbdab::UdpExtractor udp_extractor([&](uint32_t ip, uint16_t port,
                                            const uint8_t* payload, size_t len) {
        total_udp++;
        dvbdab::StreamKey key{ip, port};
        streams[key]++;

        // Print first few UDP packets for verification
        if (total_udp <= 5) {
            std::cout << "UDP #" << total_udp << ": "
                      << dvbdab::ipToString(ip) << ":" << port
                      << " len=" << len << std::endl;

            // Check if this looks like EDI (PF or AF)
            if (len >= 2) {
                if (payload[0] == 'P' && payload[1] == 'F') {
                    std::cout << "  -> PF packet" << std::endl;
                } else if (payload[0] == 'A' && payload[1] == 'F') {
                    std::cout << "  -> AF packet" << std::endl;
                }
            }
        }
    });

    // Create GSE-TS source
    dvbdab::GseTsSource source;
    source.setIpCallback([&](const uint8_t* ip_data, size_t len) {
        total_ip++;
        udp_extractor.process(ip_data, len);
    });

    // Read and process file
    std::vector<uint8_t> buffer(65536);
    size_t total_bytes = 0;

    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount()) {
        size_t bytes_read = file.gcount();
        total_bytes += bytes_read;
        source.feed(buffer.data(), bytes_read);
    }

    // Print summary
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "File: " << filename << std::endl;
    std::cout << "Total bytes: " << total_bytes << std::endl;
    std::cout << "TS packets: " << source.getTsPacketCount() << std::endl;
    std::cout << "Discontinuities: " << source.getDiscontinuityCount() << std::endl;
    std::cout << "GSE packets: " << source.getGsePacketCount() << std::endl;
    std::cout << "IPv4 packets: " << total_ip << std::endl;
    std::cout << "UDP packets: " << total_udp << std::endl;
    std::cout << "Unique streams: " << streams.size() << std::endl;

    std::cout << "\n=== Streams ===" << std::endl;
    for (const auto& [key, count] : streams) {
        std::cout << "  " << dvbdab::ipToString(key.ip) << ":" << key.port
                  << " - " << count << " packets" << std::endl;
    }

    return streams.empty() ? 1 : 0;
}
