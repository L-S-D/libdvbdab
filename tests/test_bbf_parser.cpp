// Test BBF parser with nrk_gse_capture.ts
// This file contains BBF-in-pseudoTS format: 188-byte TS packets with BBF/GSE

#include "../src/sources/bbf_ts_source.hpp"
#include "../src/parsers/udp_extractor.hpp"
#include <iostream>
#include <fstream>
#include <map>

int main(int argc, char* argv[]) {
    const char* filename = "/usr/src/libdvbdab/nrk_gse_capture.ts";
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

    // Create BBF-TS source
    dvbdab::BbfTsSource source;
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

    // Flush any remaining data
    source.flush();

    // Print summary
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "File: " << filename << std::endl;
    std::cout << "Total bytes: " << total_bytes << std::endl;
    std::cout << "TS packets: " << source.getTsPacketCount() << std::endl;
    std::cout << "Discontinuities: " << source.getDiscontinuityCount() << std::endl;
    std::cout << "BBF frames: " << source.getBbfFrameCount() << std::endl;
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
