// Extract raw ETI frames from MPE TS file
#include "../src/sources/mpe_ts_source.hpp"
#include "../src/parsers/udp_extractor.hpp"
#include "../src/edi_parser.hpp"
#include <iostream>
#include <fstream>
#include <arpa/inet.h>

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <file.ts> <mpe_pid> <ip:port> <output.eti>\n";
        return 1;
    }

    uint16_t mpe_pid = static_cast<uint16_t>(std::stoi(argv[2]));
    std::string filter = argv[3];
    size_t colon = filter.find(':');
    struct in_addr addr;
    inet_aton(filter.substr(0, colon).c_str(), &addr);
    uint32_t filter_ip = ntohl(addr.s_addr);
    uint16_t filter_port = static_cast<uint16_t>(std::stoi(filter.substr(colon + 1)));

    std::ifstream infile(argv[1], std::ios::binary);
    if (!infile) { std::cerr << "Cannot open: " << argv[1] << std::endl; return 1; }

    std::ofstream outfile(argv[4], std::ios::binary);
    if (!outfile) { std::cerr << "Cannot create: " << argv[4] << std::endl; return 1; }

    std::cout << "Extracting ETI from " << argv[1] << "\n";
    std::cout << "MPE PID: " << mpe_pid << ", Filter: " << filter << "\n";
    std::cout << "Output: " << argv[4] << "\n";

    size_t eti_frames = 0;

    EdiParser edi_parser([&](const uint8_t* frame, size_t len, uint16_t dflc) {
        if (len == 6144) {
            outfile.write(reinterpret_cast<const char*>(frame), len);
            eti_frames++;
        }
    });

    dvbdab::UdpExtractor udp_extractor([&](uint32_t ip, uint16_t port, const uint8_t* payload, size_t len) {
        edi_parser.feed(payload, len);
    });

    dvbdab::MpeTsSource source(mpe_pid);
    source.setIpFilter(filter_ip, filter_port);
    source.setIpCallback([&](const uint8_t* ip_data, size_t len) {
        udp_extractor.process(ip_data, len);
    });

    std::vector<uint8_t> buffer(65536);
    while (infile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || infile.gcount()) {
        source.feed(buffer.data(), infile.gcount());
    }

    std::cout << "Extracted " << eti_frames << " ETI frames (" << (eti_frames * 6144) << " bytes)\n";
    return 0;
}
