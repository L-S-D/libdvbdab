// Test library's MpeTsSource produces same results as standalone
#include "../src/sources/mpe_ts_source.hpp"
#include "../src/parsers/udp_extractor.hpp"
#include <iostream>
#include <fstream>
#include <map>
#include <arpa/inet.h>

// PF reassembler - exact copy from standalone
class PfReassembler {
public:
    struct Collector {
        uint16_t pseq;
        uint32_t fcount;
        std::map<uint32_t, std::vector<uint8_t>> fragments;
    };
    std::map<uint16_t, Collector> collectors;
    std::vector<std::vector<uint8_t>> af_packets;

    void feed(const uint8_t* pf, size_t len) {
        if (len < 14 || pf[0] != 'P' || pf[1] != 'F') return;
        uint16_t pseq = (pf[2] << 8) | pf[3];
        uint32_t findex = (pf[4] << 16) | (pf[5] << 8) | pf[6];
        uint32_t fcount = (pf[7] << 16) | (pf[8] << 8) | pf[9];
        uint8_t fec_flag = (pf[10] >> 7) & 1;
        uint8_t addr_flag = (pf[10] >> 6) & 1;
        uint16_t plen = ((pf[10] & 0x3F) << 8) | pf[11];
        size_t hdr_size = 14 + (fec_flag ? 2 : 0) + (addr_flag ? 4 : 0);
        if (fcount == 0 || fcount > 256 || findex >= fcount || len < hdr_size + plen) return;
        auto& c = collectors[pseq];
        if (c.pseq != pseq || c.fcount != fcount) { c.pseq = pseq; c.fcount = fcount; c.fragments.clear(); }
        if (c.fragments.find(findex) == c.fragments.end()) {
            c.fragments[findex] = std::vector<uint8_t>(pf + hdr_size, pf + hdr_size + plen);
        }
        if (c.fragments.size() == c.fcount) {
            std::vector<uint8_t> af;
            for (uint32_t i = 0; i < c.fcount; i++) {
                auto it = c.fragments.find(i);
                if (it != c.fragments.end()) af.insert(af.end(), it->second.begin(), it->second.end());
            }
            af_packets.push_back(af);
            collectors.erase(pseq);
        }
    }
};

int extractFct(const std::vector<uint8_t>& af) {
    if (af.size() < 10 || af[0] != 'A' || af[1] != 'F') return -1;
    size_t pos = 10;
    while (pos + 8 <= af.size()) {
        uint32_t tag_len_bits = (af[pos+4] << 24) | (af[pos+5] << 16) | (af[pos+6] << 8) | af[pos+7];
        uint32_t tag_len = (tag_len_bits + 7) / 8;
        if (af[pos] == 'd' && af[pos+1] == 'e' && af[pos+2] == 't' && af[pos+3] == 'i') {
            if (pos + 8 + 2 <= af.size()) return af[pos + 8 + 1];
        }
        pos += 8 + tag_len;
    }
    return -1;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <file.ts> <mpe_pid> <ip:port>\n";
        return 1;
    }

    uint16_t mpe_pid = static_cast<uint16_t>(std::stoi(argv[2]));
    std::string filter = argv[3];
    size_t colon = filter.find(':');
    struct in_addr addr;
    inet_aton(filter.substr(0, colon).c_str(), &addr);
    uint32_t filter_ip = ntohl(addr.s_addr);
    uint16_t filter_port = static_cast<uint16_t>(std::stoi(filter.substr(colon + 1)));

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) { std::cerr << "Cannot open: " << argv[1] << std::endl; return 1; }

    std::cout << "Processing " << argv[1] << " (using library MpeTsSource)\n";
    std::cout << "MPE PID: " << mpe_pid << ", Filter: " << filter << std::endl;

    size_t udp_packets = 0;
    PfReassembler pf;

    dvbdab::UdpExtractor udp_extractor([&](uint32_t ip, uint16_t port, const uint8_t* payload, size_t len) {
        udp_packets++;
        pf.feed(payload, len);
    });

    dvbdab::MpeTsSource source(mpe_pid);
    source.setIpFilter(filter_ip, filter_port);
    source.setIpCallback([&](const uint8_t* ip_data, size_t len) {
        udp_extractor.process(ip_data, len);
    });

    std::vector<uint8_t> buffer(65536);
    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount()) {
        source.feed(buffer.data(), file.gcount());
    }

    size_t eti_frames = 0;
    int prev_fct = -1, fct_gaps = 0;
    for (auto& af : pf.af_packets) {
        int fct = extractFct(af);
        if (fct < 0) continue;
        eti_frames++;
        if (prev_fct >= 0 && fct != (prev_fct + 1) % 250) fct_gaps++;
        prev_fct = fct;
    }

    std::cout << "\n=== RESULTS (library MpeTsSource) ===\n";
    std::cout << "UDP packets: " << udp_packets << std::endl;
    std::cout << "AF packets: " << pf.af_packets.size() << std::endl;
    std::cout << "ETI frames: " << eti_frames << std::endl;
    std::cout << "FCT gaps: " << fct_gaps << std::endl;
    if (eti_frames > 0) std::cout << "Gap rate: " << (100.0 * fct_gaps / eti_frames) << "%\n";
    return fct_gaps > 0 ? 1 : 0;
}
