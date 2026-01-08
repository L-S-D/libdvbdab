// Test FCT continuity through the library pipeline
// Uses exact code from standalone check_fct_direct.cpp

#include <iostream>
#include <fstream>
#include <cstdint>
#include <vector>
#include <map>
#include <arpa/inet.h>

// MPE extractor - exact copy from standalone check_fct_direct.cpp
class MpeExtractor {
public:
    std::vector<uint8_t> buffer;
    uint16_t section_len = 0;
    bool in_section = false;
    std::vector<std::vector<uint8_t>> packets;

    void process(const uint8_t* ts, uint16_t target_pid, uint32_t filter_ip, uint16_t filter_port);
    void extractUdp(const uint8_t* sec, size_t sec_len, uint32_t filter_ip, uint16_t filter_port);
};

void MpeExtractor::process(const uint8_t* ts, uint16_t target_pid, uint32_t filter_ip, uint16_t filter_port) {
    if (ts[0] != 0x47) return;
    uint16_t pid = ((ts[1] & 0x1F) << 8) | ts[2];
    if (pid != target_pid) return;
    bool pusi = (ts[1] >> 6) & 1;
    int adapt = (ts[3] >> 4) & 3;
    int start = 4;
    if (adapt == 2) return;
    if (adapt == 3) { if (ts[4] >= 183) return; start = 5 + ts[4]; }
    if (start >= 188) return;
    const uint8_t* p = ts + start;
    int len = 188 - start;

    if (pusi) {
        int ptr = p[0]; p++; len--;
        if (ptr > 0 && ptr <= len) {
            if (in_section) {
                buffer.insert(buffer.end(), p, p + ptr);
                if (buffer.size() >= section_len + 3 && buffer[0] == 0x3E)
                    extractUdp(buffer.data(), buffer.size(), filter_ip, filter_port);
            }
            p += ptr; len -= ptr;
        }
        buffer.clear(); in_section = false; section_len = 0;
        while (len >= 3 && p[0] != 0xFF) {
            section_len = ((p[1] & 0x0F) << 8) | p[2];
            int total = 3 + section_len;
            if (total <= len) {
                if (p[0] == 0x3E) extractUdp(p, total, filter_ip, filter_port);
                p += total; len -= total;
            } else { buffer.assign(p, p + len); in_section = true; break; }
        }
        if (!in_section && len > 0 && len < 3 && p[0] != 0xFF) {
            buffer.assign(p, p + len); in_section = true; section_len = 0;
        }
    } else if (in_section) {
        if (section_len == 0 && buffer.size() < 3) {
            size_t need = 3 - buffer.size();
            size_t copy = std::min(need, (size_t)len);
            buffer.insert(buffer.end(), p, p + copy); p += copy; len -= copy;
            if (buffer.size() >= 3) section_len = ((buffer[1] & 0x0F) << 8) | buffer[2];
            else return;
        }
        if (len == 0) return;
        size_t needed = (section_len + 3) - buffer.size();
        size_t to_copy = std::min(needed, (size_t)len);
        buffer.insert(buffer.end(), p, p + to_copy);
        if (buffer.size() >= section_len + 3) {
            if (buffer[0] == 0x3E) extractUdp(buffer.data(), buffer.size(), filter_ip, filter_port);
            buffer.clear(); in_section = false;
        }
    }
}

void MpeExtractor::extractUdp(const uint8_t* sec, size_t sec_len, uint32_t filter_ip, uint16_t filter_port) {
    if (sec_len < 16) return;
    const uint8_t* ip = sec + 12;
    size_t ip_len = sec_len - 16;
    if (ip_len < 28 || (ip[0] >> 4) != 4 || ip[9] != 17) return;
    uint32_t dst_ip = (ip[16] << 24) | (ip[17] << 16) | (ip[18] << 8) | ip[19];
    if (filter_ip != 0 && dst_ip != filter_ip) return;
    int ip_hdr = (ip[0] & 0x0F) * 4;
    if (ip_hdr < 20 || (size_t)ip_hdr + 8 > ip_len) return;
    const uint8_t* udp = ip + ip_hdr;
    uint16_t dst_port = (udp[2] << 8) | udp[3];
    if (filter_port != 0 && dst_port != filter_port) return;
    int udp_len = (udp[4] << 8) | udp[5];
    if (udp_len < 8) return;
    const uint8_t* payload = udp + 8;
    int payload_len = udp_len - 8;
    if (payload_len > 0) packets.push_back(std::vector<uint8_t>(payload, payload + payload_len));
}

// PF reassembler - exact copy from standalone check_fct_direct.cpp
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
        if (c.pseq != pseq || c.fcount != fcount) {
            c.pseq = pseq;
            c.fcount = fcount;
            c.fragments.clear();
        }

        if (c.fragments.find(findex) == c.fragments.end()) {
            c.fragments[findex] = std::vector<uint8_t>(pf + hdr_size, pf + hdr_size + plen);
        }

        if (c.fragments.size() == c.fcount) {
            std::vector<uint8_t> af;
            for (uint32_t i = 0; i < c.fcount; i++) {
                auto it = c.fragments.find(i);
                if (it != c.fragments.end()) {
                    af.insert(af.end(), it->second.begin(), it->second.end());
                }
            }
            af_packets.push_back(af);
            collectors.erase(pseq);
        }
    }
};

// Extract FCT from AF packet - exact copy from standalone
int extractFct(const std::vector<uint8_t>& af) {
    if (af.size() < 10 || af[0] != 'A' || af[1] != 'F') return -1;

    size_t pos = 10;
    while (pos + 8 <= af.size()) {
        uint32_t tag_len_bits = (af[pos+4] << 24) | (af[pos+5] << 16) | (af[pos+6] << 8) | af[pos+7];
        uint32_t tag_len = (tag_len_bits + 7) / 8;

        if (af[pos] == 'd' && af[pos+1] == 'e' && af[pos+2] == 't' && af[pos+3] == 'i') {
            if (pos + 8 + 2 <= af.size()) {
                return af[pos + 8 + 1];  // FCT is second byte of deti
            }
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

    const char* filename = argv[1];
    uint16_t mpe_pid = static_cast<uint16_t>(std::stoi(argv[2]));

    // Parse IP:port filter
    std::string filter = argv[3];
    size_t colon = filter.find(':');
    struct in_addr addr;
    inet_aton(filter.substr(0, colon).c_str(), &addr);
    uint32_t filter_ip = ntohl(addr.s_addr);
    uint16_t filter_port = static_cast<uint16_t>(std::stoi(filter.substr(colon + 1)));

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open: " << filename << std::endl;
        return 1;
    }

    std::cout << "Processing " << filename << std::endl;
    std::cout << "MPE PID: " << mpe_pid << ", Filter: " << filter << std::endl;

    // Use standalone MPE extractor
    MpeExtractor mpe;
    uint8_t ts[188];
    while (file.read((char*)ts, 188)) {
        mpe.process(ts, mpe_pid, filter_ip, filter_port);
    }

    std::cout << "UDP packets extracted: " << mpe.packets.size() << std::endl;

    // Use standalone PF reassembler
    PfReassembler pf;
    for (auto& pkt : mpe.packets) {
        pf.feed(pkt.data(), pkt.size());
    }

    std::cout << "AF packets assembled: " << pf.af_packets.size() << std::endl;

    // Check FCT continuity
    size_t eti_frames = 0;
    int prev_fct = -1;
    int fct_gaps = 0;

    for (auto& af : pf.af_packets) {
        int fct = extractFct(af);
        if (fct < 0) continue;

        eti_frames++;

        if (prev_fct >= 0) {
            int expected = (prev_fct + 1) % 250;
            if (fct != expected) {
                fct_gaps++;
            }
        }
        prev_fct = fct;
    }

    // Print results
    std::cout << "\n=== RESULTS ===" << std::endl;
    std::cout << "ETI frames: " << eti_frames << std::endl;
    std::cout << "FCT gaps: " << fct_gaps << std::endl;

    if (eti_frames > 0) {
        std::cout << "Gap rate: " << (100.0 * fct_gaps / eti_frames) << "%" << std::endl;
    }

    return fct_gaps > 0 ? 1 : 0;
}
