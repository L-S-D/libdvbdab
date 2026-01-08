// Test DAB+ superframe sync detection and firecode verification
// Requires 5+ ETI frames to find superframe boundaries

#include "../src/sources/mpe_ts_source.hpp"
#include "../src/parsers/udp_extractor.hpp"
#include "../src/edi_parser.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <arpa/inet.h>
#include <iomanip>

class FireCodeCRC {
    uint16_t lut[256];
public:
    FireCodeCRC() {
        for (int i = 0; i < 256; i++) {
            uint16_t crc = i << 8;
            for (int j = 0; j < 8; j++)
                crc = (crc & 0x8000) ? ((crc << 1) ^ 0x782F) : (crc << 1);
            lut[i] = crc;
        }
    }
    uint16_t calc(const uint8_t* data, size_t len) {
        uint16_t crc = 0;
        for (size_t i = 0; i < len; i++)
            crc = (crc << 8) ^ lut[((crc >> 8) ^ data[i]) & 0xFF];
        return crc;
    }
};

struct SubchannelInfo {
    uint8_t scid;
    uint16_t stl;           // Size in 64-bit units
    std::vector<uint8_t> buffer;  // Accumulated data
    int sync_offset = -1;   // Superframe sync position
    bool is_dabplus = false;
    bool sync_verified = false;
    int superframes_checked = 0;
    int superframes_valid = 0;
};

class SuperframeChecker {
    FireCodeCRC crc_;
    std::vector<SubchannelInfo> subchannels_;
    int frames_collected_ = 0;
    static const int FRAMES_NEEDED = 10;  // Collect 10 frames (2 superframes)

public:
    void processFrame(const uint8_t* frame, size_t len) {
        if (len != 6144) return;

        uint8_t nst = frame[5] & 0x7F;
        uint8_t mid = (frame[6] >> 3) & 0x03;
        uint8_t ficf = (frame[5] >> 7) & 1;

        // Initialize subchannels on first frame
        if (subchannels_.empty()) {
            subchannels_.resize(nst);
            for (int i = 0; i < nst; i++) {
                const uint8_t* stc = frame + 8 + i * 4;
                subchannels_[i].scid = (stc[0] >> 2) & 0x3F;
                subchannels_[i].stl = ((stc[2] & 0x03) << 8) | stc[3];
            }
        }

        // Calculate MST start
        size_t eoh_end = 8 + nst * 4 + 4;
        size_t fic_len = ficf ? ((mid == 3) ? 128 : 96) : 0;
        size_t offset = eoh_end + fic_len;

        // Extract each subchannel's data
        for (int i = 0; i < nst && i < subchannels_.size(); i++) {
            size_t size = subchannels_[i].stl * 8;
            if (offset + size <= len) {
                subchannels_[i].buffer.insert(
                    subchannels_[i].buffer.end(),
                    frame + offset, frame + offset + size
                );
            }
            offset += size;
        }

        frames_collected_++;

        // After collecting enough frames, find sync
        if (frames_collected_ == FRAMES_NEEDED) {
            findAllSync();
        }

        // Continue verifying superframes
        if (frames_collected_ > FRAMES_NEEDED && frames_collected_ % 5 == 0) {
            verifySuperframes();
        }
    }

    void findAllSync() {
        for (auto& sc : subchannels_) {
            if (sc.buffer.size() < 11) continue;

            // Search for firecode match
            for (size_t pos = 0; pos + 11 < sc.buffer.size(); pos++) {
                uint16_t stored = (sc.buffer[pos] << 8) | sc.buffer[pos + 1];
                uint16_t calc = crc_.calc(sc.buffer.data() + pos + 2, 9);

                if (stored == calc && stored != 0) {
                    sc.sync_offset = pos;
                    sc.is_dabplus = true;
                    sc.sync_verified = true;

                    // Parse header
                    uint8_t hdr = sc.buffer[pos + 2];
                    break;
                }
            }
        }
    }

    void verifySuperframes() {
        for (auto& sc : subchannels_) {
            if (!sc.is_dabplus || sc.sync_offset < 0) continue;

            size_t sf_size = sc.stl * 8 * 5;  // 5 frames per superframe
            size_t pos = sc.sync_offset;

            while (pos + 11 < sc.buffer.size()) {
                uint16_t stored = (sc.buffer[pos] << 8) | sc.buffer[pos + 1];
                uint16_t calc = crc_.calc(sc.buffer.data() + pos + 2, 9);

                sc.superframes_checked++;
                if (stored == calc) sc.superframes_valid++;

                pos += sf_size;
            }
        }
    }

    void printResults() {
        std::cout << "\n=== Superframe Sync Results ===" << std::endl;
        std::cout << "Frames collected: " << frames_collected_ << std::endl;
        std::cout << "Subchannels: " << subchannels_.size() << std::endl;

        int audio_count = 0, data_count = 0;
        int total_checked = 0, total_valid = 0;

        for (size_t i = 0; i < subchannels_.size(); i++) {
            auto& sc = subchannels_[i];
            std::cout << "  SCID=" << std::setw(2) << (int)sc.scid
                      << " (" << std::setw(4) << (sc.stl * 8) << "B): ";

            if (sc.is_dabplus) {
                audio_count++;
                uint8_t hdr = sc.buffer[sc.sync_offset + 2];
                std::cout << "DAB+ sync@" << sc.sync_offset
                          << " sbr=" << ((hdr>>5)&1)
                          << " ch=" << ((hdr>>4)&1);

                if (sc.superframes_checked > 0) {
                    total_checked += sc.superframes_checked;
                    total_valid += sc.superframes_valid;
                    std::cout << " verified=" << sc.superframes_valid 
                              << "/" << sc.superframes_checked;
                }
            } else {
                data_count++;
                std::cout << "DATA (no sync)";
            }
            std::cout << std::endl;
        }

        std::cout << "\nSummary: " << audio_count << " audio, " 
                  << data_count << " data services" << std::endl;

        if (total_checked > 0) {
            std::cout << "Superframes verified: " << total_valid << "/" << total_checked;
            if (total_valid == total_checked) {
                std::cout << " - ALL OK";
            } else {
                std::cout << " - ERRORS!";
            }
            std::cout << std::endl;
        }
    }

    bool allValid() {
        for (auto& sc : subchannels_) {
            if (sc.is_dabplus && sc.superframes_checked > 0) {
                if (sc.superframes_valid != sc.superframes_checked) return false;
            }
        }
        return true;
    }
};

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
    if (!file) {
        std::cerr << "Cannot open: " << argv[1] << std::endl;
        return 1;
    }

    std::cout << "Processing " << argv[1] << std::endl;
    std::cout << "PID: " << mpe_pid << ", Filter: " << filter << std::endl;

    SuperframeChecker checker;
    int frame_count = 0;
    const int MAX_FRAMES = 100;  // Check first 100 frames (20 superframes)

    EdiParser edi_parser([&](const uint8_t* frame, size_t len, uint16_t dflc) {
        if (frame_count < MAX_FRAMES) {
            checker.processFrame(frame, len);
            frame_count++;
        }
    });

    dvbdab::UdpExtractor udp_extractor([&](uint32_t ip, uint16_t port,
                                            const uint8_t* payload, size_t len) {
        edi_parser.feed(payload, len);
    });

    dvbdab::MpeTsSource source(mpe_pid);
    source.setIpFilter(filter_ip, filter_port);
    source.setIpCallback([&](const uint8_t* ip_data, size_t len) {
        udp_extractor.process(ip_data, len);
    });

    std::vector<uint8_t> buffer(65536);
    while (frame_count < MAX_FRAMES && 
           (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount())) {
        source.feed(buffer.data(), file.gcount());
    }

    checker.printResults();

    return checker.allValid() ? 0 : 1;
}
