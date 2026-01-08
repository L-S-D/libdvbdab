// Test audio extraction from DAB/DAB+ subchannels
// Outputs AAC (with ADTS) for DAB+ and MP2 frames for DAB

#include "../src/sources/mpe_ts_source.hpp"
#include "../src/parsers/udp_extractor.hpp"
#include "../src/edi_parser.hpp"
#include "../src/output/dabplus_decoder.hpp"
#include "../src/output/dab_mp2_decoder.hpp"
#include <iostream>
#include <fstream>
#include <map>
#include <arpa/inet.h>
#include <iomanip>
#include <variant>

// FireCode CRC for DAB+ detection
static uint16_t fireCodeCrc(const uint8_t* data, size_t len) {
    static const uint16_t fire_lut[256] = {
        0x0000, 0x782f, 0xf05e, 0x8871, 0x9893, 0xe0bc, 0x68cd, 0x10e2,
        0x4909, 0x3126, 0xb957, 0xc178, 0xd19a, 0xa9b5, 0x21c4, 0x59eb,
        0x9212, 0xea3d, 0x624c, 0x1a63, 0x0a81, 0x72ae, 0xfadf, 0x82f0,
        0xdb1b, 0xa334, 0x2b45, 0x536a, 0x4388, 0x3ba7, 0xb3d6, 0xcbf9,
        0x5c0b, 0x2424, 0xac55, 0xd47a, 0xc498, 0xbcb7, 0x34c6, 0x4ce9,
        0x1502, 0x6d2d, 0xe55c, 0x9d73, 0x8d91, 0xf5be, 0x7dcf, 0x05e0,
        0xce19, 0xb636, 0x3e47, 0x4668, 0x568a, 0x2ea5, 0xa6d4, 0xdefb,
        0x8710, 0xff3f, 0x774e, 0x0f61, 0x1f83, 0x67ac, 0xefdd, 0x97f2,
        0xb816, 0xc039, 0x4848, 0x3067, 0x2085, 0x58aa, 0xd0db, 0xa8f4,
        0xf11f, 0x8930, 0x0141, 0x796e, 0x698c, 0x11a3, 0x99d2, 0xe1fd,
        0x2a04, 0x522b, 0xda5a, 0xa275, 0xb297, 0xcab8, 0x42c9, 0x3ae6,
        0x630d, 0x1b22, 0x9353, 0xeb7c, 0xfb9e, 0x83b1, 0x0bc0, 0x73ef,
        0xe41d, 0x9c32, 0x1443, 0x6c6c, 0x7c8e, 0x04a1, 0x8cd0, 0xf4ff,
        0xad14, 0xd53b, 0x5d4a, 0x2565, 0x3587, 0x4da8, 0xc5d9, 0xbdf6,
        0x760f, 0x0e20, 0x8651, 0xfe7e, 0xee9c, 0x96b3, 0x1ec2, 0x66ed,
        0x3f06, 0x4729, 0xcf58, 0xb777, 0xa795, 0xdfba, 0x57cb, 0x2fe4,
        0x0803, 0x702c, 0xf85d, 0x8072, 0x9090, 0xe8bf, 0x60ce, 0x18e1,
        0x410a, 0x3925, 0xb154, 0xc97b, 0xd999, 0xa1b6, 0x29c7, 0x51e8,
        0x9a11, 0xe23e, 0x6a4f, 0x1260, 0x0282, 0x7aad, 0xf2dc, 0x8af3,
        0xd318, 0xab37, 0x2346, 0x5b69, 0x4b8b, 0x33a4, 0xbbd5, 0xc3fa,
        0x5408, 0x2c27, 0xa456, 0xdc79, 0xcc9b, 0xb4b4, 0x3cc5, 0x44ea,
        0x1d01, 0x652e, 0xed5f, 0x9570, 0x8592, 0xfdbd, 0x75cc, 0x0de3,
        0xc61a, 0xbe35, 0x3644, 0x4e6b, 0x5e89, 0x26a6, 0xaed7, 0xd6f8,
        0x8f13, 0xf73c, 0x7f4d, 0x0762, 0x1780, 0x6faf, 0xe7de, 0x9ff1,
        0xb015, 0xc83a, 0x404b, 0x3864, 0x2886, 0x50a9, 0xd8d8, 0xa0f7,
        0xf91c, 0x8133, 0x0942, 0x716d, 0x618f, 0x19a0, 0x91d1, 0xe9fe,
        0x2207, 0x5a28, 0xd259, 0xaa76, 0xba94, 0xc2bb, 0x4aca, 0x32e5,
        0x6b0e, 0x1321, 0x9b50, 0xe37f, 0xf39d, 0x8bb2, 0x03c3, 0x7bec,
        0xec1e, 0x9431, 0x1c40, 0x646f, 0x748d, 0x0ca2, 0x84d3, 0xfcfc,
        0xa517, 0xdd38, 0x5549, 0x2d66, 0x3d84, 0x45ab, 0xcdda, 0xb5f5,
        0x7e0c, 0x0623, 0x8e52, 0xf67d, 0xe69f, 0x9eb0, 0x16c1, 0x6eee,
        0x3705, 0x4f2a, 0xc75b, 0xbf74, 0xaf96, 0xd7b9, 0x5fc8, 0x27e7
    };
    uint16_t crc = 0;
    for (size_t i = 0; i < len; i++)
        crc = (crc << 8) ^ fire_lut[((crc >> 8) ^ data[i]) & 0xff];
    return crc;
}

enum class SubchannelType { Unknown, DabPlus, Dab, Data };

struct SubchannelState {
    uint8_t scid;
    uint16_t stl;  // Size per frame in 64-bit units
    int bitrate;   // kbps
    SubchannelType type = SubchannelType::Unknown;
    std::unique_ptr<dvbdab::DabPlusDecoder> dabplus_decoder;
    std::unique_ptr<dvbdab::DabMp2Decoder> mp2_decoder;
    std::unique_ptr<std::ofstream> output_file;
    std::vector<uint8_t> detect_buffer;  // For type detection
    size_t frames_fed = 0;
    size_t audio_frames = 0;
    size_t crc_errors = 0;
};

class AudioExtractor {
    std::vector<SubchannelState> subchannels_;
    std::string output_prefix_;
    int target_scid_ = -1;  // -1 = all
    static const int DETECT_FRAMES = 6;  // Frames needed for detection

public:
    AudioExtractor(const std::string& prefix, int scid = -1)
        : output_prefix_(prefix), target_scid_(scid) {}

    void processFrame(const uint8_t* frame, size_t len) {
        if (len != 6144) return;

        uint8_t nst = frame[5] & 0x7F;
        uint8_t mid = (frame[6] >> 3) & 0x03;
        uint8_t ficf = (frame[5] >> 7) & 1;

        // Initialize on first frame
        if (subchannels_.empty()) {
            subchannels_.resize(nst);
            for (int i = 0; i < nst; i++) {
                const uint8_t* stc = frame + 8 + i * 4;
                auto& sc = subchannels_[i];
                sc.scid = (stc[0] >> 2) & 0x3F;
                sc.stl = ((stc[2] & 0x03) << 8) | stc[3];
                sc.bitrate = (sc.stl * 8 * 8) / 24;  // STL*8 bytes per 24ms

                // Skip if targeting specific SCID
                if (target_scid_ >= 0 && sc.scid != target_scid_) {
                    sc.type = SubchannelType::Data;  // Mark as skipped
                }
            }
        }

        // Calculate MST start
        size_t eoh_end = 8 + nst * 4 + 4;
        size_t fic_len = ficf ? ((mid == 3) ? 128 : 96) : 0;
        size_t offset = eoh_end + fic_len;

        // Process each subchannel
        for (size_t i = 0; i < subchannels_.size() && i < nst; i++) {
            auto& sc = subchannels_[i];
            size_t size = sc.stl * 8;

            if (offset + size > len) {
                offset += size;
                continue;
            }

            const uint8_t* data = frame + offset;
            offset += size;

            // Skip if already marked as data/skipped
            if (sc.type == SubchannelType::Data) continue;

            // Detection phase
            if (sc.type == SubchannelType::Unknown) {
                sc.detect_buffer.insert(sc.detect_buffer.end(), data, data + size);

                if (sc.detect_buffer.size() >= size * DETECT_FRAMES) {
                    detectSubchannelType(sc);
                }
                continue;
            }

            // Feed to appropriate decoder
            sc.frames_fed++;
            if (sc.type == SubchannelType::DabPlus && sc.dabplus_decoder) {
                sc.dabplus_decoder->feedFrame(data, size);
            } else if (sc.type == SubchannelType::Dab && sc.mp2_decoder) {
                sc.mp2_decoder->feedFrame(data, size);
            }
        }
    }

    void detectSubchannelType(SubchannelState& sc) {
        // Check for DAB+ firecode
        for (size_t pos = 0; pos + 11 < sc.detect_buffer.size(); pos++) {
            uint16_t stored = (sc.detect_buffer[pos] << 8) | sc.detect_buffer[pos + 1];
            uint16_t calc = fireCodeCrc(sc.detect_buffer.data() + pos + 2, 9);
            if (stored == calc && stored != 0) {
                sc.type = SubchannelType::DabPlus;
                setupDabPlusDecoder(sc);

                // Feed buffered data
                size_t frame_size = sc.stl * 8;
                for (size_t f = 0; f < sc.detect_buffer.size() / frame_size; f++) {
                    sc.dabplus_decoder->feedFrame(
                        sc.detect_buffer.data() + f * frame_size, frame_size);
                }
                sc.detect_buffer.clear();
                return;
            }
        }

        // Check for MP2 sync
        for (size_t pos = 0; pos + 4 < sc.detect_buffer.size(); pos++) {
            if (sc.detect_buffer[pos] == 0xFF &&
                (sc.detect_buffer[pos + 1] & 0xE0) == 0xE0) {
                int layer = (sc.detect_buffer[pos + 1] >> 1) & 3;
                if (layer == 2) {  // Layer 2
                    sc.type = SubchannelType::Dab;
                    setupMp2Decoder(sc);

                    // Feed buffered data
                    size_t frame_size = sc.stl * 8;
                    for (size_t f = 0; f < sc.detect_buffer.size() / frame_size; f++) {
                        sc.mp2_decoder->feedFrame(
                            sc.detect_buffer.data() + f * frame_size, frame_size);
                    }
                    sc.detect_buffer.clear();
                    return;
                }
            }
        }

        // Neither DAB+ nor DAB - mark as data
        sc.type = SubchannelType::Data;
        sc.detect_buffer.clear();
        std::cout << "SCID " << (int)sc.scid << ": " << sc.bitrate << " kbps -> DATA (skipped)" << std::endl;
    }

    void setupDabPlusDecoder(SubchannelState& sc) {
        sc.dabplus_decoder = std::make_unique<dvbdab::DabPlusDecoder>(sc.bitrate);

        std::string filename = output_prefix_ + "_scid" + std::to_string(sc.scid) + ".aac";
        sc.output_file = std::make_unique<std::ofstream>(filename, std::ios::binary);

        SubchannelState* psc = &sc;
        sc.dabplus_decoder->setCallback([psc](const uint8_t* data, size_t len) {
            if (psc->output_file) {
                psc->output_file->write(reinterpret_cast<const char*>(data), len);
                psc->audio_frames++;
            }
        });

        std::cout << "SCID " << (int)sc.scid << ": " << sc.bitrate << " kbps DAB+ -> " << filename << std::endl;
    }

    void setupMp2Decoder(SubchannelState& sc) {
        sc.mp2_decoder = std::make_unique<dvbdab::DabMp2Decoder>(sc.bitrate);

        std::string filename = output_prefix_ + "_scid" + std::to_string(sc.scid) + ".mp2";
        sc.output_file = std::make_unique<std::ofstream>(filename, std::ios::binary);

        SubchannelState* psc = &sc;
        sc.mp2_decoder->setCallback([psc](const uint8_t* data, size_t len) {
            if (psc->output_file) {
                psc->output_file->write(reinterpret_cast<const char*>(data), len);
                psc->audio_frames++;
            }
        });

        std::cout << "SCID " << (int)sc.scid << ": " << sc.bitrate << " kbps DAB -> " << filename << std::endl;
    }

    void printStats() {
        std::cout << "\n=== Audio Extraction Stats ===" << std::endl;
        for (auto& sc : subchannels_) {
            if (sc.type == SubchannelType::Data || sc.type == SubchannelType::Unknown) continue;

            std::cout << "SCID " << std::setw(2) << (int)sc.scid
                      << ": " << std::setw(3) << sc.bitrate << " kbps "
                      << (sc.type == SubchannelType::DabPlus ? "DAB+" : "DAB ")
                      << ", " << sc.frames_fed << " frames fed"
                      << ", " << sc.audio_frames << " audio frames";

            if (sc.type == SubchannelType::DabPlus && sc.dabplus_decoder) {
                std::cout << ", " << sc.dabplus_decoder->getCrcErrors() << " CRC errors";
            } else if (sc.type == SubchannelType::Dab && sc.mp2_decoder) {
                std::cout << ", " << sc.mp2_decoder->getSyncErrors() << " sync errors";
            }
            std::cout << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <file.ts> <mpe_pid> <ip:port> [scid]\n";
        std::cerr << "  scid: optional, extract only this subchannel\n";
        return 1;
    }

    uint16_t mpe_pid = static_cast<uint16_t>(std::stoi(argv[2]));
    std::string filter = argv[3];
    size_t colon = filter.find(':');
    struct in_addr addr;
    inet_aton(filter.substr(0, colon).c_str(), &addr);
    uint32_t filter_ip = ntohl(addr.s_addr);
    uint16_t filter_port = static_cast<uint16_t>(std::stoi(filter.substr(colon + 1)));

    int target_scid = (argc > 4) ? std::stoi(argv[4]) : -1;

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open: " << argv[1] << std::endl;
        return 1;
    }

    std::cout << "Extracting audio from " << argv[1] << std::endl;
    std::cout << "PID: " << mpe_pid << ", Filter: " << filter << std::endl;
    if (target_scid >= 0) std::cout << "Target SCID: " << target_scid << std::endl;

    AudioExtractor extractor("/tmp/audio", target_scid);
    int frame_count = 0;

    EdiParser edi_parser([&](const uint8_t* frame, size_t len, uint16_t dflc) {
        extractor.processFrame(frame, len);
        frame_count++;
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
    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount()) {
        source.feed(buffer.data(), file.gcount());
    }

    std::cout << "\nProcessed " << frame_count << " ETI frames" << std::endl;
    extractor.printStats();

    return 0;
}
