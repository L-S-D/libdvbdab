/**
 * edi_info - Analyze EDI streams in BBF/GSE/MPE encapsulation
 *
 * Extracts subchannel information from EDI streams without requiring FIC.
 * Detects audio codec (MP2 or DAB+) by analyzing the data.
 *
 * Usage: edi_info <format> <input.ts> [pid]
 *   format: bbf, gse, or mpe
 *   pid: PID for MPE format (default 3000)
 */

#include "sources/bbf_ts_source.hpp"
#include "sources/gse_ts_source.hpp"
#include "sources/mpe_ts_source.hpp"
#include "parsers/udp_extractor.hpp"
#include "parsers/pf_reassembler.hpp"
#include "utils/byte_utils.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <map>
#include <cstring>

using namespace dvbdab;

struct SubchannelInfo {
    uint8_t scid;           // SubChannel ID
    uint16_t sad;           // Start Address
    uint8_t tpl;            // Type + Protection Level
    size_t frame_count = 0;
    size_t total_bytes = 0;
    std::vector<uint8_t> first_frame;
    int mp2_votes = 0;
    int dabplus_votes = 0;
};

// Check for MP2 (MPEG-1 Layer II) sync
static bool looks_like_mp2(const uint8_t* data, size_t len) {
    if (len < 4) return false;
    for (size_t i = 0; i + 4 <= len && i < 32; i++) {
        if (data[i] == 0xFF && (data[i+1] & 0xF0) == 0xF0) {
            uint8_t layer = (data[i+1] >> 1) & 0x03;
            if (layer == 2) return true;  // Layer II
        }
    }
    return false;
}

// Check for DAB+ superframe (FireCode CRC)
static const uint16_t fire_code_table[256] = {
    0x0000, 0x782F, 0xF05E, 0x8871, 0x9893, 0xE0BC, 0x68CD, 0x10E2,
    0x4909, 0x3126, 0xB957, 0xC178, 0xD19A, 0xA9B5, 0x21C4, 0x59EB,
    0x9212, 0xEA3D, 0x624C, 0x1A63, 0x0A81, 0x72AE, 0xFADF, 0x82F0,
    0xDB1B, 0xA334, 0x2B45, 0x536A, 0x4388, 0x3BA7, 0xB3D6, 0xCBF9,
    0x5C0B, 0x2424, 0xAC55, 0xD47A, 0xC498, 0xBCB7, 0x34C6, 0x4CE9,
    0x1502, 0x6D2D, 0xE55C, 0x9D73, 0x8D91, 0xF5BE, 0x7DCF, 0x05E0,
    0xCE19, 0xB636, 0x3E47, 0x4668, 0x568A, 0x2EA5, 0xA6D4, 0xDEFB,
    0x8710, 0xFF3F, 0x774E, 0x0F61, 0x1F83, 0x67AC, 0xEFDD, 0x97F2,
    0xB816, 0xC039, 0x4848, 0x3067, 0x2085, 0x58AA, 0xD0DB, 0xA8F4,
    0xF11F, 0x8930, 0x0141, 0x796E, 0x698C, 0x11A3, 0x99D2, 0xE1FD,
    0x2A04, 0x522B, 0xDA5A, 0xA275, 0xB297, 0xCAB8, 0x42C9, 0x3AE6,
    0x630D, 0x1B22, 0x9353, 0xEB7C, 0xFB9E, 0x83B1, 0x0BC0, 0x73EF,
    0xE41D, 0x9C32, 0x1443, 0x6C6C, 0x7C8E, 0x04A1, 0x8CD0, 0xF4FF,
    0xAD14, 0xD53B, 0x5D4A, 0x2565, 0x3587, 0x4DA8, 0xC5D9, 0xBDF6,
    0x760F, 0x0E20, 0x8651, 0xFE7E, 0xEE9C, 0x96B3, 0x1EC2, 0x66ED,
    0x3F06, 0x4729, 0xCF58, 0xB777, 0xA795, 0xDFBA, 0x57CB, 0x2FE4,
    0x0803, 0x702C, 0xF85D, 0x8072, 0x9090, 0xE8BF, 0x60CE, 0x18E1,
    0x410A, 0x3925, 0xB154, 0xC97B, 0xD999, 0xA1B6, 0x29C7, 0x51E8,
    0x9A11, 0xE23E, 0x6A4F, 0x1260, 0x0282, 0x7AAD, 0xF2DC, 0x8AF3,
    0xD318, 0xAB37, 0x2346, 0x5B69, 0x4B8B, 0x33A4, 0xBBD5, 0xC3FA,
    0x5408, 0x2C27, 0xA456, 0xDC79, 0xCC9B, 0xB4B4, 0x3CC5, 0x44EA,
    0x1D01, 0x652E, 0xED5F, 0x9570, 0x8592, 0xFDBD, 0x75CC, 0x0DE3,
    0xC61A, 0xBE35, 0x3644, 0x4E6B, 0x5E89, 0x26A6, 0xAED7, 0xD6F8,
    0x8F13, 0xF73C, 0x7F4D, 0x0762, 0x1780, 0x6FAF, 0xE7DE, 0x9FF1,
    0xB015, 0xC83A, 0x404B, 0x3864, 0x2886, 0x50A9, 0xD8D8, 0xA0F7,
    0xF91C, 0x8133, 0x0942, 0x716D, 0x618F, 0x19A0, 0x91D1, 0xE9FE,
    0x2207, 0x5A28, 0xD259, 0xAA76, 0xBA94, 0xC2BB, 0x4ACA, 0x32E5,
    0x6B0E, 0x1321, 0x9B50, 0xE37F, 0xF39D, 0x8BB2, 0x03C3, 0x7BEC,
    0xEC1E, 0x9431, 0x1C40, 0x646F, 0x748D, 0x0CA2, 0x84D3, 0xFCFC,
    0xA517, 0xDD38, 0x5549, 0x2D66, 0x3D84, 0x45AB, 0xCDDA, 0xB5F5,
    0x7E0C, 0x0623, 0x8E52, 0xF67D, 0xE69F, 0x9EB0, 0x16C1, 0x6EEE,
    0x3705, 0x4F2A, 0xC75B, 0xBF74, 0xAF96, 0xD7B9, 0x5FC8, 0x27E7
};

static bool check_firecode(const uint8_t* buf, size_t len) {
    if (len < 12) return false;
    // Don't match all-zeros
    bool all_zero = true;
    for (int i = 0; i < 12 && all_zero; i++) {
        if (buf[i] != 0) all_zero = false;
    }
    if (all_zero) return false;

    uint16_t crc = 0;
    for (int i = 2; i < 12; i++) {
        crc = fire_code_table[(crc >> 8) ^ buf[i]] ^ (crc << 8);
    }
    uint16_t expected = (buf[0] << 8) | buf[1];
    return crc == expected;
}

static bool looks_like_dabplus(const uint8_t* data, size_t len) {
    return check_firecode(data, len);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <format> <input.ts> [pid]\n";
        std::cerr << "  format: bbf, gse, or mpe\n";
        std::cerr << "  pid: PID for MPE format (default 3000)\n";
        return 1;
    }

    const char* format = argv[1];
    const char* filename = argv[2];
    int mpe_pid = (argc > 3) ? std::stoi(argv[3]) : 3000;

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open: " << filename << std::endl;
        return 1;
    }

    // Create appropriate source
    std::unique_ptr<InputSource> source;
    if (strcmp(format, "bbf") == 0) {
        source = std::make_unique<BbfTsSource>();
    } else if (strcmp(format, "gse") == 0) {
        source = std::make_unique<GseTsSource>();
    } else if (strcmp(format, "mpe") == 0) {
        source = std::make_unique<MpeTsSource>(mpe_pid);
    } else {
        std::cerr << "Unknown format: " << format << "\n";
        return 1;
    }

    PF_Reassembler pf;
    std::map<int, SubchannelInfo> subchannels;
    std::map<std::pair<uint32_t, uint16_t>, size_t> streams;
    size_t af_count = 0;
    bool has_fic = false;
    uint8_t dab_mode = 0;

    UdpExtractor udp_extractor([&](uint32_t ip, uint16_t port,
                                    const uint8_t* payload, size_t len) {
        streams[{ip, port}]++;

        if (len < 2 || payload[0] != 'P' || payload[1] != 'F') return;

        PF_Header hdr;
        if (!pf.parse_pf_header(payload, len, hdr)) return;

        size_t af_len = 0;
        const uint8_t* af = pf.add_fragment(hdr, payload, len, af_len);
        if (!af || af_len < 10) return;
        if (af[0] != 'A' || af[1] != 'F') return;

        af_count++;
        uint32_t taglength = read_be32(af + 2);
        const uint8_t* tagpkt = af + 10;

        // Parse tags
        for (size_t i = 0; i + 8 <= taglength; ) {
            uint32_t tagId = read_be32(tagpkt + i);
            uint32_t taglen_bits = read_be32(tagpkt + i + 4);
            if (taglen_bits % 8 != 0) break;
            uint32_t taglen = taglen_bits / 8;
            const uint8_t* val = tagpkt + i + 8;

            // deti tag - check for FIC
            if (tagId == 0x64657469 && taglen >= 6) {
                uint16_t detiHeader = read_be16(val);
                bool ficf = (detiHeader >> 14) & 1;
                if (ficf) has_fic = true;

                uint32_t etiHeader = read_be32(val + 2);
                dab_mode = (etiHeader >> 22) & 0x03;
            }

            // est? tags
            if ((tagId & 0xFFFFFF00) == 0x65737400 && taglen >= 3) {
                int idx = tagId & 0xFF;
                uint32_t sstc = (val[0] << 16) | (val[1] << 8) | val[2];

                auto& info = subchannels[idx];
                if (info.frame_count == 0) {
                    info.scid = (sstc >> 18) & 0x3F;
                    info.sad = (sstc >> 8) & 0x3FF;
                    info.tpl = (sstc >> 2) & 0x3F;
                }

                const uint8_t* audio = val + 3;
                size_t audio_len = taglen - 3;

                info.frame_count++;
                info.total_bytes += audio_len;

                if (info.first_frame.empty() && audio_len > 0) {
                    info.first_frame.assign(audio, audio + std::min(audio_len, (size_t)32));
                }

                if (audio_len > 4) {
                    if (looks_like_mp2(audio, audio_len)) info.mp2_votes++;
                    if (looks_like_dabplus(audio, audio_len)) info.dabplus_votes++;
                }
            }

            i += 8 + taglen;
        }
    });

    source->setIpCallback([&](const uint8_t* ip_data, size_t len) {
        udp_extractor.process(ip_data, len);
    });

    std::vector<uint8_t> buffer(65536);
    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount()) {
        source->feed(buffer.data(), file.gcount());
    }

    if (auto* bbf = dynamic_cast<BbfTsSource*>(source.get())) {
        bbf->flush();
    }

    // Output results
    std::cout << "=== EDI Stream Analysis ===" << std::endl;
    std::cout << "File: " << filename << std::endl;
    std::cout << "Format: " << format << std::endl;
    std::cout << "AF packets: " << af_count << std::endl;
    std::cout << "DAB mode: " << (int)dab_mode << std::endl;
    std::cout << "FIC present: " << (has_fic ? "yes" : "NO") << std::endl;
    std::cout << std::endl;

    std::cout << "=== Streams ===" << std::endl;
    for (const auto& [key, count] : streams) {
        std::cout << "  " << ((key.first >> 24) & 0xFF) << "."
                  << ((key.first >> 16) & 0xFF) << "."
                  << ((key.first >> 8) & 0xFF) << "."
                  << (key.first & 0xFF) << ":" << key.second
                  << " - " << count << " packets" << std::endl;
    }
    std::cout << std::endl;

    std::cout << "=== Subchannels ===" << std::endl;
    std::cout << std::left
              << std::setw(6) << "Index"
              << std::setw(6) << "SCID"
              << std::setw(10) << "Bitrate"
              << std::setw(12) << "Codec"
              << std::setw(10) << "Frames"
              << "Header" << std::endl;
    std::cout << std::string(70, '-') << std::endl;

    for (const auto& [idx, info] : subchannels) {
        double bitrate_kbps = 0;
        if (info.frame_count > 0) {
            double avg_frame = (double)info.total_bytes / info.frame_count;
            bitrate_kbps = (avg_frame * 8) / 24.0;
        }

        std::string codec = "unknown";
        if (info.mp2_votes > info.frame_count / 2) {
            codec = "MP2";
        } else if (info.dabplus_votes > info.frame_count / 10) {
            codec = "DAB+";
        } else if (bitrate_kbps < 16) {
            codec = "data";
        }

        std::cout << std::left
                  << std::setw(6) << idx
                  << std::setw(6) << (int)info.scid
                  << std::setw(10) << (std::to_string((int)bitrate_kbps) + " kbps")
                  << std::setw(12) << codec
                  << std::setw(10) << info.frame_count;

        // Show header bytes
        for (size_t j = 0; j < std::min(info.first_frame.size(), (size_t)8); j++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << (int)info.first_frame[j] << " ";
        }
        std::cout << std::dec << std::setfill(' ') << std::endl;
    }

    if (!has_fic) {
        std::cout << "\nNote: No FIC data - use edi_extract to extract raw audio" << std::endl;
    }

    return 0;
}
