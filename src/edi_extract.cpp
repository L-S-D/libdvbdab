/**
 * edi_extract - Extract audio from EDI streams without FIC
 *
 * Extracts raw audio data from subchannels in BBF/GSE/MPE encapsulated
 * EDI streams. Works even when FIC data is not present.
 *
 * Usage: edi_extract <format> <input.ts> <subchannel> <output> [pid]
 *   format: bbf, gse, or mpe
 *   subchannel: subchannel index (1-64) or "all" for all audio
 *   output: output filename (or prefix if "all")
 *   pid: PID for MPE format (default 3000)
 *
 * Output format is determined by codec detection:
 *   - MP2: raw MPEG audio (.mp2)
 *   - DAB+: AAC with ADTS headers (.aac) - requires fdk-aac
 */

#include "sources/bbf_ts_source.hpp"
#include "sources/gse_ts_source.hpp"
#include "sources/mpe_ts_source.hpp"
#include "parsers/udp_extractor.hpp"
#include "parsers/pf_reassembler.hpp"
#include "utils/byte_utils.hpp"
#include <iostream>
#include <fstream>
#include <map>
#include <cstring>

using namespace dvbdab;

struct SubchannelData {
    std::vector<uint8_t> buffer;
    size_t frame_count = 0;
    int mp2_votes = 0;
    int dabplus_votes = 0;
};

// Check for MP2 sync
static bool looks_like_mp2(const uint8_t* data, size_t len) {
    if (len < 4) return false;
    for (size_t i = 0; i + 4 <= len && i < 32; i++) {
        if (data[i] == 0xFF && (data[i+1] & 0xF0) == 0xF0) {
            uint8_t layer = (data[i+1] >> 1) & 0x03;
            if (layer == 2) return true;
        }
    }
    return false;
}

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <format> <input.ts> <subchannel> <output> [pid]\n";
    std::cerr << "  format: bbf, gse, or mpe\n";
    std::cerr << "  subchannel: index (1-64) or 'all' for all audio channels\n";
    std::cerr << "  output: output file (or prefix for 'all')\n";
    std::cerr << "  pid: PID for MPE format (default 3000)\n";
    std::cerr << "\nExamples:\n";
    std::cerr << "  " << prog << " bbf input.ts 1 channel1.mp2\n";
    std::cerr << "  " << prog << " bbf input.ts all output_\n";
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        print_usage(argv[0]);
        return 1;
    }

    const char* format = argv[1];
    const char* filename = argv[2];
    const char* subchan_arg = argv[3];
    const char* output_arg = argv[4];
    int mpe_pid = (argc > 5) ? std::stoi(argv[5]) : 3000;

    bool extract_all = (strcmp(subchan_arg, "all") == 0);
    int target_subchan = extract_all ? -1 : std::stoi(subchan_arg);

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
    std::map<int, SubchannelData> subchannels;
    size_t af_count = 0;

    UdpExtractor udp_extractor([&](uint32_t ip, uint16_t port,
                                    const uint8_t* payload, size_t len) {
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

        // Find est? tags
        for (size_t i = 0; i + 8 <= taglength; ) {
            uint32_t tagId = read_be32(tagpkt + i);
            uint32_t taglen_bits = read_be32(tagpkt + i + 4);
            if (taglen_bits % 8 != 0) break;
            uint32_t taglen = taglen_bits / 8;
            const uint8_t* val = tagpkt + i + 8;

            if ((tagId & 0xFFFFFF00) == 0x65737400 && taglen >= 3) {
                int idx = tagId & 0xFF;

                if (extract_all || idx == target_subchan) {
                    const uint8_t* audio = val + 3;
                    size_t audio_len = taglen - 3;

                    auto& data = subchannels[idx];
                    data.buffer.insert(data.buffer.end(), audio, audio + audio_len);
                    data.frame_count++;

                    if (audio_len > 4 && looks_like_mp2(audio, audio_len)) {
                        data.mp2_votes++;
                    }
                }
            }

            i += 8 + taglen;
        }
    });

    source->setIpCallback([&](const uint8_t* ip_data, size_t len) {
        udp_extractor.process(ip_data, len);
    });

    std::cout << "Processing " << filename << "..." << std::endl;

    std::vector<uint8_t> buffer(65536);
    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount()) {
        source->feed(buffer.data(), file.gcount());
    }

    if (auto* bbf = dynamic_cast<BbfTsSource*>(source.get())) {
        bbf->flush();
    }

    std::cout << "AF packets processed: " << af_count << std::endl;

    // Write output
    int written = 0;
    for (const auto& [idx, data] : subchannels) {
        if (data.buffer.empty()) continue;

        // Determine codec
        bool is_mp2 = (data.mp2_votes > data.frame_count / 2);
        const char* ext = is_mp2 ? ".mp2" : ".raw";
        std::string codec = is_mp2 ? "MP2" : "unknown";

        // Build output filename
        std::string outname;
        if (extract_all) {
            outname = std::string(output_arg) + std::to_string(idx) + ext;
        } else {
            outname = output_arg;
        }

        std::ofstream outfile(outname, std::ios::binary);
        if (!outfile) {
            std::cerr << "Cannot create: " << outname << std::endl;
            continue;
        }

        outfile.write(reinterpret_cast<const char*>(data.buffer.data()), data.buffer.size());
        written++;

        double bitrate = 0;
        if (data.frame_count > 0) {
            double avg = (double)data.buffer.size() / data.frame_count;
            bitrate = (avg * 8) / 24.0;
        }

        std::cout << "  Subchannel " << idx << ": "
                  << data.buffer.size() << " bytes, "
                  << data.frame_count << " frames, "
                  << (int)bitrate << " kbps, "
                  << codec << " -> " << outname << std::endl;
    }

    if (written == 0) {
        std::cerr << "No data extracted" << std::endl;
        return 1;
    }

    std::cout << "\nExtracted " << written << " subchannel(s)" << std::endl;
    std::cout << "Play with: ffplay <file> or mpv <file>" << std::endl;

    return 0;
}
