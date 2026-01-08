// Extract raw subchannel data and analyze for MP2/DAB+ signatures
#include "../src/sources/mpe_ts_source.hpp"
#include "../src/parsers/udp_extractor.hpp"
#include "../src/edi_parser.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <arpa/inet.h>

struct SubchInfo {
    uint8_t scid;
    uint16_t stl;
    std::vector<uint8_t> data;
};

bool checkFireCode(const uint8_t* buf) {
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
    for (int i = 0; i < 9; i++)
        crc = (crc << 8) ^ fire_lut[((crc >> 8) ^ buf[2 + i]) & 0xff];
    return (crc >> 8) == buf[0] && (crc & 0xff) == buf[1];
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
    if (!file) {
        std::cerr << "Cannot open: " << argv[1] << std::endl;
        return 1;
    }

    std::vector<SubchInfo> subchannels;
    int frame_count = 0;
    const int MAX_FRAMES = 10;  // Get 10 frames = 2 superframes

    EdiParser edi_parser([&](const uint8_t* frame, size_t len, uint16_t dflc) {
        if (len != 6144 || frame_count >= MAX_FRAMES) return;

        uint8_t nst = frame[5] & 0x7F;
        uint8_t mid = (frame[6] >> 3) & 0x03;
        uint8_t ficf = (frame[5] >> 7) & 1;

        if (frame_count == 0) {
            subchannels.resize(nst);
            for (int i = 0; i < nst; i++) {
                const uint8_t* stc = frame + 8 + i * 4;
                subchannels[i].scid = (stc[0] >> 2) & 0x3F;
                subchannels[i].stl = ((stc[2] & 0x03) << 8) | stc[3];
            }
        }

        size_t eoh = 8 + nst * 4 + 4;
        size_t fic_len = ficf ? ((mid == 3) ? 128 : 96) : 0;
        size_t offset = eoh + fic_len;

        for (size_t i = 0; i < subchannels.size(); i++) {
            size_t size = subchannels[i].stl * 8;
            if (offset + size <= len) {
                subchannels[i].data.insert(subchannels[i].data.end(),
                    frame + offset, frame + offset + size);
            }
            offset += size;
        }

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
    while (frame_count < MAX_FRAMES &&
           (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount())) {
        source.feed(buffer.data(), file.gcount());
    }

    std::cout << "Collected " << frame_count << " ETI frames\n" << std::endl;

    for (auto& sc : subchannels) {
        int bitrate = (sc.stl * 8 * 8) / 24;
        std::cout << "SCID " << (int)sc.scid << " (" << bitrate << " kbps, "
                  << sc.data.size() << " bytes): ";

        // Check for firecode (DAB+)
        bool has_fire = false;
        for (size_t i = 0; i + 11 < sc.data.size(); i++) {
            if (checkFireCode(sc.data.data() + i)) {
                std::cout << "DAB+ (firecode@" << i << ")" << std::endl;
                has_fire = true;
                break;
            }
        }

        if (!has_fire) {
            // Look for MP2 sync
            bool has_mp2 = false;
            for (size_t i = 0; i + 4 < sc.data.size(); i++) {
                if (sc.data[i] == 0xFF && (sc.data[i+1] & 0xE0) == 0xE0) {
                    int layer = (sc.data[i+1] >> 1) & 3;
                    if (layer == 2) {  // Layer 2
                        std::cout << "DAB/MP2 (sync@" << i << " 0x"
                                  << std::hex << (int)sc.data[i] << " " << (int)sc.data[i+1]
                                  << std::dec << ")" << std::endl;
                        has_mp2 = true;
                        break;
                    }
                }
            }
            if (!has_mp2) {
                std::cout << "DATA (first 16: ";
                for (int i = 0; i < 16 && i < sc.data.size(); i++)
                    printf("%02x ", sc.data[i]);
                std::cout << ")" << std::endl;
            }
        }
    }

    return 0;
}
