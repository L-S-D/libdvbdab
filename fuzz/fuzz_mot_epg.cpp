// Fuzz harness: the bytes of a data subchannel into the packet mode and MOT
// decoder (its files into the EHB parser, as the stream processor does), or
// the input as an EHB file. The first byte chooses.

#include "../src/parsers/packet_decoder.hpp"
#include "../src/parsers/ehb_parser.hpp"
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

using namespace dvbdab;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    uint8_t mode = data[0];
    data++;
    size--;
    EhbParser ehb;
    ehb.setScheduleCallback([](const ServiceSchedule& s) {
        for (const auto& e : s.events) (void)e.title.size();
    });
    if (mode & 1) {
        std::vector<uint8_t> file(data, data + size);
        ehb.parse("w20261118d1234.EHB", file.data(), file.size());
        return 0;
    }
    PacketDecoder dec;
    dec.setMotCallback([&](uint16_t, const MOTHeaderInfo& hdr, const uint8_t* file, size_t len) {
        ehb.parse(hdr.content_name, file, len);
    });
    // in pieces of a subchannel frame (the size from the second byte)
    size_t piece = 24 * (1 + (mode >> 1) % 16);
    while (size) {
        size_t n = size < piece ? size : piece;
        std::vector<uint8_t> x(data, data + n);
        dec.feedSubchannelData(x.data(), n);
        data += n;
        size -= n;
    }
    return 0;
}
