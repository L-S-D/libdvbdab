// Fuzz harness: PAD into the PAD decoder, the labels it gives into RDS
// RadioText and its UECP frames (the parts of a long one, the whole label),
// the MOT data groups of the slideshow into a MOT decoder and its objects
// into the frames of a slide. The input is a sequence of frames
// [length of the X-PAD room, 1 byte][the room][F-PAD, 2 bytes]; a room of
// length 255 stands for lost frames.

#include "../src/output/pad_decoder.hpp"
#include "../src/output/charsets.hpp"
#include "../src/output/rds_uecp.hpp"
#include "../src/parsers/packet_decoder.hpp"
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

using namespace dvbdab;

namespace {

bool valid_utf8(const std::string& s) {
    for (size_t i = 0; i < s.size();) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
        if (!n || i + n > s.size()) return false;
        for (size_t k = 1; k < n; k++)
            if ((static_cast<unsigned char>(s[i + k]) >> 6) != 2) return false;
        i += n;
    }
    return true;
}

void on_label(const std::string& text) {
    if (!valid_utf8(text)) abort();
    std::string rt = rdsRadioText(text);
    if (rt.size() > RDS_RT_MAX) abort();
    std::vector<uint8_t> f = uecpRadioTextFrame(rt, true);
    if (f.size() < 2 || f.front() != 0xFE || f.back() != 0xFF) abort();
    for (size_t i = 1; i + 1 < f.size(); i++)
        if (f[i] >= 0xFE) abort();
    for (const auto& part : rdsRadioTextParts(text))
        if (part.text.empty() || part.text.size() > RDS_RT_MAX) abort();
    std::vector<uint8_t> l = uecpLabelFrame(text);
    if (!text.empty() && (l.size() < 2 || l.front() != 0xFE || l.back() != 0xFF)) abort();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    PadDecoder pad;
    pad.setDLSCallback(on_label);
    pad.setDLPlusCallback([](const std::string& text, const std::vector<DLPlusTag>& tags) {
        for (const auto& t : tags) (void)t.extract(text);
    });
    PacketDecoder mot;
    mot.setMotCallback([](uint16_t, const MOTHeaderInfo& hdr, const uint8_t* file, size_t len) {
        (void)hdr.content_name.size();
        for (const auto& f : uecpSlideFrames(1, file, len))
            if (f.size() < 2 || f.front() != 0xFE || f.back() != 0xFF) abort();
    });
    pad.setMotDataGroupCallback([&mot](const uint8_t* dg, size_t len) {
        std::vector<uint8_t> x(dg, dg + len);
        mot.feedDataGroup(x.data(), x.size());
    });
    while (size >= 1) {
        size_t room = data[0];
        data++;
        size--;
        if (room == 255) {
            pad.discontinuity();
            continue;
        }
        if (size < room + 2) break;
        // from a block of exactly the size: a sanitizer sees a read behind it
        std::vector<uint8_t> x(data, data + room + 2);
        pad.process(x.data(), room, x.data() + room);
        data += room + 2;
        size -= room + 2;
    }
    // as the PAD of DAB+ AUs too
    if (size >= 2) {
        std::vector<uint8_t> au(data, data + size);
        pad.processAu(au.data(), au.size());
    }
    return 0;
}
