// RDS RadioText in UECP frames (IEC 62106-10)

#include "rds_uecp.hpp"
#include "charsets.hpp"
#include "../utils/crc_utils.hpp"

namespace dvbdab {

namespace {

constexpr uint8_t UECP_STA = 0xFE;   // start of a frame
constexpr uint8_t UECP_STP = 0xFF;   // its end
constexpr uint8_t UECP_STUFF = 0xFD; // FD, FE, FF inside a frame: FD 00, FD 01, FD 02
constexpr uint8_t MEC_RT = 0x0A;     // RadioText
constexpr uint8_t MEC_MANUFACTURER = 0x2D;  // manufacturer's specific command
constexpr uint8_t MEC_ODA_CONF = 0x40;  // ODA configuration and short message command
constexpr uint8_t MEC_ODA_DATA = 0x46;  // ODA data
constexpr uint16_t RT_PLUS_AID = 0x4BD7;  // the application identification of RT+

} // namespace

// Where an RDS text of this length is cut: at its last space within
// RDS_RT_MAX (if that is not before the middle), else after RDS_RT_MAX
static size_t cutAt(const std::string& rds) {
    if (rds.size() <= RDS_RT_MAX) return rds.size();
    size_t cut = rds.rfind(' ', RDS_RT_MAX);
    return cut != std::string::npos && cut >= RDS_RT_MAX / 2 ? cut : RDS_RT_MAX;
}

std::string rdsRadioText(const std::string& utf8) {
    return rdsRadioTextMapped(utf8).text;
}

// the text in the RDS character set, with where each character of the source went
static RdsText rdsWhole(const std::string& utf8) {
    RdsText r;
    for (size_t i = 0; i < utf8.size();) {
        size_t n = 1;
        while (i + n < utf8.size() && (static_cast<unsigned char>(utf8[i + n]) & 0xC0) == 0x80) n++;
        std::string one = utf8ToRds(utf8.substr(i, n));
        r.at.push_back(static_cast<int>(r.text.size()));
        r.width.push_back(static_cast<int>(one.size()));
        r.text += one;
        i += n;
    }
    return r;
}

std::vector<RdsText> rdsRadioTextParts(const std::string& utf8) {
    RdsText whole = rdsWhole(utf8);
    std::vector<RdsText> parts;
    size_t pos = 0;
    while (parts.size() < RDS_RT_PARTS) {
        while (pos < whole.text.size() && whole.text[pos] == ' ' && !parts.empty()) pos++;   // (cut at a space)
        if (pos >= whole.text.size()) break;
        RdsText p;
        p.text = whole.text.substr(pos);
        p.text.resize(cutAt(p.text));
        size_t taken = p.text.size();
        while (!p.text.empty() && p.text.back() == ' ') p.text.pop_back();
        p.at.assign(whole.at.size(), -1);
        p.width = whole.width;
        for (size_t c = 0; c < whole.at.size(); c++) {
            size_t from = static_cast<size_t>(whole.at[c]), to = from + static_cast<size_t>(whole.width[c]);
            if (from >= pos && to <= pos + p.text.size()) p.at[c] = static_cast<int>(from - pos);
        }
        pos += taken;
        if (!p.text.empty()) parts.push_back(std::move(p));
    }
    return parts;
}

RdsText rdsRadioTextMapped(const std::string& utf8) {
    std::vector<RdsText> parts = rdsRadioTextParts(utf8);
    if (!parts.empty()) return parts.front();
    // no text: every character of the source is nowhere
    RdsText r = rdsWhole(utf8);
    r.text.clear();
    for (int& a : r.at) a = -1;
    return r;
}

// A UECP frame around a message field: address, sequence counter, length,
// the message elements, CRC; with start and stop byte and byte stuffing
static std::vector<uint8_t> uecpFrame(const std::vector<uint8_t>& msg) {
    std::vector<uint8_t> body = {0x00, 0x00,  // address: all sites and encoders
                                 0x00};       // sequence counter: not used
    body.push_back(static_cast<uint8_t>(msg.size()));
    body.insert(body.end(), msg.begin(), msg.end());
    // CCITT, preset to ones, inverted: over address, sequence counter, length and message
    uint16_t crc = crc16_ccitt_xor(body.data(), body.size());
    body.push_back(static_cast<uint8_t>(crc >> 8));
    body.push_back(static_cast<uint8_t>(crc));

    std::vector<uint8_t> frame = {UECP_STA};
    for (uint8_t b : body) {
        if (b >= UECP_STUFF) {
            frame.push_back(UECP_STUFF);
            frame.push_back(static_cast<uint8_t>(b - UECP_STUFF));
        } else {
            frame.push_back(b);
        }
    }
    frame.push_back(UECP_STP);
    return frame;
}

std::vector<uint8_t> uecpRadioTextFrame(const std::string& rds_text, bool ab_flag) {
    // message element: MEC, data set number, programme service number, message
    // element length, then the RadioText configuration (buffer configuration
    // 00 = this text alone, number of transmissions 0, A/B flag) and the text
    std::vector<uint8_t> msg = {MEC_RT, 0x00, 0x00, static_cast<uint8_t>(1 + rds_text.size()),
                                static_cast<uint8_t>(ab_flag ? 0x01 : 0x00)};
    msg.insert(msg.end(), rds_text.begin(), rds_text.end());
    return uecpFrame(msg);
}

std::vector<uint8_t> uecpLabelFrame(const std::string& utf8) {
    if (utf8.empty()) return {};
    // at most UECP_LABEL_MAX bytes, not cut inside a character
    size_t n = utf8.size();
    if (n > UECP_LABEL_MAX) {
        n = UECP_LABEL_MAX;
        while (n > 0 && (static_cast<unsigned char>(utf8[n]) & 0xC0) == 0x80) n--;
    }
    // message element: MEC, message element length, the designation, the
    // command (0x01: a dynamic label in UTF-8), the text
    std::vector<uint8_t> msg = {MEC_MANUFACTURER, static_cast<uint8_t>(3 + n), 'd', 'l', 0x01};
    msg.insert(msg.end(), utf8.begin(), utf8.begin() + static_cast<std::ptrdiff_t>(n));
    return uecpFrame(msg);
}

std::vector<RtPlusTag> rtPlusTags(const RdsText& mapped,
                                  const std::vector<std::array<uint8_t, 3>>& dl_plus_tags) {
    std::vector<RtPlusTag> out;
    for (const auto& t : dl_plus_tags) {
        size_t first = t[1], last = static_cast<size_t>(t[1]) + t[2];
        // RT+ has 6 bits for the content type; the whole tag must be in the text
        if (t[0] == 0 || t[0] > 63 || last >= mapped.at.size() || mapped.at[first] < 0 || mapped.at[last] < 0) continue;
        int start = mapped.at[first];
        int length = mapped.at[last] + mapped.width[last] - start;
        if (length < 1 || start > 63 || length > 64) continue;
        out.push_back({t[0], static_cast<uint8_t>(start), static_cast<uint8_t>(length - 1)});
    }
    return out;
}

std::vector<uint8_t> uecpRtPlusFrame(const std::vector<RtPlusTag>& tags, bool item_toggle, bool item_running) {
    if (tags.empty()) return {};

    // Two tags per group; the second place has 5 bits for the length. A tag
    // longer than that takes a first place, with another short one or alone.
    std::vector<std::array<RtPlusTag, 2>> groups;
    std::vector<RtPlusTag> long_tags, short_tags;
    for (const auto& t : tags) (t.length_minus_1 > 31 ? long_tags : short_tags).push_back(t);
    size_t s = 0;
    for (const auto& t : long_tags) {
        groups.push_back({t, s < short_tags.size() ? short_tags[s] : RtPlusTag{}});
        if (s < short_tags.size()) s++;
    }
    for (; s < short_tags.size(); s += 2) {
        groups.push_back({short_tags[s], s + 1 < short_tags.size() ? short_tags[s + 1] : RtPlusTag{}});
    }

    // ODA configuration and short message command: group type code 11A,
    // AID, buffer configuration (cyclic), the message bits of the 3A group
    // (RT+ of the RadioText, no template), data input timeout off
    std::vector<uint8_t> msg = {MEC_ODA_CONF, 0x16, RT_PLUS_AID >> 8, RT_PLUS_AID & 0xFF, 0x02, 0x00, 0x00, 0x00};
    for (const auto& g : groups) {
        // ODA data: length, AID, configuration (normal priority and mode,
        // sent once), then the 37 bits of the group - 5 bits of block 2,
        // block 3, block 4: item toggle, item running, and per tag content
        // type (6 bits), start (6), length - 1 (6, and 5 for the second)
        uint64_t bits = static_cast<uint64_t>(item_toggle) << 36 | static_cast<uint64_t>(item_running) << 35 |
                        static_cast<uint64_t>(g[0].content_type & 0x3F) << 29 |
                        static_cast<uint64_t>(g[0].start & 0x3F) << 23 |
                        static_cast<uint64_t>(g[0].length_minus_1 & 0x3F) << 17 |
                        static_cast<uint64_t>(g[1].content_type & 0x3F) << 11 |
                        static_cast<uint64_t>(g[1].start & 0x3F) << 5 | (g[1].length_minus_1 & 0x1F);
        msg.insert(msg.end(), {MEC_ODA_DATA, 0x08, RT_PLUS_AID >> 8, RT_PLUS_AID & 0xFF, 0x00,
                               static_cast<uint8_t>(bits >> 32), static_cast<uint8_t>(bits >> 24),
                               static_cast<uint8_t>(bits >> 16), static_cast<uint8_t>(bits >> 8),
                               static_cast<uint8_t>(bits)});
    }
    return uecpFrame(msg);
}

} // namespace dvbdab
