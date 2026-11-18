// Tests for dynamic labels: the PAD decoder (X-PAD data groups to labels),
// the character sets, and RDS RadioText in UECP frames. Synthetic PAD, no
// capture needed.

#include "../src/output/pad_decoder.hpp"
#include "../src/output/charsets.hpp"
#include "../src/output/rds_uecp.hpp"
#include "../src/utils/crc_utils.hpp"
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace dvbdab;

static int failures = 0;

static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

using Bytes = std::vector<uint8_t>;

// a dynamic label segment as data group (EN 300 401, 7.4.5.2): prefix, characters, CRC
static Bytes segment(int toggle, int num, bool last, uint8_t charset, const std::string& chars) {
    Bytes dg;
    bool first = num == 0;
    dg.push_back(static_cast<uint8_t>(toggle << 7 | (first ? 0x40 : 0) | (last ? 0x20 : 0) | (chars.size() - 1)));
    dg.push_back(static_cast<uint8_t>(first ? charset << 4 : num << 4));
    dg.insert(dg.end(), chars.begin(), chars.end());
    uint16_t c = crc16_ccitt_xor(dg.data(), dg.size());
    dg.push_back(c >> 8);
    dg.push_back(c & 0xFF);
    return dg;
}

// DL Plus tags (TS 102 980) for the label with this toggle
static Bytes dlplus(int link, uint8_t type, uint8_t start, uint8_t len) {
    Bytes dg = {0x12, static_cast<uint8_t>(link << 7 | 3), 0x00, type, start, len};
    uint16_t c = crc16_ccitt_xor(dg.data(), dg.size());
    dg.push_back(c >> 8);
    dg.push_back(c & 0xFF);
    return dg;
}

// The PAD of one frame with this data group in a variable size X-PAD: one
// contents indicator (data group start, 24 bytes), the end marker, the bytes;
// all in reverse order before the F-PAD
static void feed(PadDecoder& pad, const Bytes& dg) {
    Bytes x = {static_cast<uint8_t>(5 << 5 | 2), 0x00};
    x.insert(x.end(), dg.begin(), dg.end());
    x.resize(2 + 24, 0);
    Bytes room(x.rbegin(), x.rend());
    const uint8_t fpad[2] = {0x20, 0x02};
    pad.process(room.data(), room.size(), fpad);
}

static void feed_label(PadDecoder& pad, int toggle, const std::string& text, size_t per_segment = 16) {
    int n = static_cast<int>((text.size() + per_segment - 1) / per_segment);
    for (int i = 0; i < n; i++)
        feed(pad, segment(toggle, i, i == n - 1, DAB_CHARSET_EBU_LATIN, text.substr(i * per_segment, per_segment)));
}

int main() {
    {
        PadDecoder pad;
        std::vector<std::string> labels;
        pad.setDLSCallback([&](const std::string& t) { labels.push_back(t); });
        feed_label(pad, 0, "Hello World");
        check(labels.size() == 1 && labels[0] == "Hello World", "a label in one segment");
        feed_label(pad, 0, "Hello World");
        check(labels.size() == 1, "the same label again is not a new one");
        feed_label(pad, 1, "A longer text that needs three segments");
        check(labels.size() == 2 && labels[1] == "A longer text that needs three segments", "a label in three segments");
    }
    {
        PadDecoder pad;
        std::vector<std::string> labels;
        pad.setDLSCallback([&](const std::string& t) { labels.push_back(t); });
        const std::string text = "Segments come in any order here!";
        feed(pad, segment(0, 1, true, 0, text.substr(16)));
        check(labels.empty(), "the last segment alone is no label");
        feed(pad, segment(0, 0, false, 0, text.substr(0, 16)));
        check(labels.size() == 1 && labels[0] == text, "both segments are, whatever their order");
    }
    {
        PadDecoder pad;
        std::vector<std::string> labels;
        pad.setDLSCallback([&](const std::string& t) { labels.push_back(t); });
        Bytes bad = segment(0, 0, true, 0, "Damaged text");
        bad[5] ^= 0x04;
        feed(pad, bad);
        check(labels.empty() && pad.getCrcErrors() == 1, "a data group with a wrong CRC is not taken");
        feed(pad, segment(0, 0, true, 0, "Damaged text"));
        check(labels.size() == 1 && labels[0] == "Damaged text", "and the label comes with the next good one");
    }
    {
        // a segment of the old label must not complete the new one
        PadDecoder pad;
        std::vector<std::string> labels;
        pad.setDLSCallback([&](const std::string& t) { labels.push_back(t); });
        feed(pad, segment(0, 0, false, 0, "First half of on"));
        feed(pad, segment(1, 1, true, 0, "e, end of other"));
        check(labels.empty(), "segments of two toggle states are no label");
    }
    {
        PadDecoder pad;
        std::string text;
        std::vector<DLPlusTag> tags;
        pad.setDLPlusCallback([&](const std::string& t, const std::vector<DLPlusTag>& tg) {
            text = t;
            tags = tg;
        });
        feed_label(pad, 0, "Artist - Title");
        feed(pad, dlplus(0, static_cast<uint8_t>(DLPlusContentType::ITEM_TITLE), 9, 4));
        check(tags.size() == 1 && tags[0].extract(text) == "Title", "DL Plus tags of the label");
        // a marker behind the end of the text
        DLPlusTag t{DLPlusContentType::ITEM_TITLE, 100, 20};
        check(t.extract("short").empty(), "a tag behind the end of the text is empty");
    }
    {
        std::string out;
        const uint8_t ebu[] = {0x91, 0x97, 0x99};
        check(dabLabelToUtf8(ebu, 3, DAB_CHARSET_EBU_LATIN, out) && out == "\xC3\xA4\xC3\xB6\xC3\xBC",
              "EBU Latin: a, o and u with diaeresis");
        const uint8_t ucs2[] = {0x00, 0xE4, 0x20, 0xAC};
        check(dabLabelToUtf8(ucs2, 4, DAB_CHARSET_UCS2_BE, out) && out == "\xC3\xA4\xE2\x82\xAC", "UCS-2");
        const uint8_t utf8[] = {'o', 'k', 0xC3, 0xA4};
        check(dabLabelToUtf8(utf8, 4, DAB_CHARSET_UTF8, out) && out == "ok\xC3\xA4", "UTF-8");
        check(!dabLabelToUtf8(ebu, 3, 3, out), "a character set that is not known is refused");
        const uint8_t odd[] = {0x00};
        dabLabelToUtf8(odd, 1, DAB_CHARSET_UCS2_BE, out);
        const uint8_t cut[] = {'a', 0xE2, 0x82};
        dabLabelToUtf8(cut, 3, DAB_CHARSET_UTF8, out);
        check(true, "half a UCS-2 character and a cut UTF-8 sequence are survived");
    }
    {
        check(utf8ToRds("\xC3\xA4") == "\x91", "RDS: a with diaeresis");
        check(utf8ToRds("\xE4\xB8\xAD") == "?", "RDS: a character the set does not have becomes ?");
        std::string longtext;
        for (int i = 0; i < 20; i++) longtext += "word" + std::to_string(i) + " ";
        std::string rt = rdsRadioText(longtext);
        check(rt.size() <= RDS_RT_MAX && rt.size() >= RDS_RT_MAX / 2 && rt.back() != ' ' &&
                  longtext.compare(0, rt.size(), rt) == 0 && longtext[rt.size()] == ' ',
              "RadioText: a long text is cut at a word within 64 characters");
        check(rdsRadioText(std::string(200, 'x')).size() == RDS_RT_MAX, "and one without a space after 64");
    }
    {
        // a text with the bytes a frame must not have inside
        std::string text = "A\xFD" "B\xFE" "C\xFF" "D";
        std::vector<uint8_t> f = uecpRadioTextFrame(text, true);
        bool framed = f.size() > 2 && f.front() == 0xFE && f.back() == 0xFF;
        Bytes u;
        bool clean = true;
        for (size_t i = 1; i + 1 < f.size(); i++) {
            if (f[i] >= 0xFE) clean = false;
            if (f[i] == 0xFD && i + 2 < f.size()) u.push_back(static_cast<uint8_t>(0xFD + f[++i]));
            else u.push_back(f[i]);
        }
        check(framed && clean, "UECP: start, end, and none of them inside the frame");
        bool crc_ok = u.size() > 6 && crc16_ccitt_xor(u.data(), u.size() - 2) ==
                                          static_cast<uint16_t>(u[u.size() - 2] << 8 | u[u.size() - 1]);
        check(crc_ok, "UECP: the CRC of the frame");
        bool msg_ok = u.size() == 6u + 5 + text.size() && u[3] == 5 + text.size() && u[4] == 0x0A &&
                      u[7] == 1 + text.size() && u[8] == 0x01 &&
                      std::string(u.begin() + 9, u.end() - 2) == text;
        check(msg_ok, "UECP: a RadioText message with the text and the A/B flag");
    }

    std::printf("%s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
