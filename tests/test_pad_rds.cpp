// Tests for dynamic labels: the PAD decoder (X-PAD data groups to labels),
// the character sets, and RDS RadioText in UECP frames. Synthetic PAD, no
// capture needed.

#include "../src/output/pad_decoder.hpp"
#include "../src/output/charsets.hpp"
#include "../src/output/rds_uecp.hpp"
#include "../src/output/ts_muxer.hpp"
#include "../src/utils/crc_utils.hpp"
#include <algorithm>
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
static Bytes dlplus(int link, uint8_t type, uint8_t start, uint8_t len, bool item_toggle = false,
                    bool item_running = false) {
    Bytes dg = {0x12, static_cast<uint8_t>(link << 7 | 3), static_cast<uint8_t>(item_toggle << 3 | item_running << 2),
                type, start, len};
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
        check(!tags[0].item_toggle && !tags[0].item_running, "without the item bits of the command");
        feed(pad, dlplus(0, static_cast<uint8_t>(DLPlusContentType::ITEM_TITLE), 9, 4, true, true));
        check(tags.size() == 1 && tags[0].item_toggle && tags[0].item_running,
              "a command with other item bits is a new one, and the tags have them");
        // the markers count characters: two letters of two bytes before the tag
        DLPlusTag lied{DLPlusContentType::ITEM_TITLE, 8, 3};
        check(lied.extract("\xC3\x84rzte \xE2\x80\x93 Lied") == "Lied" &&
                  DLPlusTag{DLPlusContentType::ITEM_ARTIST, 0, 4}.extract("\xC3\x84rzte - Lied") == "\xC3\x84rzte",
              "a tag is taken out by characters, not bytes");
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
        check(utf8ToRds("Fu\xC3\x9F" "ball") == "Fu\x8D" "ball", "RDS: sharp s");
        check(utf8ToRds("\xE2\x80\x9C" "a\xE2\x80\x9D \xE2\x80\x93 b\xE2\x80\x99s\xE2\x80\xA6") == "\"a\" - b's...",
              "RDS: typographic quotes, dash and ellipsis by what comes closest");
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

    {
        // RadioText Plus: the tags of DL Plus, by where their characters are in the RadioText
        const uint8_t TITLE = 1, ARTIST = 4, ALBUM = 2;
        RdsText m = rdsRadioTextMapped("Artist - Title");
        std::vector<RtPlusTag> tags = rtPlusTags(m, {{ARTIST, 0, 5}, {TITLE, 9, 4}});
        check(m.text == "Artist - Title" && tags.size() == 2 && tags[0].content_type == ARTIST && tags[0].start == 0 &&
                  tags[0].length_minus_1 == 5 && tags[1].content_type == TITLE && tags[1].start == 9 &&
                  tags[1].length_minus_1 == 4,
              "RT+: tags of a label that is the RadioText as it is");

        // the frame, read as Kodi reads it (VideoPlayerRadioRDS.cpp)
        struct Group {
            bool toggle, running;
            int typ[2], start[2], len[2];
        };
        auto read = [](const std::vector<uint8_t>& f, bool& announced) {
            std::vector<Group> groups;
            Bytes u;
            for (size_t i = 1; i + 1 < f.size(); i++) {
                if (f[i] == 0xFD && i + 2 < f.size()) u.push_back(static_cast<uint8_t>(0xFD + f[++i]));
                else u.push_back(f[i]);
            }
            announced = false;
            if (u.size() < 6 || u[3] + 6u != u.size() ||
                crc16_ccitt_xor(u.data(), u.size() - 2) != static_cast<uint16_t>(u[u.size() - 2] << 8 | u[u.size() - 1]))
                return groups;
            const uint8_t* e = u.data() + 4;
            size_t left = u[3];
            while (left > 0) {
                if (e[0] == 0x40 && left >= 8) {   // ODA configuration: 8 bytes
                    announced = e[1] == 0x16 && e[2] == 0x4B && e[3] == 0xD7;
                    e += 8;
                    left -= 8;
                } else if (e[0] == 0x46 && left >= 10 && e[1] == 8 && e[2] == 0x4B && e[3] == 0xD7) {
                    Group g;
                    g.toggle = e[5] & 0x10;
                    g.running = e[5] & 0x08;
                    g.typ[0] = (0x38 & e[5] << 3) | e[6] >> 5;
                    g.start[0] = (0x3e & e[6] << 1) | e[7] >> 7;
                    g.len[0] = 0x3f & e[7] >> 1;
                    g.typ[1] = (0x20 & e[7] << 5) | e[8] >> 3;
                    g.start[1] = (0x38 & e[8] << 3) | e[9] >> 5;
                    g.len[1] = 0x1f & e[9];
                    groups.push_back(g);
                    e += 10;
                    left -= 10;
                } else {
                    groups.clear();
                    break;
                }
            }
            return groups;
        };
        bool announced = false;
        std::vector<Group> g = read(uecpRtPlusFrame(tags, true, true), announced);
        check(announced && g.size() == 1 && g[0].toggle && g[0].running && g[0].typ[0] == ARTIST && g[0].start[0] == 0 &&
                  g[0].len[0] == 5 && g[0].typ[1] == TITLE && g[0].start[1] == 9 && g[0].len[1] == 4,
              "RT+: the application is announced, a group has both tags and the item bits");
        g = read(uecpRtPlusFrame(tags, false, false), announced);
        check(g.size() == 1 && !g[0].toggle && !g[0].running, "RT+: item bits that are not set");
        check(uecpRtPlusFrame({}, true, true).empty(), "RT+: no frame without tags");

        // a character that becomes three ("..."), and letters outside ASCII
        m = rdsRadioTextMapped("Wait\xE2\x80\xA6 Title \xC3\xA4\xC3\xB6");
        tags = rtPlusTags(m, {{TITLE, 6, 4}, {ALBUM, 12, 1}});
        check(m.text.substr(0, 13) == "Wait... Title" && tags.size() == 2 && tags[0].start == 8 &&
                  tags[0].length_minus_1 == 4 && tags[1].start == 14 && tags[1].length_minus_1 == 1 &&
                  m.text.substr(tags[0].start, tags[0].length_minus_1 + 1u) == "Title",
              "RT+: markers follow the characters into the RadioText");

        // a label longer than a RadioText: tags behind the cut or across it are left out
        std::string longlabel = "Artist Name - " + std::string(20, 'a') + " " + std::string(20, 'b') + " " +
                                std::string(20, 'c') + " the end";
        m = rdsRadioTextMapped(longlabel);
        tags = rtPlusTags(m, {{ARTIST, 0, 10}, {TITLE, 14, 70}, {ALBUM, 80, 6}, {0, 0, 0}, {70, 0, 3}});
        check(m.text.size() <= RDS_RT_MAX && tags.size() == 1 && tags[0].content_type == ARTIST,
              "RT+: of a label that was cut only the tags that are whole in the RadioText; no dummy, no type above 63");

        // three tags, one too long for a second place: two groups, the long one in a first place
        m = rdsRadioTextMapped(std::string(40, 't') + " by Artist on Album");
        tags = rtPlusTags(m, {{ARTIST, 44, 5}, {TITLE, 0, 39}, {ALBUM, 54, 4}});
        g = read(uecpRtPlusFrame(tags, false, true), announced);
        check(tags.size() == 3 && g.size() == 2 && g[0].typ[0] == TITLE && g[0].len[0] == 39 && g[0].typ[1] == ARTIST &&
                  g[0].start[1] == 44 && g[1].typ[0] == ALBUM && g[1].start[0] == 54 && g[1].typ[1] == 0,
              "RT+: a tag of 40 characters takes a first place, three tags are two groups");
    }
    {
        // in the TS: the RT+ frame follows the RadioText in its PES, and goes with the text
        TsMuxer mux;
        std::vector<uint8_t> ts;
        mux.setOutput([&](const uint8_t* d, size_t n) { ts.insert(ts.end(), d, d + n); });
        TsService svc{};
        svc.sid = 0x1000;
        svc.pmt_pid = 0x100;
        svc.audio_pid = 0x1000;
        svc.rds_pid = 0x1100;
        mux.addService(svc);
        auto run = [&](int64_t from) {
            for (int i = 0; i < 200; i++) mux.tick(from + i * 2160);
        };
        const uint8_t oda[] = {0x46, 0x08, 0x4B, 0xD7};
        auto count = [&](size_t from) {
            size_t n = 0;
            for (auto it = ts.begin() + static_cast<std::ptrdiff_t>(from);
                 (it = std::search(it, ts.end(), oda, oda + 4)) != ts.end(); ++it)
                n++;
            return n;
        };
        mux.setRadioText(0x1000, "Artist - Title");
        mux.setRadioTextPlus(0x1000, "Another text", {{4, 0, 5}}, true, true);
        run(90000);
        check(count(0) == 0, "RT+ tags of a label that is not the RadioText are not sent");
        size_t mark = ts.size();
        mux.setRadioTextPlus(0x1000, "Artist - Title", {{4, 0, 5}, {1, 9, 4}}, true, true);
        run(90000 + 200 * 2160);
        check(count(mark) >= 1, "RT+ tags of the RadioText are in the TS");
        mark = ts.size();
        mux.setRadioText(0x1000, "Something else");
        run(90000 + 400 * 2160);
        check(count(mark) == 0, "with a new RadioText the old tags are gone");
    }

    {
        // a label longer than a RadioText: its parts, each a RadioText, and the tags in each
        const std::string text = "Now on air: The Morning Show with the latest news, the weather and "
                                 "the traffic for the whole region, every half hour";
        auto parts = rdsRadioTextParts(text);
        bool ok = text.size() > 64 && parts.size() == 2 && parts[0].text.size() <= 64 && parts[1].text.size() <= 64 &&
                  parts[0].text + " " + parts[1].text == text && rdsRadioTextMapped(text).text == parts[0].text;
        check(ok, "a long label is whole in two RadioTexts, cut at a space");
        check(rdsRadioTextParts("Short").size() == 1 && rdsRadioTextParts("Short")[0].text == "Short" &&
                  rdsRadioTextParts("").empty() && rdsRadioTextMapped("").text.empty(),
              "a short label is one RadioText, an empty one none");
        std::string huge;
        for (int i = 0; i < 60; i++) huge += "word ";
        auto many = rdsRadioTextParts(huge);
        bool fits = many.size() == RDS_RT_PARTS;
        for (const auto& m : many) fits = fits && !m.text.empty() && m.text.size() <= 64 && m.text.back() != ' ';
        check(fits, "no more parts than RDS_RT_PARTS, none longer than a RadioText");
        size_t at = text.find("traffic");
        std::vector<std::array<uint8_t, 3>> tags = {{1, static_cast<uint8_t>(at), 6}, {4, 12, 15}};
        auto t0 = rtPlusTags(parts[0], tags), t1 = rtPlusTags(parts[1], tags);
        check(ok && t0.size() == 1 && t0[0].content_type == 4 && t0[0].start == 12 && t0[0].length_minus_1 == 15 &&
                  t1.size() == 1 && t1[0].content_type == 1 && t1[0].start == parts[1].text.find("traffic") &&
                  t1[0].length_minus_1 == 6,
              "each part has the RT+ tags that are in it, by where they are in that part");

        // the whole label in a frame of its own
        auto unstuff = [](const std::vector<uint8_t>& f) {
            std::vector<uint8_t> u;
            for (size_t i = 1; i + 1 < f.size(); i++) {
                if (f[i] == 0xFD && i + 2 < f.size()) u.push_back(static_cast<uint8_t>(0xFD + f[++i]));
                else u.push_back(f[i]);
            }
            return u;
        };
        auto f = uecpLabelFrame(text);
        auto u = unstuff(f);
        bool frame_ok = f.size() > 12 && f.front() == 0xFE && f.back() == 0xFF && u.size() == 4 + 5 + text.size() + 2 &&
                        u[3] == 5 + text.size() && u[4] == 0x2D && u[5] == 3 + text.size() && u[6] == 'd' &&
                        u[7] == 'l' && u[8] == 0x01 && std::string(u.begin() + 9, u.end() - 2) == text &&
                        crc16_ccitt_xor(u.data(), u.size() - 2) == static_cast<uint16_t>(u[u.size() - 2] << 8 | u.back());
        check(frame_ok, "the whole label in a manufacturer's specific command (MEC 0x2D, 'dl', 0x01)");
        std::string wide;
        for (int i = 0; i < 150; i++) wide += "\xC3\xA4";   // 150 times a letter of two bytes
        auto w = unstuff(uecpLabelFrame(wide));
        check(uecpLabelFrame("").empty() && w.size() == 4 + 5 + 250 + 2 && w[5] == 253 && w[w.size() - 3] == 0xA4,
              "a label of more than 250 bytes is cut between two characters; none without a text");

        // in the TS: the parts take turns, each with the other A/B flag; the whole label goes with them
        TsMuxer mux;
        std::vector<uint8_t> rds;   // the PES payloads of the RDS PID
        mux.setOutput([&](const uint8_t* d, size_t n) {
            for (size_t i = 0; i + 188 <= n; i += 188) {
                const uint8_t* t = d + i;
                if ((((t[1] & 0x1F) << 8) | t[2]) != 0x1100) continue;
                size_t off = 4 + ((t[3] & 0x20) ? 1 + t[4] : 0);
                if ((t[1] & 0x40) && off + 9 <= 188) off += 9 + t[off + 8];
                if (off < 188) rds.insert(rds.end(), t + off, t + 188);
            }
        });
        TsService svc{};
        svc.sid = 0x1000;
        svc.pmt_pid = 0x100;
        svc.audio_pid = 0x1000;
        svc.rds_pid = 0x1100;
        mux.addService(svc);
        mux.setRadioText(0x1000, text);
        mux.setRadioTextPlus(0x1000, text, tags, false, true);
        for (int i = 0; i < 1000; i++) mux.tick(90000 + i * 2160);   // 24 s
        // the RadioText frames in order: which part, which A/B flag
        std::vector<std::pair<int, int>> seen;
        for (size_t i = 0; i + 5 < rds.size(); i++) {
            if (rds[i] != 0xFE || rds[i + 5] != 0x0A) continue;
            size_t len = rds[i + 8];
            if (len < 1 || i + 9 + len > rds.size()) continue;
            std::string rt(rds.begin() + static_cast<std::ptrdiff_t>(i) + 10, rds.begin() + static_cast<std::ptrdiff_t>(i + 9 + len));
            int part = rt == parts[0].text ? 0 : rt == parts[1].text ? 1 : -1;
            if (seen.empty() || seen.back().first != part) seen.push_back({part, rds[i + 9] & 1});
        }
        bool turns = seen.size() >= 4;
        for (size_t i = 0; turns && i < seen.size(); i++) {
            turns = seen[i].first == static_cast<int>(i % 2) && (i == 0 || seen[i].second != seen[i - 1].second);
        }
        check(turns, "in the TS the parts of a long label take turns, each a new RadioText (A/B flag)");
        size_t labels = 0;
        for (auto it = rds.begin(); (it = std::search(it, rds.end(), text.begin(), text.end())) != rds.end(); ++it) labels++;
        check(labels >= 6, "and the whole label goes with every one of them");
    }

    std::printf("%s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
