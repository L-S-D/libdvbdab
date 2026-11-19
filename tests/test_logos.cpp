// Tests for the logos of the services: the service information file of the
// programme guide (ETSI TS 102 371, built here as the standard says and as
// a real one looks), what an image file is, and the stream processor that
// puts the two together. Synthetic data, no capture needed.

#include "../src/output/dab_stream_processor.hpp"
#include "../src/parsers/spi_si_parser.hpp"
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace dvbdab;

static int failures = 0;

static void check(bool ok, const char* what) {
    printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

using Bytes = std::vector<uint8_t>;

// an element or attribute: tag, length (1 byte, or 0xFE and 2), content
static Bytes item(uint8_t tag, const Bytes& content) {
    Bytes b{tag};
    if (content.size() < 0xFE) {
        b.push_back(static_cast<uint8_t>(content.size()));
    } else {
        b.push_back(0xFE);
        b.push_back(static_cast<uint8_t>(content.size() >> 8));
        b.push_back(static_cast<uint8_t>(content.size()));
    }
    b.insert(b.end(), content.begin(), content.end());
    return b;
}

static Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes b;
    for (const auto& p : parts) b.insert(b.end(), p.begin(), p.end());
    return b;
}

static Bytes text(const std::string& s) { return Bytes(s.begin(), s.end()); }

// a name element: CDATA (tag 0x01) with the text
static Bytes name(uint8_t tag, const std::string& s) { return item(tag, item(0x01, text(s))); }

static Bytes bearer(uint16_t eid, uint32_t sid, bool long_sid = false) {
    Bytes id{static_cast<uint8_t>(long_sid ? 0x50 : 0x40), 0xE0, static_cast<uint8_t>(eid >> 8), static_cast<uint8_t>(eid)};
    if (long_sid) {
        id.push_back(static_cast<uint8_t>(sid >> 24));
        id.push_back(static_cast<uint8_t>(sid >> 16));
    }
    id.push_back(static_cast<uint8_t>(sid >> 8));
    id.push_back(static_cast<uint8_t>(sid));
    return item(0x29, item(0x80, id));
}

// mediaDescription with one multimedia element
static Bytes logo(const std::string& url, int type, int w, int h) {
    Bytes mm = item(0x82, text(url));
    if (type) mm = cat({mm, item(0x83, {static_cast<uint8_t>(type)})});
    if (w) mm = cat({mm, item(0x84, {static_cast<uint8_t>(w >> 8), static_cast<uint8_t>(w)})});
    if (h) mm = cat({mm, item(0x85, {static_cast<uint8_t>(h >> 8), static_cast<uint8_t>(h)})});
    return item(0x13, item(0x2B, mm));
}

static Bytes service_info(const Bytes& services) {
    Bytes ensemble = cat({item(0x80, {0xE0, 0x10, 0xEC}), name(0x10, "ENS"), name(0x11, "Ensemble"), services});
    return item(0x03, cat({item(0x06, text("de")), item(0x26, ensemble)}));
}

static Bytes png(int w, int h, uint8_t fill = 0) {
    Bytes b{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, 'I', 'H', 'D', 'R',
            static_cast<uint8_t>(w >> 24), static_cast<uint8_t>(w >> 16), static_cast<uint8_t>(w >> 8), static_cast<uint8_t>(w),
            static_cast<uint8_t>(h >> 24), static_cast<uint8_t>(h >> 16), static_cast<uint8_t>(h >> 8), static_cast<uint8_t>(h),
            8, 2, 0, 0, 0};
    b.resize(200, fill);
    return b;
}

static Bytes jpeg(int w, int h) {
    Bytes b{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0,   // APP0
            0xFF, 0xDB, 0x00, 0x04, 0x00, 0x00,                                                    // (a short DQT)
            0xFF, 0xC2, 0x00, 0x11, 0x08, static_cast<uint8_t>(h >> 8), static_cast<uint8_t>(h),
            static_cast<uint8_t>(w >> 8), static_cast<uint8_t>(w), 0x03};
    b.resize(120, 0);
    return b;
}

struct Told {
    uint16_t sid;
    std::string mime;
    int w, h;
    size_t len;
};

static void mot(DabStreamProcessor& p, uint16_t tid, int type, int subtype, const std::string& name_, const Bytes& data) {
    MOTHeaderInfo hdr;
    hdr.content_type = static_cast<uint8_t>(type);
    hdr.content_subtype = static_cast<uint16_t>(subtype);
    hdr.content_name = name_;
    hdr.body_size = static_cast<uint32_t>(data.size());
    hdr.valid = true;
    p.onMotObject(tid, hdr, data.data(), data.size());
}

static void add(DabStreamProcessor& p, uint16_t sid, uint8_t subch) {
    TsService s{};
    s.sid = sid;
    s.pmt_pid = static_cast<uint16_t>(0x100 + subch);
    s.audio_pid = static_cast<uint16_t>(0x1000 + subch);
    s.name = "Service";
    s.dabplus = true;
    s.subchannel_id = subch;
    s.bitrate = 64;
    p.addService(s);
}

int main() {
    {
        // the service information file
        Bytes si = service_info(cat({
            item(0x28, cat({bearer(0x10EC, 0xD391), name(0x10, "RADIO 1"), name(0x11, "Radio One"),
                            logo("d391-a.png", 2, 128, 128), item(0x14, {0x80, 0x03, 0x03, 0x06, 0x04})})),
            item(0x28, cat({bearer(0x10EC, 0xD592), bearer(0x10FA, 0xD692), name(0x10, "RADIO 2"),
                            logo("d592-a.png", 2, 128, 128), logo("d592-b.png", 6, 112, 32),
                            logo("d592-c.png", 2, 320, 240), logo("d592-d.png", 4, 0, 0)})),
            item(0x28, cat({bearer(0x10EC, 0xE0D01234, true), logo("data.png", 4, 32, 32)})),
            item(0x28, cat({name(0x10, "no bearer"), logo("none.png", 4, 32, 32)})),
        }));
        SpiServiceInfo out;
        bool ok = parseSpiServiceInformation(si.data(), si.size(), out);
        check(ok && out.has_ensemble && out.ecc == 0xE0 && out.eid == 0x10EC && out.logos.size() == 10,
              "service information: the ensemble and a logo per image and bearer of its service");
        check(ok && out.logos.size() == 10 && out.logos[0].sid == 0xD391 && out.logos[0].url == "d391-a.png" &&
                  out.logos[0].type == 2 && out.logos[0].width == 128 && out.logos[0].height == 128 &&
                  out.logos[1].sid == 0xD592 && out.logos[2].url == "d592-b.png" && out.logos[2].type == 6 &&
                  out.logos[2].width == 112 && out.logos[2].height == 32 && out.logos[4].type == 4 &&
                  out.logos[4].width == 0 && out.logos[5].sid == 0xD692 && out.logos[5].eid == 0x10FA &&
                  out.logos[9].sid == 0xE0D01234 && out.logos[9].url == "data.png",
              "url, type and size of the logos; a service with two bearers; a 32-bit SId");

        // a file byte by byte, as an encoder writes it: the default
        // language, short lengths, the names as CDATA
        const uint8_t real[] = {0x03, 0x61, 0x06, 0x02, 0x64, 0x65, 0x26, 0x5B, 0x80, 0x03, 0xE0, 0x10, 0xEC, 0x10, 0x05,
                                0x01, 0x03, 0x45, 0x4E, 0x53, 0x11, 0x05, 0x01, 0x03, 0x45, 0x4E, 0x53, 0x28, 0x46, 0x29,
                                0x08, 0x80, 0x06, 0x40, 0xE0, 0x10, 0xEC, 0xD3, 0x91, 0x10, 0x07, 0x01, 0x05, 0x52, 0x41,
                                0x44, 0x49, 0x4F, 0x11, 0x07, 0x01, 0x05, 0x52, 0x41, 0x44, 0x49, 0x4F, 0x13, 0x28, 0x2B,
                                0x26, 0x82, 0x19, 'd',  '3',  '9',  '1',  '-',  '0',  '1',  '2',  '3',  '4',  '5',  '6',
                                '7',  '8',  '9',  'a',  'b',  'c',  'd',  'e',  'f',  '.',  'p',  'n',  'g',  0x83, 0x01,
                                0x02, 0x84, 0x02, 0x00, 0x80, 0x85, 0x02, 0x00, 0x80};
        SpiServiceInfo r;
        check(parseSpiServiceInformation(real, sizeof(real), r) && r.eid == 0x10EC && r.logos.size() == 1 &&
                  r.logos[0].sid == 0xD391 && r.logos[0].url == "d391-0123456789abcdef.png" && r.logos[0].width == 128,
              "a file as it is sent");

        // not one, and cut ones
        Bytes epg = item(0x02, item(0x21, {}));
        SpiServiceInfo e;
        check(!parseSpiServiceInformation(epg.data(), epg.size(), e) && !parseSpiServiceInformation(si.data(), 3, e) &&
                  !parseSpiServiceInformation(nullptr, 0, e) && !parseSpiServiceInformation(si.data(), si.size() - 1, e),
              "another file, an empty one and one that is cut are refused");
        bool sane = true;
        for (size_t cut = 0; cut < si.size(); cut++) {
            // the top-level length made to fit: what is inside is cut
            Bytes c(si.begin() + 4, si.begin() + static_cast<std::ptrdiff_t>(cut < 4 ? 4 : cut));
            Bytes f = item(0x03, c);
            SpiServiceInfo o;
            parseSpiServiceInformation(f.data(), f.size(), o);
            sane = sane && o.logos.size() <= 10;
        }
        check(sane, "a file cut anywhere inside gives no more than it has");
    }

    {
        // what an image file is
        int w = -1, h = -1;
        Bytes a = png(32, 32), b = jpeg(320, 240), c = text("GIF89a..........................");
        const char* ma = imageFileInfo(a.data(), a.size(), w, h);
        bool ok = ma && std::string(ma) == "image/png" && w == 32 && h == 32;
        const char* mb = imageFileInfo(b.data(), b.size(), w, h);
        ok = ok && mb && std::string(mb) == "image/jpeg" && w == 320 && h == 240;
        ok = ok && !imageFileInfo(c.data(), c.size(), w, h) && w == 0 && h == 0;
        const char* mc = imageFileInfo(a.data(), 12, w, h);
        ok = ok && mc && w == 0 && h == 0 && !imageFileInfo(a.data(), 4, w, h);
        const char* md = imageFileInfo(b.data(), 28, w, h);
        ok = ok && md && w == 0 && h == 0;
        check(ok, "PNG and JPEG with their size in pixels; anything else is none; a cut one has no size");
    }

    {
        // the processor: the image and the service information, in either order
        DabStreamProcessor p;
        std::vector<Told> told;
        p.setLogoCallback([&](const DabStreamProcessor::ServiceLogo& l) {
            told.push_back({l.sid, l.mime_type, l.width, l.height, l.len});
        });
        p.setEnsemble(0x10EC, "Ensemble", "Ensemble");
        add(p, 0xD391, 1);
        add(p, 0xD592, 2);
        Bytes si = service_info(cat({
            item(0x28, cat({bearer(0x10EC, 0xD391), logo("a.png", 2, 128, 128), logo("a.jpg", 2, 320, 240)})),
            item(0x28, cat({bearer(0x10EC, 0xD592), logo("b.png", 4, 0, 0), logo("a.png", 2, 128, 128)})),
            item(0x28, cat({bearer(0x10EC, 0xD999), logo("c.png", 4, 0, 0)})),
            item(0x28, cat({bearer(0x10EC, 0xD777), logo("late.png", 6, 0, 0)})),
        }));
        mot(p, 1, 2, 3, "a.png", png(128, 128));
        mot(p, 2, 2, 3, "c.png", png(32, 32));
        mot(p, 3, 2, 3, "other.png", png(32, 32));
        check(told.empty(), "an image alone is the logo of no service");
        mot(p, 4, 7, 0, "si.EIB", si);
        check(told.size() == 2 && told[0].sid != told[1].sid && told[0].w == 128 && told[0].mime == "image/png" &&
                  told[0].len == 200,
              "with the service information it is told to the services it belongs to, not to a service that is not there");
        mot(p, 5, 2, 1, "a.jpg", jpeg(320, 240));
        mot(p, 6, 2, 3, "b.png", png(32, 32));
        check(told.size() == 4 && told[2].sid == 0xD391 && told[2].mime == "image/jpeg" && told[2].w == 320 &&
                  told[2].h == 240 && told[3].sid == 0xD592 && told[3].w == 32,
              "an image that comes after the service information is told then");
        // the carousel comes round
        mot(p, 1, 2, 3, "a.png", png(128, 128));
        mot(p, 4, 7, 0, "si.EIB", si);
        mot(p, 6, 2, 3, "b.png", png(32, 32));
        check(told.size() == 4, "the same again is not told again");
        mot(p, 7, 2, 3, "b.png", png(32, 32, 0x55));
        check(told.size() == 5 && told[4].sid == 0xD592, "another image under the same name is told");
        // a service that comes after its logo
        mot(p, 8, 2, 3, "late.png", png(112, 32));
        size_t before = told.size();
        add(p, 0xD777, 3);
        check(before == 5 && told.size() == 6 && told[5].sid == 0xD777 && told[5].w == 112 && told[5].h == 32,
              "a service that is added after its logo came gets it then");
        // not an image, and too much
        mot(p, 9, 2, 3, "b.png", text("not an image at all, whatever its name says"));
        check(told.size() == 6, "a file that is no PNG or JPEG is no logo");
    }

    {
        // without a callback nothing is kept: a callback set later starts from nothing
        DabStreamProcessor p;
        add(p, 0xD391, 1);
        Bytes si = service_info(item(0x28, cat({bearer(0x10EC, 0xD391), logo("a.png", 2, 128, 128)})));
        mot(p, 1, 2, 3, "a.png", png(128, 128));
        mot(p, 2, 7, 0, "x.EIB", si);
        int n = 0;
        p.setLogoCallback([&](const DabStreamProcessor::ServiceLogo&) { n++; });
        mot(p, 2, 7, 0, "x.EIB", si);
        bool none = n == 0;
        mot(p, 1, 2, 3, "a.png", png(128, 128));
        check(none && n == 1, "without a callback the images are not kept");
    }

    printf("%s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
