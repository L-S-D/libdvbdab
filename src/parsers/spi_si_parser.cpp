#include "spi_si_parser.hpp"
#include <algorithm>

namespace dvbdab {

namespace {

// Tags of ETSI TS 102 371 (annexes D and E)
constexpr uint8_t TAG_SERVICE_INFORMATION = 0x03;
constexpr uint8_t TAG_MEDIA_DESCRIPTION = 0x13;
constexpr uint8_t TAG_ENSEMBLE = 0x26;
constexpr uint8_t TAG_SERVICE = 0x28;
constexpr uint8_t TAG_BEARER = 0x29;
constexpr uint8_t TAG_MULTIMEDIA = 0x2B;
constexpr uint8_t ATTR_ID = 0x80;              // of ensemble and bearer
constexpr uint8_t ATTR_MM_URL = 0x82;          // of multimedia
constexpr uint8_t ATTR_MM_TYPE = 0x83;
constexpr uint8_t ATTR_MM_WIDTH = 0x84;
constexpr uint8_t ATTR_MM_HEIGHT = 0x85;

constexpr size_t MAX_LOGOS = 4096;
constexpr size_t MAX_URL = 255;
constexpr int MAX_DEPTH = 8;

// An element or attribute: a tag, a length of 1, 3 (0xFE) or 4 (0xFF) bytes,
// its bytes. False when it does not fit into what is left.
struct Item {
    uint8_t tag;
    const uint8_t* data;
    size_t len;
};

bool next(const uint8_t* d, size_t len, size_t& pos, Item& it) {
    if (pos + 2 > len) return false;
    it.tag = d[pos];
    size_t n = d[pos + 1];
    size_t head = 2;
    if (n == 0xFE) {
        if (pos + 4 > len) return false;
        n = static_cast<size_t>(d[pos + 2]) << 8 | d[pos + 3];
        head = 4;
    } else if (n == 0xFF) {
        if (pos + 5 > len) return false;
        n = static_cast<size_t>(d[pos + 2]) << 16 | static_cast<size_t>(d[pos + 3]) << 8 | d[pos + 4];
        head = 5;
    }
    if (n > len - pos - head) return false;
    it.data = d + pos + head;
    it.len = n;
    pos += head + n;
    return true;
}

struct Bearer {
    uint32_t sid;
    uint8_t ecc;
    uint16_t eid;
};

struct Picture {
    std::string url;
    uint8_t type{0};
    uint16_t width{0}, height{0};
};

// multimedia: where the image is and what it is
bool multimedia(const Item& mm, Picture& p) {
    size_t pos = 0;
    Item a;
    while (next(mm.data, mm.len, pos, a)) {
        switch (a.tag) {
            case ATTR_MM_URL:
                if (a.len == 0 || a.len > MAX_URL) return false;
                p.url.assign(reinterpret_cast<const char*>(a.data), a.len);
                break;
            case ATTR_MM_TYPE:
                if (a.len == 1) p.type = a.data[0];
                break;
            case ATTR_MM_WIDTH:
                if (a.len == 2) p.width = static_cast<uint16_t>(a.data[0] << 8 | a.data[1]);
                break;
            case ATTR_MM_HEIGHT:
                if (a.len == 2) p.height = static_cast<uint16_t>(a.data[0] << 8 | a.data[1]);
                break;
            default:
                break;
        }
    }
    return !p.url.empty();
}

// service: its bearers in the dab: domain and the images of its
// mediaDescription elements
void service(const Item& svc, SpiServiceInfo& out) {
    std::vector<Bearer> bearers;
    std::vector<Picture> pictures;
    size_t pos = 0;
    Item e;
    while (next(svc.data, svc.len, pos, e)) {
        if (e.tag == TAG_BEARER) {
            // id: Rfa, Ens flag, X-PAD flag, SId flag, SCIdS (4 bits); ECC; EId; SId of 16 or 32 bits
            size_t p2 = 0;
            Item a;
            while (next(e.data, e.len, p2, a)) {
                if (a.tag != ATTR_ID || a.len < 6) continue;
                bool long_sid = a.data[0] & 0x10;
                if (a.len != (long_sid ? 8u : 6u)) continue;
                Bearer b;
                b.ecc = a.data[1];
                b.eid = static_cast<uint16_t>(a.data[2] << 8 | a.data[3]);
                b.sid = long_sid ? static_cast<uint32_t>(a.data[4]) << 24 | static_cast<uint32_t>(a.data[5]) << 16 |
                                       static_cast<uint32_t>(a.data[6]) << 8 | a.data[7]
                                 : static_cast<uint32_t>(a.data[4]) << 8 | a.data[5];
                if (bearers.size() < 16) bearers.push_back(b);
            }
        } else if (e.tag == TAG_MEDIA_DESCRIPTION) {
            size_t p2 = 0;
            Item m;
            while (next(e.data, e.len, p2, m)) {
                Picture p;
                if (m.tag == TAG_MULTIMEDIA && multimedia(m, p) && pictures.size() < 32) pictures.push_back(p);
            }
        }
    }
    for (const Bearer& b : bearers) {
        for (const Picture& p : pictures) {
            if (out.logos.size() >= MAX_LOGOS) return;
            SpiLogo l;
            l.sid = b.sid;
            l.ecc = b.ecc;
            l.eid = b.eid;
            l.url = p.url;
            l.type = p.type;
            l.width = p.width;
            l.height = p.height;
            out.logos.push_back(l);
        }
    }
}

// serviceInformation or ensemble: services are children of either (of the
// ensemble with DAB, of serviceInformation with DRM)
void container(const uint8_t* d, size_t len, SpiServiceInfo& out, int depth) {
    size_t pos = 0;
    Item e;
    while (next(d, len, pos, e)) {
        if (e.tag == TAG_SERVICE) {
            service(e, out);
        } else if (e.tag == TAG_ENSEMBLE && depth < MAX_DEPTH) {
            // its id: ECC and EId
            size_t p2 = 0;
            Item a;
            while (next(e.data, e.len, p2, a)) {
                if (a.tag == ATTR_ID && a.len == 3 && !out.has_ensemble) {
                    out.has_ensemble = true;
                    out.ecc = a.data[0];
                    out.eid = static_cast<uint16_t>(a.data[1] << 8 | a.data[2]);
                }
            }
            container(e.data, e.len, out, depth + 1);
        }
    }
}

} // namespace

bool parseSpiServiceInformation(const uint8_t* data, size_t len, SpiServiceInfo& out) {
    out = SpiServiceInfo{};
    size_t pos = 0;
    Item top;
    if (!data || !next(data, len, pos, top) || top.tag != TAG_SERVICE_INFORMATION) return false;
    container(top.data, top.len, out, 0);
    return true;
}

const char* imageFileInfo(const uint8_t* d, size_t len, int& width, int& height) {
    width = height = 0;
    static const uint8_t png[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    if (len >= 8 && std::equal(png, png + 8, d)) {
        // the IHDR chunk comes first: length, "IHDR", width, height
        if (len >= 24 && d[12] == 'I' && d[13] == 'H' && d[14] == 'D' && d[15] == 'R' && !(d[16] & 0x80) &&
            !(d[20] & 0x80)) {
            width = d[16] << 24 | d[17] << 16 | d[18] << 8 | d[19];
            height = d[20] << 24 | d[21] << 16 | d[22] << 8 | d[23];
        }
        return "image/png";
    }
    if (len >= 3 && d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF) {
        // marker segments up to the frame header (SOF0..SOF15 but DHT, JPG
        // and DAC): precision, height, width
        size_t pos = 2;
        while (pos + 4 <= len && d[pos] == 0xFF) {
            uint8_t m = d[pos + 1];
            if (m == 0xFF) {            // a fill byte
                pos++;
                continue;
            }
            if (m == 0xD8 || (m >= 0xD0 && m <= 0xD7) || m == 0x01) {   // markers without a length
                pos += 2;
                continue;
            }
            size_t n = static_cast<size_t>(d[pos + 2]) << 8 | d[pos + 3];
            if (n < 2) break;
            if (m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC) {
                if (n >= 7 && pos + 9 <= len) {
                    height = d[pos + 5] << 8 | d[pos + 6];
                    width = d[pos + 7] << 8 | d[pos + 8];
                }
                break;
            }
            if (m == 0xDA || m == 0xD9) break;   // the image data begins, or the file ends
            pos += 2 + n;
        }
        return "image/jpeg";
    }
    return nullptr;
}

} // namespace dvbdab
