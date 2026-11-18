// Tests for the EDI input (AF and PF packets as the payload of UDP datagrams):
// what a well-formed packet gives, and that a damaged or crafted one is
// dropped - none may write or read behind a buffer or ask for much memory.
// Synthetic packets, no capture needed.

#include "../src/ensemble_manager.hpp"
#include "../src/logging.h"
#include "../src/utils/crc_utils.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

using namespace dvbdab;

static int failures = 0;

static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

// The largest single request for memory: a field of a packet must not set it
static size_t g_largest = 0;
void* operator new(std::size_t n) {
    if (n > g_largest) g_largest = n;
    void* p = std::malloc(n ? n : 1);
    if (!p) throw std::bad_alloc();
    return p;
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

using Bytes = std::vector<uint8_t>;

static void be32(Bytes& v, uint32_t x) {
    v.push_back(x >> 24);
    v.push_back(x >> 16);
    v.push_back(x >> 8);
    v.push_back(x);
}

static void tag(Bytes& v, const char* id, const Bytes& val) {
    v.insert(v.end(), id, id + 4);
    be32(v, static_cast<uint32_t>(val.size() * 8));
    v.insert(v.end(), val.begin(), val.end());
}

static Bytes starptr() { return {'D', 'E', 'T', 'I', 0, 0, 0, 0}; }

// a deti TAG with a FIC of mode I (96 bytes of zeros)
static Bytes deti(uint16_t dflc) {
    Bytes v;
    uint16_t h = 0x4000 | ((dflc / 250) << 8) | (dflc % 250);  // FICF
    v.push_back(h >> 8);
    v.push_back(h & 0xFF);
    be32(v, 1u << 22);  // MID 1
    v.insert(v.end(), 96, 0);
    return v;
}

// an est TAG: subchannel id, start address, TPL; then the stream data
static Bytes est(uint8_t scid, size_t bytes, uint8_t fill = 0xAA) {
    Bytes v = {static_cast<uint8_t>(scid << 2), 0, 0};
    v.insert(v.end(), bytes, fill);
    return v;
}

static Bytes af(const Bytes& tags, bool crc = true) {
    Bytes v = {'A', 'F'};
    be32(v, static_cast<uint32_t>(tags.size()));
    v.push_back(0);
    v.push_back(0);
    v.push_back(crc ? 0x90 : 0x10);
    v.push_back('T');
    v.insert(v.end(), tags.begin(), tags.end());
    if (crc) {
        uint16_t c = crc16_ccitt_xor(v.data(), v.size());
        v.push_back(c >> 8);
        v.push_back(c & 0xFF);
    }
    return v;
}

static Bytes pf(uint16_t pseq, uint32_t findex, uint32_t fcount, const uint8_t* d, size_t n, bool good_crc = true) {
    Bytes v = {'P', 'F', static_cast<uint8_t>(pseq >> 8), static_cast<uint8_t>(pseq),
               static_cast<uint8_t>(findex >> 16), static_cast<uint8_t>(findex >> 8), static_cast<uint8_t>(findex),
               static_cast<uint8_t>(fcount >> 16), static_cast<uint8_t>(fcount >> 8), static_cast<uint8_t>(fcount),
               static_cast<uint8_t>((n >> 8) & 0x3F), static_cast<uint8_t>(n)};
    uint16_t c = crc16_ccitt_xor(v.data(), v.size());
    if (!good_crc) c ^= 0x0100;
    v.push_back(c >> 8);
    v.push_back(c & 0xFF);
    v.insert(v.end(), d, d + n);
    return v;
}

// a frame as AF packet: one DAB+ stream of 72 bytes
static Bytes frame_af(uint16_t dflc) {
    Bytes tags;
    tag(tags, "*ptr", starptr());
    tag(tags, "deti", deti(dflc));
    tag(tags, "est\x01", est(1, 72));
    return af(tags);
}

struct Rig {
    EnsembleManager m;
    int frames = 0;
    size_t last_len = 0;
    Rig() {
        m.setEtiCallback([this](const StreamKey&, const uint8_t*, size_t len, uint16_t) {
            frames++;
            last_len = len;
        });
    }
    // from a heap block of exactly the size, so that a sanitizer sees a read behind it
    void feed(const Bytes& p, uint32_t ip = 0xEF010101, uint16_t port = 1234) {
        uint8_t* b = static_cast<uint8_t*>(std::malloc(p.size() ? p.size() : 1));
        std::memcpy(b, p.data(), p.size());
        m.processUdp(ip, port, b, p.size());
        std::free(b);
    }
};

int main() {
    // the packets here have no FIC worth the name: its warnings are not the point
    set_log_callback([](LogLevel, const char*, const char*) {});

    {
        Rig r;
        r.feed(frame_af(1));
        check(r.frames == 1 && r.last_len == 6144, "an AF packet with *ptr, deti and est1 is one ETI frame");
    }
    {
        Rig r;
        Bytes a = frame_af(1);
        size_t h = a.size() / 2;
        r.feed(pf(10, 0, 2, a.data(), h));
        check(r.frames == 0, "the first of two PF fragments is no frame yet");
        r.feed(pf(10, 1, 2, a.data() + h, a.size() - h));
        check(r.frames == 1, "both PF fragments are the frame");
    }
    {
        Rig r;
        Bytes a = frame_af(1);
        size_t h = a.size() / 2;
        r.feed(pf(10, 0, 2, a.data(), h, false));
        r.feed(pf(10, 1, 2, a.data() + h, a.size() - h));
        check(r.frames == 0, "a PF fragment with a wrong header CRC is not taken");
    }
    {
        // an AF of which the middle fragment is lost, between complete ones
        Rig r;
        for (int i = 0; i < 4; i++) {
            Bytes a = frame_af(static_cast<uint16_t>(1 + i));
            size_t t = a.size() / 3;
            r.feed(pf(static_cast<uint16_t>(20 + i), 0, 3, a.data(), t));
            if (i != 2) r.feed(pf(static_cast<uint16_t>(20 + i), 1, 3, a.data() + t, t));
            r.feed(pf(static_cast<uint16_t>(20 + i), 2, 3, a.data() + 2 * t, a.size() - 2 * t));
        }
        check(r.frames == 3, "an AF with a lost fragment costs its frame, not the ones around it");
    }
    {
        // the sender starts anew: its sequence numbers go on far behind the last
        Rig r;
        auto send = [&](uint16_t pseq, uint16_t dflc) {
            Bytes a = frame_af(dflc);
            size_t h = a.size() / 2;
            r.feed(pf(pseq, 0, 2, a.data(), h));
            r.feed(pf(pseq, 1, 2, a.data() + h, a.size() - h));
        };
        for (int i = 0; i < 100; i++) send(static_cast<uint16_t>(40000 + i), static_cast<uint16_t>(i));
        int before = r.frames;
        for (int i = 0; i < 100; i++) send(static_cast<uint16_t>(36000 + i), static_cast<uint16_t>(100 + i));
        check(before == 100 && r.frames >= before + 90, "after a jump back of the PF sequence number frames go on at once");
    }
    {
        Rig r;
        Bytes tags;
        tag(tags, "*ptr", starptr());
        tag(tags, "deti", deti(1));
        tag(tags, "est\x01", est(1, 20000));
        r.feed(af(tags));
        check(r.frames == 0, "an est TAG larger than an ETI frame is no frame");
    }
    {
        Rig r;
        Bytes tags;
        tag(tags, "*ptr", starptr());
        tag(tags, "deti", deti(1));
        for (int i = 0; i < 4; i++) tag(tags, (std::string("est") + static_cast<char>(i + 1)).c_str(), est(i + 1, 2000));
        r.feed(af(tags));
        check(r.frames == 0, "est TAGs that together do not fit into an ETI frame are no frame");
    }
    {
        Rig r;
        Bytes tags;
        tag(tags, "*ptr", starptr());
        tag(tags, "deti", deti(1));
        for (int i = 0; i < 70; i++) tag(tags, "est\x01", est(1, 8));
        r.feed(af(tags));
        check(r.frames == 0, "the same est TAG 70 times is no frame");
    }
    {
        Rig r;
        Bytes tags;
        tag(tags, "*ptr", starptr());
        tag(tags, "deti", deti(1));
        tag(tags, "est\x01", est(1, 72));
        tag(tags, "est\x03", est(3, 72));
        r.feed(af(tags));
        check(r.frames == 0, "est1 and est3 without est2 are no frame");
    }
    {
        Rig r;
        Bytes tags;
        tag(tags, "*ptr", starptr());
        tag(tags, "deti", Bytes{0xC0, 0x01});  // says time stamp and FIC, has 2 bytes
        r.feed(af(tags, false));
        check(r.frames == 0, "a deti TAG shorter than its flags say is no frame");
    }
    {
        Rig r;
        r.feed(frame_af(1));
        uint8_t d[100] = {0};
        g_largest = 0;
        r.feed(pf(10, 0, 0xFFFFFF, d, 100));
        r.feed(pf(11, 0, 2, d, 100));
        r.feed(pf(12, 0, 1000, d, 100));
        r.feed(pf(13, 0, 2, d, 100));
        check(g_largest < 256 * 1024, "the fragment count of a PF header does not set how much memory is taken");
        r.feed(frame_af(2));
        check(r.frames == 2, "and frames go on after it");
    }
    {
        // without a filter: every UDP destination of a transponder comes here
        Rig r;
        Bytes junk(200, 0x42);
        for (int i = 0; i < 500; i++) r.feed(junk, 0xEF020000 + i, 5000);
        check(r.m.getStreamCount() == 0, "a destination that does not send EDI gets no parser");
        for (int i = 0; i < 500; i++) r.feed(frame_af(1), 0xEF030000 + i, 5000);
        check(r.m.getStreamCount() > 0 && r.m.getStreamCount() <= 64, "and there are parsers for 64 EDI streams at most");
    }

    std::printf("%s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
