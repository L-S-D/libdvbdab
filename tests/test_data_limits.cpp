// Tests for the limits of what the packet mode and MOT decoder collects:
// bytes that are no packets (the audio of a subchannel looks like that to
// it) must not make it take memory without end. No capture needed.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>
#define private public
#include "../src/parsers/packet_decoder.hpp"
#undef private
#include "../src/parsers/ehb_parser.hpp"
#include "../src/utils/crc_utils.hpp"
#include <cstdio>
#include <cstdlib>
#include <new>

using namespace dvbdab;

static int failures = 0;

static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

static size_t g_largest = 0;
void* operator new(std::size_t n) {
    if (n > g_largest) g_largest = n;
    void* p = std::malloc(n ? n : 1);
    if (!p) throw std::bad_alloc();
    return p;
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

static uint64_t seed = 0x9E3779B97F4A7C15ull;
static uint64_t rnd() {
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    return seed;
}

// a packet of 24 bytes for address addr with udl bytes of data, its CRC right
static std::vector<uint8_t> packet(uint16_t addr, int ci, bool first, bool last, const uint8_t* d, size_t udl) {
    std::vector<uint8_t> p(24, 0);
    p[0] = static_cast<uint8_t>(ci << 4 | (first ? 8 : 0) | (last ? 4 : 0) | (addr >> 8));
    p[1] = addr & 0xFF;
    p[2] = static_cast<uint8_t>(udl);
    for (size_t i = 0; i < udl; i++) p[3 + i] = d[i];
    uint16_t c = crc16_ccitt_xor(p.data(), 22);
    p[22] = c >> 8;
    p[23] = c & 0xFF;
    return p;
}

static size_t collected(const PacketDecoder& dec) {
    size_t n = dec.stream_buffer_.size();
    for (const auto& [a, b] : dec.dg_buffers_) n += b.data.size();
    for (const auto& [t, o] : dec.mot_objects_) n += o.bytes;
    for (const auto& [t, d] : dec.directory_accumulators_) n += d.bytes;
    return n;
}

int main() {
    {
        // 6 hours of a 96 kbit/s subchannel of random bytes
        PacketDecoder dec;
        size_t objects = 0;
        dec.setMotCallback([&](uint16_t, const MOTHeaderInfo&, const uint8_t*, size_t) { objects++; });
        std::vector<uint8_t> buf(288);
        g_largest = 0;
        for (size_t f = 0; f < 6 * 3600 * 1000 / 24; f++) {
            for (size_t i = 0; i < buf.size(); i += 8) {
                uint64_t r = rnd();
                for (int k = 0; k < 8; k++) buf[i + k] = static_cast<uint8_t>(r >> (8 * k));
            }
            dec.feedSubchannelData(buf.data(), buf.size());
        }
        std::printf("-- random bytes: %zu packets by chance, largest request %zu bytes, %zu bytes collected\n",
                    dec.packet_count_, g_largest, collected(dec));
        check(g_largest < 1024 * 1024, "random bytes never make the decoder ask for a megabyte at once");
        check(collected(dec) < 16u * 1024 * 1024 && dec.mot_objects_.size() <= PacketDecoder::MAX_MOT_OBJECTS,
              "and what it keeps of them stays small");
    }
    {
        // a data group that never ends: first packet, then continuations for ever
        PacketDecoder dec;
        uint8_t d[19];
        for (auto& b : d) b = 0x33;
        auto first = packet(5, 0, true, false, d, 19);
        dec.feedSubchannelData(first.data(), first.size());
        for (int i = 1; i < 20000; i++) {
            auto p = packet(5, i & 3, false, false, d, 19);
            dec.feedSubchannelData(p.data(), p.size());
        }
        check(collected(dec) <= PacketDecoder::MAX_DATA_GROUP + 4096, "a data group without an end is not collected for ever");
    }
    {
        EhbParser ehb;
        std::vector<uint8_t> big(2 * 1024 * 1024, 0x02);
        check(!ehb.parse("w20261118d1234.EHB", big.data(), big.size()), "an EHB file of 2 MB is not parsed");
        // garbage of all lengths: survived, and never much memory
        g_largest = 0;
        for (int i = 0; i < 20000; i++) {
            std::vector<uint8_t> junk(rnd() % 2000);
            for (auto& b : junk) b = static_cast<uint8_t>(rnd());
            if (junk.size() > 4 && rnd() % 2) {
                junk[0] = 0x02;  // an EPG element, its length the rest
                junk[1] = 0xFE;
                junk[2] = static_cast<uint8_t>((junk.size() - 4) >> 8);
                junk[3] = static_cast<uint8_t>(junk.size() - 4);
                if (junk.size() > 8) junk[4] = 0x04;  // then a token table
            }
            ehb.parse("w20261118d1234.EHB", junk.data(), junk.size());
        }
        check(g_largest < 8u * 1024 * 1024, "garbage as an EHB file is survived without a large request");
    }

    std::printf("%s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
