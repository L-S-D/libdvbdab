// Tests for the DAB+ decoder (superframes of five frames to AUs): synthetic
// superframes with a right Fire code and AU CRCs, with lost frames, and frame
// sizes a DAB+ subchannel cannot have. No capture needed.

#include "../src/output/dabplus_decoder.hpp"
#include "../src/utils/crc_utils.hpp"
#include <cstdint>
#include <cstdio>
#include <vector>

using namespace dvbdab;

static int failures = 0;

static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

// A superframe of a 24 kbit/s subchannel (72 bytes per frame): 48 kHz with
// SBR, so 3 AUs; their bytes are `fill`, their CRCs right
static std::vector<uint8_t> superframe(uint8_t fill) {
    const size_t fs = 72, audio = fs * 5 - (24 / 8) * 10;  // without the RS parity
    std::vector<uint8_t> sf(fs * 5, 0);
    sf[2] = 0x60;                                // dac_rate, sbr_flag: 3 AUs
    const size_t start[4] = {6, 114, 222, audio};
    // au_start of AU 2 and 3: 12 bits each from bit 24
    sf[3] = start[1] >> 4;
    sf[4] = static_cast<uint8_t>((start[1] & 0x0F) << 4 | (start[2] >> 8));
    sf[5] = start[2] & 0xFF;
    for (int i = 0; i < 3; i++) {
        size_t len = start[i + 1] - start[i];
        for (size_t k = 0; k + 2 < len; k++) sf[start[i] + k] = fill;
        uint16_t c = static_cast<uint16_t>(~crc16_ccitt(sf.data() + start[i], len - 2));
        sf[start[i] + len - 2] = c >> 8;
        sf[start[i] + len - 1] = c & 0xFF;
    }
    uint16_t crc = 0;
    for (int i = 0; i < 9; i++) crc = static_cast<uint16_t>((crc << 8) ^ firecode_table[((crc >> 8) ^ sf[2 + i]) & 0xFF]);
    sf[0] = crc >> 8;
    sf[1] = crc & 0xFF;
    return sf;
}

int main() {
    {
        DabPlusDecoder d(24);
        size_t aus = 0;
        d.setTimedCallback([&](const uint8_t*, size_t, int64_t) { aus++; });
        int64_t fn = 0;
        for (int s = 0; s < 20; s++) {
            auto sf = superframe(static_cast<uint8_t>(s + 1));
            for (int f = 0; f < 5; f++) d.feedFrame(sf.data() + f * 72, 72, fn++);
        }
        check(aus == 60, "20 superframes with SBR are 60 AUs");
    }
    {
        // every fourth superframe loses its third frame: the others are whole
        DabPlusDecoder d(24);
        size_t aus = 0;
        d.setTimedCallback([&](const uint8_t*, size_t, int64_t) { aus++; });
        int64_t fn = 0;
        for (int s = 0; s < 20; s++) {
            auto sf = superframe(static_cast<uint8_t>(s + 1));
            for (int f = 0; f < 5; f++, fn++) {
                if (s % 4 == 3 && f == 2) continue;
                d.feedFrame(sf.data() + f * 72, 72, fn);
            }
        }
        check(aus >= 45 && aus < 60, "a lost frame costs AUs of its superframe only");
    }
    {
        // sizes no DAB+ subchannel has: nothing is taken, nothing read behind them
        DabPlusDecoder d(24);
        size_t aus = 0;
        d.setTimedCallback([&](const uint8_t*, size_t, int64_t) { aus++; });
        std::vector<uint8_t> zeros(64, 0);
        bool taken = false;
        int64_t fn = 0;
        for (size_t len : {size_t(0), size_t(8), size_t(23), size_t(25)}) {
            for (int i = 0; i < 12; i++) {
                std::vector<uint8_t> exact(zeros.begin(), zeros.begin() + len);
                taken |= d.feedFrame(exact.data(), len, fn++);
            }
        }
        check(!taken && aus == 0, "frames of 0, 8, 23 and 25 bytes are not taken");
        auto sf = superframe(7);
        for (int s = 0; s < 4; s++)
            for (int f = 0; f < 5; f++) d.feedFrame(sf.data() + f * 72, 72, fn++);
        check(aus == 12, "and the decoder works with the real size after them");
    }

    std::printf("%s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
