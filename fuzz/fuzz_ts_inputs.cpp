// Fuzz harness: a transport stream into the inputs that take one - a
// streamer for ETI-NA, a streamer for TS NI, and the scanner. The first byte
// chooses; the rest is cut into TS packets, the harness sets the sync byte
// and (for the streamers) the PID.

#include <dvbdab/dvbdab_c.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

void on_ts(void*, const uint8_t* d, size_t n) {
    if (n % 188) abort();
    for (size_t i = 0; i < n; i += 188)
        if (d[i] != 0x47) abort();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static bool quiet = (dvbdab_set_log_callback([](int, const char*, const char*) {}), true);
    (void)quiet;
    if (size < 2) return 0;
    uint8_t mode = data[0] % 3;
    uint8_t opt = data[1];
    data += 2;
    size -= 2;

    // whole TS packets, in feeds of 1 to 7 of them
    std::vector<uint8_t> ts;
    for (size_t o = 0; o + 188 <= size; o += 188) {
        size_t at = ts.size();
        ts.insert(ts.end(), data + o, data + o + 188);
        ts[at] = 0x47;
        if (mode < 2) {  // PID 1000, with payload
            ts[at + 1] = static_cast<uint8_t>((ts[at + 1] & 0x40) | 0x03);
            ts[at + 2] = 0xE8;
            ts[at + 3] = static_cast<uint8_t>((ts[at + 3] & 0x0F) | 0x10);
        }
    }
    size_t step = 188 * (1 + opt % 7);

    if (mode == 2) {
        dvbdab_scanner_t* sc = dvbdab_scanner_create();
        if (!sc) return 0;
        dvbdab_scanner_set_timeout(sc, 0xFFFFFFFFu);  // not by the clock: the run must repeat
        for (size_t o = 0; o < ts.size(); o += step)
            dvbdab_scanner_feed(sc, ts.data() + o, ts.size() - o < step ? ts.size() - o : step);
        dvbdab_results_t* r = dvbdab_scanner_get_results(sc);
        dvbdab_results_free(r);
        dvbdab_scanner_destroy(sc);
        return 0;
    }

    dvbdab_streamer_config_t c;
    memset(&c, 0, sizeof(c));
    c.format = mode == 0 ? DVBDAB_FORMAT_ETI_NA : DVBDAB_FORMAT_TSNI;
    c.pid = 1000;
    c.eti_padding = 12;
    c.eti_bit_offset = (opt >> 3) & 7;
    c.eti_inverted = opt >> 7;
    dvbdab_streamer_t* s = dvbdab_streamer_create(&c);
    if (!s) return 0;
    dvbdab_streamer_set_output(s, on_ts, nullptr);
    dvbdab_streamer_start_all(s);
    for (size_t o = 0; o < ts.size(); o += step) {
        dvbdab_streamer_feed(s, ts.data() + o, ts.size() - o < step ? ts.size() - o : step);
        dvbdab_streamer_start_all(s);
    }
    dvbdab_streamer_destroy(s);
    return 0;
}
