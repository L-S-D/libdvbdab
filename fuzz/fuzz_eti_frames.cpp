// Fuzz harness: ETI frames into the FIC parser and into the stream processor
// with services set up - DAB+ (ADTS or LATM), DAB (MPEG Layer II) and a data
// subchannel. The input is cut into frames of up to 6144 bytes; the harness
// sets the sync word and the frame counter, the rest (the stream headers,
// the FIC, the subchannels) is the input.

#include "../src/dab_parser.h"
#include "../src/logging.h"
#include "../src/output/dab_stream_processor.hpp"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace dvbdab;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static bool quiet = (set_log_callback([](LogLevel, const char*, const char*) {}), true);
    (void)quiet;
    if (size < 2) return 0;
    bool latm = data[0] & 1;
    size_t frame_len = 64 + (static_cast<size_t>(data[1]) * 24) % (6144 - 64);
    data += 2;
    size -= 2;

    DABParser fic;
    DabStreamProcessor p;
    p.setOutput([](const uint8_t* d, size_t n) {
        if (n % 188) abort();
        for (size_t i = 0; i < n; i += 188)
            if (d[i] != 0x47) abort();
    });
    p.setEnsemble(0x1234, "Fuzz", "Fuzz");
    for (int i = 0; i < 2; i++) {
        TsService s{};
        s.sid = static_cast<uint16_t>(0x1000 + i);
        s.pmt_pid = static_cast<uint16_t>(0x100 + i);
        s.audio_pid = static_cast<uint16_t>(0x1000 + i);
        s.rds_pid = static_cast<uint16_t>(0x1100 + i);
        s.name = "Service";
        s.provider = "Fuzz";
        s.dabplus = i == 0;
        s.latm = i == 0 && latm;
        s.subchannel_id = static_cast<uint8_t>(i);
        s.bitrate = i == 0 ? 24 : 64;
        p.addService(s);
    }
    p.setAacOutput(latm ? 1 : 0);
    p.startAllServices();

    std::vector<uint8_t> f(6144);
    int fct = 0;
    while (size) {
        size_t n = size < frame_len ? size : frame_len;
        memset(f.data(), 0x55, f.size());
        memcpy(f.data(), data, n);
        f[0] = 0xFF;
        if (fct % 2) {
            f[1] = 0xF8;
            f[2] = 0xC5;
            f[3] = 0x49;
        } else {
            f[1] = 0x07;
            f[2] = 0x3A;
            f[3] = 0xB6;
        }
        f[4] = static_cast<uint8_t>(fct % 250);
        fic.process_eti_frame(f.data(), f.size());
        p.feedEtiFrame(f.data(), f.size());
        fct++;
        data += n;
        size -= n;
    }
    return 0;
}
