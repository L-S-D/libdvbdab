// The ETI-NA and TS NI V.11 ensembles of a TS capture.
//
//   scanner capture.ts
//
// DAB over IP is the caller's: its IPv4 packets go to a DVBDAB_FORMAT_IPV4
// streamer with filter_ip 0, which lists the ensembles it finds
// (dvbdab_streamer_get_all_ensembles()).
#include <dvbdab/ts_scanner.hpp>

#include <cstdio>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <capture.ts>\n", argv[0]);
        return 2;
    }
    std::FILE* in = std::fopen(argv[1], "rb");
    if (!in) {
        std::perror(argv[1]);
        return 1;
    }

    dvbdab::TsScanner scanner;
    scanner.setTimeout(5000);

    std::vector<uint8_t> buf(188 * 256);
    size_t n;
    while (!scanner.isDone() && (n = std::fread(buf.data(), 1, buf.size(), in)) >= 188) {
        scanner.feed(buf.data(), n - n % 188);
    }
    std::fclose(in);

    // what a streamer for an ETI-NA PID is configured with
    for (const auto& na : scanner.getEtiNaResults()) {
        std::printf("ETI-NA on PID %u: padding %d, bit offset %d, %s\n", static_cast<unsigned>(na.pid),
                    na.padding_bytes, na.sync_bit_offset, na.inverted ? "inverted" : "not inverted");
    }
    for (const auto& ensemble : scanner.getResults()) {
        std::printf("Ensemble: %s (EID=0x%04x, PID %u)\n", ensemble.label.c_str(), ensemble.eid,
                    static_cast<unsigned>(ensemble.pid));
        for (const auto& service : ensemble.services) {
            std::printf("  Service: %s (SID=0x%04x, subch=%d)\n", service.label.c_str(),
                        static_cast<unsigned>(service.sid), service.subchannel_id);
        }
    }
    return 0;
}
