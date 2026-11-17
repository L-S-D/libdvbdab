// DVBDAB_FORMAT_IPV4: the IPv4 packets of a GSE capture (BBF-in-pseudoTS,
// nrk_gse_capture.ts) fed one by one find the same ensembles as the
// BBF_TS streamer fed the capture itself. Garbage does no harm.
//
// test_ipv4_input [capture.ts]

#include <dvbdab/dvbdab_c.h>
#include "../src/sources/bbf_ts_source.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

struct Ens { std::string label; uint32_t ip; uint16_t port; int services; };

static std::map<uint16_t, Ens> ensembles(dvbdab_streamer_t* s) {
    std::map<uint16_t, Ens> out;
    int n = 0;
    dvbdab_ensemble_t* e = dvbdab_streamer_get_all_ensembles(s, &n);
    for (int i = 0; i < n; i++)
        out[e[i].eid] = Ens{e[i].label, e[i].source_ip, e[i].source_port, e[i].service_count};
    dvbdab_streamer_free_all_ensembles(e, n);
    return out;
}

int main(int argc, char* argv[]) {
    const char* filename = argc > 1 ? argv[1] : "/usr/src/libdvbdab/nrk_gse_capture.ts";
    int fails = 0;

    dvbdab_streamer_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.format = DVBDAB_FORMAT_BBF_TS;
    cfg.pid = 0x10e;
    dvbdab_streamer_t* bbf = dvbdab_streamer_create(&cfg);
    cfg.format = DVBDAB_FORMAT_IPV4;
    dvbdab_streamer_t* ip4 = dvbdab_streamer_create(&cfg);
    if (!bbf || !ip4) {
        printf("FAIL: streamers not created\n");
        return 1;
    }

    // the IPv4 packets of the capture, as a caller decoding GSE would give them
    size_t ip_packets = 0;
    dvbdab::BbfTsSource source;
    source.setIpCallback([&](const uint8_t* ip, size_t len) {
        ip_packets++;
        dvbdab_streamer_feed(ip4, ip, len);
    });

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        printf("SKIP: cannot open %s\n", filename);
        return 0;
    }
    std::vector<uint8_t> buf(188 * 1024);
    while (file) {
        file.read(reinterpret_cast<char*>(buf.data()), buf.size());
        size_t n = static_cast<size_t>(file.gcount()) / 188 * 188;
        if (n == 0) break;
        dvbdab_streamer_feed(bbf, buf.data(), n);
        source.feed(buf.data(), n);
    }

    auto a = ensembles(bbf), b = ensembles(ip4);
    printf("IPv4 packets %zu; ensembles: BBF_TS %zu, IPV4 %zu\n", ip_packets, a.size(), b.size());
    if (a.empty()) { printf("FAIL: no ensembles\n"); fails++; }
    if (a.size() != b.size()) { printf("FAIL: not the same number\n"); fails++; }
    for (const auto& [eid, e] : a) {
        auto it = b.find(eid);
        bool same = it != b.end() && it->second.label == e.label && it->second.ip == e.ip &&
                    it->second.port == e.port && it->second.services == e.services;
        printf("  0x%04X %-16s %u.%u.%u.%u:%u %d services %s\n", eid, e.label.c_str(),
               e.ip >> 24, (e.ip >> 16) & 255, (e.ip >> 8) & 255, e.ip & 255, e.port,
               e.services, same ? "same" : "DIFFERENT");
        if (!same) fails++;
    }

    // garbage: short, not IPv4, damaged headers
    uint8_t junk[1500];
    for (size_t i = 0; i < sizeof(junk); i++) junk[i] = static_cast<uint8_t>(i * 37);
    for (size_t len = 1; len < sizeof(junk); len += 97) dvbdab_streamer_feed(ip4, junk, len);
    junk[0] = 0x45;
    for (size_t len = 20; len < sizeof(junk); len += 101) dvbdab_streamer_feed(ip4, junk, len);
    if (dvbdab_streamer_feed(ip4, junk, 0) != -1) { printf("FAIL: empty feed\n"); fails++; }

    dvbdab_streamer_destroy(bbf);
    dvbdab_streamer_destroy(ip4);
    printf("%s\n", fails ? "FAILED" : "ok");
    return fails ? 1 : 0;
}
