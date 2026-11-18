// DVBDAB_FORMAT_IPV4: the IPv4 packets of an MPE capture, fed one by one,
// find its ensembles - all of them without a filter, just the one of the
// filter with it. Garbage does no harm.
//
// test_ipv4_input [capture.ts [pid]]

#include <dvbdab/dvbdab_c.h>
#include "support/mpe_ip_source.hpp"

#include <cstdio>
#include <cstdlib>
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

static dvbdab_streamer_t* streamer(uint32_t ip, uint16_t port) {
    dvbdab_streamer_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.format = DVBDAB_FORMAT_IPV4;
    cfg.filter_ip = ip;
    cfg.filter_port = port;
    return dvbdab_streamer_create(&cfg);
}

static size_t feed_file(const char* filename, uint16_t pid, dvbdab_streamer_t* s) {
    size_t ip_packets = 0;
    dvbdab::test::MpeIpSource source(pid);
    source.setIpCallback([&](const uint8_t* ip, size_t len) {
        ip_packets++;
        dvbdab_streamer_feed(s, ip, len);
    });
    std::ifstream file(filename, std::ios::binary);
    std::vector<uint8_t> buf(188 * 1024);
    while (file) {
        file.read(reinterpret_cast<char*>(buf.data()), buf.size());
        if (file.gcount() <= 0) break;
        source.feed(buf.data(), static_cast<size_t>(file.gcount()));
    }
    return ip_packets;
}

int main(int argc, char* argv[]) {
    const char* filename = argc > 1 ? argv[1] : "/usr/src/libdvbdab/astra1-wdr.ts";
    uint16_t pid = argc > 2 ? static_cast<uint16_t>(atoi(argv[2])) : 3000;
    int fails = 0;

    if (!std::ifstream(filename)) {
        printf("SKIP: cannot open %s\n", filename);
        return 77;  // ctest: skipped, not passed
    }

    // all streams
    dvbdab_streamer_t* all = streamer(0, 0);
    if (!all) {
        printf("FAIL: streamer not created\n");
        return 1;
    }
    size_t ip_packets = feed_file(filename, pid, all);
    auto a = ensembles(all);
    printf("IPv4 packets %zu; ensembles %zu\n", ip_packets, a.size());
    if (a.empty()) { printf("FAIL: no ensembles\n"); fails++; }
    for (const auto& [eid, e] : a) {
        printf("  0x%04X %-16s %u.%u.%u.%u:%u %d services\n", eid, e.label.c_str(),
               e.ip >> 24, (e.ip >> 16) & 255, (e.ip >> 8) & 255, e.ip & 255, e.port, e.services);
        if (e.label.empty() || e.services <= 0) { printf("FAIL: incomplete\n"); fails++; }
    }

    // the stream of the filter only
    if (!a.empty()) {
        const Ens& want = a.begin()->second;
        dvbdab_streamer_t* one = streamer(want.ip, want.port);
        feed_file(filename, pid, one);
        dvbdab_ensemble_t* e = dvbdab_streamer_get_ensemble(one);
        bool same = e && e->eid == a.begin()->first && want.label == e->label &&
                    e->service_count == want.services;
        printf("filtered %u.%u.%u.%u:%u: %s\n", want.ip >> 24, (want.ip >> 16) & 255,
               (want.ip >> 8) & 255, want.ip & 255, want.port, same ? "same" : "DIFFERENT");
        if (!same) fails++;
        if (e) dvbdab_streamer_free_ensemble(e);
        dvbdab_streamer_destroy(one);
    }

    // garbage: short, not IPv4, damaged headers
    uint8_t junk[1500];
    for (size_t i = 0; i < sizeof(junk); i++) junk[i] = static_cast<uint8_t>(i * 37);
    for (size_t len = 1; len < sizeof(junk); len += 97) dvbdab_streamer_feed(all, junk, len);
    junk[0] = 0x45;
    for (size_t len = 20; len < sizeof(junk); len += 101) dvbdab_streamer_feed(all, junk, len);
    if (dvbdab_streamer_feed(all, junk, 0) != -1) { printf("FAIL: empty feed\n"); fails++; }

    // the formats 1-3 of 1.x (MPE, GSE, BBFrames) are gone
    dvbdab_streamer_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    for (int f = 1; f <= 3; f++) {
        cfg.format = static_cast<dvbdab_format_t>(f);
        dvbdab_streamer_t* s = dvbdab_streamer_create(&cfg);
        if (s) { printf("FAIL: format %d created\n", f); fails++; dvbdab_streamer_destroy(s); }
    }

    dvbdab_streamer_destroy(all);
    printf("%s\n", fails ? "FAILED" : "ok");
    return fails ? 1 : 0;
}
