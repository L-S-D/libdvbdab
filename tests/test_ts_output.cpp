// Tests for the TS the library puts out: ETI frames with DAB (MPEG Layer II)
// services through the stream processor, and the result through a small TS
// checker - sync bytes, continuity counters, the CRC-32 and size of every
// section, PTS in order - and the programme guide: its period, what is
// dropped from it. Synthetic frames, no capture needed.

#include "../src/output/dab_stream_processor.hpp"
#include "../src/utils/crc_utils.hpp"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <set>
#include <vector>

using namespace dvbdab;

static int failures = 0;

static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

// ---- a small TS checker ----

struct Checker {
    size_t packets = 0, bad_sync = 0, cc_errors = 0, bad_crc = 0, sections = 0, pts_back = 0;
    std::map<uint16_t, int> cc;
    std::map<uint16_t, std::vector<uint8_t>> sec;     // per PSI PID: the bytes of sections being collected
    std::map<uint16_t, size_t> max_section;           // per PID
    std::map<uint16_t, int64_t> last_pts;
    std::map<uint16_t, size_t> pes;
    // per audio PID: PES without a PCR, the smallest PTS - PCR, the longest time between two PCRs
    std::map<uint16_t, size_t> pes_without_pcr;
    std::map<uint16_t, int64_t> last_pcr, min_lead, max_pcr_gap;
    std::map<uint16_t, std::set<uint16_t>> event_ids;      // per service
    std::map<uint16_t, std::set<std::string>> event_texts; // per service: the descriptors of its events
    std::set<uint16_t> sdt_services;
    size_t sdt_sections = 0;
    // EIT: per service the events seen (start time bytes), and how often its section 0 came
    std::map<uint16_t, std::set<std::vector<uint8_t>>> events;
    std::map<uint16_t, size_t> eit_passes;
    // EIT present/following: per service and section (0 present, 1 following) the event id (-1: none)
    // and running status of the last one seen, the versions seen; SDT: the two EIT flags of a service
    std::map<uint16_t, std::map<int, int>> pf_event, pf_running;
    std::map<uint16_t, std::set<int>> pf_versions;
    std::map<uint16_t, int> sdt_eit_flags;

    static bool psi(uint16_t pid) { return pid < 0x20 || (pid >= 0x100 && pid < 0x200); }

    void section(uint16_t pid, const uint8_t* s, size_t n) {
        sections++;
        if (n > max_section[pid]) max_section[pid] = n;
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < n; i++) crc = (crc << 8) ^ dvb_crc32_table[((crc >> 24) ^ s[i]) & 0xFF];
        if (crc != 0 && pid != 0x14) bad_crc++;   // (a TDT has no CRC)
        if (pid == 0x12 && n >= 18 && s[0] == 0x4E) {
            uint16_t sid = static_cast<uint16_t>(s[3] << 8 | s[4]);
            pf_versions[sid].insert((s[5] >> 1) & 0x1F);
            bool event = 14 + 12 <= n - 4;
            pf_event[sid][s[6]] = event ? (s[14] << 8 | s[15]) : -1;
            pf_running[sid][s[6]] = event ? s[14 + 10] >> 5 : -1;
        }
        if (pid == 0x12 && n >= 18 && s[0] == 0x50) {
            uint16_t sid = static_cast<uint16_t>(s[3] << 8 | s[4]);
            if (s[6] == 0) eit_passes[sid]++;
            for (size_t p = 14; p + 12 <= n - 4;) {
                size_t dl = static_cast<size_t>((s[p + 10] & 0x0F) << 8 | s[p + 11]);
                events[sid].insert(std::vector<uint8_t>(s + p + 2, s + p + 7));
                event_ids[sid].insert(static_cast<uint16_t>(s[p] << 8 | s[p + 1]));
                if (p + 12 + dl <= n - 4) event_texts[sid].insert(std::string(s + p + 12, s + p + 12 + dl));
                p += 12 + dl;
            }
        }
        if (pid == 0x11 && n >= 15 && s[0] == 0x42) {
            if (s[6] == 0) sdt_sections = static_cast<size_t>(s[7]) + 1;
            for (size_t p = 11; p + 5 <= n - 4;) {
                sdt_services.insert(static_cast<uint16_t>(s[p] << 8 | s[p + 1]));
                sdt_eit_flags[static_cast<uint16_t>(s[p] << 8 | s[p + 1])] = s[p + 2] & 0x03;
                p += 5 + static_cast<size_t>((s[p + 3] & 0x0F) << 8 | s[p + 4]);
            }
        }
    }

    void drain(uint16_t pid) {
        auto& b = sec[pid];
        while (b.size() >= 3 && b[0] != 0xFF) {
            size_t n = 3 + static_cast<size_t>((b[1] & 0x0F) << 8 | b[2]);
            if (b.size() < n) return;
            section(pid, b.data(), n);
            b.erase(b.begin(), b.begin() + n);
        }
        if (!b.empty() && b[0] == 0xFF) b.clear();
    }

    void feed(const uint8_t* d, size_t len) {
        if (len % 188) bad_sync++;
        for (size_t o = 0; o + 188 <= len; o += 188) {
            const uint8_t* k = d + o;
            packets++;
            if (k[0] != 0x47) {
                bad_sync++;
                continue;
            }
            uint16_t pid = static_cast<uint16_t>((k[1] & 0x1F) << 8 | k[2]);
            bool pusi = (k[1] & 0x40) != 0;
            int afc = (k[3] >> 4) & 3;
            size_t pl = 4;
            int64_t pcr = -1;
            if (afc & 2) {
                if (k[4] >= 7 && (k[5] & 0x10))
                    pcr = (static_cast<int64_t>(k[6]) << 25) | (k[7] << 17) | (k[8] << 9) | (k[9] << 1) | (k[10] >> 7);
                pl = 5 + k[4];
            }
            if (!(afc & 1) || pl >= 188) continue;
            int c = k[3] & 0x0F;
            auto it = cc.find(pid);
            if (it != cc.end() && ((it->second + 1) & 0x0F) != c) cc_errors++;
            cc[pid] = c;
            if (psi(pid)) {
                auto& b = sec[pid];
                if (pusi) {
                    size_t ptr = k[pl];
                    if (pl + 1 + ptr > 188) {
                        bad_crc++;
                        continue;
                    }
                    b.insert(b.end(), k + pl + 1, k + pl + 1 + ptr);
                    drain(pid);
                    b.assign(k + pl + 1 + ptr, k + 188);
                } else {
                    b.insert(b.end(), k + pl, k + 188);
                }
                drain(pid);
            } else if (pusi && pl + 14 <= 188 && k[pl] == 0 && k[pl + 1] == 0 && k[pl + 2] == 1 && (k[pl + 7] & 0x80)) {
                const uint8_t* q = k + pl + 9;
                int64_t pts = (static_cast<int64_t>(q[0] & 0x0E) << 29) | (q[1] << 22) | ((q[2] & 0xFE) << 14) |
                              (q[3] << 7) | (q[4] >> 1);
                auto lp = last_pts.find(pid);
                if (lp != last_pts.end() && pts < lp->second) pts_back++;
                last_pts[pid] = pts;
                pes[pid]++;
                if (pid >= 0x1000 && pid < 0x1100) {
                    if (pcr < 0) {
                        pes_without_pcr[pid]++;
                    } else {
                        if (!min_lead.count(pid) || pts - pcr < min_lead[pid]) min_lead[pid] = pts - pcr;
                        if (last_pcr.count(pid) && pcr - last_pcr[pid] > max_pcr_gap[pid]) max_pcr_gap[pid] = pcr - last_pcr[pid];
                        last_pcr[pid] = pcr;
                    }
                }
            }
        }
    }
};

// ---- ETI frames with DAB services ----

// an ETI frame with these subchannels (no FIC), frame counter fct
static std::vector<uint8_t> eti(int fct, const std::vector<std::vector<uint8_t>>& subs) {
    std::vector<uint8_t> f(6144, 0x55);
    f[0] = 0xFF;
    f[1] = 0x07;
    f[2] = 0x3A;
    f[3] = 0xB6;
    f[4] = static_cast<uint8_t>(fct);
    f[5] = static_cast<uint8_t>(subs.size());
    f[6] = 0x08;
    f[7] = 0;
    size_t off = 8 + subs.size() * 4 + 4;
    for (size_t i = 0; i < subs.size(); i++) {
        size_t stl = subs[i].size() / 8;
        f[8 + i * 4] = static_cast<uint8_t>(i << 2);
        f[8 + i * 4 + 1] = 0;
        f[8 + i * 4 + 2] = (stl >> 8) & 3;
        f[8 + i * 4 + 3] = stl & 0xFF;
        std::memcpy(&f[off], subs[i].data(), subs[i].size());
        off += subs[i].size();
    }
    return f;
}

static void add_services(DabStreamProcessor& p, int n) {
    p.setEnsemble(0x1234, "Test Ensemble", "Test Ensemble");
    for (int i = 0; i < n; i++) {
        TsService s{};
        s.sid = static_cast<uint16_t>(0x1000 + i);
        s.pmt_pid = static_cast<uint16_t>(0x100 + i);
        s.audio_pid = static_cast<uint16_t>(0x1000 + i);
        s.rds_pid = static_cast<uint16_t>(0x1100 + i);
        s.name = "Service " + std::to_string(i);
        s.provider = "Test Ensemble";
        s.dabplus = false;
        s.subchannel_id = static_cast<uint8_t>(i);
        s.bitrate = 64;
        p.addService(s);
    }
    p.startAllServices();
}

// `seconds` of DAB audio (MPEG-2 Layer II, 24 kHz, 64 kbit/s: a frame of 384
// bytes over two ETI frames) for n services; every 51st ETI frame is lost
// (with_audio: the first so many services have audio, the others 24 bytes of
// nothing - an ETI frame does not hold 60 times 192 bytes)
static void run(DabStreamProcessor& p, int n, int seconds, bool losses = true, int with_audio = 64) {
    std::vector<uint8_t> mp2(384, 0x11);
    mp2[0] = 0xFF;
    mp2[1] = 0xF5;
    mp2[2] = 0x84;
    mp2[3] = 0x00;
    mp2[382] = 0;
    mp2[383] = 0;
    int frames = seconds * 1000 / 24;
    for (int i = 0; i < frames; i++) {
        if (losses && i > 100 && i % 51 == 0) continue;
        std::vector<std::vector<uint8_t>> subs;
        for (int s = 0; s < n; s++) {
            if (s < with_audio) subs.emplace_back(mp2.begin() + (i % 2) * 192, mp2.begin() + (i % 2) * 192 + 192);
            else subs.emplace_back(24, 0x00);
        }
        auto f = eti(i % 250, subs);
        p.feedEtiFrame(f.data(), f.size());
    }
}

static EpgSchedule schedule(uint16_t sid, time_t first, int count, int seconds_each) {
    EpgSchedule sch;
    sch.service_id = sid;
    for (int e = 0; e < count; e++) {
        EpgProgramme pr;
        pr.name = "Programme " + std::to_string(e);
        pr.description = "A description of the programme, some sixty characters long.";
        pr.start_time = first + static_cast<time_t>(e) * seconds_each;
        pr.duration_seconds = seconds_each;
        sch.programmes.push_back(pr);
    }
    return sch;
}

int main() {
    const time_t now = time(nullptr);

    for (int n : {1, 16}) {
        DabStreamProcessor p;
        Checker c;
        p.setOutput([&](const uint8_t* d, size_t len) { c.feed(d, len); });
        add_services(p, n);
        for (int i = 0; i < n; i++)
            p.getMuxer().updateSchedule(static_cast<uint16_t>(0x1000 + i), schedule(static_cast<uint16_t>(0x1000 + i), now, 40, 1800));
        run(p, n, 60);
        std::printf("-- %d service(s): %zu packets, %zu sections, EIT passes %zu\n", n, c.packets, c.sections,
                    c.eit_passes[0x1000]);
        check(c.packets > 0 && c.bad_sync == 0, "every packet has 188 bytes and its sync byte");
        check(c.cc_errors == 0, "the continuity counters of all PIDs go on by one");
        check(c.sections > 0 && c.bad_crc == 0, "every section has a right CRC-32");
        check(c.max_section[0] <= 1024 && c.max_section[0x11] <= 1024 && c.max_section[0x100] <= 1024 &&
                  c.max_section[0x12] <= 4096,
              "PAT, PMT and SDT sections within 1024 bytes, EIT within 4096");
        check(c.pes[0x1000] > 100 && c.pts_back == 0, "audio PES with PTS that never go back");
        check(c.events[0x1000].size() == 40, "the 40 programmes of a service are in the EIT");
        check(c.eit_passes[0x1000] >= 5 && c.eit_passes[0x1000] <= 8,
              "the EIT of a service goes out every 10 s, whatever the number of services");
        check(c.event_ids[0x1000].size() == 40, "every programme has an event id of its own");
        // 60 s of frames of 48 ms with 28 lost frames of 24 ms: the last PTS is where the time is
        int64_t expect = 90000 + static_cast<int64_t>(60 * 1000 / 24) * 2160;
        check(c.last_pts[0x1000] > expect - 2 * 9000 && c.last_pts[0x1000] <= expect,
              "lost frames do not make the PTS of DAB audio fall behind");
        check(c.pes_without_pcr[0x1000] == 0 && c.min_lead[0x1000] >= 27000,
              "every audio PES has a PCR, at least 300 ms before its PTS");
    }
    {
        // without losses: the PCR comes often enough
        DabStreamProcessor p;
        Checker c;
        p.setOutput([&](const uint8_t* d, size_t len) { c.feed(d, len); });
        add_services(p, 2);
        run(p, 2, 20, false);
        check(c.max_pcr_gap[0x1000] > 0 && c.max_pcr_gap[0x1000] <= 9000, "a PCR at least every 100 ms");
    }
    {
        // more services than one SDT section holds
        DabStreamProcessor p;
        Checker c;
        p.setOutput([&](const uint8_t* d, size_t len) { c.feed(d, len); });
        add_services(p, 60);
        run(p, 60, 5, true, 1);
        std::printf("-- 60 services: SDT in %zu sections, largest %zu bytes\n", c.sdt_sections, c.max_section[0x11]);
        check(c.sdt_sections >= 2 && c.max_section[0x11] <= 1024 && c.sdt_services.size() == 60,
              "the SDT of 60 services is in several sections of 1024 bytes at most");
        check(c.bad_crc == 0 && c.cc_errors == 0, "and the TS is in order");
    }
    {
        // a long title is cut between two characters, not inside one
        DabStreamProcessor p;
        Checker c;
        p.setOutput([&](const uint8_t* d, size_t len) { c.feed(d, len); });
        add_services(p, 1);
        EpgSchedule sch = schedule(0x1000, now, 1, 1800);
        sch.programmes[0].name = std::string(99, 'a');
        for (int i = 0; i < 30; i++) sch.programmes[0].name += "\xC3\xA4";   // byte 120 is the second of an umlaut
        sch.programmes[0].description = sch.programmes[0].name;
        p.getMuxer().updateSchedule(0x1000, sch);
        run(p, 1, 15);
        bool whole = !c.event_texts[0x1000].empty();
        for (const auto& t : c.event_texts[0x1000]) {
            // short_event_descriptor: tag, length, language (3), then two texts of [length][0x15][UTF-8]
            size_t at = 5;
            for (int text = 0; text < 2 && at < t.size(); text++) {
                size_t len = static_cast<uint8_t>(t[at]);
                std::string body = t.substr(at + 2, len - 1);
                if (body.size() != 119 || (static_cast<uint8_t>(body.back()) & 0xC0) != 0x80 ||
                    static_cast<uint8_t>(body[body.size() - 2]) != 0xC3) whole = false;
                at += 1 + len;
            }
        }
        check(whole, "a title and a description of 159 bytes are cut to 119, after a whole character");
    }
    {
        // a programme with another title at the same start time replaces the old one
        DabStreamProcessor p;
        Checker c;
        p.setOutput([&](const uint8_t* d, size_t len) { c.feed(d, len); });
        add_services(p, 1);
        p.getMuxer().updateSchedule(0x1000, schedule(0x1000, now, 5, 1800));
        run(p, 1, 15);
        EpgSchedule changed = schedule(0x1000, now, 5, 1800);
        changed.programmes[2].name = "A corrected title";
        p.getMuxer().updateSchedule(0x1000, changed);
        c.event_texts.clear();
        run(p, 1, 15);
        bool has_new = false, has_old = false;
        for (const auto& t : c.event_texts[0x1000]) {
            if (t.find("A corrected title") != std::string::npos) has_new = true;
            if (t.find("Programme 2") != std::string::npos) has_old = true;
        }
        check(has_new && !has_old && c.events[0x1000].size() == 5, "a corrected programme replaces the old one in the EIT");
    }
    {
        DabStreamProcessor p;
        Checker c;
        p.setOutput([&](const uint8_t* d, size_t len) { c.feed(d, len); });
        add_services(p, 2);
        // service 0: 10 programmes of yesterday, 10 from now on; service 1: far too many;
        // and a service this TS does not have
        p.getMuxer().updateSchedule(0x1000, schedule(0x1000, now - 86400, 10, 1800));
        p.getMuxer().updateSchedule(0x1000, schedule(0x1000, now, 10, 1800));
        p.getMuxer().updateSchedule(0x1001, schedule(0x1001, now, 3000, 600));
        p.getMuxer().updateSchedule(0x7777, schedule(0x7777, now, 10, 1800));
        run(p, 2, 30);
        check(c.events[0x1000].size() == 10, "programmes that ended long ago are dropped from the guide");
        check(c.events[0x1001].size() == 1024, "a service keeps 1024 programmes at most");
        check(c.events.count(0x7777) == 0, "no EIT for a service the TS does not have");
        check(c.bad_crc == 0 && c.cc_errors == 0, "and the TS is still in order");
    }
    {
        // a recording of long ago: its guide is not judged by the clock of today
        DabStreamProcessor p;
        Checker c;
        p.setOutput([&](const uint8_t* d, size_t len) { c.feed(d, len); });
        add_services(p, 1);
        p.getMuxer().updateSchedule(0x1000, schedule(0x1000, 1500000000, 20, 1800));
        run(p, 1, 30);
        check(c.events[0x1000].size() == 20, "the guide of an old recording stays");
    }

    {
        // what the ensemble says about a service, in the sections
        auto has = [](const std::vector<uint8_t>& in, std::initializer_list<uint8_t> what) {
            return std::search(in.begin(), in.end(), what.begin(), what.end()) != in.end();
        };
        TsService svc{};
        svc.sid = 0x1000;
        svc.pmt_pid = 0x100;
        svc.audio_pid = 0x1000;
        svc.dabplus = true;
        std::vector<uint8_t> plain = buildPmtSection(svc, 3);
        svc.language = "nor";
        std::vector<uint8_t> with = buildPmtSection(svc, 3);
        check(with.size() == plain.size() + 6 && has(with, {0xF0, 0x06, 0x0A, 0x04, 'n', 'o', 'r', 0x00}) &&
                  !has(plain, {0x0A, 0x04}) && dvb_crc32(with.data(), with.size()) == 0 &&
                  (((with[1] & 0x0F) << 8) | with[2]) == static_cast<int>(with.size()) - 3,
              "the PMT has the language of the audio when the ensemble says it, and only then");

        EpgSchedule sch = schedule(0x1000, 1795000000, 3, 1800);
        auto und = buildEitScheduleSections(0x1000, 1, 1, 0, sch.programmes);
        auto nor = buildEitScheduleSections(0x1000, 1, 1, 0, sch.programmes, "nor", 0x62);
        check(und.size() == 1 && nor.size() == 1 && has(und[0], {0x4D}) && has(und[0], {'u', 'n', 'd'}) &&
                  !has(und[0], {0x54, 0x02}) && has(nor[0], {'n', 'o', 'r'}) && !has(nor[0], {'u', 'n', 'd'}) &&
                  has(nor[0], {0x54, 0x02, 0x62, 0x00}) && nor[0].size() == und[0].size() + 3 * 4 &&
                  dvb_crc32(nor[0].data(), nor[0].size()) == 0,
              "EIT events are in the language of the service and have its content; 'und' and none without");

        // 2026-11-18 11:06:40 UTC is MJD 61362 (0xEFB2)
        check(buildTdtSection(1795000000) == std::vector<uint8_t>({0x70, 0x70, 0x05, 0xEF, 0xB2, 0x11, 0x06, 0x40}),
              "the TDT of a time");
    }
    {
        // a TDT only when the ensemble sends a time; language and content that come later get into PMT and EIT
        for (bool with_time : {false, true}) {
            DabStreamProcessor p;
            std::vector<uint8_t> ts;
            p.setOutput([&](const uint8_t* d, size_t len) { ts.insert(ts.end(), d, d + len); });
            add_services(p, 1);
            p.getMuxer().updateSchedule(0x1000, schedule(0x1000, now, 5, 1800));
            if (with_time) p.setUtc(1795000000123);
            run(p, 1, 12);
            size_t tdt = 0, cut = ts.size();
            for (size_t i = 0; i + 188 <= ts.size(); i += 188)
                if ((((ts[i + 1] & 0x1F) << 8) | ts[i + 2]) == 0x14) tdt++;
            check(with_time ? tdt >= 2 && tdt <= 4 : tdt == 0,
                  with_time ? "a TDT every 5 s with the time of the ensemble" : "no TDT without a time from the ensemble");
            if (!with_time) continue;
            p.updateServiceInfo(0x1000, "ger", 0x61);
            run(p, 1, 12);
            const uint8_t lang[] = {0x0A, 0x04, 'g', 'e', 'r'}, content[] = {0x54, 0x02, 0x61, 0x00};
            bool before = std::search(ts.begin(), ts.begin() + static_cast<std::ptrdiff_t>(cut), lang, lang + 5) !=
                          ts.begin() + static_cast<std::ptrdiff_t>(cut);
            bool pmt = std::search(ts.begin() + static_cast<std::ptrdiff_t>(cut), ts.end(), lang, lang + 5) != ts.end();
            bool eit = std::search(ts.begin() + static_cast<std::ptrdiff_t>(cut), ts.end(), content, content + 4) != ts.end();
            check(!before && pmt && eit, "language and content that come while the stream runs are in PMT and EIT");
        }
    }

    {
        // EIT present/following by the time of the ensemble; the SDT says which service has which EIT
        const time_t t0 = 1795000000;
        auto id = [](time_t start) { return static_cast<int>((start / 60) & 0xFFFF); };
        DabStreamProcessor p;
        Checker c;
        p.setOutput([&](const uint8_t* d, size_t len) { c.feed(d, len); });
        add_services(p, 2);
        p.getMuxer().updateSchedule(0x1000, schedule(0x1000, t0, 5, 1800));   // service 1 has none
        run(p, 2, 6);
        check(c.pf_event.empty() && c.sdt_eit_flags[0x1000] == 0x02 && c.sdt_eit_flags[0x1001] == 0x00,
              "without a time from the ensemble no EIT present/following; the SDT says a schedule for the service that has one");
        p.setUtc((t0 + 2000) * 1000LL);   // in the second programme
        run(p, 2, 6);
        check(c.pf_event[0x1000][0] == id(t0 + 1800) && c.pf_running[0x1000][0] == 4 &&
                  c.pf_event[0x1000][1] == id(t0 + 3600) && c.pf_running[0x1000][1] == 1 && !c.pf_event.count(0x1001),
              "EIT present/following: the programme that is on (running) and the next one");
        check(c.sdt_eit_flags[0x1000] == 0x03 && c.sdt_eit_flags[0x1001] == 0x00 && c.event_ids[0x1000].count(
                  static_cast<uint16_t>(id(t0 + 1800))),
              "the SDT says both EITs for it, and the events have the ids of the schedule");
        size_t versions = c.pf_versions[0x1000].size();
        p.setUtc((t0 + 3700) * 1000LL);   // the third programme began
        run(p, 2, 6);
        check(c.pf_event[0x1000][0] == id(t0 + 3600) && c.pf_event[0x1000][1] == id(t0 + 5400) &&
                  c.pf_versions[0x1000].size() == versions + 1,
              "when the next programme begins it is the present one, in a new version");
        p.setUtc((t0 + 5 * 1800 + 10) * 1000LL);   // after the last programme
        run(p, 2, 6);
        check(c.pf_event[0x1000][0] == -1 && c.pf_event[0x1000][1] == -1,
              "after the last programme of the schedule both sections are without an event");
        check(c.bad_crc == 0 && c.cc_errors == 0, "and the TS is in order");
    }

    std::printf("%s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
