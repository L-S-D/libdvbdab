// Tests for the TS the library puts out: ETI frames with DAB (MPEG Layer II)
// services through the stream processor, and the result through a small TS
// checker - sync bytes, continuity counters, the CRC-32 and size of every
// section, PTS in order - and the programme guide: its period, what is
// dropped from it. Synthetic frames, no capture needed.

#include "../src/output/dab_stream_processor.hpp"
#include "../src/utils/crc_utils.hpp"
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
    // EIT: per service the events seen (start time bytes), and how often its section 0 came
    std::map<uint16_t, std::set<std::vector<uint8_t>>> events;
    std::map<uint16_t, size_t> eit_passes;

    static bool psi(uint16_t pid) { return pid < 0x20 || (pid >= 0x100 && pid < 0x200); }

    void section(uint16_t pid, const uint8_t* s, size_t n) {
        sections++;
        if (n > max_section[pid]) max_section[pid] = n;
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < n; i++) crc = (crc << 8) ^ dvb_crc32_table[((crc >> 24) ^ s[i]) & 0xFF];
        if (crc != 0) bad_crc++;
        if (pid == 0x12 && n >= 18 && s[0] == 0x50) {
            uint16_t sid = static_cast<uint16_t>(s[3] << 8 | s[4]);
            if (s[6] == 0) eit_passes[sid]++;
            for (size_t p = 14; p + 12 <= n - 4;) {
                size_t dl = static_cast<size_t>((s[p + 10] & 0x0F) << 8 | s[p + 11]);
                events[sid].insert(std::vector<uint8_t>(s + p + 2, s + p + 7));
                p += 12 + dl;
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
            if (afc & 2) pl = 5 + k[4];
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
static void run(DabStreamProcessor& p, int n, int seconds) {
    std::vector<uint8_t> mp2(384, 0x11);
    mp2[0] = 0xFF;
    mp2[1] = 0xF5;
    mp2[2] = 0x84;
    mp2[3] = 0x00;
    mp2[382] = 0;
    mp2[383] = 0;
    int frames = seconds * 1000 / 24;
    for (int i = 0; i < frames; i++) {
        if (i > 100 && i % 51 == 0) continue;
        std::vector<std::vector<uint8_t>> subs(n, std::vector<uint8_t>(mp2.begin() + (i % 2) * 192, mp2.begin() + (i % 2) * 192 + 192));
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

    std::printf("%s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
