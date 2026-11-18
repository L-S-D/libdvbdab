// Tests for what the FIC says about an ensemble and for its changes while a
// stream runs: bitrates and labels, services that must not keep the others
// waiting, and a reconfiguration - at the FIC parser, and through a streamer
// of the C API into the PAT and SDT that go out. Synthetic FIGs, no capture.

#include <dvbdab/dvbdab_c.h>
#include "../src/dab_parser.h"
#include "../src/logging.h"
#include "../src/utils/crc_utils.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace dvbdab;

static int failures = 0;

static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

using Bytes = std::vector<uint8_t>;

// ---- FIGs ----

static Bytes fig0(int ext, const Bytes& body, bool next_config = false) {
    Bytes f = {static_cast<uint8_t>(body.size() + 1), static_cast<uint8_t>((next_config ? 0x80 : 0) | ext)};
    f.insert(f.end(), body.begin(), body.end());
    return f;
}

static Bytes ensemble_info(uint16_t eid) { return fig0(0, {static_cast<uint8_t>(eid >> 8), static_cast<uint8_t>(eid), 0, 0}); }

// FIG 0/1, long form: EEP, set A or B, protection level 1-4, size in capacity units
static Bytes subch_eep(int subch, int size, int level, bool set_b = false) {
    return {static_cast<uint8_t>(subch << 2), 0,
            static_cast<uint8_t>(0x80 | (set_b ? 0x10 : 0) | ((level - 1) << 2) | (size >> 8)), static_cast<uint8_t>(size)};
}
// FIG 0/1, short form: UEP by table index
static Bytes subch_uep(int subch, int index) { return {static_cast<uint8_t>(subch << 2), 0, static_cast<uint8_t>(index)}; }

// FIG 0/2: a programme service with one audio component (DAB+ or DAB), or with a data component
static Bytes service(uint16_t sid, int subch, bool dabplus, bool data = false) {
    return {static_cast<uint8_t>(sid >> 8), static_cast<uint8_t>(sid), 0x01,
            static_cast<uint8_t>(data ? 0x40 | 5 : (dabplus ? 63 : 0)), static_cast<uint8_t>(subch << 2 | 0x02)};
}

static Bytes label(int ext, uint16_t id, const std::string& text, int charset = 0) {
    Bytes f = {static_cast<uint8_t>(0x20 | 21), static_cast<uint8_t>(charset << 4 | ext), static_cast<uint8_t>(id >> 8),
               static_cast<uint8_t>(id)};
    std::string t = text;
    t.resize(16, ' ');
    f.insert(f.end(), t.begin(), t.end());
    f.push_back(0xFF);
    f.push_back(0x00);
    return f;
}

static Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

static Bytes fib(const Bytes& figs) {
    Bytes b = figs;
    if (b.size() > 30) {
        std::printf("FAIL: the test put %zu bytes of FIGs into a FIB of 30\n", b.size());
        failures++;
        b.resize(30);
    }
    if (b.size() < 30) b.push_back(0xFF);
    b.resize(30, 0);
    uint16_t c = crc16_ccitt_xor(b.data(), 30);
    b.push_back(c >> 8);
    b.push_back(c & 0xFF);
    return b;
}

// A FIC of three FIBs: two of the configuration (the second may be empty),
// and one of the labels by turns
struct Fic {
    Bytes config, config2;
    std::vector<Bytes> labels;
    Bytes at(int frame) const {
        Bytes f = fib(config);
        Bytes b = fib(config2);
        f.insert(f.end(), b.begin(), b.end());
        b = fib(labels.empty() ? Bytes{} : labels[static_cast<size_t>(frame) % labels.size()]);
        f.insert(f.end(), b.begin(), b.end());
        return f;
    }
};

// an ETI frame with this FIC and no streams
static Bytes eti_frame(int n, const Bytes& fic) {
    Bytes f(6144, 0x55);
    f[0] = 0xFF;
    f[1] = 0x07;
    f[2] = 0x3A;
    f[3] = 0xB6;
    f[4] = static_cast<uint8_t>(n % 250);
    f[5] = 0x80;  // FICF, no streams
    f[6] = 0x08;  // mode I
    f[7] = 0;
    std::memcpy(&f[12], fic.data(), fic.size());
    return f;
}

static int feed(DABParser& p, const Fic& fic, int frames, int& n) {
    for (int i = 0; i < frames; i++, n++) {
        Bytes f = eti_frame(n, fic.at(n));
        p.process_eti_frame(f.data(), f.size());
    }
    return n;
}

static const DABService* find(const DABEnsemble& e, uint32_t sid) {
    for (const auto& s : e.services)
        if (s.sid == sid) return &s;
    return nullptr;
}

// ---- through the C API: EDI packets in, the PAT and SDT that come out ----

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

// a superframe of a 24 kbit/s DAB+ subchannel (5 frames of 72 bytes, 3 AUs)
static Bytes superframe(uint8_t fill) {
    const size_t fs = 72, audio = fs * 5 - 3 * 10;
    Bytes sf(fs * 5, 0);
    sf[2] = 0x60;
    const size_t start[4] = {6, 114, 222, audio};
    sf[3] = start[1] >> 4;
    sf[4] = static_cast<uint8_t>((start[1] & 0x0F) << 4 | (start[2] >> 8));
    sf[5] = start[2] & 0xFF;
    for (int i = 0; i < 3; i++) {
        size_t len = start[i + 1] - start[i];
        for (size_t k = 0; k + 2 < len; k++) sf[start[i] + k] = fill;
        uint16_t c = crc16_ccitt_xor(sf.data() + start[i], len - 2);
        sf[start[i] + len - 2] = c >> 8;
        sf[start[i] + len - 1] = c & 0xFF;
    }
    uint16_t crc = 0;
    for (int i = 0; i < 9; i++) crc = static_cast<uint16_t>((crc << 8) ^ firecode_table[((crc >> 8) ^ sf[2 + i]) & 0xFF]);
    sf[0] = crc >> 8;
    sf[1] = crc & 0xFF;
    return sf;
}

struct TsOut {
    std::map<uint16_t, Bytes> sec;
    std::set<uint16_t> programs;             // of the last PAT
    std::map<uint16_t, std::string> names;   // of the last SDT sections
    int pat_version = -1, pat_changes = 0;
    void section(uint16_t pid, const uint8_t* s, size_t n) {
        if (pid == 0 && s[0] == 0x00) {
            int v = (s[5] >> 1) & 0x1F;
            if (v != pat_version) {
                pat_version = v;
                pat_changes++;
            }
            programs.clear();
            for (size_t p = 8; p + 4 <= n - 4; p += 4) programs.insert(static_cast<uint16_t>(s[p] << 8 | s[p + 1]));
        }
        if (pid == 0x11 && s[0] == 0x42) {
            if (s[6] == 0) names.clear();
            for (size_t p = 11; p + 5 <= n - 4;) {
                uint16_t sid = static_cast<uint16_t>(s[p] << 8 | s[p + 1]);
                size_t dl = static_cast<size_t>((s[p + 3] & 0x0F) << 8 | s[p + 4]);
                // service descriptor: tag, length, type, provider (length, text), name (length, text)
                if (dl >= 5 && s[p + 5] == 0x48) {
                    size_t pl = s[p + 8], nl = s[p + 9 + pl];
                    names[sid] = std::string(s + p + 10 + pl, s + p + 10 + pl + nl);
                }
                p += 5 + dl;
            }
        }
    }
    void feed(const uint8_t* d, size_t len) {
        for (size_t o = 0; o + 188 <= len; o += 188) {
            const uint8_t* k = d + o;
            uint16_t pid = static_cast<uint16_t>((k[1] & 0x1F) << 8 | k[2]);
            if (pid != 0 && pid != 0x11) continue;
            size_t pl = 4;
            if (k[3] & 0x20) pl = 5 + k[4];
            if (pl >= 188) continue;
            Bytes& b = sec[pid];
            if (k[1] & 0x40) {
                size_t ptr = k[pl];
                b.assign(k + pl + 1 + ptr, k + 188);
            } else {
                b.insert(b.end(), k + pl, k + 188);
            }
            while (b.size() >= 3 && b[0] != 0xFF) {
                size_t n = 3 + static_cast<size_t>((b[1] & 0x0F) << 8 | b[2]);
                if (b.size() < n) break;
                section(pid, b.data(), n);
                b.erase(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(n));
            }
        }
    }
};

struct Stream {
    dvbdab_streamer_t* s;
    TsOut out;
    int frame = 0;
    std::vector<Bytes> sf;
    Stream() {
        dvbdab_streamer_config_t c;
        std::memset(&c, 0, sizeof(c));
        c.format = DVBDAB_FORMAT_IPV4;
        c.filter_ip = 0xEF010101;
        c.filter_port = 5000;
        s = dvbdab_streamer_create(&c);
        dvbdab_streamer_set_output(s, [](void* o, const uint8_t* d, size_t n) { static_cast<TsOut*>(o)->feed(d, n); }, &out);
        dvbdab_streamer_start_all(s);
        for (int i = 0; i < 8; i++) sf.push_back(superframe(static_cast<uint8_t>(0x40 + i)));
    }
    ~Stream() { dvbdab_streamer_destroy(s); }
    // `frames` frames of the ensemble with this FIC; the subchannels in `subchs` carry DAB+ audio
    void run(const Fic& fic, const std::vector<int>& subchs, int frames) {
        for (int i = 0; i < frames; i++, frame++) {
            Bytes deti = {static_cast<uint8_t>(0x40 | (frame % 5000) / 250), static_cast<uint8_t>(frame % 250)};
            be32(deti, 1u << 22);
            Bytes f = fic.at(frame);
            deti.insert(deti.end(), f.begin(), f.end());
            Bytes tags;
            tag(tags, "*ptr", {'D', 'E', 'T', 'I', 0, 0, 0, 0});
            tag(tags, "deti", deti);
            for (size_t k = 0; k < subchs.size(); k++) {
                Bytes est = {static_cast<uint8_t>(subchs[k] << 2), 0, 0};
                const Bytes& sfr = sf[(frame / 5) % sf.size()];
                est.insert(est.end(), sfr.begin() + (frame % 5) * 72, sfr.begin() + (frame % 5) * 72 + 72);
                tag(tags, (std::string("est") + static_cast<char>(k + 1)).c_str(), est);
            }
            Bytes af = {'A', 'F'};
            be32(af, static_cast<uint32_t>(tags.size()));
            af.push_back(0);
            af.push_back(0);
            af.push_back(0x90);
            af.push_back('T');
            af.insert(af.end(), tags.begin(), tags.end());
            uint16_t c = crc16_ccitt_xor(af.data(), af.size());
            af.push_back(c >> 8);
            af.push_back(c & 0xFF);
            Bytes p(28 + af.size());
            size_t total = p.size(), ul = 8 + af.size();
            p[0] = 0x45;
            p[2] = total >> 8;
            p[3] = total & 0xFF;
            p[8] = 64;
            p[9] = 17;
            p[16] = 0xEF;
            p[17] = p[18] = p[19] = 1;
            uint32_t sum = 0;
            for (size_t k = 0; k < 20; k += 2) sum += (static_cast<uint32_t>(p[k]) << 8) | p[k + 1];
            while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
            uint16_t ck = static_cast<uint16_t>(~sum);
            p[10] = ck >> 8;
            p[11] = ck & 0xFF;
            p[22] = 5000 >> 8;
            p[23] = 5000 & 0xFF;
            p[24] = ul >> 8;
            p[25] = ul & 0xFF;
            std::memcpy(&p[28], af.data(), af.size());
            dvbdab_streamer_feed(s, p.data(), p.size());
            dvbdab_streamer_start_all(s);
        }
    }
};

int main() {
    set_log_callback([](LogLevel, const char*, const char*) {});

    {
        // bitrates: UEP by table 8, EEP of both sets
        DABParser p;
        Fic fic;
        fic.config = cat({ensemble_info(0x1234),
                          fig0(1, cat({subch_uep(1, 35), subch_eep(2, 18, 3), subch_eep(3, 27, 1, true)}))});
        fic.config2 = fig0(2, cat({service(0x1001, 1, false), service(0x1002, 2, true), service(0x1003, 3, true)}));
        fic.labels = {label(0, 0x1234, "Ensemble"), label(1, 0x1001, "One"), label(1, 0x1002, "Two"),
                      label(1, 0x1003, "\x8F", 0)};
        int n = 0;
        feed(p, fic, 60, n);
        const DABEnsemble& e = p.get_ensemble();
        const DABService *a = find(e, 0x1001), *b = find(e, 0x1002), *c = find(e, 0x1003);
        check(p.is_complete() && a && b && c, "an ensemble of three services is complete");
        check(a && a->bitrate == 128 && !a->dabplus && a->subchannel_size == 96 && a->protection_level == 3,
              "UEP table index 35 is 128 kbit/s at level 3 in 96 capacity units");
        check(b && b->bitrate == 24 && b->dabplus, "EEP 3-A with 18 capacity units is 24 kbit/s");
        check(c && c->bitrate == 32, "EEP 1-B with 27 capacity units is 32 kbit/s");
        check(c && c->label == "\xC5\xB8", "a label in the DAB character set (0x8F is Y with diaeresis)");
    }
    {
        // a data service and a service whose subchannel never comes do not keep the others waiting
        DABParser p;
        Fic fic;
        fic.config = cat({ensemble_info(0x1234), fig0(1, cat({subch_eep(1, 18, 3), subch_eep(2, 18, 3)}))});
        fic.config2 = fig0(2, cat({service(0x1001, 1, true), service(0x2000, 2, false, true), service(0x1009, 9, true)}));
        fic.labels = {label(0, 0x1234, "Ensemble"), label(1, 0x1001, "One")};
        int n = 0;
        feed(p, fic, 240, n);
        check(!p.is_basic_ready(), "a service without its subchannel is waited for at first");
        feed(p, fic, 60, n);
        const DABEnsemble& e = p.get_ensemble();
        check(p.is_basic_ready() && find(e, 0x1001) && !find(e, 0x2000) && !find(e, 0x1009),
              "then the ensemble is ready with the audio services that are whole");
    }
    {
        // a service without a label: complete after a while, the label can still come
        DABParser p;
        Fic fic;
        fic.config = cat({ensemble_info(0x1234), fig0(1, cat({subch_eep(1, 18, 3), subch_eep(2, 18, 3)})),
                          fig0(2, cat({service(0x1001, 1, true), service(0x1002, 2, true)}))});
        fic.labels = {label(0, 0x1234, "Ensemble"), label(1, 0x1001, "One")};
        int n = 0;
        feed(p, fic, 100, n);
        check(p.is_basic_ready() && !p.is_complete(), "without the label of a service the ensemble is not complete at once");
        feed(p, fic, 250, n);
        check(p.is_complete() && find(p.get_ensemble(), 0x1002) && find(p.get_ensemble(), 0x1002)->label.empty(),
              "but after a while it is, the service without a name");
        uint32_t rev = p.revision();
        fic.labels.push_back(label(1, 0x1002, "Two"));
        feed(p, fic, 20, n);
        check(p.revision() != rev && find(p.get_ensemble(), 0x1002)->label == "Two", "a label that comes late is a change");
    }
    {
        // a reconfiguration, seen at the parser
        DABParser p;
        Fic fic;
        fic.config = cat({ensemble_info(0x1234), fig0(1, cat({subch_eep(1, 18, 3)})), fig0(2, service(0x1001, 1, true))});
        fic.labels = {label(0, 0x1234, "Ensemble"), label(1, 0x1001, "One")};
        int n = 0;
        feed(p, fic, 60, n);
        uint32_t rev = p.revision();
        check(p.is_complete() && p.get_ensemble().services.size() == 1, "one service to begin with");

        // the next configuration is announced: nothing changes yet
        Fic announce = fic;
        announce.labels.push_back(cat({fig0(1, subch_eep(2, 18, 3), true), fig0(2, service(0x1002, 2, true), true)}));
        feed(p, announce, 100, n);
        check(p.revision() == rev && p.get_ensemble().services.size() == 1, "the next configuration (C/N = 1) is not the current one");

        // it is there: a second service, the first on another subchannel
        Fic next;
        next.config = cat({ensemble_info(0x1234), fig0(1, cat({subch_eep(3, 18, 3), subch_eep(2, 18, 3)})),
                           fig0(2, cat({service(0x1001, 3, true), service(0x1002, 2, true)}))});
        next.labels = {label(0, 0x1234, "Ensemble"), label(1, 0x1001, "One"), label(1, 0x1002, "Two")};
        feed(p, next, 30, n);
        const DABService* a = find(p.get_ensemble(), 0x1001);
        check(p.revision() != rev && p.get_ensemble().services.size() == 2 && a && a->subchannel_id == 3,
              "after the reconfiguration: the new service, the old one on its new subchannel");

        // a service leaves
        Fic less;
        less.config = cat({ensemble_info(0x1234), fig0(1, subch_eep(2, 18, 3)), fig0(2, service(0x1002, 2, true))});
        less.labels = {label(0, 0x1234, "Ensemble"), label(1, 0x1002, "Two")};
        feed(p, less, 300, n);
        check(find(p.get_ensemble(), 0x1001) != nullptr, "a service that is no longer sent stays for some seconds");
        feed(p, less, 260, n);
        check(!find(p.get_ensemble(), 0x1001) && find(p.get_ensemble(), 0x1002), "and is gone after 12 s");
    }
    {
        // the same through a streamer: PAT and SDT follow
        Stream st;
        Fic fic;
        fic.config = cat({ensemble_info(0x1234), fig0(1, subch_eep(1, 18, 3)), fig0(2, service(0x1001, 1, true))});
        fic.labels = {label(0, 0x1234, "Ensemble"), label(1, 0x1001, "One")};
        st.run(fic, {1}, 150);
        check(st.out.programs == std::set<uint16_t>{0x1001} && st.out.names[0x1001] == "One",
              "a streamer: the PAT and SDT of an ensemble with one service");
        int v = st.out.pat_changes;

        Fic two;
        two.config = cat({ensemble_info(0x1234), fig0(1, cat({subch_eep(1, 18, 3), subch_eep(2, 18, 3)})),
                          fig0(2, cat({service(0x1001, 1, true), service(0x1002, 2, true)}))});
        two.labels = {label(0, 0x1234, "Ensemble"), label(1, 0x1001, "One again"), label(1, 0x1002, "Two")};
        st.run(two, {1, 2}, 150);
        check(st.out.programs == (std::set<uint16_t>{0x1001, 0x1002}) && st.out.pat_changes > v,
              "a service that comes while the stream runs is in a new version of the PAT");
        check(st.out.names[0x1001] == "One again" && st.out.names[0x1002] == "Two", "and the SDT has its name and the changed one");

        Fic one;
        one.config = cat({ensemble_info(0x1234), fig0(1, subch_eep(2, 18, 3)), fig0(2, service(0x1002, 2, true))});
        one.labels = {label(0, 0x1234, "Ensemble"), label(1, 0x1002, "Two")};
        st.run(one, {2}, 700);
        check(st.out.programs == std::set<uint16_t>{0x1002}, "a service that left is no longer in the PAT");
    }

    std::printf("%s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
