// Fuzz harness: EDI over UDP into a streamer of the C API, as tvheadend
// feeds it. The input is a sequence of records [length, 2 bytes][bytes]; each
// record is the payload of one UDP datagram to the address the streamer
// filters for (the harness makes the IPv4 and UDP headers, their checksum
// right). Behind it: PF and AF packets, TAG items, the ETI frame, the FIC,
// and with a ready ensemble the decoders, PAD, packet mode, MOT, EHB and the
// TS muxer.

#include <dvbdab/dvbdab_c.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

const uint32_t IP = 0xEF010101;  // 239.1.1.1
const uint16_t PORT = 5000;

void on_ts(void*, const uint8_t* d, size_t n) {
    // whatever comes in: what goes out is whole TS packets
    if (n % 188) abort();
    for (size_t i = 0; i < n; i += 188)
        if (d[i] != 0x47) abort();
}

void feed_udp(dvbdab_streamer_t* s, const uint8_t* payload, size_t len) {
    std::vector<uint8_t> p(28 + len);
    size_t total = p.size(), udp_len = 8 + len;
    p[0] = 0x45;
    p[2] = total >> 8;
    p[3] = total & 0xFF;
    p[8] = 64;
    p[9] = 17;
    p[16] = IP >> 24;
    p[17] = (IP >> 16) & 0xFF;
    p[18] = (IP >> 8) & 0xFF;
    p[19] = IP & 0xFF;
    uint32_t sum = 0;
    for (size_t i = 0; i < 20; i += 2) sum += (static_cast<uint32_t>(p[i]) << 8) | p[i + 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t c = static_cast<uint16_t>(~sum);
    p[10] = c >> 8;
    p[11] = c & 0xFF;
    p[22] = PORT >> 8;
    p[23] = PORT & 0xFF;
    p[24] = udp_len >> 8;
    p[25] = udp_len & 0xFF;
    if (len) memcpy(&p[28], payload, len);
    dvbdab_streamer_feed(s, p.data(), p.size());
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static bool quiet = (dvbdab_set_log_callback([](int, const char*, const char*) {}), true);
    (void)quiet;
    dvbdab_streamer_config_t c;
    memset(&c, 0, sizeof(c));
    c.format = DVBDAB_FORMAT_IPV4;
    c.filter_ip = IP;
    c.filter_port = PORT;
    // the first byte: the DAB+ output mode
    if (size) {
        c.aac_output = data[0] % 2 ? DVBDAB_AAC_LATM : DVBDAB_AAC_ADTS;
        data++;
        size--;
    }
    dvbdab_streamer_t* s = dvbdab_streamer_create(&c);
    if (!s) return 0;
    dvbdab_streamer_set_output(s, on_ts, nullptr);
    dvbdab_streamer_start_all(s);
    while (size >= 2) {
        size_t len = static_cast<size_t>(data[0] << 8 | data[1]);
        data += 2;
        size -= 2;
        if (len > size) len = size;
        feed_udp(s, data, len);
        data += len;
        size -= len;
        dvbdab_streamer_start_all(s);  // services that became known
    }
    dvbdab_ensemble_t* e = dvbdab_streamer_get_ensemble(s);
    dvbdab_streamer_free_ensemble(e);
    dvbdab_streamer_destroy(s);
    return 0;
}
