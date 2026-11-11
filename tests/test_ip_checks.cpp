// Tests for the IPv4 checks of the UDP extraction: a header with a wrong
// checksum or a UDP datagram that does not fit into its packet is dropped.

#include "../src/parsers/udp_extractor.hpp"
#include "../src/ensemble_manager.hpp"
#include <cstdint>
#include <cstdio>
#include <vector>

using namespace dvbdab;

static int failures = 0;

static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

static void set_checksum(std::vector<uint8_t>& p) {
    p[10] = p[11] = 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < 20; i += 2)
        sum += (static_cast<uint32_t>(p[i]) << 8) | p[i + 1];
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t c = static_cast<uint16_t>(~sum);
    p[10] = c >> 8;
    p[11] = c & 0xFF;
}

// an IPv4/UDP packet to ip:port with the payload, the header checksum right
static std::vector<uint8_t> make_packet(uint32_t ip, uint16_t port, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> p(28 + payload.size());
    size_t total = p.size(), udp_len = 8 + payload.size();
    p[0] = 0x45;
    p[2] = total >> 8;
    p[3] = total & 0xFF;
    p[8] = 64;
    p[9] = 17;
    p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 1;
    p[16] = ip >> 24; p[17] = (ip >> 16) & 0xFF; p[18] = (ip >> 8) & 0xFF; p[19] = ip & 0xFF;
    p[20] = 0x13; p[21] = 0x88;
    p[22] = port >> 8; p[23] = port & 0xFF;
    p[24] = udp_len >> 8; p[25] = udp_len & 0xFF;
    for (size_t i = 0; i < payload.size(); i++)
        p[28 + i] = payload[i];
    set_checksum(p);
    return p;
}

int main() {
    const uint32_t ip = 0xEFC7020C;  // 239.199.2.12
    const std::vector<uint8_t> payload(64, 0xA5);  // no EDI

    {
        auto p = make_packet(ip, 5555, payload);
        uint32_t dst_ip; uint16_t dst_port; const uint8_t* pl; size_t pl_len;
        check(ipv4HeaderChecksumOk(p.data(), 20), "checksum of a right header");
        check(extractUdpFromIpv4(p.data(), p.size(), dst_ip, dst_port, pl, pl_len) &&
              dst_ip == ip && dst_port == 5555 && pl_len == payload.size(),
              "a right packet is extracted");

        auto bad = p;
        bad[19] ^= 0x08;  // 239.199.2.12 -> .4, the checksum not updated
        check(!ipv4HeaderChecksumOk(bad.data(), 20), "checksum of a damaged header");
        check(!extractUdpFromIpv4(bad.data(), bad.size(), dst_ip, dst_port, pl, pl_len),
              "a packet with a damaged header is dropped");

        auto longer = p;
        longer[24] = 0x40;  // UDP length 16384, the packet is 92 bytes
        check(!extractUdpFromIpv4(longer.data(), longer.size(), dst_ip, dst_port, pl, pl_len),
              "a UDP datagram longer than its packet is dropped");
    }

    {
        EnsembleManager m;
        auto p = make_packet(ip, 5555, payload);
        auto bad = p;
        bad[18] ^= 0x01;
        m.processIpPacket(bad.data(), bad.size());
        check(m.getStreamCount() == 0, "a damaged header makes no stream");
        m.processIpPacket(p.data(), p.size());
        check(m.getStreamCount() == 1, "a right packet makes a stream");
    }

    std::printf("%s\n", failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}
