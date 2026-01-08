#include "udp_extractor.hpp"

namespace dvbdab {

UdpExtractor::UdpExtractor(UdpPacketCallback callback)
    : callback_(std::move(callback))
{
}

void UdpExtractor::reset() {
    ip_packet_count_ = 0;
    udp_packet_count_ = 0;
    non_udp_count_ = 0;
}

void UdpExtractor::process(const uint8_t* ip_packet, size_t len) {
    ip_packet_count_++;

    uint32_t dst_ip;
    uint16_t dst_port;
    const uint8_t* payload;
    size_t payload_len;

    if (extractUdpFromIpv4(ip_packet, len, dst_ip, dst_port, payload, payload_len)) {
        udp_packet_count_++;
        callback_(dst_ip, dst_port, payload, payload_len);
    } else {
        non_udp_count_++;
    }
}

// Exact copy of standalone extractUdp logic
bool extractUdpFromIpv4(const uint8_t* ip_packet, size_t len,
                        uint32_t& dst_ip, uint16_t& dst_port,
                        const uint8_t*& payload_ptr, size_t& payload_len) {
    // Minimum: 20 byte IPv4 header + 8 byte UDP header
    if (len < 28) return false;

    // Verify IPv4 version
    if ((ip_packet[0] >> 4) != 4) return false;

    // Check protocol (17 = UDP)
    if (ip_packet[9] != 17) return false;

    // Extract destination IP (bytes 16-19, big-endian)
    dst_ip = (ip_packet[16] << 24) | (ip_packet[17] << 16) | (ip_packet[18] << 8) | ip_packet[19];

    // Get IP header length (in 32-bit words)
    int ip_hdr = (ip_packet[0] & 0x0F) * 4;
    if (ip_hdr < 20 || (size_t)ip_hdr + 8 > len) return false;

    // UDP header starts after IP header
    const uint8_t* udp = ip_packet + ip_hdr;

    // Extract destination port (bytes 2-3 of UDP header, big-endian)
    dst_port = (udp[2] << 8) | udp[3];

    // Get UDP length directly from UDP header (no truncation)
    int udp_len = (udp[4] << 8) | udp[5];
    if (udp_len < 8) return false;

    // Payload starts after 8-byte UDP header
    payload_ptr = udp + 8;
    payload_len = udp_len - 8;

    return true;
}

} // namespace dvbdab
