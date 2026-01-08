#pragma once

#include <dvbdab/dvbdab.hpp>
#include <cstdint>
#include <functional>

namespace dvbdab {

// UDP Extractor - shared component that extracts UDP payloads from IPv4 packets
// All input sources converge at IPv4 level, this extracts (dst_ip, dst_port, payload)
// for routing to per-ensemble EDI parsers
class UdpExtractor {
public:
    explicit UdpExtractor(UdpPacketCallback callback);

    // Process an IPv4 packet, extract UDP payload and emit via callback
    void process(const uint8_t* ip_packet, size_t len);

    // Reset statistics
    void reset();

    // Statistics
    size_t getIpPacketCount() const { return ip_packet_count_; }
    size_t getUdpPacketCount() const { return udp_packet_count_; }
    size_t getNonUdpCount() const { return non_udp_count_; }

private:
    UdpPacketCallback callback_;

    size_t ip_packet_count_{0};
    size_t udp_packet_count_{0};
    size_t non_udp_count_{0};
};

// Standalone function for simple extraction without callback management
// Returns true if UDP was successfully extracted
// Fills dst_ip, dst_port, payload_ptr, payload_len on success
bool extractUdpFromIpv4(const uint8_t* ip_packet, size_t len,
                        uint32_t& dst_ip, uint16_t& dst_port,
                        const uint8_t*& payload_ptr, size_t& payload_len);

} // namespace dvbdab
