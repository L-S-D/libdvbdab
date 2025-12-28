#pragma once

#include <dvbdab/dvbdab.hpp>
#include <cstdint>
#include <vector>
#include <functional>

namespace dvbdab {

// MPE (Multi-Protocol Encapsulation) Section Parser
// Input: TS packets with MPEG-2 PSI section framing (table_id 0x3E)
// Output: Complete IPv4 packets via callback
//
// MPE Section structure (ETSI EN 301 192):
//   byte 0: table_id (0x3E for MPE)
//   bytes 1-2: section_syntax_indicator(1) + reserved(3) + section_length(12)
//   bytes 3-4: MAC_address_5, MAC_address_4
//   bytes 5-6: reserved(2) + payload_scrambling(2) + address_scrambling(2) + LLC_SNAP_flag(1) + current_next(1) + section_number(8)
//   byte 7: last_section_number
//   bytes 8-11: MAC_address_3-0
//   bytes 12+: IP datagram
//   last 4 bytes: CRC32
//
// TS packet handling:
//   PUSI=1: First byte is pointer_field, section starts at pointer_field+1
//   PUSI=0: Continuation of previous section
class MpeParser {
public:
    explicit MpeParser(IpPacketCallback callback);

    // Feed a single TS packet payload (after adaptation field handling)
    // pusi: Payload Unit Start Indicator from TS header
    void feedTsPayload(const uint8_t* payload, size_t len, bool pusi);

    // Reset parser state
    void reset();

    // Statistics
    size_t getSectionCount() const { return section_count_; }
    size_t getIpPacketCount() const { return ip_packet_count_; }

private:
    // Process a complete MPE section
    void processSection();

    IpPacketCallback callback_;

    // Section accumulation buffer
    std::vector<uint8_t> section_buffer_;
    size_t section_length_{0};      // Expected section length (from header)
    bool in_section_{false};        // Currently accumulating a section

    // Statistics
    size_t section_count_{0};
    size_t ip_packet_count_{0};
};

} // namespace dvbdab
