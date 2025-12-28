#pragma once

#include <dvbdab/dvbdab.hpp>
#include <cstdint>
#include <vector>
#include <array>
#include <functional>

namespace dvbdab {

// GSE fragment reassembly buffer
struct GseFragment {
    std::vector<uint8_t> data;
    size_t total_length{0};
    size_t current_pos{0};
    bool active{false};
};

// GSE (Generic Stream Encapsulation) Parser
// Input: Raw GSE packets (with S/E/LT/length header)
// Output: Complete IPv4 packets via callback
//
// GSE Header (2 bytes):
//   Bit 7: Start (S) - 1=first/only fragment
//   Bit 6: End (E) - 1=last/only fragment
//   Bits 5-4: Label Type (LT) - 0=6-byte, 1=3-byte, 2=broadcast, 3=reuse
//   Bits 3-0 + byte 1: GSE Length (12 bits)
//
// Fragment handling:
//   S=1,E=1: Complete packet, no fragmentation
//   S=1,E=0: First fragment (includes FragID + TotalLength)
//   S=0,E=0: Middle fragment (includes FragID)
//   S=0,E=1: Last fragment (includes FragID + CRC32)
//
// TS boundary handling:
//   GSE packets may span multiple TS packets, but padding at the end
//   of a TS payload signals that the next GSE packet starts at the
//   beginning of the next TS payload. Use feedTsPayload() for proper
//   boundary-aware parsing.
class GseParser {
public:
    explicit GseParser(IpPacketCallback callback);

    // Feed raw GSE data from a single TS payload (184 bytes typically)
    // This method properly handles padding at end of TS payload
    void feedTsPayload(const uint8_t* data, size_t len);

    // Feed raw GSE data (can be partial packets)
    // Handles internal buffering and fragment reassembly
    // Requires sync first if not already synced
    void feed(const uint8_t* data, size_t len);

    // Feed GSE data from a known-good source (e.g., BBF frame)
    // Bypasses sync detection, assumes data starts at valid GSE boundary
    void feedSynced(const uint8_t* data, size_t len);

    // Reset parser state
    void reset();

    // Statistics
    size_t getPacketCount() const { return packet_count_; }
    size_t getFragmentCount() const { return fragment_count_; }

private:
    // Find sync point (first valid GSE packet)
    // Returns position or SIZE_MAX if not found
    size_t findSync();

    // Process a single complete GSE packet
    // Returns true if packet was valid, false on padding/error
    bool processGsePacket(const uint8_t* data, size_t len, size_t& consumed);

    // Handle complete (possibly reassembled) GSE payload
    void handleCompleteGsePayload(const uint8_t* data, size_t len);

    // Extract and emit IPv4 packet from GSE payload
    void emitIpv4Packet(const uint8_t* ip_data, size_t len);

    IpPacketCallback callback_;

    // Accumulation buffer for partial GSE packets
    std::vector<uint8_t> buffer_;

    // Sync state
    bool synced_{false};

    // Fragment reassembly buffers (indexed by fragment ID 0-255)
    std::array<GseFragment, GSE_FRAGMENT_ID_COUNT> fragments_;

    // Statistics
    size_t packet_count_{0};
    size_t fragment_count_{0};
};

} // namespace dvbdab
