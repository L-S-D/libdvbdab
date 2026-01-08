#pragma once

#include <dvbdab/input_source.hpp>
#include "../parsers/mpe_parser.hpp"
#include <vector>

namespace dvbdab {

// Constants for TS packets
constexpr size_t MPE_TS_PACKET_SIZE = 188;
constexpr size_t MPE_TS_HEADER_SIZE = 4;

// Input source for MPE-in-TS format (e.g., astra1-wdr.ts)
// Format: Standard MPEG-2 TS with MPE sections (table_id 0x3E)
//
// This format is used for traditional DVB-T/S/C MPE encapsulation.
// The PID is configurable (e.g., 3000 for WDR).
class MpeTsSource : public InputSource {
public:
    // Constructor with configurable PID (default 3000 for WDR)
    explicit MpeTsSource(uint16_t pid = 3000);

    // Feed arbitrary amount of data (handles partial TS packets internally)
    void feed(const uint8_t* data, size_t len) override;

    // Feed exactly one 188-byte TS packet (no buffering needed)
    void feedPacket(const uint8_t* ts_packet);

    void reset() override;
    const char* description() const override { return "MPE-in-TS"; }

    // Statistics
    size_t getTsPacketCount() const { return ts_packet_count_; }
    size_t getMpeSectionCount() const { return mpe_parser_.getSectionCount(); }
    size_t getIpPacketCount() const { return mpe_parser_.getIpPacketCount(); }
    size_t getFilteredPacketCount() const { return filtered_packet_count_; }

    // Get/set target PID
    uint16_t getPid() const { return target_pid_; }
    void setPid(uint16_t pid) { target_pid_ = pid; }

    // Set IP:port filter (0 = no filter)
    void setIpFilter(uint32_t ip, uint16_t port) { filter_ip_ = ip; filter_port_ = port; }

private:
    void processTsPacket(const uint8_t* ts_packet);
    bool matchesFilter(const uint8_t* ip_data, size_t len);

    MpeParser mpe_parser_;
    std::vector<uint8_t> partial_ts_;  // Buffer for incomplete TS packets
    uint16_t target_pid_;
    uint32_t filter_ip_{0};      // 0 = no filter
    uint16_t filter_port_{0};    // 0 = no filter
    size_t ts_packet_count_{0};
    size_t filtered_packet_count_{0};
};

} // namespace dvbdab
