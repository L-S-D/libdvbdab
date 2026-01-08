#pragma once

#include <dvbdab/input_source.hpp>
#include "../parsers/gse_parser.hpp"
#include <vector>

namespace dvbdab {

// Input source for GSE-in-TS format (e.g., live_gse_capture.bin)
// Format: 188-byte TS packets with GSE data starting at byte 4 (after TS header)
// No BBF framing - raw GSE packets directly in TS payload
//
// This format is used when GSE is carried directly in TS null packets (PID 0x1fff)
// or similar. The entire TS payload contains GSE data with no additional framing.
class GseTsSource : public InputSource {
public:
    GseTsSource();

    // Feed arbitrary amount of data (handles partial TS packets internally)
    void feed(const uint8_t* data, size_t len) override;

    // Feed exactly one 188-byte TS packet (no buffering needed)
    void feedPacket(const uint8_t* ts_packet);

    void reset() override;
    const char* description() const override { return "GSE-in-TS"; }

    // Statistics
    size_t getTsPacketCount() const { return ts_packet_count_; }
    size_t getGsePacketCount() const { return gse_parser_.getPacketCount(); }

private:
    GseParser gse_parser_;
    std::vector<uint8_t> partial_ts_;  // Buffer for incomplete TS packets
    size_t ts_packet_count_{0};
};

} // namespace dvbdab
