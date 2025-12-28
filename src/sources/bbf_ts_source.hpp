#pragma once

#include <dvbdab/input_source.hpp>
#include "../parsers/gse_parser.hpp"
#include <vector>

namespace dvbdab {

// Constants for BBF-in-pseudoTS format
constexpr size_t BBF_TS_PACKET_SIZE = 188;
constexpr size_t BBF_TS_HEADER_SIZE = 4;
constexpr uint8_t BBF_SYNC_BYTE = 0xb8;

// Input source for BBF-in-pseudoTS format (e.g., nrk_gse_capture.ts)
// Format: 188-byte TS packets with pseudo-TS framing containing BBF data
//
// Pseudo-TS structure (after 4-byte TS header):
//   bytes 0-2: header (typically 00 80 00)
//   byte 3: payload type indicator
//   bytes 4-6: varies
//   byte 7: payload length
//   byte 8+: payload data
//
// If byte 8 == 0xb8, this is start of BBF frame (output from byte 8, length bytes)
// Otherwise, this is continuation data (output from byte 9, length-1 bytes)
//
// BBF frame structure:
//   byte 0: 0xb8 sync
//   bytes 1-9: BBF header
//   bytes 10+: GSE data (until end of frame)
//   last 4 bytes: CRC32
class BbfTsSource : public InputSource {
public:
    BbfTsSource();

    // Feed arbitrary amount of data (handles partial TS packets internally)
    void feed(const uint8_t* data, size_t len) override;

    // Feed exactly one 188-byte TS packet (no buffering needed)
    void feedPacket(const uint8_t* ts_packet);

    // Flush any remaining BBF data (call at end of stream)
    void flush();

    void reset() override;
    const char* description() const override { return "BBF-in-pseudoTS"; }

    // Statistics
    size_t getTsPacketCount() const { return ts_packet_count_; }
    size_t getBbfFrameCount() const { return bbf_frame_count_; }
    size_t getGsePacketCount() const { return gse_parser_.getPacketCount(); }

private:
    void processTsPacket(const uint8_t* ts_packet);
    void processBbfData();

    GseParser gse_parser_;
    std::vector<uint8_t> partial_ts_;  // Buffer for incomplete TS packets
    std::vector<uint8_t> bbf_buffer_;  // Accumulates BBF frame data
    size_t ts_packet_count_{0};
    size_t bbf_frame_count_{0};
};

} // namespace dvbdab
