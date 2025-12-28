#include "gse_ts_source.hpp"

namespace dvbdab {

GseTsSource::GseTsSource()
    : gse_parser_([this](const uint8_t* ip_data, size_t len) {
          emitIpPacket(ip_data, len);
      })
{
    partial_ts_.reserve(TS_PACKET_SIZE);
}

void GseTsSource::reset() {
    gse_parser_.reset();
    partial_ts_.clear();
    ts_packet_count_ = 0;
}

void GseTsSource::feed(const uint8_t* data, size_t len) {
    size_t pos = 0;

    // If we have partial TS packet from previous feed, complete it first
    if (!partial_ts_.empty()) {
        size_t needed = TS_PACKET_SIZE - partial_ts_.size();
        if (len < needed) {
            // Still not enough, accumulate and return
            partial_ts_.insert(partial_ts_.end(), data, data + len);
            return;
        }

        // Complete the partial packet
        partial_ts_.insert(partial_ts_.end(), data, data + needed);
        pos = needed;

        // Process completed TS packet
        if (partial_ts_[0] == 0x47) {
            uint16_t pid = ((partial_ts_[1] & 0x1f) << 8) | partial_ts_[2];
            uint8_t cc = partial_ts_[3] & 0x0f;

            if (!checkContinuity(pid, cc)) {
                gse_parser_.reset();
            }

            ts_packet_count_++;
            gse_parser_.feedTsPayload(partial_ts_.data() + TS_HEADER_SIZE,
                                       TS_PACKET_SIZE - TS_HEADER_SIZE);
        }
        partial_ts_.clear();
    }

    // Process complete TS packets
    while (pos + TS_PACKET_SIZE <= len) {
        const uint8_t* ts_packet = data + pos;

        // Verify sync byte
        if (ts_packet[0] == 0x47) {
            // Extract PID and CC for continuity checking
            uint16_t pid = ((ts_packet[1] & 0x1f) << 8) | ts_packet[2];
            uint8_t cc = ts_packet[3] & 0x0f;

            // Check continuity - on discontinuity, reset GSE parser state
            if (!checkContinuity(pid, cc)) {
                gse_parser_.reset();
            }

            ts_packet_count_++;
            // Feed GSE data from TS payload (byte 4 onwards)
            // Use feedTsPayload for proper TS boundary handling
            gse_parser_.feedTsPayload(ts_packet + TS_HEADER_SIZE,
                                       TS_PACKET_SIZE - TS_HEADER_SIZE);
        }

        pos += TS_PACKET_SIZE;
    }

    // Save any remaining partial TS packet
    if (pos < len) {
        partial_ts_.assign(data + pos, data + len);
    }
}

void GseTsSource::feedPacket(const uint8_t* ts_packet) {
    // Direct single-packet feed - no buffering needed
    if (ts_packet[0] == 0x47) {
        // Extract PID and CC for continuity checking
        uint16_t pid = ((ts_packet[1] & 0x1f) << 8) | ts_packet[2];
        uint8_t cc = ts_packet[3] & 0x0f;

        // Check continuity - on discontinuity, reset GSE parser state
        if (!checkContinuity(pid, cc)) {
            gse_parser_.reset();
        }

        ts_packet_count_++;
        gse_parser_.feedTsPayload(ts_packet + TS_HEADER_SIZE,
                                   TS_PACKET_SIZE - TS_HEADER_SIZE);
    }
}

} // namespace dvbdab
