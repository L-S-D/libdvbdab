#include "bbf_ts_source.hpp"

namespace dvbdab {

BbfTsSource::BbfTsSource()
    : gse_parser_([this](const uint8_t* ip_data, size_t len) {
          emitIpPacket(ip_data, len);
      })
{
    partial_ts_.reserve(BBF_TS_PACKET_SIZE);
    bbf_buffer_.reserve(8192);
}

void BbfTsSource::reset() {
    gse_parser_.reset();
    partial_ts_.clear();
    bbf_buffer_.clear();
    ts_packet_count_ = 0;
    bbf_frame_count_ = 0;
    discontinuity_count_ = 0;
}

void BbfTsSource::feed(const uint8_t* data, size_t len) {
    size_t pos = 0;

    // If we have partial TS packet from previous feed, complete it first
    if (!partial_ts_.empty()) {
        size_t needed = BBF_TS_PACKET_SIZE - partial_ts_.size();
        if (len < needed) {
            // Still not enough, accumulate and return
            partial_ts_.insert(partial_ts_.end(), data, data + len);
            return;
        }

        // Complete the partial packet
        partial_ts_.insert(partial_ts_.end(), data, data + needed);
        pos = needed;

        // Process completed TS packet
        processTsPacket(partial_ts_.data());
        partial_ts_.clear();
    }

    // Process complete TS packets
    while (pos + BBF_TS_PACKET_SIZE <= len) {
        processTsPacket(data + pos);
        pos += BBF_TS_PACKET_SIZE;
    }

    // Save any remaining partial TS packet
    if (pos < len) {
        partial_ts_.assign(data + pos, data + len);
    }
}

void BbfTsSource::flush() {
    // Process any remaining BBF data at end of stream
    if (!bbf_buffer_.empty()) {
        processBbfData();
        bbf_buffer_.clear();
    }
}

void BbfTsSource::feedPacket(const uint8_t* ts_packet) {
    processTsPacket(ts_packet);
}

void BbfTsSource::processTsPacket(const uint8_t* ts_packet) {
    // Verify sync byte
    if (ts_packet[0] != 0x47) {
        return;
    }

    // Extract PID and CC for continuity checking
    uint16_t pid = ((ts_packet[1] & 0x1f) << 8) | ts_packet[2];
    uint8_t cc = ts_packet[3] & 0x0f;

    // Check continuity - on discontinuity, reset state
    if (!checkContinuity(pid, cc)) {
        gse_parser_.reset();
        bbf_buffer_.clear();
    }

    ts_packet_count_++;

    // Pseudo-TS format (per pts2bbf.cpp):
    // ts_packet[0-3]: TS header
    // ts_packet[4-6]: pseudo-TS header (00 80 00 typically)
    // ts_packet[7]: payload length
    // ts_packet[8]: first data byte (0xb8 if BBF start)
    // ts_packet[9+]: more data

    uint8_t length = ts_packet[7];

    if (length == 0) {
        return;  // No payload
    }

    if (ts_packet[8] == BBF_SYNC_BYTE) {
        // Start of BBF frame - process any previous BBF data first
        if (!bbf_buffer_.empty()) {
            processBbfData();
            bbf_buffer_.clear();
        }

        // Start new BBF frame: output from byte 8, length bytes
        if (8 + length <= BBF_TS_PACKET_SIZE) {
            bbf_buffer_.insert(bbf_buffer_.end(), ts_packet + 8, ts_packet + 8 + length);
        }
        bbf_frame_count_++;

        // Check if this might be a complete BBF frame in one packet
        // (small frames can fit entirely in one TS packet)
        if (bbf_buffer_.size() >= 11) {
            uint16_t dfl = (static_cast<uint16_t>(bbf_buffer_[5]) << 8) | bbf_buffer_[6];
            size_t expected_size = 11 + (dfl >> 3);  // sync + header + payload
            if (bbf_buffer_.size() >= expected_size) {
                processBbfData();
                bbf_buffer_.clear();
            }
        }
    } else {
        // Continuation: output from byte 9, length-1 bytes
        if (length > 0 && 9 + (length - 1) <= BBF_TS_PACKET_SIZE) {
            bbf_buffer_.insert(bbf_buffer_.end(), ts_packet + 9, ts_packet + 9 + (length - 1));
        }

        // Check if BBF frame is now complete
        if (bbf_buffer_.size() >= 11) {
            uint16_t dfl = (static_cast<uint16_t>(bbf_buffer_[5]) << 8) | bbf_buffer_[6];
            size_t expected_size = 11 + (dfl >> 3);  // sync + header + payload
            if (bbf_buffer_.size() >= expected_size) {
                processBbfData();
                bbf_buffer_.clear();
            }
        }
    }
}

void BbfTsSource::processBbfData() {
    // BBF frame structure (DVB-S2 baseband frame):
    // byte 0: 0xb8 sync
    // bytes 1-10: BBF header (10 bytes after sync)
    //   - DFL (Data Field Length) is at bytes 5-6 after sync (i.e., bbf_buffer_[5] and [6])
    // bytes 11+: GSE data (payload_bytes from DFL)
    // last 4 bytes of payload: CRC32

    if (bbf_buffer_.size() < 11) {  // Minimum: 1 sync + 10 header
        return;
    }

    // Verify BBF sync
    if (bbf_buffer_[0] != BBF_SYNC_BYTE) {
        return;
    }

    // DFL (Data Field Length) is at bytes 5-6 after sync (big-endian, in bits)
    // bbf_buffer_[0] = sync, bbf_buffer_[1-10] = header
    // So DFL is at bbf_buffer_[5] and bbf_buffer_[6]
    uint16_t dfl = (static_cast<uint16_t>(bbf_buffer_[5]) << 8) | bbf_buffer_[6];
    size_t payload_bytes = dfl >> 3;  // Convert bits to bytes

    // GSE data starts after BBF header (byte 11 = sync + 10 header bytes)
    // DFL gives exact GSE data length (CRC32 is handled separately or not present)
    size_t gse_start = 11;
    size_t gse_len = payload_bytes;

    if (gse_start + gse_len > bbf_buffer_.size()) {
        // Not enough data accumulated yet - this means we have a partial BBF
        // that was interrupted by a new BBF start. Just skip it.
        return;
    }

    if (gse_len > 0) {
        // Feed GSE data to parser
        // BBF frames are self-contained, so use feedSynced (bypasses sync detection)
        gse_parser_.feedSynced(bbf_buffer_.data() + gse_start, gse_len);
    }
}

} // namespace dvbdab
