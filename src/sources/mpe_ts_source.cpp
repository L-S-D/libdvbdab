#include "mpe_ts_source.hpp"

namespace dvbdab {

MpeTsSource::MpeTsSource(uint16_t pid)
    : mpe_parser_([this](const uint8_t* ip_data, size_t len) {
          // Apply IP:port filter if set
          if (matchesFilter(ip_data, len)) {
              filtered_packet_count_++;
              emitIpPacket(ip_data, len);
          }
      })
    , target_pid_(pid)
{
    partial_ts_.reserve(MPE_TS_PACKET_SIZE);
}

bool MpeTsSource::matchesFilter(const uint8_t* ip_data, size_t len) {
    // No filter = pass all
    if (filter_ip_ == 0 && filter_port_ == 0) {
        return true;
    }

    // Need at least IPv4 header + UDP header
    if (len < 28) return false;

    // Check IPv4
    if ((ip_data[0] >> 4) != 4) return false;

    // Check protocol (17 = UDP)
    if (ip_data[9] != 17) return false;

    // Extract destination IP (bytes 16-19)
    uint32_t dst_ip = (ip_data[16] << 24) | (ip_data[17] << 16) |
                      (ip_data[18] << 8) | ip_data[19];

    // Get IP header length
    int ip_hdr_len = (ip_data[0] & 0x0F) * 4;
    if (ip_hdr_len < 20 || (size_t)ip_hdr_len + 8 > len) return false;

    // Extract destination port from UDP header
    const uint8_t* udp = ip_data + ip_hdr_len;
    uint16_t dst_port = (udp[2] << 8) | udp[3];

    // Check against filter
    if (filter_ip_ != 0 && dst_ip != filter_ip_) return false;
    if (filter_port_ != 0 && dst_port != filter_port_) return false;

    return true;
}

void MpeTsSource::reset() {
    mpe_parser_.reset();
    partial_ts_.clear();
    ts_packet_count_ = 0;
}

void MpeTsSource::feed(const uint8_t* data, size_t len) {
    size_t pos = 0;

    // If we have partial TS packet from previous feed, complete it first
    if (!partial_ts_.empty()) {
        size_t needed = MPE_TS_PACKET_SIZE - partial_ts_.size();
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
    while (pos + MPE_TS_PACKET_SIZE <= len) {
        processTsPacket(data + pos);
        pos += MPE_TS_PACKET_SIZE;
    }

    // Save any remaining partial TS packet
    if (pos < len) {
        partial_ts_.assign(data + pos, data + len);
    }
}

void MpeTsSource::feedPacket(const uint8_t* ts_packet) {
    processTsPacket(ts_packet);
}

void MpeTsSource::processTsPacket(const uint8_t* ts_packet) {
    // Verify sync byte
    if (ts_packet[0] != 0x47) {
        return;
    }

    // Extract header fields
    uint16_t pid = ((ts_packet[1] & 0x1f) << 8) | ts_packet[2];

    // Filter by target PID
    if (pid != target_pid_) {
        return;
    }

    // Check continuity
    uint8_t cc = ts_packet[3] & 0x0f;
    if (!checkContinuity(pid, cc)) {
        mpe_parser_.reset();
    }

    ts_packet_count_++;

    // Get PUSI and adaptation field control
    bool pusi = (ts_packet[1] >> 6) & 1;
    uint8_t adapt_ctrl = (ts_packet[3] >> 4) & 3;

    // Determine payload start
    size_t payload_start = MPE_TS_HEADER_SIZE;
    if (adapt_ctrl == 2) {
        // Adaptation field only, no payload
        return;
    } else if (adapt_ctrl == 3) {
        // Adaptation field + payload
        uint8_t adapt_len = ts_packet[4];
        payload_start = 5 + adapt_len;
        if (payload_start >= MPE_TS_PACKET_SIZE) {
            return;  // No payload
        }
    }
    // adapt_ctrl == 1: Payload only (payload_start = 4)

    size_t payload_len = MPE_TS_PACKET_SIZE - payload_start;
    mpe_parser_.feedTsPayload(ts_packet + payload_start, payload_len, pusi);
}

} // namespace dvbdab
