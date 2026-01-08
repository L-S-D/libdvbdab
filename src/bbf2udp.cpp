#include "bbf2udp.hpp"
#include <algorithm>

Bbf2Udp::Bbf2Udp(UdpCallback callback)
    : callback_(std::move(callback))
{
    payload_buf_.reserve(8192);
    gse_buf_.reserve(65536);  // For raw GSE accumulation
}

void Bbf2Udp::feed(const std::uint8_t* data, std::size_t len) {
    for (std::size_t i = 0; i < len; ++i) {
        processByte(data[i]);
    }
}

void Bbf2Udp::feedGse(const std::uint8_t* data, std::size_t len) {
    // Append to GSE buffer
    gse_buf_.insert(gse_buf_.end(), data, data + len);

    // Process complete GSE packets
    std::size_t pos = 0;
    while (pos + 2 <= gse_buf_.size()) {
        std::uint8_t gse_header = gse_buf_[pos];
        std::uint16_t gse_len = ((gse_header & 0x0f) << 8) | gse_buf_[pos + 1];

        // Check for padding (upper nibble is 0)
        if ((gse_header & 0xf0) == 0) {
            // Padding - skip rest of this chunk, wait for new data
            gse_buf_.erase(gse_buf_.begin(), gse_buf_.begin() + pos);
            gse_buf_.clear();  // Padding means end of baseband frame, reset
            return;
        }

        std::size_t packet_len = gse_len + 2;
        if (pos + packet_len > gse_buf_.size()) {
            // Incomplete packet, wait for more data
            break;
        }

        // Process complete GSE packet
        std::size_t consumed = 0;
        processGsePacket(gse_buf_.data() + pos, packet_len, consumed);
        pos += consumed;
    }

    // Remove processed data from buffer
    if (pos > 0) {
        gse_buf_.erase(gse_buf_.begin(), gse_buf_.begin() + pos);
    }

    // Limit buffer size to prevent unbounded growth
    if (gse_buf_.size() > 32768) {
        gse_buf_.clear();
    }
}

void Bbf2Udp::processByte(std::uint8_t byte) {
    switch (state_) {
        case State::SEEKING_SYNC:
            if (byte == 0xb8) {
                state_ = State::READING_HEADER;
                header_pos_ = 0;
            }
            break;

        case State::READING_HEADER:
            header_buf_[header_pos_++] = byte;
            if (header_pos_ == 10) {
                // Parse BBF header
                // DFL is at bytes 4-5 (big endian), in bits
                std::uint16_t dfl = (static_cast<std::uint16_t>(header_buf_[4]) << 8)
                                  | static_cast<std::uint16_t>(header_buf_[5]);
                payload_expected_ = dfl >> 3;  // Convert bits to bytes

                payload_buf_.resize(payload_expected_);
                payload_pos_ = 0;
                state_ = State::READING_PAYLOAD;
            }
            break;

        case State::READING_PAYLOAD:
            if (payload_pos_ < payload_expected_) {
                payload_buf_[payload_pos_++] = byte;
            }
            if (payload_pos_ >= payload_expected_) {
                processGsePackets();
                state_ = State::SEEKING_SYNC;
            }
            break;
    }
}

void Bbf2Udp::processGsePackets() {
    std::size_t pos = 0;
    // Last 4 bytes are CRC32, don't process them
    std::size_t data_len = (payload_expected_ > 4) ? payload_expected_ - 4 : 0;

    while (pos < data_len) {
        std::size_t consumed = 0;
        if (!processGsePacket(payload_buf_.data() + pos, data_len - pos, consumed)) {
            break;  // Padding or error
        }
        pos += consumed;
    }
}

bool Bbf2Udp::processGsePacket(const std::uint8_t* data, std::size_t max_len, std::size_t& consumed) {
    if (max_len < 2) {
        return false;
    }

    std::uint8_t gse_header = data[0];
    std::uint16_t gse_len = ((gse_header & 0x0f) << 8) | data[1];

    // Check for padding (upper nibble is 0)
    if ((gse_header & 0xf0) == 0) {
        return false;
    }

    consumed = gse_len + 2;
    if (consumed > max_len) {
        return false;
    }

    bool start = (gse_header >> 7) & 1;
    bool stop = (gse_header >> 6) & 1;
    std::uint8_t label_type = (gse_header >> 4) & 3;

    if (start && stop) {
        // Complete GSE packet in one piece
        handleCompleteGsePacket(data + 2, gse_len);
    }
    else if (start && !stop) {
        // First fragment: START=1, STOP=0
        // Format: FragID(1) + TotalLength(2) + Protocol(2) + [Label] + Data
        if (gse_len < 3) return true;

        std::uint8_t frag_id = data[2];
        std::uint16_t total_len = (static_cast<std::uint16_t>(data[3]) << 8) | data[4];

        auto& frag = fragments_[frag_id];
        frag.data.resize(total_len + 2);  // +2 for reconstructed GSE header
        frag.total_length = total_len + 2;
        frag.current_pos = 0;
        frag.active = true;

        // Reconstruct header with START=1, STOP=1
        frag.data[0] = (gse_header | 0xC0);  // Set both S and E bits
        frag.data[1] = data[1];              // Keep length low byte (will be corrected)

        // Copy protocol + label + data (skip FragID and TotalLength)
        std::size_t payload_len = gse_len - 3;  // -3 for FragID + TotalLength
        std::copy(data + 5, data + 5 + payload_len, frag.data.data() + 2);
        frag.current_pos = 2 + payload_len;
    }
    else if (!start && !stop) {
        // Middle fragment: START=0, STOP=0
        // Format: FragID(1) + Data
        if (gse_len < 1) return true;

        std::uint8_t frag_id = data[2];
        auto& frag = fragments_[frag_id];
        if (!frag.active) return true;

        std::size_t payload_len = gse_len - 1;  // -1 for FragID
        if (frag.current_pos + payload_len <= frag.data.size()) {
            std::copy(data + 3, data + 3 + payload_len, frag.data.data() + frag.current_pos);
            frag.current_pos += payload_len;
        }
    }
    else if (!start && stop) {
        // Last fragment: START=0, STOP=1
        // Format: FragID(1) + Data + CRC32(4)
        if (gse_len < 5) return true;

        std::uint8_t frag_id = data[2];
        auto& frag = fragments_[frag_id];
        if (!frag.active) return true;

        std::size_t payload_len = gse_len - 5;  // -1 for FragID, -4 for CRC
        if (frag.current_pos + payload_len <= frag.data.size()) {
            std::copy(data + 3, data + 3 + payload_len, frag.data.data() + frag.current_pos);
            frag.current_pos += payload_len;
        }

        // Process complete reassembled packet
        handleCompleteGsePacket(frag.data.data() + 2, frag.current_pos - 2);
        frag.active = false;
    }

    return true;
}

void Bbf2Udp::handleCompleteGsePacket(const std::uint8_t* data, std::size_t len) {
    if (len < 4) return;

    // Protocol type (2 bytes)
    std::uint16_t protocol = (static_cast<std::uint16_t>(data[0]) << 8) | data[1];

    // Label type from parent - assume 3-byte label (LT=1) or 6-byte (LT=0)
    // The GSE header byte was: (gse_header >> 4) & 3 for label type
    // For simplicity, detect based on protocol position and IPv4 signature

    std::size_t ip_offset = 2;  // After protocol type

    // Try to find IPv4 header (0x45 for version 4, IHL 5)
    // Label can be 0, 3, or 6 bytes depending on label type
    for (std::size_t label_len : {0, 3, 6}) {
        if (ip_offset + label_len + 20 > len) continue;

        const std::uint8_t* ip_start = data + ip_offset + label_len;
        if (ip_start[0] == 0x45 && protocol == 0x0800) {
            extractUdpFromIpv4(ip_start, len - ip_offset - label_len);
            return;
        }
    }
}

void Bbf2Udp::extractUdpFromIpv4(const std::uint8_t* ip_data, std::size_t len) {
    if (len < 28) return;  // Minimum: 20 byte IP + 8 byte UDP

    // Verify IPv4
    if ((ip_data[0] >> 4) != 4) return;

    std::uint8_t ihl = (ip_data[0] & 0x0f) * 4;  // Header length in bytes
    std::uint8_t protocol = ip_data[9];

    if (protocol != 17) return;  // Not UDP

    std::uint16_t ip_total_len = (static_cast<std::uint16_t>(ip_data[2]) << 8) | ip_data[3];
    if (ip_total_len > len) return;

    // Extract destination IP (bytes 16-19)
    std::uint32_t dst_ip = (static_cast<std::uint32_t>(ip_data[16]) << 24)
                         | (static_cast<std::uint32_t>(ip_data[17]) << 16)
                         | (static_cast<std::uint32_t>(ip_data[18]) << 8)
                         | static_cast<std::uint32_t>(ip_data[19]);

    // UDP header starts after IP header
    const std::uint8_t* udp_data = ip_data + ihl;
    std::size_t udp_len = len - ihl;

    if (udp_len < 8) return;

    std::uint16_t dst_port = (static_cast<std::uint16_t>(udp_data[2]) << 8) | udp_data[3];
    std::uint16_t udp_total_len = (static_cast<std::uint16_t>(udp_data[4]) << 8) | udp_data[5];

    // UDP payload starts after 8-byte UDP header
    const std::uint8_t* payload = udp_data + 8;
    std::size_t payload_len = udp_total_len - 8;

    if (payload_len > udp_len - 8) {
        payload_len = udp_len - 8;
    }

    // Call callback with extracted UDP packet
    callback_(dst_ip, dst_port, payload, payload_len);
}
