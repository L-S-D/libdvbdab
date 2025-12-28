#include "gse_parser.hpp"
#include <cstring>

namespace dvbdab {

GseParser::GseParser(IpPacketCallback callback)
    : callback_(std::move(callback))
{
    buffer_.reserve(8192);
}

void GseParser::reset() {
    buffer_.clear();
    synced_ = false;
    for (auto& frag : fragments_) {
        frag.active = false;
        frag.data.clear();
    }
    packet_count_ = 0;
    fragment_count_ = 0;
}

void GseParser::feedTsPayload(const uint8_t* data, size_t len) {
    // Append this TS payload to buffer
    buffer_.insert(buffer_.end(), data, data + len);

    // If not synced, scan for first valid GSE packet start
    size_t pos = 0;
    if (!synced_) {
        pos = findSync();
        if (pos == SIZE_MAX) {
            // No sync found, keep last few bytes for next attempt
            if (buffer_.size() > 64) {
                buffer_.erase(buffer_.begin(), buffer_.end() - 64);
            }
            return;
        }
        synced_ = true;
        // Remove bytes before sync point
        if (pos > 0) {
            buffer_.erase(buffer_.begin(), buffer_.begin() + pos);
        }
        pos = 0;
    }

    // Process complete GSE packets
    while (pos + 2 <= buffer_.size()) {
        uint8_t gse_header = buffer_[pos];
        uint16_t gse_len = ((gse_header & 0x0f) << 8) | buffer_[pos + 1];

        // Check for padding (upper nibble is 0 means no S/E/LT set, or 0xff)
        // Padding signals end of GSE data in this TS payload
        if ((gse_header & 0xf0) == 0 || gse_header == 0xff) {
            // Padding found - remove all processed data and the padding
            // Next TS payload will start fresh
            buffer_.clear();
            return;
        }

        size_t packet_len = gse_len + 2;  // GSE length + 2-byte header

        // Sanity check: GSE packets shouldn't be larger than ~4KB typically
        if (packet_len > 8192) {
            // Invalid packet, lost sync - resync
            synced_ = false;
            buffer_.erase(buffer_.begin(), buffer_.begin() + pos + 1);
            return;
        }

        if (pos + packet_len > buffer_.size()) {
            // Incomplete packet - keep buffer for next TS payload
            if (pos > 0) {
                buffer_.erase(buffer_.begin(), buffer_.begin() + pos);
            }
            return;
        }

        // Process complete GSE packet
        size_t consumed = 0;
        if (!processGsePacket(buffer_.data() + pos, packet_len, consumed)) {
            // Invalid packet, try to resync
            pos++;
            continue;
        }
        pos += consumed;
    }

    // Remove processed data from buffer
    if (pos > 0) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + pos);
    }
}

void GseParser::feedSynced(const uint8_t* data, size_t len) {
    // Process GSE data that is known to start at a valid boundary
    // (e.g., from BBF frame which has its own framing)
    size_t pos = 0;

    while (pos + 2 <= len) {
        uint8_t gse_header = data[pos];
        uint16_t gse_len = ((gse_header & 0x0f) << 8) | data[pos + 1];

        // Check for padding (upper nibble is 0 means no S/E/LT set, or 0xff)
        if ((gse_header & 0xf0) == 0 || gse_header == 0xff) {
            // Padding - end of GSE data in this chunk
            return;
        }

        size_t packet_len = gse_len + 2;  // GSE length + 2-byte header

        // Sanity check
        if (packet_len > 8192) {
            return;  // Invalid, stop processing
        }

        if (pos + packet_len > len) {
            // Incomplete packet at end of chunk - this shouldn't happen in BBF
            // but just stop processing
            return;
        }

        // Process complete GSE packet
        size_t consumed = 0;
        if (!processGsePacket(data + pos, packet_len, consumed)) {
            pos++;
            continue;
        }
        pos += consumed;
        packet_count_++;
    }
}

void GseParser::feed(const uint8_t* data, size_t len) {
    // Append to buffer
    buffer_.insert(buffer_.end(), data, data + len);

    // If not synced, scan for first valid GSE packet start
    size_t pos = 0;
    if (!synced_) {
        pos = findSync();
        if (pos == SIZE_MAX) {
            // No sync found, keep last few bytes for next attempt
            if (buffer_.size() > 64) {
                buffer_.erase(buffer_.begin(), buffer_.end() - 64);
            }
            return;
        }
        synced_ = true;
        // Remove bytes before sync point
        if (pos > 0) {
            buffer_.erase(buffer_.begin(), buffer_.begin() + pos);
        }
        pos = 0;
    }

    // Process complete GSE packets
    while (pos + 2 <= buffer_.size()) {
        uint8_t gse_header = buffer_[pos];
        uint16_t gse_len = ((gse_header & 0x0f) << 8) | buffer_[pos + 1];

        // Check for padding (upper nibble is 0 means no S/E/LT set, or 0xff)
        // Padding signals end of GSE data in this chunk
        if ((gse_header & 0xf0) == 0 || gse_header == 0xff) {
            // Padding - skip rest of current chunk, erase processed data
            // Don't clear fragments - they may continue in next chunk
            buffer_.erase(buffer_.begin(), buffer_.end());
            return;
        }

        size_t packet_len = gse_len + 2;  // GSE length + 2-byte header

        // Sanity check: GSE packets shouldn't be larger than ~4KB typically
        if (packet_len > 8192) {
            // Invalid packet, lost sync - resync
            synced_ = false;
            buffer_.erase(buffer_.begin(), buffer_.begin() + pos + 1);
            return;
        }

        if (pos + packet_len > buffer_.size()) {
            // Incomplete packet, wait for more data
            break;
        }

        // Process complete GSE packet
        size_t consumed = 0;
        if (!processGsePacket(buffer_.data() + pos, packet_len, consumed)) {
            // Invalid packet, try to resync
            pos++;
            continue;
        }
        pos += consumed;
    }

    // Remove processed data from buffer
    if (pos > 0) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + pos);
    }

    // Limit buffer size to prevent unbounded growth
    if (buffer_.size() > 32768) {
        buffer_.clear();
        synced_ = false;
    }
}

size_t GseParser::findSync() {
    // Scan for a valid GSE packet start (S=1)
    // For complete packets (S=1, E=1), verify Protocol Type = 0x0800 for IPv4
    for (size_t pos = 0; pos + 22 < buffer_.size(); pos++) {
        uint8_t gse_header = buffer_[pos];
        uint16_t gse_len = ((gse_header & 0x0f) << 8) | buffer_[pos + 1];
        bool s = (gse_header >> 7) & 1;
        bool e = (gse_header >> 6) & 1;
        uint8_t lt = (gse_header >> 4) & 3;

        // Skip padding
        if ((gse_header & 0xf0) == 0) continue;

        // Look for complete IPv4 packet (S=1, E=1, Protocol=0x0800)
        if (s && e && gse_len >= 22 && gse_len <= 2000) {
            size_t label_len = (lt == 0) ? 6 : (lt == 1) ? 3 : 0;
            size_t proto_offset = pos + 2 + label_len;

            if (proto_offset + 2 < buffer_.size()) {
                uint16_t proto = (buffer_[proto_offset] << 8) | buffer_[proto_offset + 1];
                if (proto == 0x0800) {
                    // Verify IPv4 header
                    size_t ip_offset = proto_offset + 2;
                    if (ip_offset < buffer_.size() && (buffer_[ip_offset] & 0xF0) == 0x40) {
                        return pos;
                    }
                }
            }
        }
    }
    return SIZE_MAX;
}

bool GseParser::processGsePacket(const uint8_t* data, size_t len, size_t& consumed) {
    if (len < 2) {
        return false;
    }

    uint8_t gse_header = data[0];
    uint16_t gse_len = ((gse_header & 0x0f) << 8) | data[1];

    // Check for padding
    if ((gse_header & 0xf0) == 0) {
        return false;
    }

    consumed = gse_len + 2;
    if (consumed > len) {
        return false;
    }

    bool start = (gse_header >> 7) & 1;
    bool stop = (gse_header >> 6) & 1;

    if (start && stop) {
        // Complete GSE packet in one piece (S=1, E=1)
        // Payload starts at byte 2
        packet_count_++;
        handleCompleteGsePayload(data + 2, gse_len);
    }
    else if (start && !stop) {
        // First fragment (S=1, E=0)
        // Format: FragID(1) + TotalLength(2) + Protocol(2) + [Label] + Data
        if (gse_len < 7) return true;  // Need FragID + TotalLen + Protocol

        uint8_t frag_id = data[2];
        uint16_t total_len = (static_cast<uint16_t>(data[3]) << 8) | data[4];

        // Determine label length based on LT
        uint8_t lt = (gse_header >> 4) & 3;
        size_t label_len = (lt == 0) ? 6 : (lt == 1) ? 3 : 0;

        // Check if this is IPv4 (protocol 0x0800)
        size_t proto_offset = 5 + label_len;
        if (proto_offset + 2 > gse_len + 2) return true;

        uint16_t protocol = (static_cast<uint16_t>(data[proto_offset]) << 8) | data[proto_offset + 1];

        // Only process IPv4 fragments, skip others
        if (protocol != 0x0800) {
            return true;  // Not IPv4, skip
        }

        // For IPv4, sanity check the total length (max ~1500 for UDP)
        if (total_len > 2000 || total_len < 28) {
            return true;  // Unreasonable IPv4 size
        }

        auto& frag = fragments_[frag_id];
        frag.data.resize(total_len + 2);  // +2 for reconstructed GSE header
        frag.total_length = total_len + 2;
        frag.current_pos = 0;
        frag.active = true;

        // Reconstruct header with S=1, E=1
        frag.data[0] = (gse_header | 0xC0);  // Set both S and E bits
        frag.data[1] = data[1];              // Keep length low byte

        // Copy protocol + label + data (skip FragID and TotalLength)
        size_t payload_len = gse_len - 3;  // -3 for FragID + TotalLength
        if (2 + payload_len <= frag.data.size()) {
            std::memcpy(frag.data.data() + 2, data + 5, payload_len);
            frag.current_pos = 2 + payload_len;
        } else {
            frag.active = false;  // Can't fit, mark inactive
        }

        fragment_count_++;
    }
    else if (!start && !stop) {
        // Middle fragment (S=0, E=0)
        // Format: FragID(1) + Data
        if (gse_len < 1) return true;

        uint8_t frag_id = data[2];
        auto& frag = fragments_[frag_id];
        if (!frag.active) return true;

        size_t payload_len = gse_len - 1;  // -1 for FragID
        if (frag.current_pos + payload_len <= frag.data.size()) {
            std::memcpy(frag.data.data() + frag.current_pos, data + 3, payload_len);
            frag.current_pos += payload_len;
        }

        fragment_count_++;
    }
    else if (!start && stop) {
        // Last fragment (S=0, E=1)
        // Format: FragID(1) + Data + CRC32(4)
        if (gse_len < 5) return true;

        uint8_t frag_id = data[2];
        auto& frag = fragments_[frag_id];
        if (!frag.active) return true;

        size_t payload_len = gse_len - 5;  // -1 for FragID, -4 for CRC
        if (frag.current_pos + payload_len <= frag.data.size()) {
            std::memcpy(frag.data.data() + frag.current_pos, data + 3, payload_len);
            frag.current_pos += payload_len;
        }

        // Process complete reassembled packet
        packet_count_++;
        handleCompleteGsePayload(frag.data.data() + 2, frag.current_pos - 2);
        frag.active = false;

        fragment_count_++;
    }

    return true;
}

void GseParser::handleCompleteGsePayload(const uint8_t* data, size_t len) {
    if (len < 4) return;

    // Protocol type (2 bytes, big-endian)
    uint16_t protocol = (static_cast<uint16_t>(data[0]) << 8) | data[1];

    // For IPv4, protocol type is 0x0800
    if (protocol != 0x0800) return;

    // Label can be 0, 3, or 6 bytes depending on label type in header
    // Since we don't track LT through fragmentation, try to detect IPv4 signature
    size_t ip_offset = 2;  // After protocol type

    for (size_t label_len : {size_t(0), size_t(3), size_t(6)}) {
        if (ip_offset + label_len + 20 > len) continue;

        const uint8_t* ip_start = data + ip_offset + label_len;
        // Check for IPv4 header: version=4, IHL=5 (no options) -> 0x45
        if ((ip_start[0] & 0xF0) == 0x40) {
            emitIpv4Packet(ip_start, len - ip_offset - label_len);
            return;
        }
    }
}

void GseParser::emitIpv4Packet(const uint8_t* ip_data, size_t len) {
    if (len < 20) return;  // Minimum IPv4 header

    // Verify IPv4 version
    if ((ip_data[0] >> 4) != 4) return;

    // Get total length from IP header
    uint16_t ip_total_len = (static_cast<uint16_t>(ip_data[2]) << 8) | ip_data[3];
    if (ip_total_len > len) {
        ip_total_len = static_cast<uint16_t>(len);  // Truncate if necessary
    }

    // Emit the complete IPv4 packet
    callback_(ip_data, ip_total_len);
}

} // namespace dvbdab
