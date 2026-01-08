#include "packet_decoder.hpp"
#include "../utils/crc_utils.hpp"
#include <algorithm>
#include <cstring>
#include <set>
#include <vector>
#include <zlib.h>

namespace dvbdab {

PacketDecoder::PacketDecoder() {
}

void PacketDecoder::reset() {
    dg_buffers_.clear();
    stream_buffer_.clear();
    packet_count_ = 0;
    dg_count_ = 0;
    crc_errors_ = 0;
    prbs_state_ = 0x1FF;  // Reset PRBS to all 1s
}

uint16_t PacketDecoder::crc16(const uint8_t* data, size_t len) {
    return crc16_ccitt_xor(data, len);
}

// PRBS generator for energy dispersal (EN 300 401 section 14.2)
// Polynomial: x^9 + x^5 + 1
void prbs_descramble(uint8_t* output, const uint8_t* input, size_t len, uint16_t& prbs) {
    for (size_t i = 0; i < len; i++) {
        uint8_t prbs_byte = 0;
        for (int bit = 7; bit >= 0; bit--) {
            // Output bit
            prbs_byte |= ((prbs >> 8) & 1) << bit;
            // Feedback: x^9 XOR x^5
            uint8_t feedback = ((prbs >> 8) ^ (prbs >> 4)) & 1;
            prbs = ((prbs << 1) | feedback) & 0x1FF;
        }
        output[i] = input[i] ^ prbs_byte;
    }
}

void PacketDecoder::feedSubchannelData(const uint8_t* data, size_t len) {
    // Parse DAB packets (EN 300 401 section 5.3.2)
    // This subchannel uses packet mode since DSCTy=56 has DG=0.
    // Packets carry data groups for different SCIds (service components).

    // Accumulate raw data (ETI data is already descrambled)
    stream_buffer_.insert(stream_buffer_.end(), data, data + len);

    // Try to parse complete packets from the buffer
    size_t pos = 0;
    while (pos + 5 < stream_buffer_.size()) {
        const uint8_t* buf = stream_buffer_.data() + pos;

        uint8_t pl_code = (buf[0] >> 6) & 0x03;
        uint8_t ci = (buf[0] >> 4) & 0x03;
        bool first = (buf[0] >> 3) & 0x01;
        bool last = (buf[0] >> 2) & 0x01;
        uint16_t addr = ((buf[0] & 0x03) << 8) | buf[1];
        bool cmd = (buf[2] >> 7) & 0x01;
        uint8_t udl = buf[2] & 0x7F;

        // Packet sizes: 0=24, 1=48, 2=72, 3=96
        static const size_t pkt_sizes[] = {24, 48, 72, 96};
        size_t pkt_len = pkt_sizes[pl_code];
        size_t max_udl = pkt_len - 5;  // 3 header + 2 CRC

        // Validate packet header - allow any non-zero address
        if (addr == 0 || udl > max_udl) {
            pos++;
            continue;
        }

        // Check if we have the complete packet
        if (pos + pkt_len > stream_buffer_.size()) {
            break;
        }

        // Verify CRC over entire packet minus CRC
        uint16_t calc_crc = crc16(buf, pkt_len - 2);
        uint16_t recv_crc = (buf[pkt_len - 2] << 8) | buf[pkt_len - 1];

        if (calc_crc != recv_crc) {
            crc_errors_++;
            pos++;
            continue;
        }

        // Valid packet!
        packet_count_++;

        // Process packet data
        if (udl > 0 && !cmd) {
            PacketHeader hdr;
            hdr.packet_length = pl_code;
            hdr.continuity_index = ci;
            hdr.first_last_first = first;
            hdr.first_last_last = last;
            hdr.address = addr;
            hdr.command = cmd;
            hdr.useful_data_len = udl;
            processPacketData(hdr, buf + 3, udl);
        }

        pos += pkt_len;
    }

    // Remove processed data
    if (pos > 0) {
        stream_buffer_.erase(stream_buffer_.begin(), stream_buffer_.begin() + pos);
    }

    // Limit buffer size
    if (stream_buffer_.size() > 4096) {
        stream_buffer_.erase(stream_buffer_.begin(), stream_buffer_.end() - 1024);
    }
}

void PacketDecoder::parseMscDataGroups() {
    // For MOT header mode (EN 301 234), data groups must have:
    // - CRC flag = 1
    // - Segment flag = 1 (segmented transfer)
    // - User Access flag = 1 (transport ID present)
    // Valid MOT data group patterns:
    // - 0x73 = Type 3 (MOT-Header) with seg+ua+crc
    // - 0x74 = Type 4 (MOT-Body) with seg+ua+crc
    // - 0xF3/0xF4 = with extension flag

    size_t pos = 0;

    while (pos + 16 < stream_buffer_.size()) {
        const uint8_t* buf = stream_buffer_.data() + pos;

        uint8_t b0 = buf[0];
        uint8_t dg_type = b0 & 0x0F;
        bool ext_flag = (b0 >> 7) & 1;
        bool crc_flag = (b0 >> 6) & 1;
        bool seg_flag = (b0 >> 5) & 1;
        bool ua_flag = (b0 >> 4) & 1;

        // MOT requires type 3 or 4 with CRC, Segment, and UA flags set
        bool is_mot = (dg_type == 3 || dg_type == 4) && crc_flag && seg_flag && ua_flag;

        if (is_mot) {

            // Calculate header length and parse fields
            // Header structure:
            // - Byte 0: flags + type
            // - Byte 1: CI(4) + RepIdx(4)
            // - Bytes 2-3: Extension (if ext_flag)
            // - Bytes 2-3 or 4-5: Segment field (Last + SegNum)
            // - User Access field (if ua_flag): RFA(3) + TID_flag(1) + LenInd(4) + data

            size_t hdr_len = 2;
            size_t seg_offset = 2;

            if (ext_flag) {
                seg_offset = 4;
                hdr_len += 2;
            }

            // Segment field (we know seg_flag=true for MOT)
            hdr_len += 2;  // Segment field is 2 bytes

            // User Access field (we know ua_flag=true for MOT)
            size_t ua_offset = hdr_len;
            if (pos + ua_offset >= stream_buffer_.size()) {
                pos++;
                continue;
            }
            uint8_t rfa_tid_len = buf[ua_offset];
            bool tid_flag = (rfa_tid_len >> 4) & 1;
            uint8_t len_ind = rfa_tid_len & 0x0F;

            // MOT requires transport ID - skip if not present
            if (!tid_flag || len_ind < 2) {
                pos++;
                continue;
            }

            hdr_len += 1 + len_ind;  // UA header byte + UA data

            // Skip if header would exceed buffer
            if (pos + hdr_len + 4 >= stream_buffer_.size()) {
                pos++;
                continue;
            }

            // Parse segment info
            bool is_last = (buf[seg_offset] >> 7) & 1;
            uint16_t seg_num = ((buf[seg_offset] & 0x7F) << 8) | buf[seg_offset + 1];

            // Parse transport ID from User Access field
            uint16_t transport_id = (buf[ua_offset + 1] << 8) | buf[ua_offset + 2];

            // Validate transport ID is non-zero
            if (transport_id == 0) {
                pos++;
                continue;
            }

            // Only parse segment 0 for MOT header structure
            bool is_first_segment = (seg_num == 0);

            // Try different data lengths
            // MOT segments are typically 300-1500 bytes (optimize by stepping)
            // Step by 1 for small lengths, by larger steps for bigger lengths
            for (size_t try_len = 16; try_len <= 1600 && pos + hdr_len + try_len + 2 <= stream_buffer_.size(); ) {
                size_t total_len = hdr_len + try_len + 2;

                uint16_t calc_crc = crc16(buf, hdr_len + try_len);
                uint16_t recv_crc = (buf[hdr_len + try_len] << 8) | buf[hdr_len + try_len + 1];

                if (calc_crc == recv_crc) {
                    const uint8_t* payload = buf + hdr_len;

                    // Trust CRC validation - only light sanity checks
                    bool valid_mot = true;

                    // For segment 0, check content type is valid (0-7)
                    if (is_first_segment && dg_type == 3 && try_len >= 7) {
                        uint8_t content_type = ((payload[3] & 0x0F) << 2) | ((payload[4] >> 6) & 0x03);
                        if (content_type > 7) valid_mot = false;
                    }

                    if (valid_mot) {
                        // Accumulate this segment for reassembly
                        processMotDataGroup(dg_type, transport_id, seg_num, is_last,
                                           payload, try_len);

                        dg_count_++;
                        pos += total_len;
                        goto next_position;
                    }
                }

                // Step size depends on current length (optimize search)
                if (try_len < 100) try_len += 4;
                else if (try_len < 500) try_len += 8;
                else try_len += 16;
            }
        }

        pos++;
        next_position:;
    }

    // Keep last part of buffer for cross-frame data groups
    if (stream_buffer_.size() > 4096) {
        stream_buffer_.erase(stream_buffer_.begin(), stream_buffer_.end() - 2048);
    }
}

void PacketDecoder::processMotDataGroup(uint8_t dg_type, uint16_t transport_id,
                                         uint16_t seg_num, bool is_last,
                                         const uint8_t* payload, size_t payload_len) {
    auto& obj = mot_objects_[transport_id];

    if (dg_type == 3) {
        // MOT Header segment
        if (obj.header_segments.find(seg_num) == obj.header_segments.end()) {
            // New segment - store it
            obj.header_segments[seg_num] = std::vector<uint8_t>(payload, payload + payload_len);

            if (is_last) {
                obj.header_last_seg = seg_num;
            }

            // If this is segment 0, parse the header core
            if (seg_num == 0 && payload_len >= 7) {
                parseMotHeaderCore(payload, payload_len, obj.header_info);
            }

            tryCompleteMotObject(transport_id);
        }
    }
    else if (dg_type == 4) {
        // MOT Body segment
        if (obj.body_segments.find(seg_num) == obj.body_segments.end()) {
            // New segment - store it
            obj.body_segments[seg_num] = std::vector<uint8_t>(payload, payload + payload_len);

            if (is_last) {
                obj.body_last_seg = seg_num;
            }

            tryCompleteMotObject(transport_id);
        }
    }
}

bool PacketDecoder::parseMotHeaderCore(const uint8_t* data, size_t len, MOTHeaderInfo& info) {
    if (len < 7) return false;

    // MOT Header Core (EN 301 234 section 6.3)
    // Bytes 0-3: BodySize (28 bits) + ContentType high (4 bits)
    // Byte 4: ContentType low (2 bits) + ContentSubType high (6 bits)
    // Bytes 5-6: ContentSubType low (3 bits) + HeaderSize (13 bits)

    info.body_size = ((data[0] << 20) | (data[1] << 12) | (data[2] << 4) | (data[3] >> 4)) & 0x0FFFFFFF;
    info.content_type = ((data[3] & 0x0F) << 2) | ((data[4] >> 6) & 0x03);
    info.content_subtype = ((data[4] & 0x3F) << 3) | ((data[5] >> 5) & 0x07);
    uint16_t header_ext_len = ((data[5] & 0x1F) << 8) | data[6];

    // Parse extension for ContentName (parameter 12)
    size_t ext_pos = 7;
    while (ext_pos < len && ext_pos < 7 + header_ext_len) {
        uint8_t pli = (data[ext_pos] >> 6) & 0x03;
        uint8_t pid = data[ext_pos] & 0x3F;
        ext_pos++;

        size_t plen = 0;
        switch (pli) {
            case 0: plen = 0; break;
            case 1: plen = 1; break;
            case 2: plen = 4; break;
            case 3:
                if (ext_pos < len) {
                    if (data[ext_pos] & 0x80) {
                        if (ext_pos + 1 < len)
                            plen = ((data[ext_pos] & 0x7F) << 8) | data[ext_pos + 1];
                        ext_pos += 2;
                    } else {
                        plen = data[ext_pos];
                        ext_pos++;
                    }
                }
                break;
        }
        if (ext_pos + plen > len) break;

        if (pid == 12 && plen > 1) {  // ContentName
            info.content_name = std::string(reinterpret_cast<const char*>(data + ext_pos + 1), plen - 1);
        }
        ext_pos += plen;
    }

    info.valid = true;
    return true;
}

void PacketDecoder::tryCompleteMotObject(uint16_t transport_id) {
    auto& obj = mot_objects_[transport_id];

    // Check for header info from Directory Mode (type 6 data groups)
    // In directory mode, headers come from mot_directory_entries_, not from type 3 segments
    bool header_from_directory = false;
    if (!obj.header_info.valid) {
        auto dir_it = mot_directory_entries_.find(transport_id);
        if (dir_it != mot_directory_entries_.end() && dir_it->second.valid) {
            obj.header_info = dir_it->second;
            header_from_directory = true;
        }
    }

    // Check if we have all header segments (for Header Mode)
    bool header_complete = false;
    if (obj.header_info.valid) {
        // If we got header from directory, we don't need header segments
        if (header_from_directory || obj.header_last_seg < 0) {
            header_complete = obj.header_info.valid;
        } else {
            header_complete = true;
            for (int i = 0; i <= obj.header_last_seg; i++) {
                if (obj.header_segments.find(i) == obj.header_segments.end()) {
                    header_complete = false;
                    break;
                }
            }
        }
    }

    // Check if we have all body segments
    bool body_complete = false;
    if (obj.body_last_seg >= 0) {
        body_complete = true;
        for (int i = 0; i <= obj.body_last_seg; i++) {
            if (obj.body_segments.find(i) == obj.body_segments.end()) {
                body_complete = false;
                break;
            }
        }
    }

    // If both header and body are complete, emit the object
    if (header_complete && body_complete && obj.header_info.valid) {
        // Reassemble body
        std::vector<uint8_t> body_data;
        for (int i = 0; i <= obj.body_last_seg; i++) {
            const auto& seg = obj.body_segments[i];
            body_data.insert(body_data.end(), seg.begin(), seg.end());
        }

        // Invoke callback with completed MOT object
        if (mot_callback_) {
            mot_callback_(transport_id, obj.header_info, body_data.data(), body_data.size());
        }

        // Clear this object to prepare for next version
        obj.header_segments.clear();
        obj.body_segments.clear();
        obj.header_last_seg = -1;
        obj.body_last_seg = -1;
        obj.header_info = MOTHeaderInfo();
    }
}

bool PacketDecoder::parsePacket(const uint8_t* data, size_t len, PacketHeader& header) {
    if (len < 3) return false;

    // Byte 0: Packet length (2) + Continuity index (2) + First/Last (2) + Address high (2)
    header.packet_length = (data[0] >> 6) & 0x03;
    header.continuity_index = (data[0] >> 4) & 0x03;
    header.first_last_first = (data[0] >> 3) & 0x01;
    header.first_last_last = (data[0] >> 2) & 0x01;
    header.address = ((data[0] & 0x03) << 8) | data[1];

    // Byte 2: Command (1) + Useful data length (7)
    header.command = (data[2] >> 7) & 0x01;
    header.useful_data_len = data[2] & 0x7F;

    return true;
}

void PacketDecoder::processPacketData(const PacketHeader& header, const uint8_t* data, size_t len) {
    uint16_t addr = header.address;

    // Get or create buffer for this address
    auto& buf = dg_buffers_[addr];

    // Check if this is the first packet of a new data group
    if (header.first_last_first) {
        // Start new data group
        buf.data.clear();
        buf.expected_ci = header.continuity_index;
        buf.in_progress = true;
    }

    if (!buf.in_progress) {
        // Not in a data group, wait for first packet
        return;
    }

    // Check continuity
    if (header.continuity_index != buf.expected_ci) {
        // Continuity error - reset
        buf.in_progress = false;
        return;
    }

    // Append data
    buf.data.insert(buf.data.end(), data, data + len);

    // Update expected CI
    buf.expected_ci = (buf.expected_ci + 1) & 0x03;

    // Check if this is the last packet
    if (header.first_last_last) {
        // Data group complete
        buf.in_progress = false;
        processDataGroup(addr, buf.data.data(), buf.data.size());
        buf.data.clear();
    }
}

bool PacketDecoder::parseDataGroupHeader(const uint8_t* data, size_t len, DataGroupHeader& header, size_t& header_len) {
    if (len < 2) return false;

    // Byte 0: Extension flag (1) + CRC flag (1) + Segment flag (1) + User access flag (1) + Type (4)
    header.extension_flag = (data[0] >> 7) & 0x01;
    header.crc_flag = (data[0] >> 6) & 0x01;
    header.segment_flag = (data[0] >> 5) & 0x01;
    header.user_access_flag = (data[0] >> 4) & 0x01;
    header.type = data[0] & 0x0F;

    // Byte 1: Continuity index (4) + Repetition index (4)
    header.continuity_index = (data[1] >> 4) & 0x0F;
    header.repetition_index = data[1] & 0x0F;

    header_len = 2;

    // Optional extension field (2 bytes)
    if (header.extension_flag) {
        if (len < header_len + 2) return false;
        header.extension = (data[header_len] << 8) | data[header_len + 1];
        header_len += 2;
    }

    // Optional segment field
    if (header.segment_flag) {
        if (len < header_len + 2) return false;
        header.last_segment = (data[header_len] >> 7) & 0x01;
        header.segment_number = ((data[header_len] & 0x7F) << 8) | data[header_len + 1];
        header_len += 2;
    }

    // Optional user access field
    if (header.user_access_flag) {
        if (len < header_len + 1) return false;
        header.transport_id_flag = (data[header_len] >> 4) & 0x01;
        header.length_indicator = data[header_len] & 0x0F;
        header_len++;

        if (header.transport_id_flag) {
            if (len < header_len + 2) return false;
            header.transport_id = (data[header_len] << 8) | data[header_len + 1];
            header_len += 2;
        }
        // Skip remaining user access data
        int remaining = header.length_indicator - (header.transport_id_flag ? 2 : 0);
        if (remaining > 0) {
            header_len += remaining;
        }
    }

    return header_len <= len;
}

void PacketDecoder::processDataGroup(uint16_t address, const uint8_t* data, size_t len) {
    if (len < 2) return;

    DataGroupHeader header;
    size_t header_len;

    if (!parseDataGroupHeader(data, len, header, header_len)) {
        return;
    }

    // Get payload
    const uint8_t* payload = data + header_len;
    size_t payload_len = len - header_len;

    // Check CRC if present
    if (header.crc_flag) {
        if (payload_len < 2) return;
        payload_len -= 2;

        // CRC is calculated over header + data (excluding CRC itself)
        uint16_t calc_crc = crc16(data, len - 2);
        uint16_t recv_crc = (data[len - 2] << 8) | data[len - 1];

        if (calc_crc != recv_crc) {
            crc_errors_++;
            return;
        }
    }

    dg_count_++;

    // Callback for data group
    if (dg_callback_) {
        dg_callback_(address, header, payload, payload_len);
    }

    // Handle MOT data groups
    if (header.type == 6) {
        // MOT Directory - contains info about all objects in the carousel
        // Directory is usually segmented, so accumulate segments first
        if (header.segment_flag && header.user_access_flag && header.transport_id_flag) {
            accumulateMotSegment(header.transport_id, 6, header.segment_number,
                                 header.last_segment, payload, payload_len);
        } else {
            // Non-segmented directory (unusual but possible)
            parseMotDirectory(payload, payload_len);
        }
    } else if (header.type == 3) {
        // MOT Header - describes a single object (Header Mode)
        parseMotHeader(payload, payload_len);

        // Accumulate header segments
        if (header.segment_flag && header.user_access_flag && header.transport_id_flag) {
            accumulateMotSegment(header.transport_id, 3, header.segment_number,
                                 header.last_segment, payload, payload_len);
        }
    } else if (header.type == 4) {
        // MOT Body - object data segment
        if (header.segment_flag && header.user_access_flag && header.transport_id_flag) {
            accumulateMotSegment(header.transport_id, 4, header.segment_number,
                                 header.last_segment, payload, payload_len);
        }
    }
}

void PacketDecoder::parseMotHeader(const uint8_t* data, size_t len) {
    // MOT Header parsing for Header Mode (informational only)
    // Actual header info is extracted in parseMotHeaderCore for object assembly
    (void)data;
    (void)len;
}

void PacketDecoder::parseMotDirectory(const uint8_t* data, size_t len) {
    if (len < 13) {
        return;
    }

    // MOT Directory (EN 301 234, section 7.2.3)
    // Bytes 0-3: DirectorySize (30 bits) + CompressionFlag (1 bit) + RFU (1 bit)
    // Bytes 4-5: NumberOfObjects (16 bits)
    // Byte 6: CarouselPeriod (8 bits)
    // Bytes 7-8: SortedFlag (1 bit) + SegmentSize (13 bits) + DirectoryExtensionFlag (1 bit) + RFU (1 bit)

    uint32_t dir_size = ((data[0] << 22) | (data[1] << 14) | (data[2] << 6) | (data[3] >> 2)) & 0x3FFFFFFF;
    bool compression_flag = data[3] & 0x01;
    uint16_t num_objects = (data[4] << 8) | data[5];
    bool dir_ext_flag = (data[8] >> 1) & 0x01;

    // Calculate entries offset
    size_t entries_offset = 9;
    if (dir_ext_flag && len >= 11) {
        uint16_t dir_ext_len = (data[9] << 8) | data[10];
        entries_offset = 11 + dir_ext_len;
    }

    // Skip observed 4-byte padding (00 00 00 XX)
    if (entries_offset + 4 < len &&
        data[entries_offset] == 0x00 && data[entries_offset+1] == 0x00 &&
        data[entries_offset+2] == 0x00) {
        entries_offset += 4;
    }

    // Skip observed 3-byte prefix (00 XX XX)
    if (entries_offset + 3 < len && data[entries_offset] == 0x00) {
        entries_offset += 3;
    }

    // Handle decompression if needed
    std::vector<uint8_t> decompressed_data;
    const uint8_t* entries_data = data;
    size_t entries_len = len;

    if (compression_flag && entries_offset < len) {
        size_t compressed_len = len - entries_offset;
        size_t estimated_size = dir_size > 0 ? dir_size + 1000 : compressed_len * 10;
        decompressed_data.resize(estimated_size);

        z_stream strm = {};
        if (inflateInit(&strm) == Z_OK) {
            strm.next_in = const_cast<Bytef*>(data + entries_offset);
            strm.avail_in = compressed_len;
            strm.next_out = decompressed_data.data();
            strm.avail_out = decompressed_data.size();
            int ret = inflate(&strm, Z_FINISH);
            if (ret == Z_STREAM_END || strm.total_out > 0) {
                decompressed_data.resize(strm.total_out);
                entries_data = decompressed_data.data();
                entries_len = decompressed_data.size();
                entries_offset = 0;
            }
            inflateEnd(&strm);
        }

        // Try raw deflate if zlib failed
        if (entries_data == data) {
            strm = {};
            decompressed_data.resize(estimated_size);
            if (inflateInit2(&strm, -MAX_WBITS) == Z_OK) {
                strm.next_in = const_cast<Bytef*>(data + entries_offset);
                strm.avail_in = compressed_len;
                strm.next_out = decompressed_data.data();
                strm.avail_out = decompressed_data.size();
                int ret = inflate(&strm, Z_FINISH);
                if (ret == Z_STREAM_END || strm.total_out > 0) {
                    decompressed_data.resize(strm.total_out);
                    entries_data = decompressed_data.data();
                    entries_len = decompressed_data.size();
                    entries_offset = 0;
                }
                inflateEnd(&strm);
            }
        }
    }

    // Scan for ContentName markers (0xCC) and extract TID from fixed offset before them
    // Entry structure: TID(2) + Info(7) + ContentName(0xCC + len + charset + name)
    // ContentName marker is at offset 9 from entry start
    int obj_count = 0;

    for (size_t pos = entries_offset; pos + 15 < entries_len && obj_count < num_objects; pos++) {
        // Look for ContentName marker pattern: 0xCC followed by reasonable length
        if (entries_data[pos] != 0xcc) continue;

        uint8_t name_len = entries_data[pos + 1];
        if (name_len < 5 || name_len > 80) continue;  // Reasonable filename length
        if (pos + 2 + name_len > entries_len) continue;

        // Extract filename (skip charset indicator at pos+2)
        std::string filename(reinterpret_cast<const char*>(entries_data + pos + 3), name_len - 1);

        // Validate it looks like a filename (has extension)
        if (filename.find('.') == std::string::npos) continue;
        if (filename.find('/') != std::string::npos) continue;  // No paths

        // ContentName is at offset 9 from entry start, so TID is at pos - 9
        if (pos < entries_offset + 9) continue;
        size_t entry_start = pos - 9;

        uint16_t tid = (entries_data[entry_start] << 8) | entries_data[entry_start + 1];
        uint8_t content_type = (entries_data[entry_start + 2] >> 2) & 0x3F;

        // Validate TID - must be non-zero
        // Note: removed tid < 10000 filter which was rejecting valid EPG files
        if (tid == 0) {
            continue;
        }

        // Check if this TID is already in the map (avoid duplicates from scanning)
        if (mot_directory_entries_.find(tid) != mot_directory_entries_.end()) {
            continue;  // Skip duplicate
        }

        MOTHeaderInfo info;
        info.content_name = filename;
        // Extract body_size from header core (bytes 2-5 after TID, 28 bits)
        // Per EN 301 234 section 6.3 and qt-dab mot-object.cpp
        if (entry_start + 5 < entries_len) {
            info.body_size = (entries_data[entry_start + 2] << 20) |
                             (entries_data[entry_start + 3] << 12) |
                             (entries_data[entry_start + 4] << 4) |
                             ((entries_data[entry_start + 5] & 0xF0) >> 4);
        }
        info.content_type = content_type;
        info.content_subtype = ((entries_data[entry_start + 2] & 0x03) << 7) |
                               ((entries_data[entry_start + 3] >> 1) & 0x7F);
        info.valid = true;
        mot_directory_entries_[tid] = info;
        obj_count++;

        // Immediately check if body is waiting for this header
        auto obj_it = mot_objects_.find(tid);
        if (obj_it != mot_objects_.end() && obj_it->second.body_last_seg >= 0) {
            checkMotObjectComplete(tid);
        }

        // Skip past this ContentName to avoid re-matching
        pos += 2 + name_len;
    }
    // Build current TID set and detect changes
    std::set<uint16_t> current_tids;
    for (const auto& [tid, info] : mot_directory_entries_) {
        current_tids.insert(tid);
    }

    // Find added and removed TIDs
    std::vector<uint16_t> added, removed;
    for (uint16_t tid : current_tids) {
        if (prev_directory_tids_.find(tid) == prev_directory_tids_.end()) {
            added.push_back(tid);
        }
    }
    for (uint16_t tid : prev_directory_tids_) {
        if (current_tids.find(tid) == current_tids.end()) {
            removed.push_back(tid);
        }
    }

    // Notify about changes
    if (dir_callback_ && (!added.empty() || !removed.empty())) {
        dir_callback_(added, removed);
    }

    // Update previous TID set for next comparison
    prev_directory_tids_ = current_tids;
}

void PacketDecoder::accumulateMotSegment(uint16_t transport_id, uint8_t dg_type,
                                          uint16_t segment_number, bool is_last,
                                          const uint8_t* data, size_t len) {
    if (dg_type == 6) {
        // MOT Directory segment - accumulate and reassemble
        auto& dir = directory_accumulators_[transport_id];

        // Segment 0 starts a new carousel cycle - clear previous data
        if (segment_number == 0) {
            dir.segments.clear();
            dir.last_seg = -1;
        }

        if (dir.segments.find(segment_number) == dir.segments.end()) {
            dir.segments[segment_number] = std::vector<uint8_t>(data, data + len);
            if (is_last) {
                dir.last_seg = segment_number;
            }

            // Check if directory is complete
            if (dir.last_seg >= 0) {
                bool complete = true;
                for (int i = 0; i <= dir.last_seg; i++) {
                    if (dir.segments.find(i) == dir.segments.end()) {
                        complete = false;
                        break;
                    }
                }

                if (complete) {
                    // Reassemble directory - skip 2-byte length prefix in each segment
                    std::vector<uint8_t> full_dir;
                    for (int i = 0; i <= dir.last_seg; i++) {
                        const auto& seg = dir.segments[i];
                        // Each segment has a 2-byte length prefix that must be skipped
                        if (seg.size() > 2) {
                            full_dir.insert(full_dir.end(), seg.begin() + 2, seg.end());
                        }
                    }

                    // Parse the complete directory
                    parseMotDirectory(full_dir.data(), full_dir.size());

                    // Re-check all incomplete objects now that directory is available
                    // Some body segments may have arrived before directory was parsed
                    for (auto& [tid, obj] : mot_objects_) {
                        if (!obj.header_info.valid && obj.body_last_seg >= 0) {
                            tryCompleteMotObject(tid);
                        }
                    }

                    // Clear for next carousel cycle
                    dir.segments.clear();
                    dir.last_seg = -1;
                }
            }
        }
        return;
    }

    auto& obj = mot_objects_[transport_id];

    if (dg_type == 4) {
        // MOT Body segment - skip 2-byte length prefix
        if (obj.body_segments.find(segment_number) == obj.body_segments.end()) {
            if (len > 2) {
                obj.body_segments[segment_number] = std::vector<uint8_t>(data + 2, data + len);
            } else {
                obj.body_segments[segment_number] = std::vector<uint8_t>();
            }
            if (is_last) {
                obj.body_last_seg = segment_number;
            }
            checkMotObjectComplete(transport_id);
        }
    } else if (dg_type == 3) {
        // MOT Header segment (Header Mode) - skip 2-byte length prefix
        if (obj.header_segments.find(segment_number) == obj.header_segments.end()) {
            if (len > 2) {
                obj.header_segments[segment_number] = std::vector<uint8_t>(data + 2, data + len);
            } else {
                obj.header_segments[segment_number] = std::vector<uint8_t>();
            }
            if (is_last) {
                obj.header_last_seg = segment_number;
            }
            // Parse header core from segment 0 (after skipping 2-byte prefix)
            if (segment_number == 0 && len > 9) {
                parseMotHeaderCore(data + 2, len - 2, obj.header_info);
            }
            checkMotObjectComplete(transport_id);
        }
    }
}

void PacketDecoder::checkMotObjectComplete(uint16_t transport_id) {
    auto& obj = mot_objects_[transport_id];

    // Check if we have all body segments
    if (obj.body_last_seg < 0) return;  // Don't know last segment yet

    bool body_complete = true;
    int missing_seg = -1;
    for (int i = 0; i <= obj.body_last_seg; i++) {
        if (obj.body_segments.find(i) == obj.body_segments.end()) {
            body_complete = false;
            missing_seg = i;
            break;
        }
    }
    if (!body_complete) {
        return;
    }

    // Get header info - either from header segments (Header Mode) or directory (Directory Mode)
    MOTHeaderInfo* header_info = nullptr;
    if (obj.header_info.valid) {
        // Header Mode - header came from Type 3 data groups
        header_info = &obj.header_info;
    } else {
        // Directory Mode - check mot_directory_entries_
        auto it = mot_directory_entries_.find(transport_id);
        if (it != mot_directory_entries_.end() && it->second.valid) {
            header_info = &it->second;
        }
    }

    if (!header_info) {
        return;  // No header info available
    }


    // Reassemble body
    std::vector<uint8_t> body_data;
    for (int i = 0; i <= obj.body_last_seg; i++) {
        const auto& seg = obj.body_segments[i];
        body_data.insert(body_data.end(), seg.begin(), seg.end());
    }

    // Invoke callback with completed MOT object
    if (mot_callback_) {
        mot_callback_(transport_id, *header_info, body_data.data(), body_data.size());
    }

    // Clear this object to prepare for next version
    obj.header_segments.clear();
    obj.body_segments.clear();
    obj.header_last_seg = -1;
    obj.body_last_seg = -1;
    obj.header_info = MOTHeaderInfo();
}

} // namespace dvbdab
