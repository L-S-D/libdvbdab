#pragma once
// Shared byte manipulation utilities for DAB/DVB processing
// - Big-endian read helpers (network byte order)
// - Common TS packet helpers
//
// References:
//   ISO/IEC 13818-1 (MPEG-2 Systems) - TS packet structure
//   ETSI EN 300 468 - DVB SI (Service Information)
//   ETSI EN 300 799 - ETI (Ensemble Transport Interface)

#include <cstdint>

namespace dvbdab {

// Big-endian read helpers (network byte order)
inline uint16_t read_be16(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

inline uint32_t read_be24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16)
         | (static_cast<uint32_t>(p[1]) << 8)
         | p[2];
}

inline uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24)
         | (static_cast<uint32_t>(p[1]) << 16)
         | (static_cast<uint32_t>(p[2]) << 8)
         | p[3];
}

// Little-endian read helpers
inline uint16_t read_le16(const uint8_t* p) {
    return p[0] | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t read_le32(const uint8_t* p) {
    return p[0]
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

// ============================================================================
// TS Packet Helpers (ISO/IEC 13818-1 Section 2.4.3.2)
// ============================================================================
// TS packet header (4 bytes):
//   Byte 0:    sync_byte (0x47)
//   Byte 1:    transport_error_indicator (1) | payload_unit_start_indicator (1) |
//              transport_priority (1) | PID[12:8] (5)
//   Byte 2:    PID[7:0] (8)
//   Byte 3:    transport_scrambling_control (2) | adaptation_field_control (2) |
//              continuity_counter (4)

// Extract 13-bit PID from bytes 1-2
// Mask 0x1F extracts bits [4:0] from byte 1 (PID high bits)
inline uint16_t ts_get_pid(const uint8_t* pkt) {
    return ((pkt[1] & 0x1F) << 8) | pkt[2];
}

// Check adaptation_field_control bit 0 (byte 3, bit 4) - payload present
// adaptation_field_control: 00=reserved, 01=payload only, 10=AF only, 11=AF+payload
inline bool ts_has_payload(const uint8_t* pkt) {
    return (pkt[3] & 0x10) != 0;
}

// Check adaptation_field_control bit 1 (byte 3, bit 5) - adaptation field present
inline bool ts_has_adaptation(const uint8_t* pkt) {
    return (pkt[3] & 0x20) != 0;
}

// Extract 4-bit continuity_counter from byte 3 bits [3:0]
inline uint8_t ts_get_cc(const uint8_t* pkt) {
    return pkt[3] & 0x0F;
}

// Check payload_unit_start_indicator (byte 1, bit 6)
// For PSI: pointer_field follows; for PES: PES packet starts here
inline bool ts_payload_start(const uint8_t* pkt) {
    return (pkt[1] & 0x40) != 0;
}

// Get payload offset in TS packet (after 4-byte header and adaptation field)
// If adaptation field present, byte 4 is adaptation_field_length
inline size_t ts_payload_offset(const uint8_t* pkt) {
    size_t offset = 4;  // TS header size
    if (ts_has_adaptation(pkt)) {
        offset += 1 + pkt[4];  // 1 byte length + adaptation field data
    }
    return offset;
}

} // namespace dvbdab
