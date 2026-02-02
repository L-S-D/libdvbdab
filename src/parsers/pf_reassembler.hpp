#pragma once

#include <cstdint>
#include <cstddef>
#include <map>
#include <vector>

namespace dvbdab {

constexpr size_t MAX_PF_PAYLOAD = 65536;

// PF (Protocol Fragment) packet header - ETSI TS 102 821
struct PF_Header {
    uint16_t pseq;       // Packet sequence number
    uint32_t findex;     // Fragment index (0 to fcount-1)
    uint32_t fcount;     // Total fragment count
    bool fec;            // FEC flag
    bool addr;           // Address flag
    uint16_t plen;       // Payload length
    uint8_t rsk;         // RS k parameter (optional)
    uint8_t rsz;         // RS z parameter (optional)
    uint16_t source;     // Source address (optional)
    uint16_t dest;       // Destination address (optional)
    bool valid;
};

// Single PF fragment collector (for one Pseq)
struct PF_Collector {
    uint16_t pseq = 0;
    uint32_t fcount = 0;
    uint32_t fragments_collected = 0;
    bool fec = false;           // FEC enabled flag
    uint8_t rsk = 0;            // RS k (data bytes per chunk)
    uint8_t rsz = 0;            // RS z (trailing bytes to remove)
    bool processed = false;
    std::map<uint32_t, std::vector<uint8_t>> fragments;  // findex -> data
};

// PF fragment reassembly manager
class PF_Reassembler {
public:
    PF_Reassembler();
    void reset();

    // Parse PF header from packet
    bool parse_pf_header(const uint8_t* pkt, size_t len, PF_Header& hdr);

    // Add a fragment, returns complete AF packet data if all fragments received
    const uint8_t* add_fragment(const PF_Header& hdr, const uint8_t* pkt, size_t len, size_t& af_len);

private:
    std::map<uint16_t, PF_Collector> collectors_;
    std::vector<uint8_t> af_buffer_;

    void cleanup_old_collectors();
};

} // namespace dvbdab
