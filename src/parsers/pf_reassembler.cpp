#include "pf_reassembler.hpp"
#include "../logging.h"

namespace dvbdab {

PF_Reassembler::PF_Reassembler() {
    reset();
}

void PF_Reassembler::reset() {
    collectors_.clear();
    af_buffer_.clear();
}

void PF_Reassembler::cleanup_old_collectors() {
    // Remove completed collectors when we have too many
    if (collectors_.size() > 16) {
        auto it = collectors_.begin();
        while (collectors_.size() > 8 && it != collectors_.end()) {
            if (it->second.processed) {
                it = collectors_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

bool PF_Reassembler::parse_pf_header(const uint8_t* pkt, size_t len, PF_Header& hdr) {
    if (len < 14 || pkt[0] != 'P' || pkt[1] != 'F') return false;

    hdr.pseq = (pkt[2] << 8) | pkt[3];
    hdr.findex = (pkt[4] << 16) | (pkt[5] << 8) | pkt[6];
    hdr.fcount = (pkt[7] << 16) | (pkt[8] << 8) | pkt[9];

    uint16_t fec_addr_plen = (pkt[10] << 8) | pkt[11];
    hdr.fec = (fec_addr_plen >> 15) & 1;
    hdr.addr = (fec_addr_plen >> 14) & 1;
    hdr.plen = fec_addr_plen & 0x3FFF;

    // Sanity check: plen should fit within the packet
    if (hdr.plen > len - 14) {
        LOG_DEBUG(PF, "plen=" << hdr.plen << " > available=" << (len - 14));
        return false;
    }

    hdr.valid = true;
    return true;
}

const uint8_t* PF_Reassembler::add_fragment(const PF_Header& hdr, const uint8_t* pkt, size_t len, size_t& af_len) {
    af_len = 0;

    // Calculate header size
    size_t hdr_size = 12;
    if (hdr.fec) hdr_size += 2;
    if (hdr.addr) hdr_size += 4;
    hdr_size += 2; // HCRC

    if (len < hdr_size + hdr.plen) return nullptr;

    const uint8_t* payload = pkt + hdr_size;

    // Get or create collector for this pseq
    PF_Collector& c = collectors_[hdr.pseq];

    // Initialize if new OR if this pseq was previously processed (pseq wrapped around)
    if (c.fcount == 0 || c.processed) {
        c.pseq = hdr.pseq;
        c.fcount = hdr.fcount;
        c.fragments_collected = 0;
        c.processed = false;
        c.fragments.clear();
    }

    if (hdr.findex >= c.fcount) return nullptr;
    if (c.fragments.count(hdr.findex)) return nullptr;  // Already have this fragment

    // Store fragment
    c.fragments[hdr.findex].assign(payload, payload + hdr.plen);
    c.fragments_collected++;

    // Check if we have all fragments
    if (c.fragments_collected < c.fcount) {
        return nullptr;  // Not complete yet
    }

    // All fragments received - concatenate in order
    c.processed = true;
    af_buffer_.clear();

    for (uint32_t i = 0; i < c.fcount; i++) {
        auto it = c.fragments.find(i);
        if (it == c.fragments.end()) {
            return nullptr;  // Missing fragment
        }
        af_buffer_.insert(af_buffer_.end(), it->second.begin(), it->second.end());
    }

    cleanup_old_collectors();

    af_len = af_buffer_.size();
    return af_buffer_.data();
}

} // namespace dvbdab
