#include "pf_reassembler.hpp"
#include "../logging.h"
#include <algorithm>

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
    if (len < 12 || pkt[0] != 'P' || pkt[1] != 'F') return false;

    hdr.pseq = (pkt[2] << 8) | pkt[3];
    hdr.findex = (pkt[4] << 16) | (pkt[5] << 8) | pkt[6];
    hdr.fcount = (pkt[7] << 16) | (pkt[8] << 8) | pkt[9];

    uint16_t fec_addr_plen = (pkt[10] << 8) | pkt[11];
    hdr.fec = (fec_addr_plen >> 15) & 1;
    hdr.addr = (fec_addr_plen >> 14) & 1;
    hdr.plen = fec_addr_plen & 0x3FFF;

    // Calculate required header length
    size_t hdr_len = 12;
    if (hdr.fec) hdr_len += 2;   // RSk, RSz bytes
    if (hdr.addr) hdr_len += 4;  // Source, Dest
    hdr_len += 2;                // HCRC

    if (len < hdr_len) return false;

    size_t idx = 12;

    // RS parameters (when FEC=1)
    if (hdr.fec) {
        hdr.rsk = pkt[idx++];
        hdr.rsz = pkt[idx++];
    }

    // Optional transport header
    if (hdr.addr) {
        hdr.source = (pkt[idx] << 8) | pkt[idx + 1];
        hdr.dest = (pkt[idx + 2] << 8) | pkt[idx + 3];
        idx += 4;
    }

    // Skip HCRC (2 bytes)
    idx += 2;

    // Sanity check: plen should fit within the packet
    if (hdr.plen > len - idx) {
        LOG_DEBUG(PF, "plen=" << hdr.plen << " > available=" << (len - idx));
        return false;
    }

    hdr.valid = true;
    return true;
}

const uint8_t* PF_Reassembler::add_fragment(const PF_Header& hdr, const uint8_t* pkt, size_t len, size_t& af_len) {
    af_len = 0;

    // Calculate header size
    size_t hdr_size = 12;
    if (hdr.fec) hdr_size += 2;   // RSk, RSz
    if (hdr.addr) hdr_size += 4;  // Source, Dest
    hdr_size += 2;                // HCRC

    if (len < hdr_size + hdr.plen) return nullptr;

    const uint8_t* payload = pkt + hdr_size;

    // Get or create collector for this pseq
    PF_Collector& c = collectors_[hdr.pseq];

    // Initialize if new OR if this pseq was previously processed (pseq wrapped around)
    if (c.fcount == 0 || c.processed) {
        c.pseq = hdr.pseq;
        c.fcount = hdr.fcount;
        c.fec = hdr.fec;
        c.rsk = hdr.fec ? hdr.rsk : hdr.fcount;
        c.rsz = hdr.fec ? hdr.rsz : 0;
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

    // All fragments received - concatenate
    c.processed = true;
    af_buffer_.clear();

    if (c.fec) {
        // FEC mode: RS block de-interleaving (ETSI TS 102 821)
        // Same logic as eti-tools pf_parser.c
        auto it0 = c.fragments.find(0);
        if (it0 == c.fragments.end() || it0->second.empty()) return nullptr;
        size_t plen = it0->second.size();

        // Step 1: De-interleave all fragments into rs_block
        // rs_block[k * fcount + j] = fragment[j][k]
        size_t rs_block_size = c.fcount * plen;
        std::vector<uint8_t> rs_block(rs_block_size);

        for (uint32_t j = 0; j < c.fcount; j++) {
            auto it = c.fragments.find(j);
            if (it == c.fragments.end()) return nullptr;
            for (size_t k = 0; k < plen && k < it->second.size(); k++) {
                rs_block[k * c.fcount + j] = it->second[k];
            }
        }

        // Step 2: Extract data bytes from RS chunks
        // Each chunk is RSk+48 bytes (data + parity)
        // We only keep the first RSk bytes from each chunk
        size_t chunk_size = c.rsk + 48;
        size_t cmax = rs_block_size / chunk_size;

        // Final AF size: cmax * RSk, minus trailing padding (RSz)
        size_t af_size = cmax * c.rsk;
        if (af_size > c.rsz) {
            af_size -= c.rsz;
        }

        af_buffer_.resize(af_size);
        size_t out_pos = 0;

        for (size_t i = 0; i < cmax && out_pos < af_size; i++) {
            const uint8_t* chunk_begin = rs_block.data() + chunk_size * i;
            size_t bytes_to_copy = std::min(static_cast<size_t>(c.rsk), af_size - out_pos);
            std::copy(chunk_begin, chunk_begin + bytes_to_copy, af_buffer_.begin() + out_pos);
            out_pos += bytes_to_copy;
        }
    } else {
        // Non-FEC mode: simple concatenation
        for (uint32_t i = 0; i < c.fcount; i++) {
            auto it = c.fragments.find(i);
            if (it == c.fragments.end()) return nullptr;
            af_buffer_.insert(af_buffer_.end(), it->second.begin(), it->second.end());
        }
    }

    cleanup_old_collectors();

    af_len = af_buffer_.size();
    return af_buffer_.data();
}

} // namespace dvbdab
