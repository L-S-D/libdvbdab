#include "edi_parser.hpp"
#include <cstring>
#include <algorithm>

namespace {

inline std::uint32_t read32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24)
         | (static_cast<std::uint32_t>(p[1]) << 16)
         | (static_cast<std::uint32_t>(p[2]) << 8)
         | p[3];
}

inline std::uint16_t read16(const std::uint8_t* p) {
    return (static_cast<std::uint16_t>(p[0]) << 8) | p[1];
}

inline std::uint32_t read24(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 16)
         | (static_cast<std::uint32_t>(p[1]) << 8)
         | p[2];
}

}  // namespace

EdiParser::EdiParser(EtiFrameCallback callback)
    : callback_(std::move(callback))
{
}

// Feed function - copied exactly from standalone tool
void EdiParser::feed(const std::uint8_t* data, std::size_t len) {
    // Exact copy from standalone PfReassembler::feed()
    if (len < 14 || data[0] != 'P' || data[1] != 'F') return;

    uint16_t pseq = (data[2] << 8) | data[3];
    uint32_t findex = (data[4] << 16) | (data[5] << 8) | data[6];
    uint32_t fcount = (data[7] << 16) | (data[8] << 8) | data[9];

    uint8_t fec_flag = (data[10] >> 7) & 1;
    uint8_t addr_flag = (data[10] >> 6) & 1;
    uint16_t plen = ((data[10] & 0x3F) << 8) | data[11];

    size_t hdr_size = 14 + (fec_flag ? 2 : 0) + (addr_flag ? 4 : 0);
    if (fcount == 0 || fcount > 256 || findex >= fcount || len < hdr_size + plen) return;

    auto& c = pf_collectors_[pseq];
    if (c.pseq != pseq || c.fcount != fcount) {
        c.pseq = pseq;
        c.fcount = fcount;
        c.fragments.clear();
    }

    if (c.fragments.find(findex) == c.fragments.end()) {
        c.fragments[findex] = std::vector<uint8_t>(data + hdr_size, data + hdr_size + plen);
    }

    if (c.fragments.size() == c.fcount) {
        std::vector<uint8_t> af;
        for (uint32_t i = 0; i < c.fcount; i++) {
            auto it = c.fragments.find(i);
            if (it != c.fragments.end()) {
                af.insert(af.end(), it->second.begin(), it->second.end());
            }
        }

        // Process complete AF packet
        handleAfPacket(af.data(), af.size());
        pf_collectors_.erase(pseq);
    }
}

bool EdiParser::handlePfPacket(const std::uint8_t* data, std::size_t len) {
    // Not used - feed() handles PF directly now
    return true;
}

bool EdiParser::handleAfPacket(const std::uint8_t* data, std::size_t len) {
    // Exact check from standalone: af.size() < 10 || af[0] != 'A' || af[1] != 'F'
    if (len < 10 || data[0] != 'A' || data[1] != 'F') return false;

    // Parse tags starting at offset 10 (like standalone extractFct)
    if (decodeTagPacket(data + 10, len - 10)) {
        assembleEtiFrame();
    }

    return true;
}

bool EdiParser::decodeTagPacket(const std::uint8_t* data, std::size_t len) {
    std::size_t i = 0;
    eti_.fc.nst = 0;

    // Tag parsing like standalone: pos += 8 + tag_len
    while (i + 8 <= len) {
        std::uint32_t tag_id = read32(data + i);
        std::uint32_t tag_len_bits = read32(data + i + 4);
        std::uint32_t tag_len = (tag_len_bits + 7) / 8;  // Round up like standalone

        if (i + 8 + tag_len > len) break;

        const std::uint8_t* value = data + i + 8;

        if (tag_id == 0x2a707472) {  // "*ptr"
            decodeStarPtr(value, tag_len);
        } else if (tag_id == 0x64657469) {  // "deti"
            decodeDeti(value, tag_len);
        } else if ((tag_id & 0xFFFFFF00) == 0x65737400) {  // "est" + N
            std::uint8_t n = tag_id & 0xFF;
            decodeEstN(value, tag_len, n);
        }

        i += 8 + tag_len;
    }

    return eti_.fc_valid;
}

bool EdiParser::decodeStarPtr(const std::uint8_t* data, std::size_t len) {
    if (len < 8) return false;

    std::uint32_t proto = read32(data);
    std::uint16_t major = read16(data + 4);
    std::uint16_t minor = read16(data + 6);

    eti_.is_eti = (proto == 0x44455449 && major == 0 && minor == 0);
    return true;
}

bool EdiParser::decodeDeti(const std::uint8_t* data, std::size_t len) {
    if (len < 6) return false;

    std::uint16_t deti_header = read16(data);

    eti_.fc.atstf = (deti_header >> 15) & 1;
    eti_.fc.ficf = (deti_header >> 14) & 1;
    bool rfudf = (deti_header >> 13) & 1;
    std::uint8_t fcth = (deti_header >> 8) & 0x1F;
    std::uint8_t fct = deti_header & 0xFF;

    eti_.fc.dflc = fcth * 250 + fct;

    std::uint32_t eti_header = read32(data + 2);

    eti_.err = (eti_header >> 24) & 0xFF;
    eti_.fc.mid = (eti_header >> 22) & 0x03;
    eti_.fc.fp = (eti_header >> 19) & 0x07;
    bool rfu = (eti_header >> 16) & 1;
    eti_.mnsc = rfu ? 0xFFFF : (eti_header & 0xFFFF);

    // FIC length based on mode
    std::uint32_t fic_words = eti_.fc.ficf ? (eti_.fc.mid == 3 ? 32 : 24) : 0;
    std::uint32_t fic_length = fic_words * 4;

    std::size_t min_len = 6 + (eti_.fc.atstf ? 8 : 0) + fic_length;
    if (len < min_len) return false;

    std::size_t idx = 6;

    // ATST (optional)
    if (eti_.fc.atstf) {
        idx++;  // UTCO
        idx += 4;  // Seconds
        eti_.fc.tsta = read24(data + idx);
        idx += 3;
    } else {
        eti_.fc.tsta = 0xFFFFFF;
    }

    // FIC data
    if (eti_.fc.ficf && fic_length > 0) {
        eti_.fic.assign(data + idx, data + idx + fic_length);
        idx += fic_length;
    }

    // RFU (optional)
    if (rfudf && idx + 3 <= len) {
        std::uint32_t rfud = read24(data + idx);
        eti_.rfu = rfud >> 8;
    } else {
        eti_.rfu = 0xFFFF;
    }

    eti_.fc_valid = true;
    return true;
}

bool EdiParser::decodeEstN(const std::uint8_t* data, std::size_t len, std::uint8_t n) {
    if (len < 3 || n == 0 || n > 64) return false;

    std::uint32_t sstc = read24(data);

    auto& stc = eti_.subchannels[n - 1];
    stc.scid = (sstc >> 18) & 0x3F;
    stc.sad = (sstc >> 8) & 0x3FF;
    stc.tpl = (sstc >> 2) & 0x3F;

    stc.mst.assign(data + 3, data + len);
    eti_.fc.nst++;

    return true;
}

std::uint16_t EdiParser::crc16(const std::uint8_t* data, std::size_t len) {
    std::uint16_t crc = 0xFFFF;
    for (std::size_t i = 0; i < len; ++i) {
        crc ^= static_cast<std::uint16_t>(data[i]) << 8;
        for (int j = 0; j < 8; ++j) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc ^ 0xFFFF;
}

void EdiParser::assembleEtiFrame() {
    if (!eti_.is_eti || !eti_.fc_valid || eti_.fic.empty()) {
        return;
    }

    std::size_t expected_fic = (eti_.fc.mid == 3) ? 128 : 96;
    if (eti_.fic.size() != expected_fic) {
        return;
    }

    std::array<std::uint8_t, 6144> eti_frame{};
    std::size_t idx = 0;

    // SYNC - ERR + FSYNC
    eti_frame[0] = eti_.err;

    std::uint8_t fct = eti_.fc.dflc % 250;
    if (fct % 2 == 1) {
        eti_frame[1] = 0xF8;
        eti_frame[2] = 0xC5;
        eti_frame[3] = 0x49;
    } else {
        eti_frame[1] = 0x07;
        eti_frame[2] = 0x3A;
        eti_frame[3] = 0xB6;
    }

    // FC - FCT
    eti_frame[4] = fct;

    // FC - FICF + NST
    std::uint8_t nst = eti_.fc.nst;
    eti_frame[5] = (eti_.fc.ficf ? 0x80 : 0x00) | nst;

    // FC - FP + MID + FL
    std::uint16_t fl = nst + 1 + static_cast<std::uint16_t>(eti_.fic.size() / 4);
    for (std::uint8_t i = 0; i < nst; ++i) {
        fl += static_cast<std::uint16_t>(eti_.subchannels[i].mst.size() / 4);
    }

    std::uint16_t fp_mid_fl = (static_cast<std::uint16_t>(eti_.fc.fp) << 13)
                            | (static_cast<std::uint16_t>(eti_.fc.mid) << 11)
                            | fl;
    eti_frame[6] = fp_mid_fl >> 8;
    eti_frame[7] = fp_mid_fl & 0xFF;

    // STC entries
    for (std::uint8_t i = 0; i < nst; ++i) {
        const auto& stc = eti_.subchannels[i];
        std::uint16_t stl = static_cast<std::uint16_t>(stc.mst.size() / 8);

        eti_frame[8 + i*4 + 0] = (stc.scid << 2) | ((stc.sad >> 8) & 0x03);
        eti_frame[8 + i*4 + 1] = stc.sad & 0xFF;
        eti_frame[8 + i*4 + 2] = (stc.tpl << 2) | ((stl >> 8) & 0x03);
        eti_frame[8 + i*4 + 3] = stl & 0xFF;
    }

    idx = 8 + nst * 4;

    // EOH - MNSC
    eti_frame[idx] = eti_.mnsc >> 8;
    eti_frame[idx + 1] = eti_.mnsc & 0xFF;

    // EOH - CRC (FC to MNSC)
    std::uint16_t eoh_crc = crc16(&eti_frame[4], idx - 4 + 2);
    eti_frame[idx + 2] = eoh_crc >> 8;
    eti_frame[idx + 3] = eoh_crc & 0xFF;
    idx += 4;

    std::size_t mst_start = idx;

    // MST - FIC
    std::memcpy(&eti_frame[idx], eti_.fic.data(), eti_.fic.size());
    idx += eti_.fic.size();

    // MST - Subchannels
    for (std::uint8_t i = 0; i < nst; ++i) {
        const auto& stc = eti_.subchannels[i];
        if (idx + stc.mst.size() > 6144 - 8) {
            return;
        }
        std::memcpy(&eti_frame[idx], stc.mst.data(), stc.mst.size());
        idx += stc.mst.size();
    }

    // EOF - MST CRC
    std::uint16_t mst_crc = crc16(&eti_frame[mst_start], idx - mst_start);
    eti_frame[idx] = mst_crc >> 8;
    eti_frame[idx + 1] = mst_crc & 0xFF;

    // EOF - RFU
    eti_frame[idx + 2] = eti_.rfu >> 8;
    eti_frame[idx + 3] = eti_.rfu & 0xFF;

    // TIST
    eti_frame[idx + 4] = (eti_.fc.tsta >> 24) & 0xFF;
    eti_frame[idx + 5] = (eti_.fc.tsta >> 16) & 0xFF;
    eti_frame[idx + 6] = (eti_.fc.tsta >> 8) & 0xFF;
    eti_frame[idx + 7] = eti_.fc.tsta & 0xFF;
    idx += 8;

    // Pad to 6144 bytes (ETI-NI format)
    std::memset(&eti_frame[idx], 0x55, 6144 - idx);

    // Output complete ETI frame with DFLC for continuity checking
    callback_(eti_frame.data(), 6144, eti_.fc.dflc);
}
