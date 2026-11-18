#include "dab_stream_parser.h"
#include "logging.h"
#include "utils/crc_utils.hpp"
#include "utils/byte_utils.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace dvbdab {

DABStreamParser::DABStreamParser(uint32_t target_ip, uint16_t target_port)
    : target_ip_(target_ip), target_port_(target_port) {
    reset();
}

DABStreamParser::~DABStreamParser() = default;

void DABStreamParser::reset() {
    pf_reassembler_.reset();
    fic_parser_.reset();
    edi_ = EDI_Builder{};
    last_af_seq_ = 0;
    layout_.clear();
    layout_len_ = 0;
    last_stc_ = {};
    cur_pseq_ = -1;
    last_pseq_ = -1;
    last_dflc_ = 0;
    last_out_pseq_ = -1;
    partial_af_count_ = 0;
}

uint16_t DABStreamParser::crc16(const uint8_t* data, size_t len) {
    return crc16_ccitt_xor(data, len);
}

bool DABStreamParser::check_crc(const uint8_t* data, size_t len) {
    if (len < 2) return false;

    uint16_t crc_from_packet = read_be16(data + len - 2);
    uint16_t crc = crc16_ccitt_xor(data, len - 2);

    crc_check_count_++;
    LOG_DEBUG(STREAM, "CRC check #" << crc_check_count_ << " len=" << len
             << " expected=0x" << std::hex << crc_from_packet
             << " calculated=0x" << crc << std::dec
             << (crc_from_packet == crc ? " OK" : " FAIL"));

    return crc_from_packet == crc;
}

bool DABStreamParser::process_edi_packet(const uint8_t* edi_data, size_t len) {
    if (len > 0) {
        edi_count_++;
        handle_edi_packet(edi_data, len);
    }
    return fic_parser_.is_complete();
}

bool DABStreamParser::process_ip_packet(const uint8_t* ip, size_t len) {
    if (len < 28) return fic_parser_.is_complete();
    if ((ip[0] >> 4) != 4) return fic_parser_.is_complete();

    int ip_hdr_len = (ip[0] & 0x0F) * 4;
    if (ip_hdr_len < 20 || (size_t)ip_hdr_len > len) return fic_parser_.is_complete();

    if (ip[9] != 17) return fic_parser_.is_complete();

    if (len < (size_t)ip_hdr_len + 8) return fic_parser_.is_complete();
    const uint8_t* udp = ip + ip_hdr_len;
    uint16_t udp_len = (udp[4] << 8) | udp[5];

    if (udp_len < 8 || udp_len > len - ip_hdr_len) {
        return fic_parser_.is_complete();
    }

    const uint8_t* edi_data = udp + 8;
    size_t edi_len = udp_len - 8;

    ip_count_++;

    if (ip_count_ <= 3 || ip_count_ % 500 == 0) {
        LOG_INFO(STREAM, "process_ip_packet: ip_count=" << ip_count_
                 << " len=" << len << " ip_hdr_len=" << ip_hdr_len
                 << " udp_len=" << udp_len << " edi_len=" << edi_len
                 << " edi_type=" << (char)edi_data[0] << (char)edi_data[1]);
    }

    if (edi_len > 0 && edi_len <= len - ip_hdr_len - 8) {
        edi_count_++;
        handle_edi_packet(edi_data, edi_len);
    }

    return fic_parser_.is_complete();
}

int DABStreamParser::handle_edi_packet(const uint8_t* pkt, size_t len) {
    if (len < 2) return -1;

    if (pkt[0] == 'A' && pkt[1] == 'F') {
        int ret = handle_af_packet(pkt, len);
        if (ret > 0) {
            assemble_eti_frame();
        }
        return ret;
    } else if (pkt[0] == 'P' && pkt[1] == 'F') {
        int ret = handle_pf_packet(pkt, len);
        if (ret > 0) {
            assemble_eti_frame();
        }
        return ret;
    }

    return -1;
}

int DABStreamParser::handle_pf_packet(const uint8_t* pkt, size_t len) {
    PF_Header hdr;
    if (!pf_reassembler_.parse_pf_header(pkt, len, hdr)) {
        LOG_WARN(STREAM, "PF header parse failed, len=" << len);
        return -1;
    }

    pf_count_++;
    if (pf_count_ <= 5 || pf_count_ % 500 == 0) {
        LOG_DEBUG(STREAM, "PF packet #" << pf_count_ << " pseq=" << hdr.pseq
                  << " findex=" << hdr.findex << "/" << hdr.fcount
                  << " plen=" << hdr.plen << " len=" << len);
    }

    size_t af_len = 0;
    const uint8_t* af_data = pf_reassembler_.add_fragment(hdr, pkt, len, af_len);

    // The AFs before it that stay incomplete: what came of them (they are
    // older, their frames go out first)
    PF_Partial part;
    while (pf_reassembler_.take_partial(part)) {
        handle_partial_af(part);
    }

    if (af_data && af_len > 0) {
        af_assembled_count_++;
        if (af_assembled_count_ <= 5 || af_assembled_count_ % 100 == 0) {
            LOG_DEBUG(STREAM, "PF reassembled AF packet #" << af_assembled_count_ << " len=" << af_len);
        }
        if (!pseq_in_order(hdr.pseq)) {
            return 0;
        }
        cur_pseq_ = hdr.pseq;
        int ret = handle_af_packet(af_data, af_len);
        cur_pseq_ = -1;
        if (ret > 0) {
            last_out_pseq_ = hdr.pseq;
        }
        return ret;
    }

    return 0;
}

int DABStreamParser::handle_af_packet(const uint8_t* pkt, size_t len) {
    constexpr size_t AFPACKET_HEADER_LEN = 10;

    if (len < AFPACKET_HEADER_LEN || pkt[0] != 'A' || pkt[1] != 'F') {
        af_process_count_++;
        LOG_DEBUG(STREAM, "AF bad sync or len=" << len);
        return -1;
    }

    uint32_t taglength = read_be32(pkt + 2);
    bool has_crc = (pkt[8] >> 7) & 1;
    char pt = pkt[9];

    af_process_count_++;
    if (af_process_count_ <= 5 || af_process_count_ % 100 == 0) {
        LOG_DEBUG(STREAM, "AF #" << af_process_count_ << " taglength=" << taglength
                 << " has_crc=" << has_crc << " pt=" << pt << " buflen=" << len);
    }

    if (pt != 'T') {
        LOG_DEBUG(STREAM, "AF pt=" << (int)pt << " not T");
        return -1;
    }

    size_t total_len = AFPACKET_HEADER_LEN + taglength + (has_crc ? 2 : 0);
    if (len < total_len) {
        LOG_DEBUG(STREAM, "AF len=" << len << " < total=" << total_len);
        return -1;
    }

    if (has_crc) {
        uint16_t crc_from_pkt = read_be16(pkt + total_len - 2);
        uint16_t crc = crc16_ccitt_xor(pkt, total_len - 2);
        if (CHECKSUMS_CHECKED && crc_from_pkt != crc) {
            LOG_DEBUG(STREAM, "AF CRC fail (got=0x" << std::hex << crc_from_pkt
                     << " calc=0x" << crc << std::dec << ")");
            return -1;
        }
    }

    // Its TAG items: the layout for incomplete AFs (from PF packets) after it
    std::vector<TagPos> layout;
    decode_tagpacket(pkt + AFPACKET_HEADER_LEN, taglength, &layout);
    if (cur_pseq_ >= 0 && edi_.is_eti && edi_.m_fc_valid) {
        layout_ = std::move(layout);
        layout_len_ = total_len;
        for (int n = 0; n < 64; n++) {
            last_stc_[n].scid = edi_.m_stc[n].scid;
            last_stc_[n].sad = edi_.m_stc[n].sad;
            last_stc_[n].tpl = edi_.m_stc[n].tpl;
            last_stc_[n].size = edi_.m_stc[n].mst.size();
        }
        last_pseq_ = cur_pseq_;
        last_dflc_ = edi_.m_fc.dflc;
    }

    if (af_process_count_ <= 5) {
        LOG_DEBUG(STREAM, "AF is_eti=" << edi_.is_eti << " fc_valid=" << edi_.m_fc_valid
                 << " fic_len=" << (int)edi_.fic_length << " nst=" << (int)edi_.m_fc.nst
                 << " mid=" << (int)edi_.m_fc.mid);
    }

    return 1;
}

bool DABStreamParser::decode_tagpacket(const uint8_t* pkt, size_t tagsize) {
    return decode_tagpacket(pkt, tagsize, nullptr);
}

bool DABStreamParser::decode_tagpacket(const uint8_t* pkt, size_t tagsize, std::vector<TagPos>* layout) {
    tagpkt_count_++;
    edi_.m_fc.nst = 0;
    est_mask_ = 0;
    est_bad_ = false;
    int tag_count_local = 0;

    LOG_DEBUG(STREAM, "decode_tagpacket #" << tagpkt_count_ << " len=" << tagsize);

    if (tagpkt_count_ <= 3) {
        std::ostringstream ss;
        ss << "tagpkt hex: ";
        for (size_t j = 0; j < std::min(tagsize, (size_t)64); j++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)pkt[j] << " ";
            if ((j + 1) % 16 == 0) ss << "\n                   ";
        }
        LOG_DEBUG(STREAM, ss.str());
    }

    for (size_t i = 0; i + 8 <= tagsize; ) {
        uint32_t tagId = read_be32(pkt + i);
        uint32_t taglen_bits = read_be32(pkt + i + 4);

#if defined(LSDVB_LOG_DEBUG) || defined(LSDVB_LOG_TRACE)
        if (tagpkt_count_ <= 5 && tag_count_local < 3) {
            char id[5] = {(char)(tagId >> 24), (char)(tagId >> 16), (char)(tagId >> 8), (char)tagId, 0};
            LOG_DEBUG(STREAM, "  TAG[" << tag_count_local << "]: id='" << id << "' (0x"
                     << std::hex << tagId << ") len_bits=" << std::dec << taglen_bits);
        }
#endif

        if (taglen_bits % 8 != 0) break;
        uint32_t taglen = taglen_bits / 8;

        const uint8_t* val = pkt + i + 8;
        if (i + 8 + taglen > tagsize) break;
        if (layout) {
            // the value in the AF packet: after its 10 byte header
            layout->push_back({tagId, 10 + i + 8, taglen});
        }

        if (tagId == 0x2a707472) {  // "*ptr"
            decode_starptr(val, taglen);
        } else if (tagId == 0x64657469) {  // "deti"
            decode_deti(val, taglen);
        } else if ((tagId & 0xFFFFFF00) == 0x65737400) {  // "est?"
            if (!decode_estn(val, taglen, tagId & 0xFF)) est_bad_ = true;
        }

        i += 8 + taglen;
        tag_count_local++;
        tag_count_++;
    }

    if (est_bad_ || !est_complete()) {
        // not a frame: est TAGs must be est1..estN, each once and whole
        edi_.m_fc_valid = false;
        edi_.m_fc.nst = 0;
        return false;
    }
    return true;
}

// The est TAGs taken are est1..estN without a gap (the streams of the frame
// to build are m_stc[0..nst-1])
bool DABStreamParser::est_complete() const {
    return (est_mask_ & (est_mask_ + 1)) == 0;
}

bool DABStreamParser::decode_starptr(const uint8_t* value, size_t len) {
    if (len != 8) return false;

    uint32_t proto = read_be32(value);
    uint16_t major = read_be16(value + 4);
    uint16_t minor = read_be16(value + 6);

    edi_.is_eti = (proto == 0x44455449 && major == 0 && minor == 0);  // "DETI"
    return true;
}

bool DABStreamParser::decode_deti(const uint8_t* val, size_t len) {
    // Without all its bytes it is not taken: the frame characterization of
    // the last one must not be mixed with half of this one
    if (len < 6) {
        edi_.m_fc_valid = false;
        return false;
    }
    {
        uint16_t head = read_be16(val);
        uint8_t mid = (read_be32(val + 2) >> 22) & 0x03;
        size_t need = 6 + ((head >> 15) & 1 ? 8 : 0) +
                      ((head >> 14) & 1 ? (mid == 3 ? 32 * 4 : 24 * 4) : 0) +
                      ((head >> 13) & 1 ? 3 : 0);
        if (len < need) {
            edi_.m_fc_valid = false;
            return false;
        }
    }
    uint16_t detiHeader = read_be16(val);
    edi_.m_fc.atstf = (detiHeader >> 15) & 1;
    edi_.m_fc.ficf = (detiHeader >> 14) & 1;
    bool rfudf = (detiHeader >> 13) & 1;
    uint8_t fcth = (detiHeader >> 8) & 0x1F;
    uint8_t fct = detiHeader & 0xFF;
    edi_.m_fc.dflc = fcth * 250 + fct;

    uint32_t etiHeader = read_be32(val + 2);
    edi_.m_fc.mid = (etiHeader >> 22) & 0x03;
    edi_.m_fc.fp = (etiHeader >> 19) & 0x07;
    bool rfu = (etiHeader >> 16) & 1;
    edi_.m_mnsc = rfu ? 0xFFFF : etiHeader & 0xFFFF;

    uint32_t fic_length = edi_.m_fc.ficf ? (edi_.m_fc.mid == 3 ? 32 * 4 : 24 * 4) : 0;

    size_t i = 6;
    if (edi_.m_fc.atstf) {
        i++;  // utco
        i += 4;  // seconds
        edi_.m_fc.tsta = read_be24(val + i);
        i += 3;
    } else {
        edi_.m_fc.tsta = 0xFFFFFF;
    }

    if (edi_.m_fc.ficf) {
        edi_.fic_length = fic_length;
        std::copy(val + i, val + i + fic_length, edi_.fic.data());
        i += fic_length;
    }

    edi_.m_rfu = 0xFFFF;
    if (rfudf) {
        uint32_t rfud = read_be24(val + i);
        edi_.m_rfu = rfud >> 8;
        i += 3;
    }

    edi_.m_fc_valid = true;
    return true;
}

bool DABStreamParser::decode_estn(const uint8_t* value, size_t len, uint8_t n) {
    if (len < 3 || n == 0 || n > 64) return false;
    // a stream is in a frame once, and it fits into an ETI frame
    if (len - 3 > ETI_NI_RAW_SIZE || ((est_mask_ >> (n - 1)) & 1)) return false;
    est_mask_ |= uint64_t(1) << (n - 1);

    uint32_t sstc = read_be24(value);

    EDI_STC& stc = edi_.m_stc[n - 1];
    stc.stream_index = n - 1;
    stc.scid = (sstc >> 18) & 0x3F;
    stc.sad = (sstc >> 8) & 0x3FF;
    stc.tpl = (sstc >> 2) & 0x3F;

    stc.mst.resize(len - 3);
    std::copy(value + 3, value + len, stc.mst.data());
    edi_.m_fc.nst++;

    return true;
}

bool DABStreamParser::assemble_eti_frame() {
    return assemble_eti_frame(false, 0, true);
}

bool DABStreamParser::assemble_eti_frame(bool partial, uint64_t invalid_scids, bool fic_fresh) {
    if (!edi_.is_eti || !edi_.m_fc_valid || !edi_.fic_length) {
        LOG_DEBUG(STREAM, "assemble_eti skip: is_eti=" << edi_.is_eti
                 << " fc_valid=" << edi_.m_fc_valid << " fic_len=" << (int)edi_.fic_length);
        return false;
    }

    if ((edi_.m_fc.mid == 3 && edi_.fic_length != 32 * 4) ||
        (edi_.m_fc.mid != 3 && edi_.fic_length != 24 * 4)) {
        LOG_WARN(STREAM, "ETI FIC length mismatch: mid=" << edi_.m_fc.mid << " fic_len=" << (int)edi_.fic_length);
        return false;
    }

    // The frame must fit: header, FIC, the streams, EOF and TIST
    if (edi_.m_fc.nst > 64) return false;
    size_t frame_bytes = 8 + size_t(edi_.m_fc.nst) * 4 + 4 + edi_.fic_length + 8;
    for (int i = 0; i < edi_.m_fc.nst; i++) {
        frame_bytes += edi_.m_stc[i].mst.size();
    }
    if (frame_bytes > ETI_NI_RAW_SIZE) {
        LOG_DEBUG(STREAM, "ETI frame of " << frame_bytes << " bytes dropped");
        return false;
    }

    eti_count_++;
    if (eti_count_ <= 5 || eti_count_ % 100 == 0) {
        LOG_DEBUG(STREAM, "Assembling ETI frame #" << eti_count_ << " mid=" << edi_.m_fc.mid
                 << " nst=" << (int)edi_.m_fc.nst << " fic_len=" << (int)edi_.fic_length);
    }

    uint8_t* eti = eti_frame_.data();
    std::fill(eti, eti + ETI_NI_RAW_SIZE, 0x55);

    int idx = 0;

    // SYNC word
    uint8_t fct = edi_.m_fc.dflc % 250;
    eti[0] = 0xFF;
    if (fct % 2 == 1) {
        eti[1] = 0xF8; eti[2] = 0xC5; eti[3] = 0x49;
    } else {
        eti[1] = 0x07; eti[2] = 0x3A; eti[3] = 0xB6;
    }

    // FC
    eti[4] = fct;
    uint8_t nst = edi_.m_fc.nst;
    eti[5] = (edi_.m_fc.ficf ? 0x80 : 0) | nst;

    // Calculate FL
    uint16_t fl = nst + 1 + edi_.fic_length / 4;
    for (int i = 0; i < nst; i++) {
        fl += edi_.m_stc[i].mst.size() / 4;
    }

    uint16_t fp_mid_fl = (edi_.m_fc.fp << 13) | (edi_.m_fc.mid << 11) | fl;
    eti[6] = fp_mid_fl >> 8;
    eti[7] = fp_mid_fl & 0xFF;

    // STC
    for (int i = 0; i < nst; i++) {
        auto& stc = edi_.m_stc[i];
        eti[8 + i * 4] = (stc.scid << 2) | ((stc.sad >> 8) & 0x03);
        eti[8 + i * 4 + 1] = stc.sad & 0xFF;
        uint16_t stl = stc.mst.size() / 8;
        eti[8 + i * 4 + 2] = (stc.tpl << 2) | ((stl >> 8) & 0x03);
        eti[8 + i * 4 + 3] = stl & 0xFF;
    }

    idx = 8 + nst * 4;

    // EOH - MNSC
    eti[idx] = edi_.m_mnsc >> 8;
    eti[idx + 1] = edi_.m_mnsc & 0xFF;

    // EOH - CRC
    uint16_t hdr_crc = crc16(&eti[4], idx - 4 + 2);
    eti[idx + 2] = hdr_crc >> 8;
    eti[idx + 3] = hdr_crc & 0xFF;
    idx += 4;

    size_t mst_start = idx;

    // FIC
    std::copy(edi_.fic.data(), edi_.fic.data() + edi_.fic_length, eti + idx);
    idx += edi_.fic_length;

    // MST
    for (int i = 0; i < nst; i++) {
        std::copy(edi_.m_stc[i].mst.begin(), edi_.m_stc[i].mst.end(), eti + idx);
        idx += edi_.m_stc[i].mst.size();
    }

    // EOF - CRC
    uint16_t mst_crc = crc16(&eti[mst_start], idx - mst_start);
    eti[idx] = mst_crc >> 8;
    eti[idx + 1] = mst_crc & 0xFF;

    // RFU
    eti[idx + 2] = edi_.m_rfu >> 8;
    eti[idx + 3] = edi_.m_rfu & 0xFF;

    // TIST
    eti[idx + 4] = (edi_.m_fc.tsta >> 24) & 0xFF;
    eti[idx + 5] = (edi_.m_fc.tsta >> 16) & 0xFF;
    eti[idx + 6] = (edi_.m_fc.tsta >> 8) & 0xFF;
    eti[idx + 7] = edi_.m_fc.tsta & 0xFF;
    idx += 8;

    // Feed to FIC parser (not the FIC of an earlier frame again)
    if (fic_fresh) {
        fic_parser_.process_eti_frame(eti, ETI_NI_RAW_SIZE);
    }

    // Emit ETI frame to callback
    StreamKey key{target_ip_, target_port_};
    if (eti_callback_ && !partial) {
        eti_callback_(key, eti, ETI_NI_RAW_SIZE, edi_.m_fc.dflc);
    }
    if (eti_ex_callback_) {
        eti_ex_callback_(key, eti, ETI_NI_RAW_SIZE, edi_.m_fc.dflc, invalid_scids);
    }

    return true;
}

bool DABStreamParser::pseq_in_order(int32_t pseq) const {
    uint16_t d = static_cast<uint16_t>(pseq - last_out_pseq_);
    return last_out_pseq_ < 0 || (d != 0 && d < 32768);
}

// An AF packet of which fragments did not come: with the TAG items of the
// last complete one (the layout of an ensemble stays as long as its
// configuration), the ones whose bytes came are decoded; a subchannel whose
// data did not come is marked invalid, without the DETI the frame counter
// follows from the PF sequence number. TAG heads that came must be those of
// the layout, the AF header the same length.
void DABStreamParser::handle_partial_af(const PF_Partial& part) {
    if (layout_.empty() || last_pseq_ < 0 || part.data.size() < layout_len_ ||
        !pseq_in_order(part.pseq)) {
        return;
    }
    const uint8_t* af = part.data.data();
    if (part.covers(0, 10) &&
        (af[0] != 'A' || af[1] != 'F' ||
         10 + read_be32(af + 2) + (((af[8] >> 7) & 1) ? 2u : 0u) != layout_len_)) {
        return;
    }
    for (const auto& t : layout_) {
        if (part.covers(t.off - 8, t.off) &&
            (read_be32(af + t.off - 8) != t.id || read_be32(af + t.off - 4) != t.len * 8)) {
            return;
        }
    }

    uint64_t invalid = 0;
    bool deti = false;
    edi_.m_fc.nst = 0;
    est_mask_ = 0;
    est_bad_ = false;
    for (const auto& t : layout_) {
        bool came = part.covers(t.off, t.off + t.len);
        if (t.id == 0x2a707472) {  // "*ptr"
            if (came) decode_starptr(af + t.off, t.len);
        } else if (t.id == 0x64657469) {  // "deti"
            if (came) deti = decode_deti(af + t.off, t.len);
        } else if ((t.id & 0xFFFFFF00) == 0x65737400) {  // "est?"
            uint8_t n = t.id & 0xFF;
            if (n == 0 || n > 64) continue;
            if (came) {
                if (!decode_estn(af + t.off, t.len, n)) est_bad_ = true;
                continue;
            }
            if ((est_mask_ >> (n - 1)) & 1) continue;
            est_mask_ |= uint64_t(1) << (n - 1);
            const StcInfo& ls = last_stc_[n - 1];
            EDI_STC& stc = edi_.m_stc[n - 1];
            stc.stream_index = n - 1;
            stc.scid = ls.scid;
            stc.sad = ls.sad;
            stc.tpl = ls.tpl;
            stc.mst.assign(ls.size, 0);
            edi_.m_fc.nst++;
            invalid |= uint64_t(1) << (ls.scid & 63);
        }
    }
    if (deti) {
        last_pseq_ = part.pseq;
        last_dflc_ = edi_.m_fc.dflc;
    } else {
        uint16_t d = static_cast<uint16_t>(part.pseq - last_pseq_);
        edi_.m_fc.dflc = (last_dflc_ + d) % 5000;
    }
    if (est_bad_ || !est_complete()) return;
    partial_af_count_++;
    if (assemble_eti_frame(true, invalid, deti)) {
        last_out_pseq_ = part.pseq;
    }
}

const DABEnsemble& DABStreamParser::get_ensemble() const {
    return fic_parser_.get_ensemble();
}

bool DABStreamParser::is_complete() const {
    return fic_parser_.is_complete();
}

bool DABStreamParser::is_basic_ready() const {
    return fic_parser_.is_basic_ready();
}

bool DABStreamParser::has_data() const {
    return eti_count_ > 0;
}

} // namespace dvbdab
