#pragma once
/**
 * @file dab_stream_parser.h
 * @brief DAB stream parser - converts EDI to ETI frames
 *
 * Data flow: IPv4/UDP packets → EDI/AF packets → ETI-NI frames
 *
 * This parser handles the EDI layers (the IP packets come from the
 * caller, which takes them out of their encapsulation: MPE, GSE):
 * - EDI PF fragment reassembly
 * - EDI AF packet parsing (tag decoding: *ptr, deti, est1-64)
 * - ETI-NI frame assembly (6144 bytes, ETSI EN 300 799)
 *
 * References:
 *   ETSI TS 102 693 - EDI (Ensemble Data Interface)
 *   ETSI EN 300 799 - ETI (Ensemble Transport Interface)
 */

#include "dab_parser.h"
#include "parsers/pf_reassembler.hpp"
#include <array>
#include <vector>
#include <chrono>

namespace dvbdab {

/// EDI/AF frame characterization (from deti tag)
struct EDI_FC {
    bool atstf;
    uint32_t tsta;
    bool ficf;
    uint8_t nst;
    uint16_t dflc;
    uint8_t mid;
    uint8_t fp;
};

// EDI subchannel data
struct EDI_STC {
    uint8_t stream_index;
    uint8_t scid;
    uint16_t sad;
    uint8_t tpl;
    std::vector<uint8_t> mst;
};

// EDI builder for assembling ETI frames
struct EDI_Builder {
    bool is_eti = false;
    uint8_t m_err = 0;
    uint16_t m_mnsc = 0;
    bool m_time_valid = false;
    uint32_t m_utco = 0;
    uint32_t m_seconds = 0;
    uint8_t fic_length = 0;
    std::array<uint8_t, 128> fic{};
    uint16_t m_rfu = 0xFFFF;
    std::array<EDI_STC, 64> m_stc{};
    bool m_fc_valid = false;
    EDI_FC m_fc{};
};

/**
 * @brief Complete DAB stream parser: IPv4/UDP → EDI → ETI → FIC/FIG
 *
 * Converts the EDI packets of one multicast stream (DAB-over-IP) into
 * ETI-NI frames. Internally uses DABParser for FIC/FIG parsing to
 * extract ensemble and service information.
 *
 * Usage:
 * @code
 *   DABStreamParser parser(ip, port);
 *   parser.setEtiCallback([](StreamKey key, const uint8_t* eti, size_t len, uint16_t dflc) {
 *       // Process ETI frame
 *   });
 *   while (!parser.is_complete()) {
 *       parser.process_ip_packet(ip_packet, len);
 *   }
 *   auto ensemble = parser.get_ensemble();
 * @endcode
 */
class DABStreamParser {
public:
    /**
     * @brief Construct parser for specific multicast stream
     * @param target_ip   Multicast IP (host byte order, e.g., 0xEFC70201 for 239.199.2.1)
     * @param target_port UDP port (e.g., 1234)
     */
    DABStreamParser(uint32_t target_ip, uint16_t target_port);
    ~DABStreamParser();

    /// Reset parser state (clears all buffers and counters)
    void reset();

    // Process raw EDI packet (PF or AF) directly
    bool process_edi_packet(const uint8_t* edi_data, size_t len);

    // Process an IPv4 packet (its UDP payload: EDI)
    bool process_ip_packet(const uint8_t* ip_packet, size_t len);

    // Get parsed ensemble info
    const DABEnsemble& get_ensemble() const;

    // Check if service info is complete
    bool is_complete() const;

    // Check if basic service info is ready
    bool is_basic_ready() const;

    // Check if parser has received any useful data
    bool has_data() const;

    // Get EPG subchannel(s) detected from FIG 0/13
    const std::vector<int>& get_epg_subchannels() const { return fic_parser_.get_epg_subchannels(); }

    // Set callback for ETI frames
    void setEtiCallback(EtiFrameCallback cb) { eti_callback_ = std::move(cb); }

    // Set callback for ETI frames, also those from EDI packets with lost
    // fragments: the subchannels whose data came are in them, the others are
    // in invalid_scids (see EtiFrameExCallback)
    void setEtiExCallback(EtiFrameExCallback cb) { eti_ex_callback_ = std::move(cb); }

    // AF packets made of the fragments that came of incomplete ones
    int partial_af_count() const { return partial_af_count_; }

private:
    // The TAG items of the last complete AF packet (offset of the value in the
    // packet, its length) and its length: an incomplete one is read with it
    struct TagPos {
        uint32_t id;
        size_t off;
        size_t len;
    };
    int handle_edi_packet(const uint8_t* pkt, size_t len);
    int handle_af_packet(const uint8_t* pkt, size_t len);
    int handle_pf_packet(const uint8_t* pkt, size_t len);

    bool decode_tagpacket(const uint8_t* pkt, size_t len);
    // the same, recording the TAG items (offsets in the AF packet) into layout
    bool decode_tagpacket(const uint8_t* pkt, size_t len, std::vector<TagPos>* layout);
    bool decode_starptr(const uint8_t* value, size_t len);
    bool decode_deti(const uint8_t* value, size_t len);
    bool decode_estn(const uint8_t* value, size_t len, uint8_t n);

    bool assemble_eti_frame();
    // the same for a frame from an incomplete AF packet: invalid_scids, the
    // subchannels whose data did not come; fic_fresh, whether its FIC came
    bool assemble_eti_frame(bool partial, uint64_t invalid_scids, bool fic_fresh);

    static uint16_t crc16(const uint8_t* data, size_t len);
    bool check_crc(const uint8_t* data, size_t len);

    uint32_t target_ip_;
    uint16_t target_port_;
    uint16_t last_af_seq_ = 0;

    // Statistics counters
    size_t ip_count_ = 0;

    // Debug counters
    int edi_count_ = 0;
    int pf_count_ = 0;
    int af_assembled_count_ = 0;
    int af_process_count_ = 0;
    int tag_count_ = 0;
    int tagpkt_count_ = 0;
    int eti_count_ = 0;
    int crc_check_count_ = 0;

    PF_Reassembler pf_reassembler_;
    EDI_Builder edi_;
    DABParser fic_parser_;

    std::array<uint8_t, ETI_NI_RAW_SIZE> eti_frame_{};
    EtiFrameCallback eti_callback_;
    EtiFrameExCallback eti_ex_callback_;

    std::vector<TagPos> layout_;
    size_t layout_len_ = 0;
    struct StcInfo {
        uint8_t scid = 0;
        uint16_t sad = 0;
        uint8_t tpl = 0;
        size_t size = 0;
    };
    std::array<StcInfo, 64> last_stc_{};
    // The PF sequence number of the AF being decoded (from a PF packet);
    // the last one with a frame counter (DETI), its counter; the last one
    // that went out as a frame
    int32_t cur_pseq_ = -1;
    int32_t last_pseq_ = -1;
    uint16_t last_dflc_ = 0;
    int32_t last_out_pseq_ = -1;
    int partial_af_count_ = 0;

    // an AF packet of PF sequence number pseq that comes after the last one out
    bool pseq_in_order(int32_t pseq) const;
    bool est_complete() const;
    uint64_t est_mask_ = 0;      // est TAGs of the packet being decoded (bit n-1)
    bool est_bad_ = false;       // one of them was not taken
    void handle_partial_af(const PF_Partial& part);
};

} // namespace dvbdab
