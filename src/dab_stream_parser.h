#pragma once
/**
 * @file dab_stream_parser.h
 * @brief DAB stream parser - converts TS/MPE/EDI to ETI frames
 *
 * Data flow: TS packets → MPE sections → EDI/AF packets → ETI-NI frames
 *
 * This parser handles the outer encapsulation layers:
 * - TS packet filtering by PID
 * - MPE section accumulation
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
#include "parsers/mpe_section_accumulator.hpp"
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
 * @brief Complete DAB stream parser: TS → MPE → EDI → ETI → FIC/FIG
 *
 * Converts DVB transport stream containing DAB-over-IP (MPE encapsulation)
 * into ETI-NI frames. Internally uses DABParser for FIC/FIG parsing to
 * extract ensemble and service information.
 *
 * Usage:
 * @code
 *   DABStreamParser parser(pid, ip, port);
 *   parser.setEtiCallback([](StreamKey key, const uint8_t* eti, size_t len, uint16_t dflc) {
 *       // Process ETI frame
 *   });
 *   while (!parser.is_complete()) {
 *       parser.process_ts_data(ts_data, len);
 *   }
 *   auto ensemble = parser.get_ensemble();
 * @endcode
 */
class DABStreamParser {
public:
    /**
     * @brief Construct parser for specific multicast stream
     * @param target_pid  TS PID containing MPE sections
     * @param target_ip   Multicast IP (host byte order, e.g., 0xEFC70201 for 239.199.2.1)
     * @param target_port UDP port (e.g., 1234)
     */
    DABStreamParser(uint16_t target_pid, uint32_t target_ip, uint16_t target_port);
    ~DABStreamParser();

    /// Reset parser state (clears all buffers and counters)
    void reset();

    // Process TS packets (does MPE accumulation internally)
    bool process_ts_data(const uint8_t* data, size_t len);

    // Process a complete MPE section (skips MPE accumulation)
    bool process_mpe_section(const uint8_t* section, size_t len);

    // Process raw EDI packet (PF or AF) directly
    bool process_edi_packet(const uint8_t* edi_data, size_t len);

    // Process raw IP packet (for GSE streams)
    bool process_ip_packet(const uint8_t* ip_packet, size_t len);

    // Store ring buffer data for deferred processing
    void set_pending_ring_buffer(std::vector<uint8_t>&& data);

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

private:
    void handle_mpe_section(const uint8_t* section, size_t len);

    int handle_edi_packet(const uint8_t* pkt, size_t len);
    int handle_af_packet(const uint8_t* pkt, size_t len);
    int handle_pf_packet(const uint8_t* pkt, size_t len);

    bool decode_tagpacket(const uint8_t* pkt, size_t len);
    bool decode_starptr(const uint8_t* value, size_t len);
    bool decode_deti(const uint8_t* value, size_t len);
    bool decode_estn(const uint8_t* value, size_t len, uint8_t n);

    bool assemble_eti_frame();

    static uint16_t crc16(const uint8_t* data, size_t len);
    bool check_crc(const uint8_t* data, size_t len);

    uint16_t target_pid_;
    uint32_t target_ip_;
    uint16_t target_port_;
    uint16_t last_af_seq_ = 0;

    // Statistics counters
    size_t total_bytes_ = 0;
    size_t ts_count_ = 0;
    size_t target_pid_count_ = 0;
    size_t non_sync_count_ = 0;
    size_t mpe_count_ = 0;

    // Debug counters
    int mpe_debug_count_ = 0;
    int edi_count_ = 0;
    bool logged_first_mpe_ = false;
    int pf_count_ = 0;
    int af_assembled_count_ = 0;
    int af_process_count_ = 0;
    int tag_count_ = 0;
    int tagpkt_count_ = 0;
    int eti_count_ = 0;
    int crc_check_count_ = 0;

    MPESectionAccumulator mpe_accum_;
    PF_Reassembler pf_reassembler_;
    EDI_Builder edi_;
    DABParser fic_parser_;

    std::array<uint8_t, ETI_NI_RAW_SIZE> eti_frame_{};
    EtiFrameCallback eti_callback_;

    // Deferred ring buffer processing
    std::vector<uint8_t> pending_ring_buffer_;
    bool ring_buffer_pending_ = false;
    bool ring_buffer_processed_ = false;
    std::chrono::steady_clock::time_point ring_buffer_start_time_;
    static constexpr int RING_BUFFER_DELAY_MS = 3000;
};

} // namespace dvbdab
