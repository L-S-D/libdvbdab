#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <array>
#include <deque>
#include <functional>
#include <chrono>

namespace lsdvb {

// DAB Service Information
struct DABService {
    uint32_t sid;           // Service ID
    std::string label;      // Service label (up to 16 chars)
    int bitrate;            // Bitrate in kbps
    int subchannel_id;      // Sub-channel ID
    int start_addr;         // Start address in CUs
    int subchannel_size;    // Size in CUs
    bool dabplus;           // true for DAB+, false for DAB
    int protection_level;   // Protection level
    bool eep_protection;    // EEP (true) or UEP (false)
};

// DAB Ensemble Information
struct DABEnsemble {
    uint16_t eid;           // Ensemble ID
    std::string label;      // Ensemble label
    std::vector<DABService> services;
};

// ETI Frame Constants - sync word includes ERR byte (0xFF) + FSYNC pattern
// Frame bytes: [0xFF, F8/07, C5/3A, 49/B6] -> big-endian 32-bit value
constexpr uint32_t ETI_NI_FSYNC0 = 0xFFF8C549;  // Odd frames: ERR(0xFF) + FSYNC(0xF8C549)
constexpr uint32_t ETI_NI_FSYNC1 = 0xFF073AB6;  // Even frames: ERR(0xFF) + FSYNC(0x073AB6)
constexpr int ETI_NI_RAW_SIZE = 6144;

// TS/MPE Constants
constexpr int TS_PACKET_SIZE = 188;
constexpr int TS_HEADER_SIZE = 4;
constexpr int TS_BODY_SIZE = 184;  // 188 - 4 header bytes
constexpr int PSI_MAX_SIZE = 4096;
constexpr int AF_PACKET_HEADER_LEN = 10;
constexpr int PF_PACKET_HEADER_LEN = 14;
constexpr int NUM_PF_COLLECTORS = 64;  // Keep track of last N Pseq sequences (increased for shared-PSEQ streams)
constexpr size_t MAX_PF_PAYLOAD = 65536;  // Max size of reassembled AF packet

// ETI frame callback - called for each complete 6144-byte ETI-NI frame
// dflc = Data Flow Counter (0-7999) for continuity checking
using EtiFrameCallback = std::function<void(const uint8_t* data, size_t len, uint16_t dflc)>;

// FC (Frame Characterization) word - see ETSI EN 300 799
#pragma pack(push, 1)
struct ETI_FC {
    uint32_t fl  : 11;  // Frame length
    uint32_t mid : 2;   // DAB mode (1-4)
    uint32_t fp  : 3;   // Frame phase
    uint32_t nst : 7;   // Number of streams
    uint32_t ficf: 1;   // FIC flag
    uint32_t fct : 8;   // Frame count
};
#pragma pack(pop)

// Parse FC word from big-endian bytes
inline ETI_FC parse_fc(const uint8_t* p) {
    uint32_t val = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    ETI_FC fc;
    fc.fct  = (val >> 24) & 0xFF;
    fc.ficf = (val >> 23) & 0x01;
    fc.nst  = (val >> 16) & 0x7F;
    fc.fp   = (val >> 13) & 0x07;
    fc.mid  = (val >> 11) & 0x03;
    fc.fl   = val & 0x7FF;
    return fc;
}

// DAB FIC/FIG Parser - parses ETI frames to extract service info
class DABParser {
public:
    DABParser();
    ~DABParser();

    // Reset parser state
    void reset();

    // Process raw ETI-NI frame data (6144 bytes per frame)
    // Returns true when service info is complete
    bool process_eti_frame(const uint8_t* frame, size_t len);

    // Get parsed ensemble info
    const DABEnsemble& get_ensemble() const { return ensemble_; }

    // Check if service info is complete (all labels received)
    bool is_complete() const { return labelled_; }

    // Check if basic service info is ready (FIG 0/1 + 0/2 parsed, can start audio)
    // This allows early audio start before labels are available
    bool is_basic_ready() const { return basic_ready_; }

private:
    // Process FIC data from ETI frame
    void process_fic(const uint8_t* fic_data, int fic_len, int mode_id);

    // Process individual FIB (Fast Information Block)
    void process_fib(const uint8_t* fib);

    // Process FIG (Fast Information Group)
    void process_fig(const uint8_t* fig, int fig_len);

    // FIG type handlers
    void process_fig_0(const uint8_t* data, int len, int ext, int pd);  // Basic info (pd=Programme Data flag)
    void process_fig_1(const uint8_t* data, int len, int ext);  // Labels

    // Sub-channel info storage
    struct SubChannel {
        int subchid;
        int startaddr;
        int subchsz;
        int bitrate;
        int eepprot;
        int protlvl;
        int uep_indx;
        int dabplus;
    };
    std::map<int, SubChannel> subchannels_;

    // Service to sub-channel mapping
    struct ServiceInfo {
        uint32_t sid;
        int primary_subch;
        int secondary_subch;
    };
    std::map<uint32_t, ServiceInfo> service_map_;

    // Packet mode mapping (SCId -> subchannel + packet address)
    struct PacketModeInfo {
        int subchid;
        int packet_addr;
        int dscty;
        bool dg_flag;  // Data Group flag
    };
    std::map<int, PacketModeInfo> packet_mode_map_;  // SCId -> info

    // Labels
    std::map<uint32_t, std::string> service_labels_;
    std::string ensemble_label_;
    uint16_t ensemble_id_;

    // Debug: Track when labels were first seen (milliseconds from parser start)
    std::chrono::steady_clock::time_point start_time_;
    std::map<uint32_t, int64_t> label_first_seen_ms_;  // SID -> first seen time
    int64_t ensemble_label_first_seen_ms_ = -1;

    // State
    bool labelled_;
    bool basic_ready_;  // True when FIG 0/1 + 0/2 parsed (can start audio)
    DABEnsemble ensemble_;

    // Stability tracking for basic ready (3 frames)
    size_t last_basic_service_count_;
    size_t basic_stable_frames_;

    // Stability tracking for completion detection (10 frames)
    size_t last_service_count_;
    size_t stable_frames_;
    size_t last_label_count_;
    size_t label_stable_frames_;

    // Debug counters (per instance to avoid static variable issues)
    int eti_call_count_ = 0;
    int fib_count_ = 0;
    int fig_debug_count_ = 0;
    int fig1_count_ = 0;
    int fig02_count_ = 0;
    int fig11_count_ = 0;

    // Build final ensemble from parsed components
    void build_ensemble();
};

// EDI/AF frame characterization
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
    bool processed = false;
    // Store each fragment separately with its own size
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
    // Takes full PF packet (pkt) and length - extracts payload internally
    // Returns pointer to internal buffer (valid until next call)
    const uint8_t* add_fragment(const PF_Header& hdr, const uint8_t* pkt, size_t len, size_t& af_len);

private:
    std::map<uint16_t, PF_Collector> collectors_;  // Keyed by pseq - no collisions
    std::vector<uint8_t> af_buffer_;

    void cleanup_old_collectors();
};

// MPE/PSI section accumulator with queue for back-to-back sections
// Based on eti-tools fedi2eti.c which correctly handles multiple sections per PUSI packet
class MPESectionAccumulator {
public:
    MPESectionAccumulator();
    void reset();

    // Process a TS packet
    // After calling, use has_section() and get_section()/pop_section() to retrieve all sections
    void process_ts_packet(const uint8_t* ts);

    // Check if there are sections ready
    bool has_section() const { return !completed_sections_.empty(); }

    // Get next section (caller should copy data before calling pop_section)
    const uint8_t* get_section() const {
        return completed_sections_.empty() ? nullptr : completed_sections_.front().data();
    }
    size_t get_section_size() const {
        return completed_sections_.empty() ? 0 : completed_section_sizes_.front();
    }

    // Remove the current section from queue
    void pop_section() {
        if (!completed_sections_.empty()) {
            completed_sections_.pop_front();
            completed_section_sizes_.pop_front();
        }
    }

private:
    uint8_t cc_ = 0;

    // Working buffer for section being accumulated
    std::array<uint8_t, PSI_MAX_SIZE> buffer_{};
    uint16_t buffer_size_ = 0;   // Expected total size of current section
    uint16_t buffer_skip_ = 0;   // Bytes accumulated so far

    // Queue of completed sections (to handle multiple sections per PUSI packet)
    std::deque<std::array<uint8_t, PSI_MAX_SIZE>> completed_sections_;
    std::deque<uint16_t> completed_section_sizes_;

    // Add completed section to queue
    void emit_section();
};

// Complete DAB stream parser: TS → MPE → EDI → ETI → FIC/FIG
class DABStreamParser {
public:
    DABStreamParser(uint16_t target_pid, uint32_t target_ip, uint16_t target_port);
    ~DABStreamParser();

    // Reset parser state
    void reset();

    // Process TS packets from DVR (old method - does MPE accumulation internally)
    // Returns true when service info is complete
    bool process_ts_data(const uint8_t* data, size_t len);

    // Process a complete MPE section (new method - skips MPE accumulation)
    // Use this when a shared MPE accumulator dispatches sections by IP
    // Returns true when service info is complete
    bool process_mpe_section(const uint8_t* section, size_t len);

    // Process raw EDI packet (PF or AF) directly - for GSE streams where
    // IP/UDP is already extracted and we just have the EDI payload
    // Returns true when service info is complete
    bool process_edi_packet(const uint8_t* edi_data, size_t len);

    // Process raw IP packet - for GSE streams where IP is already extracted
    // Skips MPE layer, directly parses UDP and feeds to EDI handler
    // Returns true when service info is complete
    bool process_ip_packet(const uint8_t* ip_packet, size_t len);

    // Store ring buffer data for deferred processing
    // Will be processed after one complete PSEQ cycle is detected in live data
    void set_pending_ring_buffer(std::vector<uint8_t>&& data);

    // Get parsed ensemble info
    const DABEnsemble& get_ensemble() const;

    // Check if service info is complete (all labels received)
    bool is_complete() const;

    // Check if basic service info is ready (can start audio before labels)
    bool is_basic_ready() const;

    // Check if parser has received any useful data (ETI frames)
    bool has_data() const;

    // Set callback for ETI frames (called for each 6144-byte frame)
    void setEtiCallback(EtiFrameCallback cb) { eti_callback_ = std::move(cb); }

private:
    // MPE section callback
    void handle_mpe_section(const uint8_t* section, size_t len);

    // EDI packet processing
    int handle_edi_packet(const uint8_t* pkt, size_t len);
    int handle_af_packet(const uint8_t* pkt, size_t len);
    int handle_pf_packet(const uint8_t* pkt, size_t len);

    // Tag processing
    bool decode_tagpacket(const uint8_t* pkt, size_t len);
    bool decode_starptr(const uint8_t* value, size_t len);
    bool decode_deti(const uint8_t* value, size_t len);
    bool decode_estn(const uint8_t* value, size_t len, uint8_t n);

    // ETI frame assembly
    bool assemble_eti_frame();

    // CRC-16 CCITT
    static uint16_t crc16(const uint8_t* data, size_t len);
    bool check_crc(const uint8_t* data, size_t len);  // Non-static to use instance counter

    uint16_t target_pid_;
    uint32_t target_ip_;
    uint16_t target_port_;
    uint16_t last_af_seq_ = 0;

    // Statistics counters (per instance, not static)
    size_t total_bytes_ = 0;
    size_t ts_count_ = 0;
    size_t target_pid_count_ = 0;
    size_t non_sync_count_ = 0;
    size_t mpe_count_ = 0;

    // Debug counters (per instance to avoid static variable issues)
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

    // Deferred ring buffer processing - waits for enough live data to ensure complete PF sequences
    std::vector<uint8_t> pending_ring_buffer_;
    bool ring_buffer_pending_ = false;
    bool ring_buffer_processed_ = false;
    std::chrono::steady_clock::time_point ring_buffer_start_time_;
    static constexpr int RING_BUFFER_DELAY_MS = 3000;  // Wait 3s of live data before processing buffer
};

} // namespace lsdvb
