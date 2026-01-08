#pragma once
/**
 * @file dab_parser.h
 * @brief DAB FIC/FIG parser - extracts ensemble and service info from ETI frames
 *
 * Data flow: ETI-NI frames → FIC → FIB → FIG → Ensemble/Services
 *
 * Parses Fast Information Channel (FIC) data from ETI frames to extract:
 * - Ensemble information (EId, label)
 * - Service information (SId, labels, audio/data type)
 * - Subchannel configuration (bitrate, protection)
 * - EPG subchannel detection (FIG 0/13)
 *
 * FIG types parsed:
 * - FIG 0/0: Ensemble information
 * - FIG 0/1: Subchannel organization (basic)
 * - FIG 0/2: Service organization
 * - FIG 0/8: Service component linkage
 * - FIG 0/13: User application information (EPG detection)
 * - FIG 1/0: Ensemble label
 * - FIG 1/1: Service label
 *
 * References:
 *   ETSI EN 300 401 - DAB system specification
 *   ETSI EN 300 799 - ETI (Ensemble Transport Interface)
 */

#include <dvbdab/dvbdab.hpp>
#include <map>
#include <chrono>

namespace dvbdab {

/// @name ETI Frame Constants (ETSI EN 300 799)
/// @{
constexpr uint32_t ETI_NI_FSYNC0 = 0xFFF8C549;  ///< Sync word for odd frames
constexpr uint32_t ETI_NI_FSYNC1 = 0xFF073AB6;  ///< Sync word for even frames
constexpr int ETI_NI_RAW_SIZE = 6144;           ///< ETI-NI frame size in bytes
/// @}

/// FC (Frame Characterization) word - see ETSI EN 300 799 Section 6.1
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

/**
 * @brief DAB FIC/FIG Parser - extracts ensemble and service info from ETI frames
 *
 * Processes ETI-NI frames and extracts FIC data to build ensemble information.
 * The parser tracks readiness in two stages:
 * - Basic ready: subchannel and service structure known (can start audio)
 * - Complete: all service labels received (full EPG-ready info)
 *
 * Usage:
 * @code
 *   DABParser parser;
 *   while (!parser.is_complete()) {
 *       parser.process_eti_frame(eti_data, 6144);
 *   }
 *   auto ensemble = parser.get_ensemble();
 *   for (const auto& svc : ensemble.services) {
 *       std::cout << svc.label << " subch=" << svc.subchannel_id << "\n";
 *   }
 * @endcode
 */
class DABParser {
public:
    DABParser();
    ~DABParser();

    /// Reset parser state
    void reset();

    /**
     * @brief Process raw ETI-NI frame data
     * @param frame ETI-NI frame data (must be ETI_NI_RAW_SIZE bytes)
     * @param len   Length of frame data
     * @return true when service info is complete (all labels received)
     */
    bool process_eti_frame(const uint8_t* frame, size_t len);

    /// Get parsed ensemble info (valid after is_basic_ready())
    const DABEnsemble& get_ensemble() const { return ensemble_; }

    /// Check if service info is complete (all labels received)
    bool is_complete() const { return labelled_; }

    /// Check if basic service info is ready (FIG 0/1 + 0/2 parsed, can start audio)
    bool is_basic_ready() const { return basic_ready_; }

    /// Get EPG subchannel(s) detected from FIG 0/13 + FIG 0/8
    const std::vector<int>& get_epg_subchannels() const { return epg_subchannels_; }

private:
    void process_fic(const uint8_t* fic_data, int fic_len, int mode_id);
    void process_fib(const uint8_t* fib);
    void process_fig(const uint8_t* fig, int fig_len);
    void process_fig_0(const uint8_t* data, int len, int ext, int pd);
    void process_fig_1(const uint8_t* data, int len, int ext);

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

    struct ServiceInfo {
        uint32_t sid;
        int primary_subch;
        int secondary_subch;
    };
    std::map<uint32_t, ServiceInfo> service_map_;

    struct PacketModeInfo {
        int subchid;
        int packet_addr;
        int dscty;
        bool dg_flag;
    };
    std::map<int, PacketModeInfo> packet_mode_map_;

    std::vector<int> epg_subchannels_;

    std::map<uint32_t, std::string> service_labels_;
    std::string ensemble_label_;
    uint16_t ensemble_id_;

    std::chrono::steady_clock::time_point start_time_;
    std::map<uint32_t, int64_t> label_first_seen_ms_;
    int64_t ensemble_label_first_seen_ms_ = -1;

    bool labelled_;
    bool basic_ready_;
    DABEnsemble ensemble_;

    size_t last_basic_service_count_;
    size_t basic_stable_frames_;
    size_t last_service_count_;
    size_t stable_frames_;
    size_t last_label_count_;
    size_t label_stable_frames_;

    int eti_call_count_ = 0;
    int fib_count_ = 0;
    int fig_debug_count_ = 0;
    int fig1_count_ = 0;
    int fig02_count_ = 0;
    int fig11_count_ = 0;

    void build_ensemble();
};

} // namespace dvbdab
