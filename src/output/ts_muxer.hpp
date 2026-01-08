#pragma once
/**
 * @file ts_muxer.hpp
 * @brief FFmpeg-free MPEG-TS muxer for DAB audio streaming
 *
 * Implements complete MPEG-TS multiplexing with proper PSI/SI tables:
 * - PAT (Program Association Table) - program to PMT PID mapping
 * - PMT (Program Map Table) - elementary stream configuration per service
 * - SDT (Service Description Table) - service names and metadata
 * - TDT (Time and Date Table) - current UTC time
 * - EIT p/f (Event Information Table) - now/next playing info
 * - EIT schedule (table_id 0x50+) - full EPG schedule data
 * - PES audio packets with PCR for stream synchronization
 *
 * References:
 *   ISO/IEC 13818-1 - MPEG-2 Systems (TS packet structure, PES)
 *   ETSI EN 300 468 - DVB SI (PAT, PMT, SDT, EIT, TDT)
 */

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <ctime>
#include "../parsers/spi_parser.hpp"  // For EpgSchedule/EpgProgramme

namespace dvbdab {

/// @name TS Constants (ISO/IEC 13818-1)
/// @{
inline constexpr size_t TS_MUXER_PACKET_SIZE = 188;  ///< TS packet size in bytes
inline constexpr uint16_t PID_PAT = 0x0000;          ///< PAT always on PID 0
inline constexpr uint16_t PID_SDT = 0x0011;          ///< SDT/BAT PID
inline constexpr uint16_t PID_EIT = 0x0012;          ///< EIT PID
inline constexpr uint16_t PID_TDT = 0x0014;          ///< TDT/TOT PID
inline constexpr uint16_t PID_NULL = 0x1FFF;         ///< Null packet PID
/// @}

/// @name Stream Types (ISO/IEC 13818-1 Table 2-36)
/// @{
inline constexpr uint8_t STREAM_TYPE_AAC_ADTS = 0x0F;   ///< DAB+ (ISO/IEC 13818-7 AAC ADTS)
inline constexpr uint8_t STREAM_TYPE_MPEG_AUDIO = 0x03; ///< DAB (ISO/IEC 11172-3 MPEG Layer II)
/// @}

/**
 * @brief Callback for TS packet output
 * @param data Pointer to 188-byte aligned TS packet(s)
 * @param len  Total length in bytes (multiple of 188)
 */
using TsCallback = std::function<void(const uint8_t* data, size_t len)>;

/**
 * @brief Service configuration for TS muxing
 *
 * Defines a single program/service within the transport stream.
 * Each service has its own PMT, audio PID, and metadata.
 */
struct TsService {
    uint16_t sid;           ///< Service ID (program_number in PAT/PMT)
    uint16_t pmt_pid;       ///< PID for this service's PMT
    uint16_t audio_pid;     ///< PID for audio elementary stream
    std::string name;       ///< Service name (SDT service_name descriptor)
    std::string provider;   ///< Provider name (SDT service_provider descriptor)
    bool dabplus;           ///< true=DAB+ (AAC-LC), false=DAB (MPEG Layer II)
    uint8_t subchannel_id;  ///< DAB subchannel ID (for feedAudioFrame lookup)
    int sample_rate{48000}; ///< Audio sample rate in Hz
    int bitrate{0};         ///< Audio bitrate in kbps
};

/**
 * @brief FFmpeg-free MPEG-TS muxer for DAB audio streaming
 *
 * Generates compliant MPEG-TS output with full DVB SI support including
 * PAT, PMT, SDT, TDT, and EIT (both present/following and schedule).
 *
 * @par Usage
 * @code
 *   TsMuxer muxer;
 *   muxer.setOutput([](const uint8_t* data, size_t len) {
 *       write(fd, data, len);
 *   });
 *   muxer.setEnsemble(0x1234, "My Ensemble");
 *   muxer.addService({.sid=1, .pmt_pid=0x100, .audio_pid=0x101, ...});
 *   muxer.feedAudioFrame(1, adts_data, len, pts);
 * @endcode
 *
 * @par Thread Safety
 * Not thread-safe. All methods must be called from the same thread.
 */
class TsMuxer {
public:
    TsMuxer();

    /// @name Configuration
    /// @{

    /// Set output callback for TS packets
    void setOutput(TsCallback callback) { output_ = std::move(callback); }

    /**
     * @brief Set ensemble/network information
     * @param tsid Transport Stream ID (used in PAT, SDT)
     * @param name Ensemble name (used in SDT)
     * @param provider Provider name (used in SDT, default "DAB")
     */
    void setEnsemble(uint16_t tsid, const std::string& name, const std::string& provider = "DAB");

    /**
     * @brief Add a service to the multiplex
     * @param service Service configuration
     */
    void addService(const TsService& service);

    /// @}

    /// @name Legacy Compatibility
    /// @{
    bool initialize() { return true; }  ///< No-op (FFmpeg compatibility)
    void finalize() {}                   ///< No-op (FFmpeg compatibility)
    /// @}

    /// @name Audio Input
    /// @{

    /**
     * @brief Feed audio frame by service ID
     * @param sid  Service ID
     * @param data Audio data (ADTS for DAB+, raw MPEG frames for DAB)
     * @param len  Data length in bytes
     * @param pts  Presentation timestamp in 90kHz units
     */
    void feedAudioFrame(uint16_t sid, const uint8_t* data, size_t len, int64_t pts);

    /**
     * @brief Feed audio frame by subchannel ID (legacy compatibility)
     * @param subchannel_id DAB subchannel ID
     * @param data Audio data
     * @param len  Data length in bytes
     * @param pts  Presentation timestamp in 90kHz units
     */
    void feedAudioFrame(uint8_t subchannel_id, const uint8_t* data, size_t len, int64_t pts);

    /// @}

    /// @name Metadata Updates
    /// @{

    /**
     * @brief Update now-playing info (triggers EIT p/f regeneration)
     * @param sid    Service ID
     * @param title  Current track/programme title
     * @param artist Artist name (optional)
     */
    void setNowPlaying(uint16_t sid, const std::string& title, const std::string& artist = "");

    /// Update now-playing by subchannel ID (legacy compatibility)
    void setNowPlayingBySubch(uint8_t subchannel_id, const std::string& title, const std::string& artist = "");

    /**
     * @brief Update EPG schedule (triggers EIT schedule regeneration)
     * @param service_id Service ID
     * @param schedule   Full schedule with programmes
     */
    void updateSchedule(uint16_t service_id, const EpgSchedule& schedule);

    /**
     * @brief Update service label (triggers SDT regeneration)
     * @param sid  Service ID
     * @param name New service name
     */
    void updateServiceLabel(uint16_t sid, const std::string& name);

    /// Update service label by subchannel ID (legacy compatibility)
    void updateServiceLabelBySubch(uint8_t subchannel_id, const std::string& name);

    /// @}

    /// @name Statistics
    /// @{
    size_t getPacketCount() const { return packet_count_; }  ///< Total TS packets output
    /// @}

private:
    // Build and output PSI tables
    void outputPat();
    void outputPmt(const TsService& service);
    void outputSdt();
    void outputTdt();
    void outputEit(uint16_t sid);
    std::vector<uint8_t> buildEitSection(uint16_t sid, uint8_t section_number,
        uint16_t event_id, time_t start_time, const std::string& event_name, bool is_running);

    // EIT schedule (0x50+) methods
    void outputEitScheduleCarousel();  // Output complete EIT table for all services
    std::vector<uint8_t> buildEitScheduleSection(uint16_t service_id, uint8_t table_id,
        uint8_t section_number, uint8_t last_section_number, uint8_t segment_last_section,
        const std::vector<const EpgProgramme*>& events, size_t event_base);

    // Output a section as TS packets
    // set_discontinuity: set discontinuity_indicator on first packet (for EIT version changes)
    void outputSection(uint16_t pid, const std::vector<uint8_t>& section, bool set_discontinuity = false);

    // Output PES packet with optional PCR
    void outputPes(uint16_t pid, const uint8_t* data, size_t len, int64_t pts, bool insert_pcr, int64_t pcr);

    // Write single TS packet
    void writePacket(const uint8_t* packet);

    // CRC32 for PSI sections
    static uint32_t dvbCrc32(const uint8_t* data, size_t len);

    // Callbacks and state
    TsCallback output_;
    size_t packet_count_{0};

    // Ensemble info
    uint16_t tsid_{0x0001};
    uint16_t onid_{0x1000};
    std::string ensemble_name_{"DAB"};
    std::string provider_name_{"DAB"};

    // Services
    std::vector<TsService> services_;
    std::map<uint16_t, size_t> sid_to_index_;
    std::map<uint8_t, uint16_t> subch_to_sid_;

    // Continuity counters per PID
    std::map<uint16_t, uint8_t> cc_;

    // PSI version numbers
    uint8_t pat_version_{0};
    uint8_t pmt_version_{0};
    uint8_t sdt_version_{0};
    std::map<uint16_t, uint8_t> eit_pf_version_;  // Per-service EIT p/f version

    // Now-playing info per service
    struct NowPlaying {
        std::string title;
        std::string artist;
        uint16_t event_id{1};
    };
    std::map<uint16_t, NowPlaying> now_playing_;

    // PCR tracking per audio PID
    std::map<uint16_t, int64_t> last_pcr_;
    std::map<uint16_t, size_t> frames_since_pcr_;

    // PSI output tracking
    size_t frames_since_psi_{0};

    // EIT schedule storage
    std::map<uint16_t, EpgSchedule> service_schedules_;
    std::map<uint16_t, uint8_t> eit_schedule_version_;
    std::map<uint16_t, bool> schedule_changed_;  // Track if schedule changed since last carousel
    bool eit_carousel_pending_{false};  // True when there are pending changes to apply
    size_t eit_carousel_interval_{500};  // Output EIT every N audio frames (~12 seconds)
    size_t frames_since_eit_{0};
};

} // namespace dvbdab
