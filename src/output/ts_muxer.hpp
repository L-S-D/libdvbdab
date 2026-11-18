#pragma once
/**
 * @file ts_muxer.hpp
 * @brief FFmpeg-free MPEG-TS muxer for DAB audio streaming
 *
 * Implements complete MPEG-TS multiplexing with proper PSI/SI tables:
 * - PAT (Program Association Table) - program to PMT PID mapping
 * - PMT (Program Map Table) - elementary stream configuration per service
 * - SDT (Service Description Table) - service names and metadata
 * - EIT p/f (Event Information Table) - now/next playing info
 * - EIT schedule (table_id 0x50+) - full EPG schedule data
 * - PES audio packets with PCR for stream synchronization
 *
 * References:
 *   ISO/IEC 13818-1 - MPEG-2 Systems (TS packet structure, PES)
 *   ETSI EN 300 468 - DVB SI (PAT, PMT, SDT, EIT)
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
inline constexpr uint16_t PID_NULL = 0x1FFF;         ///< Null packet PID
/// @}

/// @name Stream Types (ISO/IEC 13818-1 Table 2-36)
/// @{
inline constexpr uint8_t STREAM_TYPE_AAC_ADTS = 0x0F;   ///< DAB+ (ISO/IEC 13818-7 AAC ADTS)
inline constexpr uint8_t STREAM_TYPE_AAC_LATM = 0x11;   ///< DAB+ (ISO/IEC 14496-3 LATM in LOAS)
inline constexpr uint8_t STREAM_TYPE_MPEG_AUDIO = 0x04; ///< DAB (ISO/IEC 13818-3 MPEG-2 Layer II)
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
    uint16_t rds_pid{0};    ///< PID for its dynamic label as RDS RadioText (UECP), 0 = none
    std::string name;       ///< Service name (SDT service_name descriptor)
    std::string provider;   ///< Provider name (SDT service_provider descriptor)
    bool dabplus;           ///< true=DAB+ (AAC-LC), false=DAB (MPEG Layer II)
    bool latm{false};       ///< DAB+ as LATM/LOAS (else ADTS)
    uint8_t subchannel_id;  ///< DAB subchannel ID (for feedAudioFrame lookup)
    int sample_rate{48000}; ///< Audio sample rate in Hz
    int bitrate{0};         ///< Audio bitrate in kbps
};

/**
 * @brief FFmpeg-free MPEG-TS muxer for DAB audio streaming
 *
 * Generates compliant MPEG-TS output with full DVB SI support including
 * PAT, PMT, SDT, and EIT (both present/following and schedule).
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

    /**
     * @brief Remove a service (it left the ensemble): the PAT and SDT get a
     *        new version without it
     */
    void removeService(uint16_t sid);

    /// True if a service with this ID is part of the multiplex
    bool hasService(uint16_t sid) const { return sid_to_index_.count(sid) != 0; }

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
     * @brief Drop the frames of a service that wait for their PES (its audio
     *        stops: what comes when it starts again is of another time)
     */
    void dropAudio(uint16_t sid);

    /**
     * @brief Feed audio frame by subchannel ID (legacy compatibility)
     * @param subchannel_id DAB subchannel ID
     * @param data Audio data
     * @param len  Data length in bytes
     * @param pts  Presentation timestamp in 90kHz units
     */
    void feedAudioFrame(uint8_t subchannel_id, const uint8_t* data, size_t len, int64_t pts);

    /**
     * @brief The time line of the output reached pts, with no audio frame
     *        put out (one not wanted): PAT, PMT, SDT and EIT go out on time
     * @param pts Presentation timestamp in 90kHz units (real time)
     */
    void tick(int64_t pts);

    /// @}

    /// @name Metadata Updates
    /// @{

    /**
     * @brief The dynamic label of a service, put out as RDS RadioText on its
     *        rds_pid (on a change and then every few seconds); "" = none
     * @param sid  Service ID
     * @param text The label (UTF-8)
     */
    void setRadioText(uint16_t sid, const std::string& text);

    /// The same as RadioText "artist - title" (or the title alone)
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

    // EIT schedule (0x50+) methods
    void outputEitScheduleCarousel();  // Output complete EIT table for all services
    std::vector<uint8_t> buildEitScheduleSection(uint16_t service_id, uint8_t table_id,
        uint8_t section_number, uint8_t last_section_number, uint8_t segment_last_section,
        const std::vector<const EpgProgramme*>& events, size_t event_base);

    // Output a section as TS packets
    // set_discontinuity: set discontinuity_indicator on first packet (for EIT version changes)
    void outputSection(uint16_t pid, const std::vector<uint8_t>& section, bool set_discontinuity = false);

    // Output PES packet with optional PCR (stream_id 0xC0: audio, 0xBD: private stream 1)
    void outputPes(uint16_t pid, const uint8_t* data, size_t len, int64_t pts, bool insert_pcr, int64_t pcr,
                   uint8_t stream_id = 0xC0);

    // The RadioText of the services that have one: due ones out at pts
    void outputRadioTexts(int64_t pts);

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

    // RadioText per service: the UECP frame of its text, when it went out last
    struct RadioText {
        std::string text;            // in the RDS character set
        bool ab{false};              // A/B flag, changes with the text
        std::vector<uint8_t> frame;
        int64_t sent_pts{-1};        // -1 = due
    };
    std::map<uint16_t, RadioText> radio_text_;
    static constexpr int64_t RADIO_TEXT_REPEAT_PTS = 3 * 90000;  // again after 3 s

    // PCR tracking - use global timeline for multi-program sync

    // Audio frame buffering for PES aggregation (reduces overhead, improves playback)
    struct AudioBuffer {
        std::vector<uint8_t> data;
        int64_t first_pts{0};
        int64_t last_pts{-1};   // of the last frame fed (also after a flush), -1 = none
        size_t frame_count{0};
    };
    std::map<uint16_t, int64_t> frame_step_;      // per service: PTS from one frame to the next
    std::map<uint16_t, int64_t> last_audio_pts_;  // per service: PTS of the last frame put out
    static constexpr int64_t PES_TARGET_PTS = 5400;   // a PES of 60 ms at least (and a PCR within 100 ms)
    static constexpr int64_t PCR_LEAD_PTS = 36000;    // the PCR is 400 ms before the PTS
    std::map<uint16_t, AudioBuffer> audio_buffers_;
    static constexpr size_t PES_TARGET_SIZE = 1400;  // Target ~1400 bytes per PES (FFmpeg uses ~1355)

    void flushAudioBuffer(uint16_t sid);

    // Time-based PSI output (PAT/PMT every 230ms, SDT every ~667ms)
    int64_t last_psi_pts_{-1};  // Last PTS when PSI was output (-1 = not yet)
    static constexpr int64_t PSI_INTERVAL_PTS = 20700;  // 230ms in 90kHz PTS units
    static constexpr int64_t SDT_INTERVAL_PTS = 60000;  // ~667ms in 90kHz PTS units
    int64_t last_sdt_pts_{-1};

    // EIT schedule storage
    std::map<uint16_t, EpgSchedule> service_schedules_;
    std::map<uint16_t, uint8_t> eit_schedule_version_;
    std::map<uint16_t, bool> schedule_changed_;  // Track if schedule changed since last carousel
    bool eit_carousel_pending_{false};  // True when there are pending changes to apply
    static constexpr int64_t EIT_INTERVAL_PTS = 10 * 90000;  // the whole schedule every 10 s
    int64_t last_eit_pts_{-1};
    static constexpr size_t MAX_SCHEDULES = 256;         // services with a schedule
    static constexpr size_t MAX_PROGRAMMES = 1024;       // of one service
    static constexpr time_t SCHEDULE_PAST_SECONDS = 6 * 3600;  // kept after its end
};

} // namespace dvbdab
