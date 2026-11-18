#pragma once
// DabStreamProcessor - THE unified ETI frame processor
// Used by BOTH test programs AND streaming - SAME CODE PATH

#include "ts_muxer.hpp"
#include "dabplus_decoder.hpp"
#include "aac_transcoder.hpp"
#include "dab_mp2_decoder.hpp"
#include "../parsers/packet_decoder.hpp"
#include "../parsers/ehb_parser.hpp"
#include <dvbdab/dvbdab.hpp>
#include <map>
#include <set>
#include <memory>
#include <functional>

namespace dvbdab {

class DabStreamProcessor {
public:
    DabStreamProcessor();

    // Set TS output callback
    void setOutput(TsCallback callback) { muxer_.setOutput(std::move(callback)); }

    // Configure ensemble
    void setEnsemble(uint16_t eid, const std::string& name, const std::string& provider = "DAB");

    // Add a service
    void addService(const TsService& service);

    // Remove a service (it left the ensemble, or comes again as another one)
    void removeService(uint16_t sid);

    // The services as they were added
    const std::vector<TsService>& getServices() const { return services_; }

    // Whether the service of this subchannel is started
    bool isStarted(uint8_t subchannel_id) const;

    // True if the service / sub-channel was added
    bool hasService(uint16_t sid) const { return muxer_.hasService(sid); }
    bool hasSubchannel(uint8_t subchannel_id) const { return subch_to_sid_.count(subchannel_id) != 0; }

    // Start decoding a service
    void startService(uint8_t subchannel_id);

    // Stop decoding a service
    void stopService(uint8_t subchannel_id);

    // Start all configured services
    void startAllServices();

    // What becomes of DAB+ audio (DVBDAB_AAC_ADTS 0, _LATM 1, _TRANSCODE 2 of
    // dvbdab_c.h; transcoding only if built with it, else ADTS); before the
    // services are added
    void setAacOutput(int mode);

    // The output PIDs the user takes (count < 0: all, the default). With
    // transcoding, the DAB+ audio of a service is decoded and encoded again
    // only while its PMT or audio PID is among them; else it is not put out.
    void setWantedPids(const uint16_t* pids, int count);

    // Feed an ETI-NI frame - THE main entry point
    // Handles audio decoding, EPG extraction, and TS output
    void feedEtiFrame(const uint8_t* eti_ni, size_t len);

    // The same; the subchannels with their bit set in invalid_scids (SCID
    // 0..63) did not come in this frame (from an incomplete EDI packet): for
    // them it is a lost frame. The frame counter (FCT) of the ETI header
    // tells lost frames too: the audio keeps its time line, gaps stay gaps.
    void feedEtiFrame(const uint8_t* eti_ni, size_t len, uint64_t invalid_scids);

    // Flush any buffered early schedules to muxer
    void flushEarlySchedules();

    // Update service label
    void updateServiceLabel(uint16_t sid, const std::string& name);
    void updateServiceInfo(uint16_t sid, const std::string& language, uint8_t content);
    /// The time of the ensemble as of the frame that is fed next (UTC, ms since 1970)
    void setUtc(int64_t utc_ms) { muxer_.setUtc(utc_ms); }

    // Get muxer for direct access if needed
    TsMuxer& getMuxer() { return muxer_; }
    const TsMuxer& getMuxer() const { return muxer_; }

    // Set schedule callback for external tracking (e.g., gap detection)
    void setScheduleCallback(std::function<void(const ServiceSchedule&)> callback) {
        external_schedule_callback_ = std::move(callback);
    }

    // Statistics
    size_t getEtiFrameCount() const { return eti_frame_count_; }
    size_t getEtiFramesLost() const { return eti_frames_lost_; }   ///< frames missing by the frame counter

    /// What became of the frames of one service
    struct ServiceStats {
        bool dabplus{false};
        bool started{false};
        bool transcoding{false};      ///< its transcoder runs
        int output{0};                ///< 0 MP2, 1 AAC in ADTS, 2 AAC in LATM, 3 AAC-LC transcoded
        uint64_t frames{0};           ///< frames of its subchannel that came
        uint64_t audio_units{0};      ///< DAB+ AUs or MP2 frames taken out of them
        uint64_t audio_units_lost{0}; ///< DAB+: AUs of lost frames and of superframes without their header
        uint64_t crc_errors{0};       ///< DAB+: AUs dropped by their CRC
        uint64_t sync_losses{0};      ///< DAB+: superframe sync lost; DAB: frames without an MP2 header
        uint64_t transcode_errors{0}; ///< AUs the decoder of the transcoder refused
        uint64_t silent_units{0};     ///< AUs the transcoder put out as silence
        uint64_t labels{0};           ///< dynamic labels that came whole
        uint64_t pad_crc_errors{0};   ///< PAD data groups dropped by their CRC
    };
    /// false when no service has this subchannel
    bool getServiceStats(uint8_t subchannel_id, ServiceStats& stats) const;
    size_t getAudioFrameCount() const { return audio_frame_count_; }
    size_t getEpgScheduleCount() const { return epg_schedule_count_; }
    size_t getTsPacketCount() const { return muxer_.getPacketCount(); }
    size_t getDataSubchannelCount() const { return data_subchannels_.size(); }

private:
    // the dynamic label and DL Plus tags of a service (DAB+ or DAB)
    void onLabel(uint8_t subchannel_id, const std::string& text);
    void onDLPlus(uint8_t subchannel_id, const std::string& text, const std::vector<DLPlusTag>& tags);

    // Called when EHB parser produces a schedule
    void onScheduleParsed(const ServiceSchedule& schedule);

    // Convert ServiceSchedule to EpgSchedule
    static EpgSchedule convertSchedule(const ServiceSchedule& schedule);

    // TS muxer
    TsMuxer muxer_;
    bool muxer_configured_{false};

    // Audio decoders by subchannel_id
    std::map<uint8_t, std::unique_ptr<DabPlusDecoder>> dabplus_decoders_;
    std::map<uint8_t, std::unique_ptr<DabMp2Decoder>> mp2_decoders_;

    // EPG: PacketDecoders for data subchannels (SAME as test_custom_muxer)
    std::map<uint8_t, std::unique_ptr<PacketDecoder>> epg_decoders_;
    static constexpr size_t MAX_DATA_SUBCHANNELS = 8;
    std::set<uint8_t> data_subchannels_;
    std::map<uint16_t, uint32_t> processed_files_;  // MOT transport id -> hash of the EHB file parsed
    EhbParser ehb_parser_;

    // Buffer for early EPG schedules (before muxer configured) - SAME as test_custom_muxer
    std::map<uint16_t, EpgSchedule> early_schedules_;

    // Service info
    std::vector<TsService> services_;
    std::map<uint8_t, uint16_t> subch_to_sid_;

    // Frame numbers from the FCT of the ETI frames (24 ms each), the last
    // frame number each MP2 subchannel got
    int aac_output_{0};
    std::map<uint8_t, std::unique_ptr<AacTranscoder>> transcoders_;
    std::map<uint8_t, std::string> last_dls_, last_dlplus_;  // per subchannel, for the log
    bool wanted_all_{true};
    std::set<uint16_t> wanted_pids_;
    bool isWanted(const TsService& svc) const;
    void makeTranscoder(const TsService& svc);
    int last_fct_{-1};
    int64_t frame_no_{0};
    std::map<uint8_t, int64_t> mp2_last_frame_;

    // External schedule callback
    std::function<void(const ServiceSchedule&)> external_schedule_callback_;

    // Statistics
    size_t eti_frame_count_{0};
    size_t eti_frames_lost_{0};
    size_t audio_frame_count_{0};
    size_t epg_schedule_count_{0};
};

} // namespace dvbdab
