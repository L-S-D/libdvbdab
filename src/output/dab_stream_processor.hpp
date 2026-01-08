#pragma once
// DabStreamProcessor - THE unified ETI frame processor
// Used by BOTH test programs AND streaming - SAME CODE PATH

#include "ts_muxer.hpp"
#include "dabplus_decoder.hpp"
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

    // Start decoding a service
    void startService(uint8_t subchannel_id);

    // Stop decoding a service
    void stopService(uint8_t subchannel_id);

    // Start all configured services
    void startAllServices();

    // Feed an ETI-NI frame - THE main entry point
    // Handles audio decoding, EPG extraction, and TS output
    void feedEtiFrame(const uint8_t* eti_ni, size_t len);

    // Flush any buffered early schedules to muxer
    void flushEarlySchedules();

    // Update service label
    void updateServiceLabel(uint16_t sid, const std::string& name);

    // Get muxer for direct access if needed
    TsMuxer& getMuxer() { return muxer_; }
    const TsMuxer& getMuxer() const { return muxer_; }

    // Set schedule callback for external tracking (e.g., gap detection)
    void setScheduleCallback(std::function<void(const ServiceSchedule&)> callback) {
        external_schedule_callback_ = std::move(callback);
    }

    // Statistics
    size_t getEtiFrameCount() const { return eti_frame_count_; }
    size_t getAudioFrameCount() const { return audio_frame_count_; }
    size_t getEpgScheduleCount() const { return epg_schedule_count_; }
    size_t getTsPacketCount() const { return muxer_.getPacketCount(); }
    size_t getDataSubchannelCount() const { return data_subchannels_.size(); }

private:
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
    std::set<uint8_t> data_subchannels_;
    std::set<uint16_t> processed_tids_;
    EhbParser ehb_parser_;

    // Buffer for early EPG schedules (before muxer configured) - SAME as test_custom_muxer
    std::map<uint16_t, EpgSchedule> early_schedules_;

    // Service info
    std::vector<TsService> services_;
    std::map<uint8_t, uint16_t> subch_to_sid_;
    std::map<uint16_t, int64_t> pts_counter_;

    // External schedule callback
    std::function<void(const ServiceSchedule&)> external_schedule_callback_;

    // Statistics
    size_t eti_frame_count_{0};
    size_t audio_frame_count_{0};
    size_t epg_schedule_count_{0};
};

} // namespace dvbdab
