#pragma once

#include "ffmpeg_ts_muxer.hpp"
#include "dabplus_decoder.hpp"
#include "dab_mp2_decoder.hpp"
#include "../dab_parser.h"
#include <memory>
#include <map>
#include <functional>

namespace dvbdab {

// Callback for streaming output
using TsOutputCallback = std::function<void(const uint8_t* packet, size_t len)>;

// Callback for DLS text updates (SID, text)
using DLSTextCallback = std::function<void(uint16_t sid, const std::string& text)>;

// TS Packetizer - bridges ensemble discovery with TS output
// Takes discovered DAB ensemble and produces MPEG-TS stream
// Uses FFmpeg for proper TS muxing with working audio
class TsPacketizer {
public:
    TsPacketizer();
    ~TsPacketizer();

    // Set output callback for TS packets
    void setOutput(TsOutputCallback callback);

    // Set callback for DLS text updates
    void setDLSCallback(DLSTextCallback callback) { dls_callback_ = std::move(callback); }

    // Configure from discovered ensemble (uses lsdvb types from dab_parser.h)
    void configureFromEnsemble(const lsdvb::DABEnsemble& ensemble);

    // Feed an ETI frame (6144 bytes) - extracts audio and outputs TS
    void feedEtiFrame(const uint8_t* data, size_t len);

    // Finalize muxer (call when done)
    void finalize();

    // Update service label dynamically (injects new SDT)
    void updateServiceLabel(uint16_t service_id, const std::string& name);

    // Update ensemble name dynamically (injects new SDT)
    void updateEnsembleName(const std::string& name);

    // Get statistics
    size_t getPacketCount() const { return muxer_ ? muxer_->getPacketCount() : 0; }

private:
    // Extract audio access unit from subchannel data
    void processSubchannel(const lsdvb::DABService& service, const uint8_t* data, size_t len);

    std::unique_ptr<FfmpegTsMuxer> muxer_;
    TsOutputCallback output_;
    DLSTextCallback dls_callback_;

    // Service mapping: SID -> service info
    std::map<uint16_t, lsdvb::DABService> services_;

    // Subchannel mapping: subchannel_id -> SID
    std::map<uint8_t, uint16_t> subch_to_sid_;

    // PTS tracking per service (90kHz clock)
    std::map<uint16_t, int64_t> pts_counter_;

    // Frame counter
    uint32_t frame_counter_{0};

    // DAB+ decoders per subchannel
    std::map<uint8_t, std::unique_ptr<DabPlusDecoder>> decoders_;

    // DAB/MP2 decoders per subchannel
    std::map<uint8_t, std::unique_ptr<DabMp2Decoder>> mp2_decoders_;

    // Configured and initialized
    bool configured_{false};
};

} // namespace dvbdab
