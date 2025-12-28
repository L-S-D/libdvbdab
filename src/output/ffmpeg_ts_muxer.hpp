#pragma once

#include <cstdint>
#include <string>
#include <map>
#include <vector>
#include <functional>

extern "C" {
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
}

namespace dvbdab {

// PID base for audio streams: FFmpeg mpegts assigns 0x100 + stream_index
// We can't change this base without patching FFmpeg, so we use a map:
// PID = PID_AUDIO_BASE + subch_to_stream_[subchannel_id]
constexpr uint16_t PID_AUDIO_BASE = 0x100;

// TS output callback
using FfmpegTsCallback = std::function<void(const uint8_t* data, size_t len)>;

// Metadata for a service (from DL Plus)
struct FfmpegMetadata {
    std::string title;     // ITEM_TITLE
    std::string artist;    // ITEM_ARTIST
    std::string album;     // ITEM_ALBUM
    std::string text;      // Full DLS text
};

// Service info for TS muxing
struct FfmpegService {
    uint16_t sid;              // Service ID
    std::string name;          // Service name
    bool dabplus;              // true = HE-AAC, false = MPEG Layer II
    uint8_t subchannel_id;     // DAB subchannel ID
    int sample_rate;           // Sample rate (e.g., 48000 for DAB+)
    int bitrate;               // Bitrate in kbps
};

// FFmpeg-based TS Muxer
class FfmpegTsMuxer {
public:
    FfmpegTsMuxer();
    ~FfmpegTsMuxer();

    // Set output callback
    void setOutput(FfmpegTsCallback callback) { output_ = std::move(callback); }

    // Configure ensemble
    void setEnsemble(uint16_t tsid, const std::string& name);

    // Add a service (returns stream index)
    int addService(const FfmpegService& service);

    // Initialize muxer (call after adding all services)
    bool initialize();

    // Feed audio frame for a service (by subchannel ID)
    // Data should be complete ADTS frame(s)
    void feedAudioFrame(uint8_t subchannel_id, const uint8_t* data, size_t len, int64_t pts);

    // Update metadata for a service (from DL Plus)
    // This will inject timed ID3 metadata into the TS stream
    void updateMetadata(uint8_t subchannel_id, const FfmpegMetadata& metadata);

    // Update service label dynamically (injects new SDT)
    void updateServiceLabel(uint16_t service_id, const std::string& name);

    // Update service label by subchannel ID
    void updateServiceLabelBySubch(uint8_t subchannel_id, const std::string& name);

    // Update ensemble name dynamically (injects new SDT)
    void updateEnsembleName(const std::string& name);

    // Finalize and flush
    void finalize();

    // Get statistics
    size_t getPacketCount() const { return packet_count_; }

    // Dynamic subchannel mapping update (for regional windows)
    // Returns list of new subchannel IDs that need decoders
    std::vector<uint8_t> updateSubchannelMapping(uint16_t service_id, uint8_t new_subchannel_id);

    // Add a new stream for a new subchannel (after initial configuration)
    // Returns stream index, or -1 on failure
    int addNewSubchannel(uint8_t subchannel_id, bool dabplus, int sample_rate, int bitrate);

    // Get stream index for a subchannel (-1 if not found)
    int getStreamIndex(uint8_t subchannel_id) const;

    // Get PID for a subchannel (0 if not found)
    uint16_t getPid(uint8_t subchannel_id) const;

private:
    // Custom AVIO write callback (FFmpeg 6.0+ uses const uint8_t*)
    static int writePacket(void* opaque, const uint8_t* buf, int buf_size);

    // Parse ADTS header to get sample rate
    static int getAdtsSampleRate(const uint8_t* data);

    // Build and inject EIT p/f section
    void injectEit(uint16_t service_id, const std::string& event_name, const std::string& event_text);

    // Build EIT section
    std::vector<uint8_t> buildEitSection(uint16_t service_id, uint8_t section_number,
                                          const std::string& event_name, const std::string& event_text);

    // Calculate DVB CRC32
    static uint32_t dvbCrc32(const uint8_t* data, size_t len);

    // Build and inject PMT section for a program
    void injectPmt(uint16_t program_number, uint16_t pmt_pid, uint16_t pcr_pid,
                   const std::vector<std::pair<uint16_t, uint8_t>>& streams);  // (pid, stream_type)

    // Build PMT section
    std::vector<uint8_t> buildPmtSection(uint16_t program_number, uint16_t pcr_pid,
                                         const std::vector<std::pair<uint16_t, uint8_t>>& streams);

    // Build and inject SDT section
    void injectSdt();

    // Build SDT section
    std::vector<uint8_t> buildSdtSection();

    FfmpegTsCallback output_;
    AVFormatContext* fmt_ctx_{nullptr};
    AVIOContext* avio_ctx_{nullptr};
    uint8_t* avio_buffer_{nullptr};

    uint16_t tsid_{1};
    std::string ensemble_name_{"DAB Ensemble"};

    std::vector<FfmpegService> services_;
    std::map<uint8_t, int> subch_to_stream_;  // subchannel_id -> audio stream index (shared)
    std::map<uint8_t, int> subch_to_meta_stream_;  // subchannel_id -> metadata stream index
    std::map<int, int64_t> stream_pts_;       // stream index -> last PTS
    std::map<uint8_t, FfmpegMetadata> last_metadata_;  // subchannel_id -> last metadata
    std::map<uint16_t, uint8_t> eit_version_;  // service_id -> EIT version
    std::map<uint16_t, std::string> eit_event_name_;  // service_id -> last event name
    std::map<uint16_t, std::string> eit_event_text_;  // service_id -> last event text
    uint8_t eit_cc_{0};  // EIT continuity counter
    size_t eit_repeat_counter_{0};  // Counter for periodic EIT repetition
    std::map<uint16_t, uint8_t> pmt_cc_;  // PMT continuity counter per program
    std::map<uint16_t, uint8_t> sid_to_subch_;  // service_id -> current subchannel_id

    size_t packet_count_{0};
    bool initialized_{false};
    int write_error_count_{0};  // Limit error logging

    // SDT injection state
    std::map<uint16_t, std::string> service_labels_;  // service_id -> current label
    uint8_t sdt_cc_{0};        // SDT continuity counter
    uint8_t sdt_version_{0};   // SDT version number
    uint16_t onid_{0x1000};    // Original network ID
};

} // namespace dvbdab
