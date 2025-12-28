#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <map>
#include <functional>

namespace dvbdab {
namespace ts {

// TS packet size (local to ts namespace to avoid conflicts)
constexpr size_t PACKET_SIZE = 188;

// Reserved PIDs
constexpr uint16_t PID_PAT = 0x0000;
constexpr uint16_t PID_SDT = 0x0011;
constexpr uint16_t PID_EIT = 0x0012;
constexpr uint16_t PID_NULL = 0x1FFF;

// EIT table IDs
constexpr uint8_t TID_EIT_PF_ACTUAL = 0x4E;  // Present/Following actual TS

// Stream types for PMT
constexpr uint8_t STREAM_TYPE_MPEG_AUDIO = 0x03;      // MPEG-1 Layer II (DAB)
constexpr uint8_t STREAM_TYPE_AAC_ADTS = 0x0F;        // AAC ADTS (DAB+)
constexpr uint8_t STREAM_TYPE_AAC_LATM = 0x11;        // AAC LATM (alternative)
constexpr uint8_t STREAM_TYPE_PRIVATE_DATA = 0x06;   // Private data (for EDI passthrough)

// Service info for TS muxing
struct TsService {
    uint16_t sid;              // Service ID
    uint16_t pmt_pid;          // PMT PID for this service
    uint16_t audio_pid;        // Audio elementary stream PID
    std::string name;          // Service name (for SDT)
    std::string provider;      // Provider name (for SDT)
    bool dabplus;              // true = AAC, false = MPEG
    uint8_t subchannel_id;     // DAB subchannel ID
};

// Event info for EIT (Now Playing)
struct TsEvent {
    uint16_t event_id;         // Event ID (auto-incremented on change)
    std::string event_name;    // Event name (e.g., song title)
    std::string event_text;    // Short description (e.g., artist)
    uint8_t running_status;    // 4 = running
};

// TS packet callback
using TsPacketCallback = std::function<void(const uint8_t* packet)>;

// TS Muxer - creates MPEG-TS stream with PAT, PMT, SDT
class TsMuxer {
public:
    TsMuxer();

    // Set output callback for TS packets
    void setOutput(TsPacketCallback callback) { output_ = std::move(callback); }

    // Configure ensemble
    void setEnsemble(uint16_t tsid, const std::string& name, const std::string& provider = "DAB");

    // Add a service
    void addService(const TsService& service);

    // Update service label (for SDT update after labels arrive)
    void updateServiceLabel(uint16_t sid, const std::string& name);

    // Clear all services
    void clearServices();

    // Feed audio frame for a service (by SID)
    // The muxer will packetize into TS packets with PES headers
    void feedAudioFrame(uint16_t sid, const uint8_t* data, size_t len, uint64_t pts);

    // Feed raw subchannel data (MSC data from ETI)
    // For services that need the raw DAB stream
    void feedSubchannelData(uint8_t subchannel_id, const uint8_t* data, size_t len);

    // Generate and output PSI tables (PAT, PMT, SDT)
    // Call periodically (e.g., every 100ms)
    void outputPsi();

    // Generate null packets to maintain bitrate
    void outputNullPacket();

    // Set event info for a service (DLS text -> EIT)
    // event_name: typically "Artist - Title" or DLS text
    // event_text: optional additional text
    void setEventInfo(uint16_t sid, const std::string& event_name, const std::string& event_text = "");

    // Get statistics
    size_t getPacketCount() const { return packet_count_; }

private:
    // Build PSI sections
    void buildPat();
    void buildPmt(const TsService& service);
    void buildSdt();
    void buildEit();

    // Output a complete section as TS packets
    void outputSection(uint16_t pid, uint8_t table_id, const std::vector<uint8_t>& section_data);

    // Output PES packet
    void outputPes(uint16_t pid, uint8_t stream_id, const uint8_t* data, size_t len, uint64_t pts);

    // Write a TS packet
    void writePacket(uint16_t pid, bool pusi, const uint8_t* payload, size_t len);

    // CRC32 for PSI tables
    static uint32_t crc32(const uint8_t* data, size_t len);

    TsPacketCallback output_;

    // Ensemble info
    uint16_t tsid_{1};
    uint16_t onid_{0x1234};  // Original network ID
    std::string ensemble_name_{"DAB Ensemble"};
    std::string provider_name_{"DAB"};

    // Services
    std::vector<TsService> services_;
    std::map<uint16_t, size_t> sid_to_index_;      // SID -> index in services_
    std::map<uint8_t, size_t> subch_to_index_;     // subchannel_id -> index

    // Continuity counters per PID
    std::map<uint16_t, uint8_t> cc_;

    // PSI version numbers
    uint8_t pat_version_{0};
    uint8_t pmt_version_{0};
    uint8_t sdt_version_{0};
    uint8_t eit_version_{0};

    // Event info per service (for EIT)
    std::map<uint16_t, TsEvent> events_;  // SID -> event

    // Statistics
    size_t packet_count_{0};

    // PCR (Program Clock Reference) tracking
    uint64_t pcr_base_{90000};       // PCR base value (90kHz) - start at 1 second offset
    size_t audio_frame_count_{0};    // Count frames to determine PCR insertion

    // Working buffer for section building
    std::vector<uint8_t> section_buf_;

    // PES buffer per service
    std::map<uint16_t, std::vector<uint8_t>> pes_buffers_;
};

} // namespace ts
} // namespace dvbdab
