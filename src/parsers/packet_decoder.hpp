#pragma once
// DAB Packet Mode Decoder
// Extracts data from packet-mode subchannels (EN 300 401, section 5.3.2)
// Used for EPG, TPEG, Journaline, and other data services

#include <cstdint>
#include <cstddef>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <string>

namespace dvbdab {

// Packet lengths (EN 300 401, Table 31)
constexpr size_t PACKET_LENGTH_24 = 24;
constexpr size_t PACKET_LENGTH_48 = 48;
constexpr size_t PACKET_LENGTH_72 = 72;
constexpr size_t PACKET_LENGTH_96 = 96;

// Data group types (EN 300 401, section 5.3.3)
enum class DataGroupType : uint8_t {
    GENERAL_DATA = 0,
    CA_MESSAGE = 1,
    // Types 2-15 defined by user application
    MOT_HEADER = 3,      // For MOT transport
    MOT_BODY = 4,        // For MOT transport
    MOT_DIRECTORY = 6,   // For MOT directory mode
};

// Parsed packet header
struct PacketHeader {
    uint8_t packet_length;    // 0=24, 1=48, 2=72, 3=96 bytes
    uint8_t continuity_index; // 0-3, increments per packet address
    bool first_last_first;    // First packet of data group
    bool first_last_last;     // Last packet of data group
    uint16_t address;         // 10-bit packet address (identifies data stream)
    bool command;             // 1 = command, 0 = data
    uint8_t useful_data_len;  // Number of useful bytes in packet (0-127)
};

// Data group header
struct DataGroupHeader {
    bool extension_flag;
    bool crc_flag;
    bool segment_flag;
    bool user_access_flag;
    uint8_t type;             // Data group type (4 bits)
    uint8_t continuity_index; // 4 bits
    uint8_t repetition_index; // 4 bits
    // Optional extension field (if extension_flag)
    uint16_t extension;
    // Optional segment info (if segment_flag)
    bool last_segment;
    uint16_t segment_number;
    // Optional user access (if user_access_flag)
    uint8_t transport_id_flag;
    uint8_t length_indicator;
    uint16_t transport_id;
};

// Callback for complete data groups
using DataGroupCallback = std::function<void(uint16_t address, const DataGroupHeader& header,
                                              const uint8_t* data, size_t len)>;

// MOT object header info
struct MOTHeaderInfo {
    uint32_t body_size = 0;
    uint8_t content_type = 0;
    uint16_t content_subtype = 0;
    std::string content_name;
    bool valid = false;
};

// Callback for complete MOT objects
using MotObjectCallback = std::function<void(uint16_t transport_id, const MOTHeaderInfo& header,
                                              const uint8_t* body_data, size_t body_len)>;

// Callback for MOT directory changes (carousel updates)
// added: TIDs newly appearing in directory (new files)
// removed: TIDs no longer in directory (deleted files)
using MotDirectoryCallback = std::function<void(const std::vector<uint16_t>& added,
                                                 const std::vector<uint16_t>& removed)>;

// Packet mode decoder
class PacketDecoder {
public:
    PacketDecoder();

    // Reset state
    void reset();

    // Set callbacks
    void setDataGroupCallback(DataGroupCallback cb) { dg_callback_ = std::move(cb); }
    void setMotCallback(MotObjectCallback cb) { mot_callback_ = std::move(cb); }
    void setDirectoryCallback(MotDirectoryCallback cb) { dir_callback_ = std::move(cb); }

    // Get current directory entries (for muxer to track what EPG files exist)
    const std::map<uint16_t, MOTHeaderInfo>& getDirectoryEntries() const { return mot_directory_entries_; }

    // Feed subchannel data (one frame of packet-mode subchannel)
    void feedSubchannelData(const uint8_t* data, size_t len);

    // Statistics
    size_t getPacketCount() const { return packet_count_; }
    size_t getDataGroupCount() const { return dg_count_; }
    size_t getCrcErrors() const { return crc_errors_; }

private:
    // Parse a single packet
    bool parsePacket(const uint8_t* data, size_t len, PacketHeader& header);

    // Process useful data from packet
    void processPacketData(const PacketHeader& header, const uint8_t* data, size_t len);

    // Assemble data group from packets
    void assembleDataGroup(uint16_t address);

    // Parse data group header
    bool parseDataGroupHeader(const uint8_t* data, size_t len, DataGroupHeader& header, size_t& header_len);

    // Process complete data group
    void processDataGroup(uint16_t address, const uint8_t* data, size_t len);

    // CRC-16 for data groups
    static uint16_t crc16(const uint8_t* data, size_t len);

    // Parse MOT header (data group type 3)
    void parseMotHeader(const uint8_t* data, size_t len);

    // Parse MOT directory (data group type 6)
    void parseMotDirectory(const uint8_t* data, size_t len);

    // Parse MSC data groups directly (for transparent mode DG=1)
    void parseMscDataGroups();

    // Process a validated MOT data group
    void processMotDataGroup(uint8_t dg_type, uint16_t transport_id,
                             uint16_t seg_num, bool is_last,
                             const uint8_t* payload, size_t payload_len);

    // Try to complete a MOT object
    void tryCompleteMotObject(uint16_t transport_id);

    // Parse MOT header core from segment 0
    bool parseMotHeaderCore(const uint8_t* data, size_t len, MOTHeaderInfo& info);

    // Stream buffer for accumulating subchannel data across frames
    std::vector<uint8_t> stream_buffer_;

    // Accumulate MOT segment (directory, header, or body)
    void accumulateMotSegment(uint16_t transport_id, uint8_t dg_type,
                              uint16_t segment_number, bool is_last,
                              const uint8_t* data, size_t len);

    // Check if MOT object is complete and emit it
    void checkMotObjectComplete(uint16_t transport_id);

    // MOT object accumulator per transport ID
    struct MOTObjectAccumulator {
        std::map<uint16_t, std::vector<uint8_t>> header_segments;  // seg_num -> data
        std::map<uint16_t, std::vector<uint8_t>> body_segments;    // seg_num -> data
        int16_t header_last_seg = -1;  // -1 = unknown
        int16_t body_last_seg = -1;    // -1 = unknown
        MOTHeaderInfo header_info;
    };
    std::map<uint16_t, MOTObjectAccumulator> mot_objects_;  // transport_id -> accumulator

    // MOT Directory entries - headers parsed from directory (type 6)
    // In Directory mode, headers come from directory not separate type 3 data groups
    std::map<uint16_t, MOTHeaderInfo> mot_directory_entries_;  // transport_id -> header info

    // Directory segment accumulator (per directory transport ID)
    struct DirectoryAccumulator {
        std::map<uint16_t, std::vector<uint8_t>> segments;  // seg_num -> data
        int16_t last_seg = -1;  // -1 = unknown
    };
    std::map<uint16_t, DirectoryAccumulator> directory_accumulators_;  // directory_tid -> accumulator

    // Data group assembly buffer per address
    struct DataGroupBuffer {
        std::vector<uint8_t> data;
        uint8_t expected_ci;    // Expected continuity index
        bool in_progress;
    };
    std::map<uint16_t, DataGroupBuffer> dg_buffers_;

    // Callbacks
    DataGroupCallback dg_callback_;
    MotObjectCallback mot_callback_;
    MotDirectoryCallback dir_callback_;

    // Track previous directory entries for change detection
    std::set<uint16_t> prev_directory_tids_;

    // Statistics
    size_t packet_count_ = 0;
    size_t dg_count_ = 0;
    size_t crc_errors_ = 0;

    // PRBS state for energy dispersal (maintained across frames)
    uint16_t prbs_state_ = 0x1FF;
};

} // namespace dvbdab
