#pragma once
// EHB (EPG/Schedule) Parser
// Parses DAB EPG Binary format (ETSI TS 102 371) broadcast via MOT carousel
// EHB = EPG binary file containing scheduleInfo element
//
// Based on working Python implementation from eti-na-parser project.

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <ctime>

namespace dvbdab {

// EPG event structure
struct EpgEvent {
    std::string title;
    std::string description;
    time_t start_time = 0;
    uint32_t duration_seconds = 0;  // Duration in seconds
    uint32_t event_id = 0;          // Event ID (can be 3 bytes)
};

// Schedule for a single service
struct ServiceSchedule {
    uint16_t service_id = 0;      // DAB service component ID (e.g., 0xdf95)
    std::string service_name;
    std::vector<EpgEvent> events;
    time_t base_date = 0;         // Base date from filename
};

// Callback for parsed schedules
using EhbScheduleCallback = std::function<void(const ServiceSchedule& schedule)>;

class EhbParser {
public:
    EhbParser();

    // Parse an EHB file (ETSI TS 102 371 binary format)
    // filename: e.g., "w20251220ddf95c0.EHB"
    // data: raw EHB file content
    // len: file length
    bool parse(const std::string& filename, const uint8_t* data, size_t len);

    // Set callback for parsed schedules
    void setScheduleCallback(EhbScheduleCallback cb) { schedule_callback_ = std::move(cb); }

    // Get last parsed schedule
    const ServiceSchedule& getLastSchedule() const { return last_schedule_; }

private:
    // Parse filename to extract date and service ID
    bool parseFilename(const std::string& filename, time_t& base_date, uint16_t& service_id);

    // Parse string/token table from EHB data
    bool parseStringTable(const uint8_t* data, size_t len, size_t& end_offset);

    // Decode string with inline token expansion
    // Token bytes: 0x01-0x08, 0x0b, 0x0c, 0x0e-0x13 (NOT 0x09 tab, 0x0a newline, 0x0d CR)
    std::string decodeTokenString(const uint8_t* data, size_t len);

    // Expand tokens in a string
    std::string expandTokens(const std::string& text);

    // Parse standard ETSI TS 102 371 TLV format
    bool parseEtsiFormat(const std::string& filename, const uint8_t* data, size_t len);

    // Parse schedule element (tag 0x21)
    void parseScheduleElement(const uint8_t* data, size_t len);

    // Parse programme element (tag 0x1C)
    void parseProgrammeElement(const uint8_t* data, size_t len);

    // Parse mediaDescription element (tag 0x13)
    void parseMediaDescription(const uint8_t* data, size_t len, EpgEvent& event);

    // Parse location element (tag 0x19)
    void parseLocationElement(const uint8_t* data, size_t len, EpgEvent& event);

    // Parse time element (tag 0x2C)
    void parseTimeElement(const uint8_t* data, size_t len, EpgEvent& event);

    // Parse time point per ETSI TS 102 371 section 4.7.4
    // Handles MJD date encoding and LTO (Local Time Offset)
    void parseTimePoint(const uint8_t* data, size_t len, time_t& result);

    // Parse string element with optional xml:lang attribute
    std::string parseStringElement(const uint8_t* data, size_t len);

    // String table (index -> string)
    std::map<uint8_t, std::string> string_table_;

    // Last parsed schedule
    ServiceSchedule last_schedule_;

    // Callback
    EhbScheduleCallback schedule_callback_;
};

} // namespace dvbdab
