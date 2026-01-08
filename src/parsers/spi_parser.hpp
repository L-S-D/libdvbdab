#pragma once
// DAB SPI (Service and Programme Information) Parser
// Parses EPG data from MOT objects containing ETSI TS 102 818 XML
// Used for schedule information (programme guide) in DAB

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <ctime>

namespace dvbdab {

// Forward declaration
struct MOTHeaderInfo;

// Programme information from SPI XML
struct EpgProgramme {
    std::string short_id;           // Unique ID within schedule
    std::string name;               // Programme name (short/medium/long)
    std::string description;        // Programme description
    time_t start_time = 0;          // UTC start time
    time_t end_time = 0;            // UTC end time (0 if duration-based)
    int duration_seconds = 0;       // Duration in seconds

    // Optional metadata
    std::string genre;              // Genre/category
    std::string broadcast_url;      // Link to more info

    // Computed helpers
    time_t getEndTime() const {
        if (end_time > 0) return end_time;
        if (start_time > 0 && duration_seconds > 0) {
            return start_time + duration_seconds;
        }
        return 0;
    }

    bool isValid() const {
        return !name.empty() && start_time > 0;
    }
};

// Service schedule (list of programmes for a service)
struct EpgSchedule {
    uint32_t service_id = 0;        // DAB service ID (SId)
    std::string service_name;       // Service name from SPI
    std::vector<EpgProgramme> programmes;
    time_t last_update = 0;         // When this schedule was last updated
};

// Callback for parsed EPG schedules
// Called when a complete schedule is parsed from SPI XML
using EpgScheduleCallback = std::function<void(const EpgSchedule& schedule)>;

// SPI Parser - processes MOT objects containing EPG XML
class SpiParser {
public:
    SpiParser();

    // Set callback for parsed schedules
    void setScheduleCallback(EpgScheduleCallback cb) { schedule_callback_ = std::move(cb); }

    // Process a complete MOT object
    // content_type 2 (application/xml) with subtype for SPI
    // content_name typically ends in .xml
    void onMotObject(uint16_t transport_id, const MOTHeaderInfo& header,
                     const uint8_t* data, size_t len);

    // Get cached schedules by service ID
    const EpgSchedule* getSchedule(uint32_t service_id) const;

    // Get all cached schedules
    const std::map<uint32_t, EpgSchedule>& getAllSchedules() const { return schedules_; }

    // Statistics
    size_t getXmlCount() const { return xml_count_; }
    size_t getScheduleCount() const { return schedules_.size(); }
    size_t getParseErrors() const { return parse_errors_; }

private:
    // Parse SPI XML document
    bool parseSpiXml(const uint8_t* data, size_t len, const std::string& filename);

    // Parse schedule element from XML
    bool parseSchedule(const void* schedule_node, uint32_t service_id);

    // Parse programme element from XML
    bool parseProgramme(const void* prog_node, EpgProgramme& prog);

    // Parse ISO 8601 datetime
    static time_t parseDateTime(const std::string& dt_str);

    // Parse ISO 8601 duration (PTnHnMnS)
    static int parseDuration(const std::string& dur_str);

    // Extract service ID from scope/serviceScope
    static uint32_t parseServiceId(const std::string& scope_str);

    // Cached schedules by service ID
    std::map<uint32_t, EpgSchedule> schedules_;

    // Callback
    EpgScheduleCallback schedule_callback_;

    // Statistics
    size_t xml_count_ = 0;
    size_t parse_errors_ = 0;
};

} // namespace dvbdab
