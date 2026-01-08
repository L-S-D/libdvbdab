// DAB SPI (Service and Programme Information) Parser
// Parses EPG data from MOT objects containing ETSI TS 102 818 XML

#include "spi_parser.hpp"
#include "packet_decoder.hpp"
#include <pugixml.hpp>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>

// Debug output
// #define SPI_DEBUG

namespace dvbdab {

SpiParser::SpiParser() = default;

void SpiParser::onMotObject(uint16_t transport_id, const MOTHeaderInfo& header,
                             const uint8_t* data, size_t len) {
    // Check if this is an XML file (SPI uses content type 2 = general data)
    // The content_name should indicate XML
    bool is_xml = false;

    // Check by extension
    if (header.content_name.size() >= 4) {
        std::string ext = header.content_name.substr(header.content_name.size() - 4);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (ext == ".xml") {
            is_xml = true;
        }
    }

    // Also check by content - XML starts with <?xml or <
    if (!is_xml && len > 5) {
        if (memcmp(data, "<?xml", 5) == 0 || data[0] == '<') {
            is_xml = true;
        }
    }

    // Check for gzip-compressed XML (1f 8b magic)
    // Note: Would need zlib decompression - skip for now
    if (!is_xml && len > 2 && data[0] == 0x1f && data[1] == 0x8b) {
#ifdef SPI_DEBUG
        fprintf(stderr, "[SPI] Skipping gzip-compressed XML: %s\n", header.content_name.c_str());
#endif
        return;
    }

    if (!is_xml) {
#ifdef SPI_DEBUG
        fprintf(stderr, "[SPI] Ignoring non-XML MOT object: %s (type=%d)\n",
                header.content_name.c_str(), header.content_type);
#endif
        return;
    }

#ifdef SPI_DEBUG
    fprintf(stderr, "[SPI] Processing XML: %s (%zu bytes)\n",
            header.content_name.c_str(), len);
#endif

    xml_count_++;
    parseSpiXml(data, len, header.content_name);
}

bool SpiParser::parseSpiXml(const uint8_t* data, size_t len, const std::string& filename) {
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_buffer(data, len);

    if (!result) {
#ifdef SPI_DEBUG
        fprintf(stderr, "[SPI] XML parse error: %s at offset %zu\n",
                result.description(), result.offset);
#endif
        parse_errors_++;
        return false;
    }

    // ETSI TS 102 818 uses various root elements:
    // - serviceInformation (SI) - service metadata
    // - epg - EPG schedule data
    // - groupInformation - group metadata

    pugi::xml_node root = doc.first_child();
    std::string root_name = root.name();

#ifdef SPI_DEBUG
    fprintf(stderr, "[SPI] Root element: %s\n", root_name.c_str());
#endif

    // Handle <epg> element (main EPG container)
    if (root_name == "epg") {
        // Look for schedule elements
        for (pugi::xml_node schedule = root.child("schedule"); schedule;
             schedule = schedule.next_sibling("schedule")) {
            // Get service scope
            pugi::xml_node scope = schedule.child("scope");
            if (!scope) continue;

            pugi::xml_node service_scope = scope.child("serviceScope");
            if (!service_scope) continue;

            std::string sid_str = service_scope.attribute("id").as_string();
            uint32_t service_id = parseServiceId(sid_str);

            if (service_id == 0) {
#ifdef SPI_DEBUG
                fprintf(stderr, "[SPI] Could not parse service ID from: %s\n", sid_str.c_str());
#endif
                continue;
            }

            parseSchedule(&schedule, service_id);
        }
        return true;
    }

    // Handle <serviceInformation> element
    if (root_name == "serviceInformation") {
        // SI contains service metadata, possibly with embedded schedules
        for (pugi::xml_node services = root.child("services"); services;
             services = services.next_sibling("services")) {
            for (pugi::xml_node service = services.child("service"); service;
                 service = service.next_sibling("service")) {
                // Get service ID
                std::string sid_str = service.attribute("id").as_string();
                uint32_t service_id = parseServiceId(sid_str);

                // Look for embedded schedule
                pugi::xml_node schedule = service.child("schedule");
                if (schedule && service_id != 0) {
                    parseSchedule(&schedule, service_id);
                }
            }
        }
        return true;
    }

    // Handle <programmeGroups> or standalone <schedule>
    if (root_name == "schedule") {
        // Try to get service ID from scope
        pugi::xml_node scope = root.child("scope");
        if (scope) {
            pugi::xml_node service_scope = scope.child("serviceScope");
            if (service_scope) {
                std::string sid_str = service_scope.attribute("id").as_string();
                uint32_t service_id = parseServiceId(sid_str);
                if (service_id != 0) {
                    parseSchedule(&root, service_id);
                    return true;
                }
            }
        }
    }

#ifdef SPI_DEBUG
    fprintf(stderr, "[SPI] Unhandled root element: %s in %s\n",
            root_name.c_str(), filename.c_str());
#endif
    return false;
}

bool SpiParser::parseSchedule(const void* schedule_node_ptr, uint32_t service_id) {
    const pugi::xml_node& schedule_node = *static_cast<const pugi::xml_node*>(schedule_node_ptr);

    EpgSchedule schedule;
    schedule.service_id = service_id;
    schedule.last_update = time(nullptr);

    // Parse all programme elements
    for (pugi::xml_node prog = schedule_node.child("programme"); prog;
         prog = prog.next_sibling("programme")) {
        EpgProgramme programme;
        if (parseProgramme(&prog, programme)) {
            schedule.programmes.push_back(std::move(programme));
        }
    }

    if (schedule.programmes.empty()) {
#ifdef SPI_DEBUG
        fprintf(stderr, "[SPI] No programmes found for service 0x%08x\n", service_id);
#endif
        return false;
    }

    // Sort by start time
    std::sort(schedule.programmes.begin(), schedule.programmes.end(),
              [](const EpgProgramme& a, const EpgProgramme& b) {
                  return a.start_time < b.start_time;
              });

#ifdef SPI_DEBUG
    fprintf(stderr, "[SPI] Parsed %zu programmes for service 0x%08x\n",
            schedule.programmes.size(), service_id);
    for (const auto& p : schedule.programmes) {
        fprintf(stderr, "[SPI]   %s - %s\n",
                p.name.c_str(),
                ctime(&p.start_time));
    }
#endif

    // Store in cache
    schedules_[service_id] = schedule;

    // Notify callback
    if (schedule_callback_) {
        schedule_callback_(schedule);
    }

    return true;
}

bool SpiParser::parseProgramme(const void* prog_node_ptr, EpgProgramme& prog) {
    const pugi::xml_node& prog_node = *static_cast<const pugi::xml_node*>(prog_node_ptr);

    // Get short ID
    prog.short_id = prog_node.attribute("shortId").as_string();

    // Get name (try short, medium, long in order of preference for display)
    for (pugi::xml_node name_node = prog_node.child("mediumName"); name_node;
         name_node = name_node.next_sibling("mediumName")) {
        prog.name = name_node.text().as_string();
        if (!prog.name.empty()) break;
    }
    if (prog.name.empty()) {
        for (pugi::xml_node name_node = prog_node.child("shortName"); name_node;
             name_node = name_node.next_sibling("shortName")) {
            prog.name = name_node.text().as_string();
            if (!prog.name.empty()) break;
        }
    }
    if (prog.name.empty()) {
        for (pugi::xml_node name_node = prog_node.child("longName"); name_node;
             name_node = name_node.next_sibling("longName")) {
            prog.name = name_node.text().as_string();
            if (!prog.name.empty()) break;
        }
    }

    // Get description (from mediaDescription/shortDescription or longDescription)
    pugi::xml_node media_desc = prog_node.child("mediaDescription");
    if (media_desc) {
        pugi::xml_node short_desc = media_desc.child("shortDescription");
        if (short_desc) {
            prog.description = short_desc.text().as_string();
        }
        if (prog.description.empty()) {
            pugi::xml_node long_desc = media_desc.child("longDescription");
            if (long_desc) {
                prog.description = long_desc.text().as_string();
            }
        }
    }

    // Get location (contains time info)
    pugi::xml_node location = prog_node.child("location");
    if (location) {
        pugi::xml_node time_node = location.child("time");
        if (time_node) {
            std::string time_str = time_node.attribute("time").as_string();
            std::string duration_str = time_node.attribute("duration").as_string();

            prog.start_time = parseDateTime(time_str);
            prog.duration_seconds = parseDuration(duration_str);
        }

        // Alternative: relativeTime
        pugi::xml_node rel_time = location.child("relativeTime");
        if (rel_time && prog.start_time == 0) {
            std::string time_str = rel_time.attribute("time").as_string();
            std::string duration_str = rel_time.attribute("duration").as_string();
            prog.start_time = parseDateTime(time_str);
            prog.duration_seconds = parseDuration(duration_str);
        }
    }

    // Get genre
    pugi::xml_node genre_node = prog_node.child("genre");
    if (genre_node) {
        pugi::xml_node name_node = genre_node.child("name");
        if (name_node) {
            prog.genre = name_node.text().as_string();
        }
    }

    return prog.isValid();
}

time_t SpiParser::parseDateTime(const std::string& dt_str) {
    if (dt_str.empty()) return 0;

    // ISO 8601 format: 2024-12-21T14:00:00+01:00 or 2024-12-21T14:00:00Z
    struct tm tm = {};
    int tz_offset_hours = 0;
    int tz_offset_mins = 0;

    // Parse date and time parts
    int year, month, day, hour, min, sec;
    char tz_sign = 'Z';
    int parsed = sscanf(dt_str.c_str(), "%d-%d-%dT%d:%d:%d%c%d:%d",
                        &year, &month, &day, &hour, &min, &sec,
                        &tz_sign, &tz_offset_hours, &tz_offset_mins);

    if (parsed < 6) {
        // Try without timezone
        parsed = sscanf(dt_str.c_str(), "%d-%d-%dT%d:%d:%d",
                        &year, &month, &day, &hour, &min, &sec);
        if (parsed < 6) return 0;
    }

    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = min;
    tm.tm_sec = sec;
    tm.tm_isdst = 0;

    // Convert to UTC timestamp
    time_t result = timegm(&tm);

    // Apply timezone offset
    if (tz_sign == '+') {
        result -= tz_offset_hours * 3600 + tz_offset_mins * 60;
    } else if (tz_sign == '-') {
        result += tz_offset_hours * 3600 + tz_offset_mins * 60;
    }
    // 'Z' means UTC, no adjustment needed

    return result;
}

int SpiParser::parseDuration(const std::string& dur_str) {
    if (dur_str.empty() || dur_str[0] != 'P') return 0;

    // ISO 8601 duration: PT1H30M or PT90M or PT5400S
    int hours = 0, mins = 0, secs = 0;

    const char* p = dur_str.c_str() + 1;  // Skip 'P'
    if (*p == 'T') p++;  // Skip 'T' (time designator)

    while (*p) {
        int value = 0;
        while (*p >= '0' && *p <= '9') {
            value = value * 10 + (*p - '0');
            p++;
        }
        if (*p == 'H') {
            hours = value;
            p++;
        } else if (*p == 'M') {
            mins = value;
            p++;
        } else if (*p == 'S') {
            secs = value;
            p++;
        } else {
            p++;  // Skip unknown character
        }
    }

    return hours * 3600 + mins * 60 + secs;
}

uint32_t SpiParser::parseServiceId(const std::string& scope_str) {
    // Service ID format in SPI:
    // - dab:de0.d393.d393.0 (ECC.EId.SId.SCIdS)
    // - e1.d393 (ECC.SId short form)
    // - 0xd393 (hex SId)
    // - d393 (decimal SId)

    if (scope_str.empty()) return 0;

    // Try dab: URI format
    if (scope_str.substr(0, 4) == "dab:") {
        // Parse dab:cc.eid.sid.scids
        std::string uri = scope_str.substr(4);
        std::vector<std::string> parts;
        std::stringstream ss(uri);
        std::string part;
        while (std::getline(ss, part, '.')) {
            parts.push_back(part);
        }
        // SId is typically the 3rd part (index 2)
        if (parts.size() >= 3) {
            // Parse as hex
            uint32_t sid = 0;
            if (sscanf(parts[2].c_str(), "%x", &sid) == 1) {
                return sid;
            }
        }
    }

    // Try hex format with 0x prefix
    if (scope_str.size() > 2 && scope_str[0] == '0' && scope_str[1] == 'x') {
        uint32_t sid = 0;
        if (sscanf(scope_str.c_str(), "%x", &sid) == 1) {
            return sid;
        }
    }

    // Try plain hex (common for DAB SId)
    uint32_t sid = 0;
    if (sscanf(scope_str.c_str(), "%x", &sid) == 1) {
        return sid;
    }

    return 0;
}

const EpgSchedule* SpiParser::getSchedule(uint32_t service_id) const {
    auto it = schedules_.find(service_id);
    return (it != schedules_.end()) ? &it->second : nullptr;
}

} // namespace dvbdab
