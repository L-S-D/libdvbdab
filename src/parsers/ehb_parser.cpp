#include "ehb_parser.hpp"
#include <cstring>
#include <cstdio>
#include <algorithm>

// ETSI TS 102 371 EPG Binary Parser
// Based on working Python implementation from eti-na-parser

namespace dvbdab {

// Element tags per ETSI TS 102 371
enum EhbElementTag : uint8_t {
    TAG_EPG = 0x02,
    TAG_SERVICE_INFO = 0x03,
    TAG_TOKEN_TABLE = 0x04,
    TAG_OBSOLETE = 0x05,
    TAG_DEFAULT_LANGUAGE = 0x06,
    TAG_SHORT_NAME = 0x10,
    TAG_MEDIUM_NAME = 0x11,
    TAG_LONG_NAME = 0x12,
    TAG_MEDIA_DESCRIPTION = 0x13,
    TAG_GENRE = 0x14,
    TAG_KEYWORDS = 0x16,
    TAG_MEMBER_OF = 0x17,
    TAG_LINK = 0x18,
    TAG_LOCATION = 0x19,
    TAG_SHORT_DESCRIPTION = 0x1A,
    TAG_LONG_DESCRIPTION = 0x1B,
    TAG_PROGRAMME = 0x1C,
    TAG_PROGRAMME_GROUPS = 0x20,
    TAG_SCHEDULE = 0x21,
    TAG_PROGRAMME_GROUP = 0x23,
    TAG_SCOPE = 0x24,
    TAG_SERVICE_SCOPE = 0x25,
    TAG_ENSEMBLE = 0x26,
    TAG_SERVICE = 0x28,
    TAG_BEARER = 0x29,
    TAG_MULTIMEDIA = 0x2B,
    TAG_TIME = 0x2C,
    TAG_BEARER_2 = 0x2D,
    TAG_RELATIVE_TIME = 0x2F,
    TAG_RADIODNS = 0x31,
    TAG_GEOLOCATION = 0x32,
    TAG_COUNTRY = 0x33,
    TAG_ON_DEMAND = 0x36,
    TAG_PRESENTATION_TIME = 0x37,
    TAG_ACQUISITION_TIME = 0x38,
};

// Token bytes per ETSI TS 102 371: 0x01-0x08, 0x0b, 0x0c, 0x0e-0x13
// NOT tokens: 0x00, 0x09 (tab), 0x0a (newline), 0x0d (CR)
static inline bool isTokenByte(uint8_t b) {
    // Tokens: 1-8, 11, 12, 14-19
    if (b >= 1 && b <= 8) return true;
    if (b == 11 || b == 12) return true;
    if (b >= 14 && b <= 19) return true;
    return false;
}

// Get bits value from byte array (MSB first)
static uint32_t getBitsValue(const uint8_t* data, size_t start_bit, size_t num_bits) {
    uint32_t value = 0;
    for (size_t i = 0; i < num_bits; i++) {
        size_t bit_pos = start_bit + i;
        size_t byte_idx = bit_pos / 8;
        size_t bit_idx = 7 - (bit_pos % 8);  // MSB first
        uint8_t bit = (data[byte_idx] >> bit_idx) & 1;
        value = (value << 1) | bit;
    }
    return value;
}

// Convert MJD (Modified Julian Date) to Unix timestamp
static time_t mjdToUnix(uint32_t mjd) {
    // MJD 40587 = Unix epoch (January 1, 1970)
    return (static_cast<int64_t>(mjd) - 40587) * 86400;
}

EhbParser::EhbParser() = default;

bool EhbParser::parseFilename(const std::string& filename, time_t& base_date, uint16_t& service_id) {
    // Filename format: w20251220ddf95c0.EHB
    // w = prefix
    // 20251220 = date YYYYMMDD
    // d = delimiter
    // df95 = service component ID (hex)
    // c0 = suffix
    // .EHB = extension

    // Extract just the filename if path is included
    std::string fname = filename;
    size_t slash_pos = fname.rfind('/');
    if (slash_pos != std::string::npos) {
        fname = fname.substr(slash_pos + 1);
    }

    if (fname.length() < 17) return false;
    if (fname[0] != 'w') return false;

    // Parse date
    int year = 0, month = 0, day = 0;
    if (sscanf(fname.c_str() + 1, "%4d%2d%2d", &year, &month, &day) != 3) {
        return false;
    }

    // Convert to time_t (midnight of that day, UTC)
    struct tm tm = {};
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    tm.tm_isdst = 0;
    base_date = timegm(&tm);  // UTC

    // Parse service ID (after 'd' at position 9)
    if (fname[9] != 'd') return false;

    char hex_str[5] = {};
    strncpy(hex_str, fname.c_str() + 10, 4);
    service_id = static_cast<uint16_t>(strtol(hex_str, nullptr, 16));

    return true;
}

bool EhbParser::parseStringTable(const uint8_t* data, size_t len, size_t& end_offset) {
    // This is called for TAG_TOKEN_TABLE (0x04)
    // The data pointer is already positioned after the tag+length header
    // Each entry: tag(1 byte) + length field + string data

    string_table_.clear();
    size_t pos = 0;

    while (pos < len) {
        if (pos + 2 > len) break;

        uint8_t tag = data[pos];

        // End condition: tag >= 0x20 typically means we've left the token table
        if (tag >= 0x20 && tag != 0xFE && tag != 0xFF) break;

        // Parse length field
        size_t length = 0;
        size_t header_len = 2;
        uint8_t len_byte = data[pos + 1];

        if (len_byte == 0xFE && pos + 4 <= len) {
            length = (data[pos + 2] << 8) | data[pos + 3];
            header_len = 4;
        } else if (len_byte == 0xFF && pos + 5 <= len) {
            length = (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4];
            header_len = 5;
        } else {
            length = len_byte;
        }

        if (pos + header_len + length > len) break;

        // Store string if valid token index (1-19)
        if (tag >= 1 && tag <= 19) {
            std::string s(reinterpret_cast<const char*>(data + pos + header_len), length);
            string_table_[tag] = s;
        }

        pos += header_len + length;
    }

    end_offset = pos;
    return !string_table_.empty();
}

std::string EhbParser::decodeTokenString(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(len * 2);

    for (size_t i = 0; i < len; i++) {
        uint8_t byte = data[i];

        if (isTokenByte(byte)) {
            // Token reference - look up in string table
            auto it = string_table_.find(byte);
            if (it != string_table_.end()) {
                result += it->second;
            }
            // If not found, skip silently
        } else if (byte == 0x00) {
            // Null terminator - end of string
            break;
        } else {
            // Regular character (including 0x09 tab, 0x0a newline, 0x0d CR)
            result += static_cast<char>(byte);
        }
    }

    return result;
}

std::string EhbParser::expandTokens(const std::string& text) {
    std::string result;
    result.reserve(text.size() * 2);

    for (unsigned char c : text) {
        if (isTokenByte(c)) {
            auto it = string_table_.find(c);
            if (it != string_table_.end()) {
                result += it->second;
            }
        } else if (c != 0x00) {
            // Keep all characters including newlines, tabs, CR
            result += static_cast<char>(c);
        }
    }
    return result;
}

// Parse time point per ETSI TS 102 371 section 4.7.4
// Bit structure:
// - bit 0: RFA (reserved)
// - bits 1-17: MJD (17 bits)
// - bit 18: RFA
// - bit 19: LTO flag (if set, last 6 bits contain timezone offset)
// - bit 20: UTC flag (0=short form, 1=long form with seconds)
// - bits 21-25: hours (5 bits)
// - bits 26-31: minutes (6 bits)
// - If UTC flag=1: bits 32-37: seconds (6 bits)
// - If LTO flag=1: last 6 bits = sign (1 bit) + half-hours (5 bits)
void EhbParser::parseTimePoint(const uint8_t* data, size_t len, time_t& result) {
    if (len < 4) return;

    // Convert to bits for easier extraction
    size_t total_bits = len * 8;

    // Extract MJD from bits 1-17 (17 bits)
    uint32_t mjd = getBitsValue(data, 1, 17);

    // Get base date from MJD
    time_t base_date = mjdToUnix(mjd);

    // Extract flags
    bool lto_flag = (total_bits > 19) ? ((data[2] >> 4) & 1) : false;
    bool utc_flag = (total_bits > 20) ? ((data[2] >> 3) & 1) : false;

    // Extract time fields
    uint32_t hours = getBitsValue(data, 21, 5);
    uint32_t minutes = getBitsValue(data, 26, 6);

    // Long form includes seconds
    uint32_t seconds = 0;
    if (utc_flag && total_bits >= 38) {
        seconds = getBitsValue(data, 32, 6);
    }

    // LTO (Local Time Offset) is present but we store UTC for EIT compatibility
    // The time in the binary data is UTC, LTO is just metadata about the local timezone
    // We ignore LTO here - times are stored as UTC

    result = base_date + hours * 3600 + minutes * 60 + seconds;
}

bool EhbParser::parse(const std::string& filename, const uint8_t* data, size_t len) {
    last_schedule_ = ServiceSchedule();
    string_table_.clear();

    if (len < 4) return false;

    // Parse filename for date and service ID
    time_t base_date = 0;
    uint16_t service_id = 0;
    parseFilename(filename, base_date, service_id);

    last_schedule_.base_date = base_date;
    last_schedule_.service_id = service_id;

    // All EHB files are ETSI TS 102 371 format
    // TAG_EPG (0x02) = schedule data, TAG_SERVICE_INFO (0x03) = service info
    return parseEtsiFormat(filename, data, len);
}

// Parse standard ETSI TS 102 371 TLV format
bool EhbParser::parseEtsiFormat(const std::string& filename, const uint8_t* data, size_t len) {
    size_t pos = 0;

    // Check top-level tag
    uint8_t top_tag = data[pos];
    if (top_tag != TAG_EPG && top_tag != TAG_SERVICE_INFO) {
        return false;
    }

    // Parse length field
    size_t content_len = 0;
    size_t header_len = 2;
    uint8_t len_byte = data[pos + 1];

    if (len_byte == 0xFE && pos + 4 <= len) {
        content_len = (data[pos + 2] << 8) | data[pos + 3];
        header_len = 4;
    } else if (len_byte == 0xFF && pos + 5 <= len) {
        content_len = (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4];
        header_len = 5;
    } else {
        content_len = len_byte;
    }

    size_t end_pos = pos + header_len + content_len;
    if (end_pos > len) end_pos = len;

    pos += header_len;

    // Parse child elements
    while (pos < end_pos) {
        if (pos + 2 > end_pos) break;

        uint8_t tag = data[pos];

        // Parse element length
        size_t elem_len = 0;
        size_t elem_header = 2;
        uint8_t elem_len_byte = data[pos + 1];

        if (elem_len_byte == 0xFE && pos + 4 <= end_pos) {
            elem_len = (data[pos + 2] << 8) | data[pos + 3];
            elem_header = 4;
        } else if (elem_len_byte == 0xFF && pos + 5 <= end_pos) {
            elem_len = (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4];
            elem_header = 5;
        } else {
            elem_len = elem_len_byte;
        }

        size_t elem_end = pos + elem_header + elem_len;
        if (elem_end > end_pos) elem_end = end_pos;

        const uint8_t* elem_data = data + pos + elem_header;
        size_t elem_data_len = elem_end - pos - elem_header;

        switch (tag) {
            case TAG_TOKEN_TABLE: {
                size_t dummy = 0;
                parseStringTable(elem_data, elem_data_len, dummy);
                break;
            }
            case TAG_DEFAULT_LANGUAGE:
                // Skip for now
                break;
            case TAG_SCHEDULE:
                parseScheduleElement(elem_data, elem_data_len);
                break;
            case TAG_PROGRAMME_GROUPS:
                // Skip for now
                break;
            default:
                // Skip unknown elements
                break;
        }

        pos = elem_end;
    }

    // Invoke callback
    if (schedule_callback_ && !last_schedule_.events.empty()) {
        // Debug: print actual coverage (earliest start to latest end)
        time_t min_start = last_schedule_.events[0].start_time;
        time_t max_end = min_start + last_schedule_.events[0].duration_seconds;
        for (const auto& ev : last_schedule_.events) {
            if (ev.start_time < min_start) min_start = ev.start_time;
            time_t ev_end = ev.start_time + ev.duration_seconds;
            if (ev_end > max_end) max_end = ev_end;
        }
        struct tm* min_tm = gmtime(&min_start);
        int min_day = min_tm->tm_mday, min_hour = min_tm->tm_hour, min_min = min_tm->tm_min;
        struct tm* max_tm = gmtime(&max_end);
        int max_day = max_tm->tm_mday, max_hour = max_tm->tm_hour, max_min = max_tm->tm_min;
        fprintf(stderr, "[EHB-RANGE] SID=0x%04x events=%zu coverage=day%02d/%02d:%02d-day%02d/%02d:%02d\n",
                last_schedule_.service_id, last_schedule_.events.size(),
                min_day, min_hour, min_min, max_day, max_hour, max_min);
        schedule_callback_(last_schedule_);
    }

    return !last_schedule_.events.empty();
}

// Parse schedule element (0x21)
void EhbParser::parseScheduleElement(const uint8_t* data, size_t len) {
    size_t pos = 0;

    while (pos < len) {
        if (pos + 2 > len) break;

        uint8_t tag = data[pos];

        // Parse element length
        size_t elem_len = 0;
        size_t elem_header = 2;
        uint8_t len_byte = data[pos + 1];

        if (len_byte == 0xFE && pos + 4 <= len) {
            elem_len = (data[pos + 2] << 8) | data[pos + 3];
            elem_header = 4;
        } else if (len_byte == 0xFF && pos + 5 <= len) {
            elem_len = (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4];
            elem_header = 5;
        } else {
            elem_len = len_byte;
        }

        size_t elem_end = pos + elem_header + elem_len;
        if (elem_end > len) elem_end = len;

        const uint8_t* elem_data = data + pos + elem_header;
        size_t elem_data_len = elem_end - pos - elem_header;

        switch (tag) {
            case TAG_SCOPE:
                // Could extract scope info here
                break;
            case TAG_PROGRAMME:
                parseProgrammeElement(elem_data, elem_data_len);
                break;
            case TAG_MEDIUM_NAME:
            case TAG_LONG_NAME:
                // Schedule name - skip for now
                break;
            default:
                // Skip unknown elements
                break;
        }

        pos = elem_end;
    }
}

// Parse programme element (0x1C)
void EhbParser::parseProgrammeElement(const uint8_t* data, size_t len) {
    EpgEvent event;
    size_t pos = 0;

    while (pos < len) {
        if (pos + 2 > len) break;

        uint8_t tag = data[pos];

        // Parse element length
        size_t elem_len = 0;
        size_t elem_header = 2;
        uint8_t len_byte = data[pos + 1];

        if (len_byte == 0xFE && pos + 4 <= len) {
            elem_len = (data[pos + 2] << 8) | data[pos + 3];
            elem_header = 4;
        } else if (len_byte == 0xFF && pos + 5 <= len) {
            elem_len = (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4];
            elem_header = 5;
        } else {
            elem_len = len_byte;
        }

        size_t elem_end = pos + elem_header + elem_len;
        if (elem_end > len) elem_end = len;

        const uint8_t* elem_data = data + pos + elem_header;
        size_t elem_data_len = elem_end - pos - elem_header;

        switch (tag) {
            case TAG_SHORT_NAME:
            case TAG_MEDIUM_NAME:
            case TAG_LONG_NAME:
                // Parse name - prefer longer names
                if (event.title.empty() || tag == TAG_LONG_NAME) {
                    event.title = parseStringElement(elem_data, elem_data_len);
                }
                break;
            case TAG_MEDIA_DESCRIPTION:
                parseMediaDescription(elem_data, elem_data_len, event);
                break;
            case TAG_LOCATION:
                parseLocationElement(elem_data, elem_data_len, event);
                break;
            case 0x80:  // id attribute
                // Event ID string
                break;
            case 0x81:  // shortId attribute
                if (elem_data_len >= 3) {
                    event.event_id = (elem_data[0] << 16) | (elem_data[1] << 8) | elem_data[2];
                }
                break;
            default:
                // Skip unknown elements
                break;
        }

        pos = elem_end;
    }

    if (!event.title.empty() || event.start_time > 0) {
        // Default duration if not set
        if (event.duration_seconds == 0) {
            event.duration_seconds = 3600;  // 1 hour default
        }
        last_schedule_.events.push_back(event);
    }
}

// Parse mediaDescription element (0x13)
void EhbParser::parseMediaDescription(const uint8_t* data, size_t len, EpgEvent& event) {
    size_t pos = 0;

    while (pos < len) {
        if (pos + 2 > len) break;

        uint8_t tag = data[pos];

        // Parse element length
        size_t elem_len = 0;
        size_t elem_header = 2;
        uint8_t len_byte = data[pos + 1];

        if (len_byte == 0xFE && pos + 4 <= len) {
            elem_len = (data[pos + 2] << 8) | data[pos + 3];
            elem_header = 4;
        } else if (len_byte == 0xFF && pos + 5 <= len) {
            elem_len = (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4];
            elem_header = 5;
        } else {
            elem_len = len_byte;
        }

        size_t elem_end = pos + elem_header + elem_len;
        if (elem_end > len) elem_end = len;

        const uint8_t* elem_data = data + pos + elem_header;
        size_t elem_data_len = elem_end - pos - elem_header;

        switch (tag) {
            case TAG_SHORT_DESCRIPTION:
            case TAG_LONG_DESCRIPTION:
                // Parse description - prefer longer
                if (event.description.empty() || tag == TAG_LONG_DESCRIPTION) {
                    event.description = parseStringElement(elem_data, elem_data_len);
                }
                break;
            default:
                break;
        }

        pos = elem_end;
    }
}

// Parse location element (0x19)
void EhbParser::parseLocationElement(const uint8_t* data, size_t len, EpgEvent& event) {
    size_t pos = 0;

    while (pos < len) {
        if (pos + 2 > len) break;

        uint8_t tag = data[pos];

        // Parse element length
        size_t elem_len = 0;
        size_t elem_header = 2;
        uint8_t len_byte = data[pos + 1];

        if (len_byte == 0xFE && pos + 4 <= len) {
            elem_len = (data[pos + 2] << 8) | data[pos + 3];
            elem_header = 4;
        } else if (len_byte == 0xFF && pos + 5 <= len) {
            elem_len = (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4];
            elem_header = 5;
        } else {
            elem_len = len_byte;
        }

        size_t elem_end = pos + elem_header + elem_len;
        if (elem_end > len) elem_end = len;

        const uint8_t* elem_data = data + pos + elem_header;
        size_t elem_data_len = elem_end - pos - elem_header;

        if (tag == TAG_TIME) {
            parseTimeElement(elem_data, elem_data_len, event);
        }

        pos = elem_end;
    }
}

// Parse time element (0x2C)
void EhbParser::parseTimeElement(const uint8_t* data, size_t len, EpgEvent& event) {
    size_t pos = 0;

    while (pos < len) {
        if (pos + 2 > len) break;

        uint8_t tag = data[pos];

        // Parse element length
        size_t elem_len = 0;
        size_t elem_header = 2;
        uint8_t len_byte = data[pos + 1];

        if (len_byte == 0xFE && pos + 4 <= len) {
            elem_len = (data[pos + 2] << 8) | data[pos + 3];
            elem_header = 4;
        } else if (len_byte == 0xFF && pos + 5 <= len) {
            elem_len = (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4];
            elem_header = 5;
        } else {
            elem_len = len_byte;
        }

        size_t elem_end = pos + elem_header + elem_len;
        if (elem_end > len) elem_end = len;

        const uint8_t* elem_data = data + pos + elem_header;
        size_t elem_data_len = elem_end - pos - elem_header;

        switch (tag) {
            case 0x80:  // time
                if (elem_data_len >= 4) {
                    parseTimePoint(elem_data, elem_data_len, event.start_time);
                }
                break;
            case 0x81:  // duration
                if (elem_data_len >= 2) {
                    // Duration in seconds (2 bytes big-endian)
                    uint32_t raw_duration = (elem_data[0] << 8) | elem_data[1];
                    // DAB EPG binary format uses 16-bit duration (max 65535 seconds = ~18:12)
                    // Values near max typically mean "all day" - map to 24 hours
                    if (raw_duration >= 65520) {  // >= 0xFFF0 (~18:12)
                        event.duration_seconds = 86400;  // 24 hours
                    } else {
                        event.duration_seconds = raw_duration;
                    }
                }
                break;
            default:
                break;
        }

        pos = elem_end;
    }
}

// Parse string element with optional xml:lang attribute
std::string EhbParser::parseStringElement(const uint8_t* data, size_t len) {
    size_t pos = 0;

    // Check for xml:lang attribute (0x80)
    if (len > 2 && data[0] == 0x80) {
        uint8_t attr_len = data[1];
        pos = 2 + attr_len;
        if (pos >= len) return "";
    }

    // Check for string prefix (0x01 = length-prefixed string)
    size_t str_len = len - pos;
    if (pos < len && data[pos] == 0x01) {
        pos++;
        if (pos >= len) return "";

        uint8_t len_byte = data[pos];
        if (len_byte == 0xFE && pos + 3 <= len) {
            str_len = (data[pos + 1] << 8) | data[pos + 2];
            pos += 3;
        } else if (len_byte == 0xFF && pos + 4 <= len) {
            str_len = (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
            pos += 4;
        } else {
            str_len = len_byte;
            pos++;
        }
    }

    if (pos >= len) return "";
    if (str_len > len - pos) str_len = len - pos;

    // Decode string with token expansion
    return decodeTokenString(data + pos, str_len);
}

} // namespace dvbdab
