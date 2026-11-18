// The PSI/SI sections of the TS that goes out (ISO/IEC 13818-1, EN 300 468)

#include "ts_tables.hpp"
#include "../utils/crc_utils.hpp"
#include <algorithm>

namespace dvbdab {

/* A text of the SDT service descriptor (length byte + text). The labels are
 * UTF-8: with a non-ASCII character the text starts with 0x15, the DVB
 * character table selector for UTF-8 (EN 300 468 annex A) - without it
 * receivers read the bytes as ISO 6937 / ISO 8859-1 and show mojibake */
static void appendDvbString(std::vector<uint8_t>& section, const std::string& text)
{
    bool ascii = std::all_of(text.begin(), text.end(),
                             [](char c) { return static_cast<unsigned char>(c) < 0x80; });
    size_t n = std::min<size_t>(text.size(), ascii ? 255 : 254);
    while (!ascii && n > 0 && n < text.size() &&
           (static_cast<unsigned char>(text[n]) & 0xC0) == 0x80) {
        n--;   // do not cut a character
    }
    section.push_back(static_cast<uint8_t>(n + (ascii ? 0 : 1)));
    if (!ascii) section.push_back(0x15);
    for (size_t i = 0; i < n; i++) section.push_back(static_cast<uint8_t>(text[i]));
}

/* The first bytes of a UTF-8 text, at most max_bytes and no character cut */
static std::string utf8Prefix(const std::string& text, size_t max_bytes)
{
    if (text.size() <= max_bytes) return text;
    size_t n = max_bytes;
    while (n > 0 && (static_cast<unsigned char>(text[n]) & 0xC0) == 0x80) n--;
    return text.substr(0, n);
}

std::vector<uint8_t> buildPatSection(uint16_t tsid, uint8_t version, const std::vector<TsService>& services) {
    std::vector<uint8_t> section;
    section.reserve(64);  // PAT: ~12 bytes header + 4 bytes/service + 4 bytes CRC

    // table_id = 0x00 (PAT)
    section.push_back(0x00);

    // section_syntax_indicator(1) + '0'(1) + reserved(2) + section_length(12)
    size_t len_pos = section.size();
    section.push_back(0x00);
    section.push_back(0x00);

    // transport_stream_id
    section.push_back((tsid >> 8) & 0xFF);
    section.push_back(tsid & 0xFF);

    // reserved(2) + version_number(5) + current_next_indicator(1)
    section.push_back(0xC1 | ((version & 0x1F) << 1));

    // section_number
    section.push_back(0x00);

    // last_section_number
    section.push_back(0x00);

    // Program entries
    for (const auto& svc : services) {
        section.push_back((svc.sid >> 8) & 0xFF);
        section.push_back(svc.sid & 0xFF);
        section.push_back(0xE0 | ((svc.pmt_pid >> 8) & 0x1F));
        section.push_back(svc.pmt_pid & 0xFF);
    }

    // Calculate and set section_length (includes CRC)
    size_t section_length = section.size() - 3 + 4;
    section[len_pos] = 0xB0 | ((section_length >> 8) & 0x0F);
    section[len_pos + 1] = section_length & 0xFF;

    // CRC32
    uint32_t crc = dvb_crc32(section.data(), section.size());
    section.push_back((crc >> 24) & 0xFF);
    section.push_back((crc >> 16) & 0xFF);
    section.push_back((crc >> 8) & 0xFF);
    section.push_back(crc & 0xFF);

    return section;
}

std::vector<uint8_t> buildPmtSection(const TsService& service, uint8_t version) {
    std::vector<uint8_t> section;
    section.reserve(32);  // PMT: fixed ~21 bytes + 4 bytes CRC

    // table_id = 0x02 (PMT)
    section.push_back(0x02);

    size_t len_pos = section.size();
    section.push_back(0x00);
    section.push_back(0x00);

    // program_number (service_id)
    section.push_back((service.sid >> 8) & 0xFF);
    section.push_back(service.sid & 0xFF);

    // reserved(2) + version_number(5) + current_next_indicator(1)
    section.push_back(0xC1 | ((version & 0x1F) << 1));

    // section_number
    section.push_back(0x00);

    // last_section_number
    section.push_back(0x00);

    // reserved(3) + PCR_PID(13) - use audio PID for PCR
    section.push_back(0xE0 | ((service.audio_pid >> 8) & 0x1F));
    section.push_back(service.audio_pid & 0xFF);

    // reserved(4) + program_info_length(12) = 0
    section.push_back(0xF0);
    section.push_back(0x00);

    // Elementary stream entry
    uint8_t stream_type = !service.dabplus ? STREAM_TYPE_MPEG_AUDIO :
                          service.latm ? STREAM_TYPE_AAC_LATM : STREAM_TYPE_AAC_ADTS;
    section.push_back(stream_type);

    // reserved(3) + elementary_PID(13)
    section.push_back(0xE0 | ((service.audio_pid >> 8) & 0x1F));
    section.push_back(service.audio_pid & 0xFF);

    // reserved(4) + ES_info_length(12): the language of the audio, when it
    // is known (ISO_639_language_descriptor, audio_type 0 = undefined)
    if (service.language.size() == 3) {
        section.push_back(0xF0);
        section.push_back(0x06);
        section.push_back(0x0A);
        section.push_back(0x04);
        for (char c : service.language) section.push_back(static_cast<uint8_t>(c));
        section.push_back(0x00);
    } else {
        section.push_back(0xF0);
        section.push_back(0x00);
    }

    // its dynamic label as RDS: stream type 0x89 with an ancillary_data_descriptor
    // (EN 300 468: tag 0x6B, ancillary_data_identifier bit 6 = RDS via UECP coding)
    if (service.rds_pid) {
        section.push_back(0x89);
        section.push_back(0xE0 | ((service.rds_pid >> 8) & 0x1F));
        section.push_back(service.rds_pid & 0xFF);
        section.push_back(0xF0);
        section.push_back(0x03);
        section.push_back(0x6B);
        section.push_back(0x01);
        section.push_back(0x40);
    }

    // Section length
    size_t section_length = section.size() - 3 + 4;
    section[len_pos] = 0xB0 | ((section_length >> 8) & 0x0F);
    section[len_pos + 1] = section_length & 0xFF;

    // CRC32
    uint32_t crc = dvb_crc32(section.data(), section.size());
    section.push_back((crc >> 24) & 0xFF);
    section.push_back((crc >> 16) & 0xFF);
    section.push_back((crc >> 8) & 0xFF);
    section.push_back(crc & 0xFF);

    return section;
}

std::vector<std::vector<uint8_t>> buildSdtSections(uint16_t tsid, uint16_t onid, uint8_t version,
                                                   const std::vector<TsService>& services,
                                                   const std::string& default_provider) {
    // The entry of each service
    std::vector<std::vector<uint8_t>> entries;
    for (const auto& svc : services) {
        std::vector<uint8_t> e;
        e.push_back((svc.sid >> 8) & 0xFF);
        e.push_back(svc.sid & 0xFF);

        // reserved(6) + EIT_schedule_flag(1) + EIT_present_following_flag(1):
        // there is a schedule, no present/following
        e.push_back(0xFE);

        // running_status(3) + free_CA_mode(1) + descriptors_loop_length(12)
        size_t desc_len_pos = e.size();
        e.push_back(0x00);
        e.push_back(0x00);
        size_t desc_start = e.size();

        // Service descriptor (0x48)
        e.push_back(0x48);
        size_t desc_size_pos = e.size();
        e.push_back(0x00);

        // service_type = 0x02 (radio)
        e.push_back(0x02);

        // provider_name
        std::string provider = svc.provider.empty() ? default_provider : svc.provider;
        appendDvbString(e, provider);

        // service_name
        appendDvbString(e, svc.name);

        // Fill descriptor length
        e[desc_size_pos] = static_cast<uint8_t>(e.size() - desc_size_pos - 1);

        // Fill descriptors_loop_length with running_status=4 (running)
        size_t desc_len = e.size() - desc_start;
        e[desc_len_pos] = 0x80 | ((desc_len >> 8) & 0x0F);  // running=4, free_CA=0
        e[desc_len_pos + 1] = desc_len & 0xFF;
        entries.push_back(std::move(e));
    }

    // Into sections of 1024 bytes at most (11 bytes before the entries, the CRC after them)
    constexpr size_t MAX_ENTRIES_BYTES = 1024 - 11 - 4;
    std::vector<std::vector<uint8_t>> bodies(1);
    for (const auto& e : entries) {
        if (!bodies.back().empty() && bodies.back().size() + e.size() > MAX_ENTRIES_BYTES) {
            bodies.emplace_back();
        }
        bodies.back().insert(bodies.back().end(), e.begin(), e.end());
    }

    std::vector<std::vector<uint8_t>> sections;
    for (size_t n = 0; n < bodies.size(); n++) {
        std::vector<uint8_t> section;
        section.reserve(11 + bodies[n].size() + 4);

        // table_id = 0x42 (SDT actual)
        section.push_back(0x42);

        size_t section_length = 8 + bodies[n].size() + 4;
        section.push_back(0xF0 | ((section_length >> 8) & 0x0F));
        section.push_back(section_length & 0xFF);

        // transport_stream_id
        section.push_back((tsid >> 8) & 0xFF);
        section.push_back(tsid & 0xFF);

        // reserved(2) + version_number(5) + current_next_indicator(1)
        section.push_back(0xC1 | ((version & 0x1F) << 1));

        // section_number, last_section_number
        section.push_back(static_cast<uint8_t>(n));
        section.push_back(static_cast<uint8_t>(bodies.size() - 1));

        // original_network_id
        section.push_back((onid >> 8) & 0xFF);
        section.push_back(onid & 0xFF);

        // reserved_future_use
        section.push_back(0xFF);

        section.insert(section.end(), bodies[n].begin(), bodies[n].end());

        // CRC32
        uint32_t crc = dvb_crc32(section.data(), section.size());
        section.push_back((crc >> 24) & 0xFF);
        section.push_back((crc >> 16) & 0xFF);
        section.push_back((crc >> 8) & 0xFF);
        section.push_back(crc & 0xFF);

        sections.push_back(std::move(section));
    }
    return sections;
}

namespace {

// One section of an EIT schedule with these events
std::vector<uint8_t> buildEitScheduleSection(uint16_t service_id, uint16_t tsid, uint16_t onid, uint8_t version,
    uint8_t table_id, uint8_t section_number, uint8_t last_section_number, uint8_t segment_last_section,
    const std::vector<const EpgProgramme*>& events, const std::string& language, uint8_t content) {

    std::vector<uint8_t> section;
    section.reserve(4096);  // EIT schedule: max section size

    // table_id (0x50 = EIT schedule actual)
    section.push_back(table_id);

    size_t len_pos = section.size();
    section.push_back(0x00);
    section.push_back(0x00);

    // service_id
    section.push_back((service_id >> 8) & 0xFF);
    section.push_back(service_id & 0xFF);

    // reserved(2) + version_number(5) + current_next_indicator(1)
    // Version increments when EHB data changes
    section.push_back(0xC1 | ((version & 0x1F) << 1));

    // section_number
    section.push_back(section_number);

    // last_section_number (highest section across all segments)
    section.push_back(last_section_number);

    // transport_stream_id
    section.push_back((tsid >> 8) & 0xFF);
    section.push_back(tsid & 0xFF);

    // original_network_id
    section.push_back((onid >> 8) & 0xFF);
    section.push_back(onid & 0xFF);

    // segment_last_section_number (highest section within this 3-hour segment)
    section.push_back(segment_last_section);

    // last_table_id
    section.push_back(table_id);

    // Add events
    auto toBcd = [](int val) -> uint8_t { return ((val / 10) << 4) | (val % 10); };

    for (size_t i = 0; i < events.size(); i++) {
        const EpgProgramme* prog = events[i];

        // event_id: from the start time, in minutes - the same for a
        // programme whatever was put before it, and no two alike in the 45
        // days it takes to come round
        uint16_t event_id = static_cast<uint16_t>((prog->start_time / 60) & 0xFFFF);
        section.push_back((event_id >> 8) & 0xFF);
        section.push_back(event_id & 0xFF);

        // start_time: MJD(2) + BCD time(3)
        int64_t days = prog->start_time / 86400;
        int mjd = 40587 + static_cast<int>(days);
        section.push_back((mjd >> 8) & 0xFF);
        section.push_back(mjd & 0xFF);

        // (gmtime() is not for several threads: each ensemble has its own)
        struct tm utc_tm = {};
        struct tm* utc = gmtime_r(&prog->start_time, &utc_tm);
        if (!utc) utc = &utc_tm;
        section.push_back(toBcd(utc->tm_hour));
        section.push_back(toBcd(utc->tm_min));
        section.push_back(toBcd(utc->tm_sec));

        // duration in BCD (HH:MM:SS)
        int dur_hours = prog->duration_seconds / 3600;
        int dur_mins = (prog->duration_seconds % 3600) / 60;
        int dur_secs = prog->duration_seconds % 60;
        section.push_back(toBcd(dur_hours));
        section.push_back(toBcd(dur_mins));
        section.push_back(toBcd(dur_secs));

        // Prepare short_event_descriptor
        std::string name = utf8Prefix(prog->name, 120);
        std::string desc = utf8Prefix(prog->description, 120);

        // descriptors_loop_length placeholder
        size_t desc_len_pos = section.size();
        section.push_back(0x00);
        section.push_back(0x00);
        size_t desc_start = section.size();

        // Short event descriptor (0x4D)
        section.push_back(0x4D);
        size_t desc_size_pos = section.size();
        section.push_back(0x00);

        // the language of the service; "und" (undetermined) when the
        // ensemble does not say it
        for (char c : language) section.push_back(static_cast<uint8_t>(c));

        // event_name with UTF-8 charset prefix (0x15 per EN 300 468)
        section.push_back(static_cast<uint8_t>(name.size() + 1));
        section.push_back(0x15);  // UTF-8
        for (char c : name) section.push_back(static_cast<uint8_t>(c));

        // text with UTF-8 charset prefix
        section.push_back(static_cast<uint8_t>(desc.size() + 1));
        section.push_back(0x15);  // UTF-8
        for (char c : desc) section.push_back(static_cast<uint8_t>(c));

        // Fill descriptor length
        section[desc_size_pos] = static_cast<uint8_t>(section.size() - desc_size_pos - 1);

        // Content descriptor (0x54): what the service broadcasts
        if (content) {
            section.push_back(0x54);
            section.push_back(0x02);
            section.push_back(content);
            section.push_back(0x00);
        }

        // Fill descriptors_loop_length with running_status=1 (not running)
        size_t desc_len = section.size() - desc_start;
        section[desc_len_pos] = 0x20 | ((desc_len >> 8) & 0x0F);  // running_status=1
        section[desc_len_pos + 1] = desc_len & 0xFF;
    }

    // Section length
    size_t section_length = section.size() - 3 + 4;  // +4 for CRC
    section[len_pos] = 0xF0 | ((section_length >> 8) & 0x0F);
    section[len_pos + 1] = section_length & 0xFF;

    // CRC32
    uint32_t crc = dvb_crc32(section.data(), section.size());
    section.push_back((crc >> 24) & 0xFF);
    section.push_back((crc >> 16) & 0xFF);
    section.push_back((crc >> 8) & 0xFF);
    section.push_back(crc & 0xFF);

    return section;
}

} // namespace

std::vector<std::vector<uint8_t>> buildEitScheduleSections(uint16_t service_id, uint16_t tsid, uint16_t onid,
                                                           uint8_t version,
                                                           const std::vector<EpgProgramme>& programmes,
                                                           const std::string& language, uint8_t content) {
    constexpr size_t MAX_SECTION_PAYLOAD = 4000;
    const std::string lang = language.size() == 3 ? language : "und";

    // Pack events into packed
    std::vector<std::vector<const EpgProgramme*>> packed;
    std::vector<const EpgProgramme*> current_section;
    size_t current_size = 14;  // EIT section header size

    for (const auto& prog : programmes) {
        size_t event_size = 12 + 10 + prog.name.size() + prog.description.size() + (content ? 4 : 0);

        if (current_size + event_size > MAX_SECTION_PAYLOAD && !current_section.empty()) {
            packed.push_back(std::move(current_section));
            current_section.clear();
            current_size = 14;
        }

        current_section.push_back(&prog);
        current_size += event_size;
    }

    if (!current_section.empty()) {
        packed.push_back(std::move(current_section));
    }

    if (packed.empty()) return {};

    uint8_t last_section = static_cast<uint8_t>(packed.size() - 1);

    std::vector<std::vector<uint8_t>> sections;
    for (size_t i = 0; i < packed.size(); i++) {
        sections.push_back(buildEitScheduleSection(service_id, tsid, onid, version, 0x50,
            static_cast<uint8_t>(i), last_section, last_section, packed[i], lang, content));
    }
    return sections;
}

std::vector<uint8_t> buildTdtSection(int64_t utc_seconds) {
    auto bcd = [](int v) { return static_cast<uint8_t>((v / 10) << 4 | (v % 10)); };
    int64_t days = utc_seconds / 86400;
    int rest = static_cast<int>(utc_seconds % 86400);
    int mjd = 40587 + static_cast<int>(days);
    // table_id 0x70, section_syntax_indicator 0, section_length 5, no CRC
    return {0x70, 0x70, 0x05, static_cast<uint8_t>(mjd >> 8), static_cast<uint8_t>(mjd),
            bcd(rest / 3600), bcd(rest % 3600 / 60), bcd(rest % 60)};
}

} // namespace dvbdab
