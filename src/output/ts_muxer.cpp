#include "ts_muxer.hpp"
#include "../utils/crc_utils.hpp"
#include <algorithm>

namespace dvbdab {

TsMuxer::TsMuxer() = default;

uint32_t TsMuxer::dvbCrc32(const uint8_t* data, size_t len) {
    return dvb_crc32(data, len);
}

void TsMuxer::setEnsemble(uint16_t tsid, const std::string& name, const std::string& provider) {
    tsid_ = tsid;
    ensemble_name_ = name;
    provider_name_ = provider;
    onid_ = tsid;  // Use same as TSID for simplicity
}

void TsMuxer::addService(const TsService& service) {
    services_.push_back(service);
    sid_to_index_[service.sid] = services_.size() - 1;
    subch_to_sid_[service.subchannel_id] = service.sid;
    cc_[service.pmt_pid] = 0;
    cc_[service.audio_pid] = 0;
    frames_since_pcr_[service.audio_pid] = 0;
}

void TsMuxer::updateServiceLabel(uint16_t sid, const std::string& name) {
    auto it = sid_to_index_.find(sid);
    if (it != sid_to_index_.end()) {
        services_[it->second].name = name;
        sdt_version_ = (sdt_version_ + 1) & 0x1F;
    }
}

void TsMuxer::setNowPlaying(uint16_t sid, const std::string& title, const std::string& artist) {
    auto& np = now_playing_[sid];
    if (np.title != title || np.artist != artist) {
        np.title = title;
        np.artist = artist;
        np.event_id++;
        // EIT p/f disabled - we don't have proper duration or following event info
        // EIT schedule (0x50) from EHB data provides the real EPG
    }
}

void TsMuxer::writePacket(const uint8_t* packet) {
    if (output_) {
        output_(packet, TS_MUXER_PACKET_SIZE);
        packet_count_++;
    }
}

void TsMuxer::outputSection(uint16_t pid, const std::vector<uint8_t>& section, bool set_discontinuity) {
    if (section.empty()) return;

    size_t offset = 0;
    bool first = true;

    while (offset < section.size()) {
        uint8_t packet[TS_MUXER_PACKET_SIZE];
        std::fill(packet, packet + TS_MUXER_PACKET_SIZE, 0xFF);

        // TS header
        packet[0] = 0x47;  // Sync byte
        packet[1] = (first ? 0x40 : 0x00) | ((pid >> 8) & 0x1F);
        packet[2] = pid & 0xFF;

        uint8_t& cc = cc_[pid];

        size_t payload_start;
        if (first && set_discontinuity) {
            // Add adaptation field with discontinuity_indicator for EIT version changes
            packet[3] = 0x30 | (cc & 0x0F);  // Adaptation + payload
            packet[4] = 1;  // Adaptation field length
            packet[5] = 0x80;  // discontinuity_indicator=1
            packet[6] = 0x00;  // Pointer field
            payload_start = 7;
            set_discontinuity = false;  // Only on first packet
        } else {
            packet[3] = 0x10 | (cc & 0x0F);  // Payload only, no adaptation
            payload_start = 4;
            if (first) {
                packet[4] = 0x00;  // Pointer field
                payload_start = 5;
            }
        }
        cc = (cc + 1) & 0x0F;

        if (first) first = false;

        size_t payload_len = TS_MUXER_PACKET_SIZE - payload_start;
        size_t to_copy = std::min(payload_len, section.size() - offset);
        std::copy(section.data() + offset, section.data() + offset + to_copy, packet + payload_start);
        offset += to_copy;

        writePacket(packet);
    }
}

void TsMuxer::outputPat() {
    std::vector<uint8_t> section;
    section.reserve(64);  // PAT: ~12 bytes header + 4 bytes/service + 4 bytes CRC

    // table_id = 0x00 (PAT)
    section.push_back(0x00);

    // section_syntax_indicator(1) + '0'(1) + reserved(2) + section_length(12)
    size_t len_pos = section.size();
    section.push_back(0x00);
    section.push_back(0x00);

    // transport_stream_id
    section.push_back((tsid_ >> 8) & 0xFF);
    section.push_back(tsid_ & 0xFF);

    // reserved(2) + version_number(5) + current_next_indicator(1)
    section.push_back(0xC1 | ((pat_version_ & 0x1F) << 1));

    // section_number
    section.push_back(0x00);

    // last_section_number
    section.push_back(0x00);

    // Program entries
    for (const auto& svc : services_) {
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
    uint32_t crc = dvbCrc32(section.data(), section.size());
    section.push_back((crc >> 24) & 0xFF);
    section.push_back((crc >> 16) & 0xFF);
    section.push_back((crc >> 8) & 0xFF);
    section.push_back(crc & 0xFF);

    outputSection(PID_PAT, section);
}

void TsMuxer::outputPmt(const TsService& service) {
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
    section.push_back(0xC1 | ((pmt_version_ & 0x1F) << 1));

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
    uint8_t stream_type = service.dabplus ? STREAM_TYPE_AAC_ADTS : STREAM_TYPE_MPEG_AUDIO;
    section.push_back(stream_type);

    // reserved(3) + elementary_PID(13)
    section.push_back(0xE0 | ((service.audio_pid >> 8) & 0x1F));
    section.push_back(service.audio_pid & 0xFF);

    // reserved(4) + ES_info_length(12) = 0
    section.push_back(0xF0);
    section.push_back(0x00);

    // Section length
    size_t section_length = section.size() - 3 + 4;
    section[len_pos] = 0xB0 | ((section_length >> 8) & 0x0F);
    section[len_pos + 1] = section_length & 0xFF;

    // CRC32
    uint32_t crc = dvbCrc32(section.data(), section.size());
    section.push_back((crc >> 24) & 0xFF);
    section.push_back((crc >> 16) & 0xFF);
    section.push_back((crc >> 8) & 0xFF);
    section.push_back(crc & 0xFF);

    outputSection(service.pmt_pid, section);
}

void TsMuxer::outputSdt() {
    std::vector<uint8_t> section;
    section.reserve(256);  // SDT: ~14 bytes header + variable per service + 4 bytes CRC

    // table_id = 0x42 (SDT actual)
    section.push_back(0x42);

    size_t len_pos = section.size();
    section.push_back(0x00);
    section.push_back(0x00);

    // transport_stream_id
    section.push_back((tsid_ >> 8) & 0xFF);
    section.push_back(tsid_ & 0xFF);

    // reserved(2) + version_number(5) + current_next_indicator(1)
    section.push_back(0xC1 | ((sdt_version_ & 0x1F) << 1));

    // section_number
    section.push_back(0x00);

    // last_section_number
    section.push_back(0x00);

    // original_network_id
    section.push_back((onid_ >> 8) & 0xFF);
    section.push_back(onid_ & 0xFF);

    // reserved_future_use
    section.push_back(0xFF);

    // Service entries
    for (const auto& svc : services_) {
        section.push_back((svc.sid >> 8) & 0xFF);
        section.push_back(svc.sid & 0xFF);

        // reserved(6) + EIT_schedule_flag(1) + EIT_present_following_flag(1)
        section.push_back(0xFF);  // Both EIT flags set

        // running_status(3) + free_CA_mode(1) + descriptors_loop_length(12)
        size_t desc_len_pos = section.size();
        section.push_back(0x00);
        section.push_back(0x00);
        size_t desc_start = section.size();

        // Service descriptor (0x48)
        section.push_back(0x48);
        size_t desc_size_pos = section.size();
        section.push_back(0x00);

        // service_type = 0x02 (radio)
        section.push_back(0x02);

        // provider_name
        std::string provider = svc.provider.empty() ? provider_name_ : svc.provider;
        section.push_back(static_cast<uint8_t>(provider.size()));
        for (char c : provider) section.push_back(static_cast<uint8_t>(c));

        // service_name
        section.push_back(static_cast<uint8_t>(svc.name.size()));
        for (char c : svc.name) section.push_back(static_cast<uint8_t>(c));

        // Fill descriptor length
        section[desc_size_pos] = static_cast<uint8_t>(section.size() - desc_size_pos - 1);

        // Fill descriptors_loop_length with running_status=4 (running)
        size_t desc_len = section.size() - desc_start;
        section[desc_len_pos] = 0x80 | ((desc_len >> 8) & 0x0F);  // running=4, free_CA=0
        section[desc_len_pos + 1] = desc_len & 0xFF;
    }

    // Section length
    size_t section_length = section.size() - 3 + 4;
    section[len_pos] = 0xF0 | ((section_length >> 8) & 0x0F);
    section[len_pos + 1] = section_length & 0xFF;

    // CRC32
    uint32_t crc = dvbCrc32(section.data(), section.size());
    section.push_back((crc >> 24) & 0xFF);
    section.push_back((crc >> 16) & 0xFF);
    section.push_back((crc >> 8) & 0xFF);
    section.push_back(crc & 0xFF);

    outputSection(PID_SDT, section);
}

// Helper to build one EIT p/f section
std::vector<uint8_t> TsMuxer::buildEitSection(uint16_t sid, uint8_t section_number,
    uint16_t event_id, time_t start_time, const std::string& event_name, bool is_running) {

    std::vector<uint8_t> section;
    section.reserve(128);  // EIT p/f: ~40 bytes header + event name + 4 bytes CRC

    // table_id = 0x4E (EIT p/f actual)
    section.push_back(0x4E);

    size_t len_pos = section.size();
    section.push_back(0x00);
    section.push_back(0x00);

    // service_id
    section.push_back((sid >> 8) & 0xFF);
    section.push_back(sid & 0xFF);

    // reserved(2) + version_number(5) + current_next_indicator(1)
    // Use fixed version 0 to avoid discontinuity errors in decoders
    section.push_back(0xC1);  // version=0, current_next=1

    // section_number (0=present, 1=following)
    section.push_back(section_number);

    // last_section_number = 1 (present + following)
    section.push_back(0x01);

    // transport_stream_id
    section.push_back((tsid_ >> 8) & 0xFF);
    section.push_back(tsid_ & 0xFF);

    // original_network_id
    section.push_back((onid_ >> 8) & 0xFF);
    section.push_back(onid_ & 0xFF);

    // segment_last_section_number = 1
    section.push_back(0x01);

    // last_table_id
    section.push_back(0x4E);

    // Event entry
    section.push_back((event_id >> 8) & 0xFF);
    section.push_back(event_id & 0xFF);

    // start_time in MJD + BCD
    int64_t days = start_time / 86400;
    int mjd = 40587 + static_cast<int>(days);
    section.push_back((mjd >> 8) & 0xFF);
    section.push_back(mjd & 0xFF);

    struct tm* utc = gmtime(&start_time);
    auto toBcd = [](int v) -> uint8_t { return ((v / 10) << 4) | (v % 10); };
    section.push_back(toBcd(utc->tm_hour));
    section.push_back(toBcd(utc->tm_min));
    section.push_back(toBcd(utc->tm_sec));

    // duration: 01:00:00
    section.push_back(0x01);
    section.push_back(0x00);
    section.push_back(0x00);

    // running_status(3) + free_CA_mode(1) + descriptors_loop_length(12)
    // running_status: 4=running, 1=not running
    size_t desc_len_pos = section.size();
    section.push_back(0x00);
    section.push_back(0x00);
    size_t desc_start = section.size();

    // Short event descriptor (0x4D)
    section.push_back(0x4D);
    size_t desc_size_pos = section.size();
    section.push_back(0x00);

    // language = "ger"
    section.push_back('g');
    section.push_back('e');
    section.push_back('r');

    // event_name
    size_t name_len = std::min(event_name.size(), size_t(250));
    section.push_back(static_cast<uint8_t>(name_len));
    for (size_t i = 0; i < name_len; i++) {
        section.push_back(static_cast<uint8_t>(event_name[i]));
    }

    // text (empty)
    section.push_back(0x00);

    // Fill descriptor length
    section[desc_size_pos] = static_cast<uint8_t>(section.size() - desc_size_pos - 1);

    // Fill descriptors_loop_length with running_status
    // running_status: 4=running (0x80), 1=not running (0x20)
    uint8_t running_bits = is_running ? 0x80 : 0x20;  // 4<<5=0x80, 1<<5=0x20
    size_t desc_len = section.size() - desc_start;
    section[desc_len_pos] = running_bits | ((desc_len >> 8) & 0x0F);
    section[desc_len_pos + 1] = desc_len & 0xFF;

    // Section length
    size_t section_length = section.size() - 3 + 4;
    section[len_pos] = 0xF0 | ((section_length >> 8) & 0x0F);
    section[len_pos + 1] = section_length & 0xFF;

    // CRC32
    uint32_t crc = dvbCrc32(section.data(), section.size());
    section.push_back((crc >> 24) & 0xFF);
    section.push_back((crc >> 16) & 0xFF);
    section.push_back((crc >> 8) & 0xFF);
    section.push_back(crc & 0xFF);

    return section;
}

void TsMuxer::outputEit(uint16_t sid) {
    auto it = now_playing_.find(sid);
    if (it == now_playing_.end()) return;

    const auto& np = it->second;
    std::string event_name = np.artist.empty() ? np.title : (np.artist + " - " + np.title);
    if (event_name.empty()) return;

    time_t now = time(nullptr);

    // Section 0: Present event (running)
    auto section0 = buildEitSection(sid, 0, np.event_id, now, event_name, true);
    outputSection(PID_EIT, section0);

    // Section 1: Following event (not running) - starts 1 hour from now
    auto section1 = buildEitSection(sid, 1, np.event_id + 1, now + 3600, event_name, false);
    outputSection(PID_EIT, section1);
}

void TsMuxer::updateSchedule(uint16_t service_id, const EpgSchedule& schedule) {
    if (schedule.programmes.empty()) return;

    // Merge programmes into existing schedule (EHB sends partial schedules)
    auto& existing = service_schedules_[service_id];
    existing.service_id = schedule.service_id;
    existing.service_name = schedule.service_name;
    existing.last_update = schedule.last_update;

    // Add new programmes (avoid duplicates by start_time)
    for (const auto& prog : schedule.programmes) {
        bool found = false;
        for (const auto& existing_prog : existing.programmes) {
            if (existing_prog.start_time == prog.start_time) {
                found = true;
                break;
            }
        }
        if (!found) {
            existing.programmes.push_back(prog);
            // Mark that this service has pending changes
            schedule_changed_[service_id] = true;
        }
    }

    // Sort by start_time for proper EPG ordering and duration adjustment
    std::sort(existing.programmes.begin(), existing.programmes.end(),
        [](const EpgProgramme& a, const EpgProgramme& b) {
            return a.start_time < b.start_time;
        });

    // Adjust "all day" placeholder durations (86400 = 24 hours, mapped from DAB EPG max ~18:12)
    // to end at the start of the next event
    for (size_t i = 0; i < existing.programmes.size(); i++) {
        auto& prog = existing.programmes[i];
        if (prog.duration_seconds == 86400 && i + 1 < existing.programmes.size()) {
            // There's a next event - adjust duration to end at its start
            time_t next_start = existing.programmes[i + 1].start_time;
            if (next_start > prog.start_time) {
                prog.duration_seconds = static_cast<int>(next_start - prog.start_time);
                schedule_changed_[service_id] = true;
            }
        }
    }

    // Mark that we have pending changes - will be applied at next carousel cycle
    if (schedule_changed_[service_id]) {
        eit_carousel_pending_ = true;
    }
}

void TsMuxer::outputEitScheduleCarousel() {
    if (!output_ || service_schedules_.empty()) return;

    // First, apply any pending changes and increment versions
    if (eit_carousel_pending_) {
        for (auto& [service_id, changed] : schedule_changed_) {
            if (changed) {
                eit_schedule_version_[service_id] = (eit_schedule_version_[service_id] + 1) & 0x1F;
                changed = false;
            }
        }
        eit_carousel_pending_ = false;
    }

    // Output complete EIT table for ALL services
    // This ensures decoders see complete table before any version change
    constexpr size_t MAX_SECTION_PAYLOAD = 4000;

    for (const auto& [service_id, schedule] : service_schedules_) {
        if (schedule.programmes.empty()) continue;

        // Pack events into sections
        std::vector<std::vector<const EpgProgramme*>> sections;
        std::vector<const EpgProgramme*> current_section;
        size_t current_size = 14;  // EIT section header size

        for (const auto& prog : schedule.programmes) {
            size_t event_size = 12 + 10 + prog.name.size() + prog.description.size();

            if (current_size + event_size > MAX_SECTION_PAYLOAD && !current_section.empty()) {
                sections.push_back(std::move(current_section));
                current_section.clear();
                current_size = 14;
            }

            current_section.push_back(&prog);
            current_size += event_size;
        }

        if (!current_section.empty()) {
            sections.push_back(std::move(current_section));
        }

        if (sections.empty()) continue;

        uint8_t last_section = static_cast<uint8_t>(sections.size() - 1);

        size_t event_base = 0;
        for (size_t i = 0; i < sections.size(); i++) {
            auto section = buildEitScheduleSection(service_id, 0x50,
                static_cast<uint8_t>(i), last_section, last_section, sections[i], event_base);
            outputSection(PID_EIT, section);
            event_base += sections[i].size();
        }
    }
}

std::vector<uint8_t> TsMuxer::buildEitScheduleSection(uint16_t service_id, uint8_t table_id,
    uint8_t section_number, uint8_t last_section_number, uint8_t segment_last_section,
    const std::vector<const EpgProgramme*>& events, size_t event_base) {

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
    uint8_t version = eit_schedule_version_[service_id] & 0x1F;
    section.push_back(0xC1 | (version << 1));

    // section_number
    section.push_back(section_number);

    // last_section_number (highest section across all segments)
    section.push_back(last_section_number);

    // transport_stream_id
    section.push_back((tsid_ >> 8) & 0xFF);
    section.push_back(tsid_ & 0xFF);

    // original_network_id
    section.push_back((onid_ >> 8) & 0xFF);
    section.push_back(onid_ & 0xFF);

    // segment_last_section_number (highest section within this 3-hour segment)
    section.push_back(segment_last_section);

    // last_table_id
    section.push_back(table_id);

    // Add events
    auto toBcd = [](int val) -> uint8_t { return ((val / 10) << 4) | (val % 10); };

    for (size_t i = 0; i < events.size(); i++) {
        const EpgProgramme* prog = events[i];

        // event_id - unique per event: high byte from SID, low byte sequential index
        uint16_t event_id = (service_id & 0xFF00) | ((event_base + i) & 0xFF);
        section.push_back((event_id >> 8) & 0xFF);
        section.push_back(event_id & 0xFF);

        // start_time: MJD(2) + BCD time(3)
        int64_t days = prog->start_time / 86400;
        int mjd = 40587 + static_cast<int>(days);
        section.push_back((mjd >> 8) & 0xFF);
        section.push_back(mjd & 0xFF);

        struct tm* utc = gmtime(&prog->start_time);
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
        std::string name = prog->name.substr(0, 120);
        std::string desc = prog->description.substr(0, 120);

        // descriptors_loop_length placeholder
        size_t desc_len_pos = section.size();
        section.push_back(0x00);
        section.push_back(0x00);
        size_t desc_start = section.size();

        // Short event descriptor (0x4D)
        section.push_back(0x4D);
        size_t desc_size_pos = section.size();
        section.push_back(0x00);

        // language = "ger"
        section.push_back('g');
        section.push_back('e');
        section.push_back('r');

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
    uint32_t crc = dvbCrc32(section.data(), section.size());
    section.push_back((crc >> 24) & 0xFF);
    section.push_back((crc >> 16) & 0xFF);
    section.push_back((crc >> 8) & 0xFF);
    section.push_back(crc & 0xFF);

    return section;
}

void TsMuxer::outputPes(uint16_t pid, const uint8_t* data, size_t len, int64_t pts, bool insert_pcr, int64_t pcr) {
    // Build PES packet
    std::vector<uint8_t> pes;
    pes.reserve(len + 20);

    // PES start code prefix
    pes.push_back(0x00);
    pes.push_back(0x00);
    pes.push_back(0x01);

    // Stream ID: 0xC0 = audio stream 0
    pes.push_back(0xC0);

    // PES packet length (6 bytes header + 5 PTS + data)
    // 0 = unbounded for large packets
    size_t pes_len = 3 + 5 + len;  // flags(2) + header_len(1) + PTS(5) + data
    if (pes_len > 0xFFFF) pes_len = 0;
    pes.push_back((pes_len >> 8) & 0xFF);
    pes.push_back(pes_len & 0xFF);

    // '10' + scrambling(2) + priority(1) + alignment(1) + copyright(1) + original(1)
    pes.push_back(0x80);

    // PTS_DTS_flags(2)=10 + other flags = 0x80
    pes.push_back(0x80);

    // PES_header_data_length = 5 (PTS only)
    pes.push_back(0x05);

    // PTS (33 bits in 5 bytes with markers)
    // Format: '0010' + PTS[32:30] + '1' + PTS[29:15] + '1' + PTS[14:0] + '1'
    int64_t pts33 = pts & 0x1FFFFFFFFLL;
    pes.push_back(0x21 | ((pts33 >> 29) & 0x0E));
    pes.push_back((pts33 >> 22) & 0xFF);
    pes.push_back(0x01 | ((pts33 >> 14) & 0xFE));
    pes.push_back((pts33 >> 7) & 0xFF);
    pes.push_back(0x01 | ((pts33 << 1) & 0xFE));

    // Audio data
    pes.insert(pes.end(), data, data + len);

    // Packetize into TS packets
    size_t offset = 0;
    bool first = true;

    while (offset < pes.size()) {
        uint8_t packet[TS_MUXER_PACKET_SIZE];
        std::fill(packet, packet + TS_MUXER_PACKET_SIZE, 0xFF);

        packet[0] = 0x47;
        packet[1] = (first ? 0x40 : 0x00) | ((pid >> 8) & 0x1F);
        packet[2] = pid & 0xFF;

        uint8_t& cc = cc_[pid];
        size_t remaining = pes.size() - offset;

        if (first && insert_pcr) {
            // First packet with adaptation field containing PCR
            // Adaptation field: length(1) + flags(1) + PCR(6) = 8 bytes
            packet[3] = 0x30 | (cc & 0x0F);  // adaptation + payload
            packet[4] = 7;  // adaptation_field_length
            packet[5] = 0x10;  // PCR_flag = 1

            // PCR: 33-bit base (90kHz * 300 = 27MHz) + 6 reserved + 9-bit extension
            // pcr is already in 27MHz (pts * 300)
            int64_t pcr_base = (pcr / 300) & 0x1FFFFFFFFLL;  // Back to 90kHz for base
            uint16_t pcr_ext = pcr % 300;  // Extension (0-299)

            // Actually PCR format: base(33) + reserved(6) + extension(9) = 48 bits
            // Let's use the full 27MHz value directly
            int64_t pcr27 = pcr & 0x1FFFFFFFFLL;  // 33 bits for base at 27MHz...
            // Wait, that's not right. Let me recalculate.
            // PCR = base * 300 + extension, where base is 33 bits at 90kHz
            // So: pcr_base (33 bits, 90kHz) = pcr / 300
            //     pcr_ext (9 bits, 0-299) = pcr % 300
            pcr_base = (pcr / 300) & 0x1FFFFFFFFLL;
            pcr_ext = pcr % 300;

            packet[6] = (pcr_base >> 25) & 0xFF;
            packet[7] = (pcr_base >> 17) & 0xFF;
            packet[8] = (pcr_base >> 9) & 0xFF;
            packet[9] = (pcr_base >> 1) & 0xFF;
            packet[10] = ((pcr_base & 1) << 7) | 0x7E | ((pcr_ext >> 8) & 0x01);
            packet[11] = pcr_ext & 0xFF;

            size_t payload_start = 12;
            size_t payload_len = TS_MUXER_PACKET_SIZE - payload_start;
            size_t to_copy = std::min(remaining, payload_len);
            std::copy(pes.data() + offset, pes.data() + offset + to_copy, packet + payload_start);
            offset += to_copy;
        } else if (remaining < TS_MUXER_PACKET_SIZE - 4) {
            // Need stuffing - use adaptation field
            size_t stuff_needed = (TS_MUXER_PACKET_SIZE - 4) - remaining;

            if (stuff_needed == 1) {
                // Just adaptation_field_length = 0
                packet[3] = 0x30 | (cc & 0x0F);
                packet[4] = 0x00;
                std::copy(pes.data() + offset, pes.data() + offset + remaining, packet + 5);
            } else {
                packet[3] = 0x30 | (cc & 0x0F);
                packet[4] = static_cast<uint8_t>(stuff_needed - 1);
                packet[5] = 0x00;  // flags
                if (stuff_needed > 2) {
                    std::fill(packet + 6, packet + 6 + stuff_needed - 2, 0xFF);
                }
                std::copy(pes.data() + offset, pes.data() + offset + remaining, packet + 4 + stuff_needed);
            }
            offset = pes.size();
        } else {
            // Full payload, no adaptation
            packet[3] = 0x10 | (cc & 0x0F);
            std::copy(pes.data() + offset, pes.data() + offset + TS_MUXER_PACKET_SIZE - 4, packet + 4);
            offset += TS_MUXER_PACKET_SIZE - 4;
        }

        cc = (cc + 1) & 0x0F;
        first = false;
        writePacket(packet);
    }
}

void TsMuxer::flushAudioBuffer(uint16_t sid) {
    auto it = sid_to_index_.find(sid);
    if (it == sid_to_index_.end()) return;

    const auto& svc = services_[it->second];
    uint16_t audio_pid = svc.audio_pid;
    auto& buf = audio_buffers_[sid];

    if (buf.data.empty()) return;

    // Determine if we should insert PCR
    // Use global PCR timeline to avoid jitter when switching between programs
    bool insert_pcr = false;
    int64_t pcr = buf.first_pts * 300;  // Convert 90kHz PTS to 27MHz PCR

    // Update global PCR to track maximum across all services
    if (pcr > global_pcr_) {
        global_pcr_ = pcr;
    }

    // Use global PCR for output to ensure monotonic timeline
    int64_t output_pcr = global_pcr_;

    if (frames_since_pcr_[audio_pid] == 0) {
        // First frame for this PID - insert PCR
        insert_pcr = true;
        frames_since_pcr_[audio_pid] = 1;
    } else {
        frames_since_pcr_[audio_pid] += buf.frame_count;
        if (frames_since_pcr_[audio_pid] >= 3) {
            insert_pcr = true;
            frames_since_pcr_[audio_pid] = 0;
        }
    }

    outputPes(audio_pid, buf.data.data(), buf.data.size(), buf.first_pts, insert_pcr, output_pcr);

    buf.data.clear();
    buf.frame_count = 0;
}

void TsMuxer::feedAudioFrame(uint16_t sid, const uint8_t* data, size_t len, int64_t pts) {
    auto it = sid_to_index_.find(sid);
    if (it == sid_to_index_.end() || len == 0) return;

    // Time-based PSI output (DVB compliant: PAT/PMT every 500ms, SDT every 2s)
    // Track maximum PTS seen to handle multi-service streams where each service has different PTS
    if (pts > last_psi_pts_) {
        bool output_psi = (last_psi_pts_ < 0) || (pts - last_psi_pts_ >= PSI_INTERVAL_PTS);
        if (output_psi) {
            last_psi_pts_ = pts;
            outputPat();
            for (const auto& s : services_) {
                outputPmt(s);
            }

            // SDT every 2 seconds (DVB max interval)
            if (last_sdt_pts_ < 0 || pts - last_sdt_pts_ >= SDT_INTERVAL_PTS) {
                last_sdt_pts_ = pts;
                outputSdt();
            }
        }
    }

    // EIT schedule carousel - output complete table periodically
    if (++frames_since_eit_ >= eit_carousel_interval_) {
        frames_since_eit_ = 0;
        outputEitScheduleCarousel();
    }

    // Buffer audio frames for PES aggregation (reduces overhead like FFmpeg)
    auto& buf = audio_buffers_[sid];

    // Store first PTS for this buffer
    if (buf.data.empty()) {
        buf.first_pts = pts;
    }

    // Append frame to buffer
    buf.data.insert(buf.data.end(), data, data + len);
    buf.frame_count++;

    // Flush when buffer reaches target size
    if (buf.data.size() >= PES_TARGET_SIZE) {
        flushAudioBuffer(sid);
    }
}

// FfmpegTsMuxer compatibility: feed by subchannel_id
void TsMuxer::feedAudioFrame(uint8_t subchannel_id, const uint8_t* data, size_t len, int64_t pts) {
    auto it = subch_to_sid_.find(subchannel_id);
    if (it != subch_to_sid_.end()) {
        feedAudioFrame(it->second, data, len, pts);
    }
}

// FfmpegTsMuxer compatibility: set now-playing by subchannel_id
void TsMuxer::setNowPlayingBySubch(uint8_t subchannel_id, const std::string& title, const std::string& artist) {
    auto it = subch_to_sid_.find(subchannel_id);
    if (it != subch_to_sid_.end()) {
        setNowPlaying(it->second, title, artist);
    }
}

// FfmpegTsMuxer compatibility: update service label by subchannel_id
void TsMuxer::updateServiceLabelBySubch(uint8_t subchannel_id, const std::string& name) {
    auto it = subch_to_sid_.find(subchannel_id);
    if (it != subch_to_sid_.end()) {
        updateServiceLabel(it->second, name);
    }
}

} // namespace dvbdab
