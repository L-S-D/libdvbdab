#include "ts_muxer.hpp"
#include <cstring>
#include <algorithm>

namespace dvbdab {
namespace ts {

// CRC32 table for MPEG PSI (polynomial 0x04C11DB7)
static const uint32_t crc32_table[256] = {
    0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
    0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
    0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
    0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
    0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
    0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
    0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
    0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
    0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
    0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
    0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
    0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
    0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
    0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
    0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
    0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
    0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
    0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
    0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
    0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
    0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
    0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
    0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
    0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
    0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
    0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
    0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
    0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
    0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
    0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
    0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
    0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
    0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
    0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
    0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
    0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
    0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
    0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
    0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
    0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
    0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
    0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
    0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
    0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
    0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
    0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
    0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
    0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
    0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
    0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
    0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
    0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
    0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
    0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
    0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
    0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
    0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
    0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
    0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
    0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
    0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
    0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
    0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
    0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

TsMuxer::TsMuxer() {
    section_buf_.reserve(4096);
}

void TsMuxer::setEnsemble(uint16_t tsid, const std::string& name, const std::string& provider) {
    tsid_ = tsid;
    ensemble_name_ = name;
    provider_name_ = provider;
    pat_version_ = (pat_version_ + 1) & 0x1F;
    sdt_version_ = (sdt_version_ + 1) & 0x1F;
}

void TsMuxer::addService(const TsService& service) {
    services_.push_back(service);
    size_t idx = services_.size() - 1;
    sid_to_index_[service.sid] = idx;
    subch_to_index_[service.subchannel_id] = idx;
    pat_version_ = (pat_version_ + 1) & 0x1F;
    pmt_version_ = (pmt_version_ + 1) & 0x1F;
    sdt_version_ = (sdt_version_ + 1) & 0x1F;
}

void TsMuxer::clearServices() {
    services_.clear();
    sid_to_index_.clear();
    subch_to_index_.clear();
    cc_.clear();
    pes_buffers_.clear();
    pat_version_ = (pat_version_ + 1) & 0x1F;
    pmt_version_ = (pmt_version_ + 1) & 0x1F;
    sdt_version_ = (sdt_version_ + 1) & 0x1F;
}

void TsMuxer::updateServiceLabel(uint16_t sid, const std::string& name) {
    auto it = sid_to_index_.find(sid);
    if (it != sid_to_index_.end() && it->second < services_.size()) {
        if (services_[it->second].name != name) {
            services_[it->second].name = name;
            sdt_version_ = (sdt_version_ + 1) & 0x1F;
        }
    }
}

uint32_t TsMuxer::crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc << 8) ^ crc32_table[((crc >> 24) ^ data[i]) & 0xFF];
    }
    return crc;
}

void TsMuxer::buildPat() {
    section_buf_.clear();

    // PAT header
    section_buf_.push_back(0x00);  // table_id = PAT
    // section_syntax_indicator(1) + '0'(1) + reserved(2) + section_length(12)
    // section_length will be filled later

    size_t length_pos = section_buf_.size();
    section_buf_.push_back(0x00);  // placeholder
    section_buf_.push_back(0x00);  // placeholder

    // transport_stream_id
    section_buf_.push_back((tsid_ >> 8) & 0xFF);
    section_buf_.push_back(tsid_ & 0xFF);

    // reserved(2) + version_number(5) + current_next_indicator(1)
    section_buf_.push_back(0xC1 | ((pat_version_ & 0x1F) << 1));

    // section_number
    section_buf_.push_back(0x00);

    // last_section_number
    section_buf_.push_back(0x00);

    // Program entries
    for (const auto& svc : services_) {
        // program_number
        section_buf_.push_back((svc.sid >> 8) & 0xFF);
        section_buf_.push_back(svc.sid & 0xFF);
        // reserved(3) + program_map_PID(13)
        section_buf_.push_back(0xE0 | ((svc.pmt_pid >> 8) & 0x1F));
        section_buf_.push_back(svc.pmt_pid & 0xFF);
    }

    // Calculate section_length (includes CRC)
    size_t section_length = section_buf_.size() - 3 + 4;  // +4 for CRC
    section_buf_[length_pos] = 0xB0 | ((section_length >> 8) & 0x0F);
    section_buf_[length_pos + 1] = section_length & 0xFF;

    // Add CRC32
    uint32_t crc = crc32(section_buf_.data(), section_buf_.size());
    section_buf_.push_back((crc >> 24) & 0xFF);
    section_buf_.push_back((crc >> 16) & 0xFF);
    section_buf_.push_back((crc >> 8) & 0xFF);
    section_buf_.push_back(crc & 0xFF);

    outputSection(PID_PAT, 0x00, section_buf_);
}

void TsMuxer::buildPmt(const TsService& service) {
    section_buf_.clear();

    // PMT header
    section_buf_.push_back(0x02);  // table_id = PMT

    size_t length_pos = section_buf_.size();
    section_buf_.push_back(0x00);  // placeholder
    section_buf_.push_back(0x00);  // placeholder

    // program_number
    section_buf_.push_back((service.sid >> 8) & 0xFF);
    section_buf_.push_back(service.sid & 0xFF);

    // reserved(2) + version_number(5) + current_next_indicator(1)
    section_buf_.push_back(0xC1 | ((pmt_version_ & 0x1F) << 1));

    // section_number
    section_buf_.push_back(0x00);

    // last_section_number
    section_buf_.push_back(0x00);

    // reserved(3) + PCR_PID(13) - use audio PID for PCR
    section_buf_.push_back(0xE0 | ((service.audio_pid >> 8) & 0x1F));
    section_buf_.push_back(service.audio_pid & 0xFF);

    // reserved(4) + program_info_length(12) = 0
    section_buf_.push_back(0xF0);
    section_buf_.push_back(0x00);

    // Elementary stream entry for audio
    uint8_t stream_type = service.dabplus ? STREAM_TYPE_AAC_ADTS : STREAM_TYPE_MPEG_AUDIO;
    section_buf_.push_back(stream_type);

    // reserved(3) + elementary_PID(13)
    section_buf_.push_back(0xE0 | ((service.audio_pid >> 8) & 0x1F));
    section_buf_.push_back(service.audio_pid & 0xFF);

    // reserved(4) + ES_info_length(12)
    // Add ISO 639 language descriptor (0x0A) - 6 bytes total
    section_buf_.push_back(0xF0);
    section_buf_.push_back(0x06);  // ES_info_length = 6

    // ISO 639 language descriptor
    section_buf_.push_back(0x0A);  // descriptor_tag
    section_buf_.push_back(0x04);  // descriptor_length
    section_buf_.push_back('d');   // language code
    section_buf_.push_back('e');
    section_buf_.push_back('u');
    section_buf_.push_back(0x00);  // audio_type = undefined

    // Calculate section_length
    size_t section_length = section_buf_.size() - 3 + 4;
    section_buf_[length_pos] = 0xB0 | ((section_length >> 8) & 0x0F);
    section_buf_[length_pos + 1] = section_length & 0xFF;

    // Add CRC32
    uint32_t crc = crc32(section_buf_.data(), section_buf_.size());
    section_buf_.push_back((crc >> 24) & 0xFF);
    section_buf_.push_back((crc >> 16) & 0xFF);
    section_buf_.push_back((crc >> 8) & 0xFF);
    section_buf_.push_back(crc & 0xFF);

    outputSection(service.pmt_pid, 0x02, section_buf_);
}

void TsMuxer::buildSdt() {
    section_buf_.clear();

    // SDT header
    section_buf_.push_back(0x42);  // table_id = SDT actual

    size_t length_pos = section_buf_.size();
    section_buf_.push_back(0x00);  // placeholder
    section_buf_.push_back(0x00);  // placeholder

    // transport_stream_id
    section_buf_.push_back((tsid_ >> 8) & 0xFF);
    section_buf_.push_back(tsid_ & 0xFF);

    // reserved(2) + version_number(5) + current_next_indicator(1)
    section_buf_.push_back(0xC1 | ((sdt_version_ & 0x1F) << 1));

    // section_number
    section_buf_.push_back(0x00);

    // last_section_number
    section_buf_.push_back(0x00);

    // original_network_id
    section_buf_.push_back((onid_ >> 8) & 0xFF);
    section_buf_.push_back(onid_ & 0xFF);

    // reserved_future_use
    section_buf_.push_back(0xFF);

    // Service entries
    for (const auto& svc : services_) {
        // service_id
        section_buf_.push_back((svc.sid >> 8) & 0xFF);
        section_buf_.push_back(svc.sid & 0xFF);

        // reserved_future_use(6) + EIT_schedule_flag(1) + EIT_present_following_flag(1)
        section_buf_.push_back(0xFD);  // EIT present/following available (bit 0 = 1)

        // running_status(3) + free_CA_mode(1) + descriptors_loop_length(12)
        // We'll add a service_descriptor (tag 0x48)
        size_t desc_len_pos = section_buf_.size();
        section_buf_.push_back(0x00);  // placeholder
        section_buf_.push_back(0x00);  // placeholder

        size_t desc_start = section_buf_.size();

        // Service descriptor (tag 0x48)
        section_buf_.push_back(0x48);  // descriptor_tag
        size_t desc_length_pos = section_buf_.size();
        section_buf_.push_back(0x00);  // placeholder for descriptor_length

        // service_type: 0x02 = radio
        section_buf_.push_back(0x02);

        // service_provider_name_length + provider name
        std::string provider = svc.provider.empty() ? provider_name_ : svc.provider;
        section_buf_.push_back(static_cast<uint8_t>(provider.size()));
        for (char c : provider) {
            section_buf_.push_back(static_cast<uint8_t>(c));
        }

        // service_name_length + service name
        section_buf_.push_back(static_cast<uint8_t>(svc.name.size()));
        for (char c : svc.name) {
            section_buf_.push_back(static_cast<uint8_t>(c));
        }

        // Fill in descriptor length
        section_buf_[desc_length_pos] = static_cast<uint8_t>(section_buf_.size() - desc_length_pos - 1);

        // Fill in descriptors_loop_length
        size_t desc_loop_len = section_buf_.size() - desc_start;
        section_buf_[desc_len_pos] = 0x80 | ((desc_loop_len >> 8) & 0x0F);  // running_status=4, free_CA=0
        section_buf_[desc_len_pos + 1] = desc_loop_len & 0xFF;
    }

    // Calculate section_length
    size_t section_length = section_buf_.size() - 3 + 4;
    section_buf_[length_pos] = 0xF0 | ((section_length >> 8) & 0x0F);
    section_buf_[length_pos + 1] = section_length & 0xFF;

    // Add CRC32
    uint32_t crc = crc32(section_buf_.data(), section_buf_.size());
    section_buf_.push_back((crc >> 24) & 0xFF);
    section_buf_.push_back((crc >> 16) & 0xFF);
    section_buf_.push_back((crc >> 8) & 0xFF);
    section_buf_.push_back(crc & 0xFF);

    outputSection(PID_SDT, 0x42, section_buf_);
}

void TsMuxer::outputSection(uint16_t pid, uint8_t /*table_id*/, const std::vector<uint8_t>& section_data) {
    if (!output_ || section_data.empty()) return;

    size_t offset = 0;
    bool first = true;

    while (offset < section_data.size()) {
        std::array<uint8_t, PACKET_SIZE> packet{};

        // TS header
        packet[0] = 0x47;  // sync byte
        packet[1] = (first ? 0x40 : 0x00) | ((pid >> 8) & 0x1F);
        packet[2] = pid & 0xFF;

        uint8_t& cc = cc_[pid];
        packet[3] = 0x10 | (cc & 0x0F);  // no adaptation, payload only
        cc = (cc + 1) & 0x0F;

        size_t payload_start = 4;
        size_t payload_len = PACKET_SIZE - payload_start;

        if (first) {
            // Pointer field
            packet[4] = 0x00;
            payload_start = 5;
            payload_len = PACKET_SIZE - payload_start;
            first = false;
        }

        size_t to_copy = std::min(payload_len, section_data.size() - offset);
        std::memcpy(&packet[payload_start], section_data.data() + offset, to_copy);
        offset += to_copy;

        // Fill remaining with 0xFF
        if (to_copy < payload_len) {
            std::memset(&packet[payload_start + to_copy], 0xFF, payload_len - to_copy);
        }

        output_(packet.data());
        packet_count_++;
    }
}

void TsMuxer::outputPsi() {
    buildPat();
    for (const auto& svc : services_) {
        buildPmt(svc);
    }
    buildSdt();
    buildEit();
}

void TsMuxer::setEventInfo(uint16_t sid, const std::string& event_name, const std::string& event_text) {
    auto it = events_.find(sid);
    if (it != events_.end()) {
        // Update existing event
        if (it->second.event_name != event_name || it->second.event_text != event_text) {
            it->second.event_id++;
            it->second.event_name = event_name;
            it->second.event_text = event_text;
            eit_version_ = (eit_version_ + 1) & 0x1F;
        }
    } else {
        // Create new event
        TsEvent event;
        event.event_id = 1;
        event.event_name = event_name;
        event.event_text = event_text;
        event.running_status = 4;  // running
        events_[sid] = event;
        eit_version_ = (eit_version_ + 1) & 0x1F;
    }
}

void TsMuxer::buildEit() {
    if (events_.empty()) return;

    // Build EIT present/following actual (table_id 0x4E)
    // One section per service that has event info

    for (const auto& [sid, event] : events_) {
        section_buf_.clear();

        // EIT header
        section_buf_.push_back(TID_EIT_PF_ACTUAL);

        size_t length_pos = section_buf_.size();
        section_buf_.push_back(0x00);  // placeholder
        section_buf_.push_back(0x00);  // placeholder

        // service_id
        section_buf_.push_back((sid >> 8) & 0xFF);
        section_buf_.push_back(sid & 0xFF);

        // reserved(2) + version_number(5) + current_next_indicator(1)
        section_buf_.push_back(0xC1 | ((eit_version_ & 0x1F) << 1));

        // section_number (0 = present event)
        section_buf_.push_back(0x00);

        // last_section_number (1 = present + following)
        section_buf_.push_back(0x01);

        // transport_stream_id
        section_buf_.push_back((tsid_ >> 8) & 0xFF);
        section_buf_.push_back(tsid_ & 0xFF);

        // original_network_id
        section_buf_.push_back((onid_ >> 8) & 0xFF);
        section_buf_.push_back(onid_ & 0xFF);

        // segment_last_section_number
        section_buf_.push_back(0x01);

        // last_table_id
        section_buf_.push_back(TID_EIT_PF_ACTUAL);

        // Event entry
        // event_id
        section_buf_.push_back((event.event_id >> 8) & 0xFF);
        section_buf_.push_back(event.event_id & 0xFF);

        // start_time (MJD + UTC) - use current time placeholder (all 0xFF = undefined)
        section_buf_.push_back(0xFF);
        section_buf_.push_back(0xFF);
        section_buf_.push_back(0xFF);
        section_buf_.push_back(0xFF);
        section_buf_.push_back(0xFF);

        // duration (BCD HHMMSS) - undefined
        section_buf_.push_back(0xFF);
        section_buf_.push_back(0xFF);
        section_buf_.push_back(0xFF);

        // running_status(3) + free_CA_mode(1) + descriptors_loop_length(12)
        size_t desc_len_pos = section_buf_.size();
        section_buf_.push_back(0x00);  // placeholder
        section_buf_.push_back(0x00);  // placeholder

        size_t desc_start = section_buf_.size();

        // Short event descriptor (tag 0x4D)
        section_buf_.push_back(0x4D);  // descriptor_tag
        size_t desc_length_pos = section_buf_.size();
        section_buf_.push_back(0x00);  // placeholder for descriptor_length

        // ISO 639 language code (3 bytes) - "eng" or "deu" for German
        section_buf_.push_back('d');
        section_buf_.push_back('e');
        section_buf_.push_back('u');

        // event_name_length + event_name
        size_t name_len = std::min(event.event_name.size(), size_t(250));
        section_buf_.push_back(static_cast<uint8_t>(name_len));
        for (size_t i = 0; i < name_len; i++) {
            section_buf_.push_back(static_cast<uint8_t>(event.event_name[i]));
        }

        // text_length + text
        size_t text_len = std::min(event.event_text.size(), size_t(250));
        section_buf_.push_back(static_cast<uint8_t>(text_len));
        for (size_t i = 0; i < text_len; i++) {
            section_buf_.push_back(static_cast<uint8_t>(event.event_text[i]));
        }

        // Fill in descriptor length
        section_buf_[desc_length_pos] = static_cast<uint8_t>(section_buf_.size() - desc_length_pos - 1);

        // Fill in descriptors_loop_length with running_status
        size_t desc_loop_len = section_buf_.size() - desc_start;
        section_buf_[desc_len_pos] = ((event.running_status & 0x07) << 5) | ((desc_loop_len >> 8) & 0x0F);
        section_buf_[desc_len_pos + 1] = desc_loop_len & 0xFF;

        // Calculate section_length
        size_t section_length = section_buf_.size() - 3 + 4;  // +4 for CRC
        section_buf_[length_pos] = 0xF0 | ((section_length >> 8) & 0x0F);
        section_buf_[length_pos + 1] = section_length & 0xFF;

        // Add CRC32
        uint32_t crc = crc32(section_buf_.data(), section_buf_.size());
        section_buf_.push_back((crc >> 24) & 0xFF);
        section_buf_.push_back((crc >> 16) & 0xFF);
        section_buf_.push_back((crc >> 8) & 0xFF);
        section_buf_.push_back(crc & 0xFF);

        outputSection(PID_EIT, TID_EIT_PF_ACTUAL, section_buf_);
    }
}

void TsMuxer::outputNullPacket() {
    if (!output_) return;

    std::array<uint8_t, PACKET_SIZE> packet{};
    packet[0] = 0x47;
    packet[1] = 0x1F;
    packet[2] = 0xFF;
    packet[3] = 0x10;
    std::memset(&packet[4], 0xFF, PACKET_SIZE - 4);

    output_(packet.data());
    packet_count_++;
}

void TsMuxer::feedAudioFrame(uint16_t sid, const uint8_t* data, size_t len, uint64_t pts) {
    auto it = sid_to_index_.find(sid);
    if (it == sid_to_index_.end()) return;

    const TsService& svc = services_[it->second];
    outputPes(svc.audio_pid, 0xC0, data, len, pts);  // 0xC0 = audio stream
}

void TsMuxer::feedSubchannelData(uint8_t subchannel_id, const uint8_t* data, size_t len) {
    auto it = subch_to_index_.find(subchannel_id);
    if (it == subch_to_index_.end()) return;

    const TsService& svc = services_[it->second];
    // For raw subchannel data, use private stream
    outputPes(svc.audio_pid, 0xBD, data, len, 0);  // 0xBD = private stream 1
}

void TsMuxer::outputPes(uint16_t pid, uint8_t stream_id, const uint8_t* data, size_t len, uint64_t pts) {
    if (!output_ || len == 0) return;

    // Determine if we need to insert PCR (every ~4 frames = ~100ms)
    bool insert_pcr = (audio_frame_count_++ % 4 == 0);
    if (insert_pcr) {
        pcr_base_ = pts;  // Use PTS as PCR base
    }

    // Build PES packet
    std::vector<uint8_t> pes;
    pes.reserve(len + 20);

    // PES start code
    pes.push_back(0x00);
    pes.push_back(0x00);
    pes.push_back(0x01);

    // Stream ID
    pes.push_back(stream_id);

    // PES packet length (0 = unbounded for video, but we'll set it for audio)
    size_t pes_len = len + (pts ? 8 : 3);  // header extension + data
    if (pes_len > 0xFFFF) pes_len = 0;  // Too long, use unbounded
    pes.push_back((pes_len >> 8) & 0xFF);
    pes.push_back(pes_len & 0xFF);

    // PES header flags
    // '10' + PES_scrambling_control(2) + PES_priority(1) + data_alignment_indicator(1) + copyright(1) + original_or_copy(1)
    pes.push_back(0x80);

    // PTS_DTS_flags(2) + ESCR_flag(1) + ES_rate_flag(1) + DSM_trick_mode_flag(1) + additional_copy_info_flag(1) + PES_CRC_flag(1) + PES_extension_flag(1)
    pes.push_back(pts ? 0x80 : 0x00);  // PTS present if non-zero

    // PES_header_data_length
    pes.push_back(pts ? 5 : 0);

    // PTS (if present)
    if (pts) {
        // PTS is 33 bits, split across 5 bytes with markers
        pes.push_back(0x21 | ((pts >> 29) & 0x0E));
        pes.push_back((pts >> 22) & 0xFF);
        pes.push_back(0x01 | ((pts >> 14) & 0xFE));
        pes.push_back((pts >> 7) & 0xFF);
        pes.push_back(0x01 | ((pts << 1) & 0xFE));
    }

    // PES payload
    pes.insert(pes.end(), data, data + len);

    // Now packetize into TS packets
    size_t offset = 0;
    bool first = true;

    while (offset < pes.size()) {
        std::array<uint8_t, PACKET_SIZE> packet{};

        packet[0] = 0x47;
        packet[1] = (first ? 0x40 : 0x00) | ((pid >> 8) & 0x1F);
        packet[2] = pid & 0xFF;

        uint8_t& cc = cc_[pid];
        size_t remaining = pes.size() - offset;

        // Insert PCR on first packet if needed
        if (first && insert_pcr) {
            // Adaptation field with PCR: 8 bytes (1 len + 1 flags + 6 PCR)
            size_t adapt_len = 8;
            size_t payload_len = PACKET_SIZE - 4 - adapt_len;

            packet[3] = 0x30 | (cc & 0x0F);  // adaptation + payload
            packet[4] = 7;  // adaptation_field_length (flags + 6 PCR bytes)
            packet[5] = 0x10;  // PCR_flag = 1

            // PCR: 33-bit base (90kHz) + 6 reserved + 9-bit extension
            // For simplicity, set extension to 0
            uint64_t pcr_base = pcr_base_ & 0x1FFFFFFFFULL;  // 33 bits
            packet[6] = (pcr_base >> 25) & 0xFF;
            packet[7] = (pcr_base >> 17) & 0xFF;
            packet[8] = (pcr_base >> 9) & 0xFF;
            packet[9] = (pcr_base >> 1) & 0xFF;
            packet[10] = ((pcr_base & 1) << 7) | 0x7E;  // reserved bits = 1
            packet[11] = 0x00;  // PCR extension = 0

            size_t to_copy = std::min(remaining, payload_len);
            std::memcpy(&packet[12], pes.data() + offset, to_copy);
            offset += to_copy;

            // Stuff if needed
            if (to_copy < payload_len) {
                std::memset(&packet[12 + to_copy], 0xFF, payload_len - to_copy);
            }
        } else if (remaining < PACKET_SIZE - 4) {
            // Need adaptation field for stuffing
            size_t payload_len = PACKET_SIZE - 4;
            size_t stuff_len = payload_len - remaining - 1;
            if (stuff_len == 0) {
                // Just adaptation_field_length = 0
                packet[3] = 0x30 | (cc & 0x0F);
                packet[4] = 0x00;
                std::memcpy(&packet[5], pes.data() + offset, remaining);
            } else {
                packet[3] = 0x30 | (cc & 0x0F);
                packet[4] = static_cast<uint8_t>(stuff_len);
                packet[5] = 0x00;  // flags
                if (stuff_len > 1) {
                    std::memset(&packet[6], 0xFF, stuff_len - 1);
                }
                std::memcpy(&packet[4 + stuff_len + 1], pes.data() + offset, remaining);
            }
            offset = pes.size();
        } else {
            packet[3] = 0x10 | (cc & 0x0F);
            std::memcpy(&packet[4], pes.data() + offset, PACKET_SIZE - 4);
            offset += PACKET_SIZE - 4;
        }

        cc = (cc + 1) & 0x0F;
        first = false;

        output_(packet.data());
        packet_count_++;
    }
}

void TsMuxer::writePacket(uint16_t pid, bool pusi, const uint8_t* payload, size_t len) {
    if (!output_) return;

    std::array<uint8_t, PACKET_SIZE> packet{};

    packet[0] = 0x47;
    packet[1] = (pusi ? 0x40 : 0x00) | ((pid >> 8) & 0x1F);
    packet[2] = pid & 0xFF;

    uint8_t& cc = cc_[pid];
    packet[3] = 0x10 | (cc & 0x0F);
    cc = (cc + 1) & 0x0F;

    size_t copy_len = std::min(len, PACKET_SIZE - 4);
    std::memcpy(&packet[4], payload, copy_len);

    if (copy_len < PACKET_SIZE - 4) {
        std::memset(&packet[4 + copy_len], 0xFF, PACKET_SIZE - 4 - copy_len);
    }

    output_(packet.data());
    packet_count_++;
}

} // namespace ts
} // namespace dvbdab
