// PAD (Programme Associated Data) of DAB and DAB+ audio: dynamic labels and DL Plus
// References: ETSI EN 300 401 (clause 7.4), ETSI TS 102 980, ETSI TS 102 563

#include "pad_decoder.hpp"
#include "charsets.hpp"
#include "../logging.h"

#include <algorithm>

namespace dvbdab {

namespace {

// X-PAD data subfield lengths by the length indicator of a contents indicator (table 26)
constexpr size_t XPAD_SUBFIELD_LEN[8] = {4, 6, 8, 12, 16, 24, 32, 48};

// X-PAD application types (table 27)
constexpr uint8_t APP_DL_START = 2;
constexpr uint8_t APP_DL_CONT = 3;

// the application type that continues one (start of a data group -> its continuation)
uint8_t continuation(uint8_t app_type) {
    switch (app_type) {
    case 2: return 3;    // dynamic label
    case 12: return 13;  // MOT
    case 14: return 15;  // MOT, conditional access
    default: return app_type;
    }
}

// CRC of an X-PAD data group: CCITT (x^16 + x^12 + x^5 + 1), preset to ones, sent inverted
uint16_t crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= static_cast<uint16_t>(data[i] << 8);
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? static_cast<uint16_t>((crc << 1) ^ 0x1021) : static_cast<uint16_t>(crc << 1);
    }
    return static_cast<uint16_t>(~crc);
}

} // namespace

PadDecoder::PadDecoder() = default;
PadDecoder::~PadDecoder() = default;

void PadDecoder::reset() {
    last_type_ = 0;
    last_len_ = 0;
    dg_.clear();
    dg_need_ = 0;
    dg_active_ = false;
    seg_toggle_ = -1;
    for (auto& s : seg_) s.clear();
    seg_have_ = 0;
    seg_last_ = -1;
    label_toggle_ = -1;
    label_text_.clear();
    label_done_ = false;
    tags_.clear();
    tags_link_ = -1;
    tags_done_ = false;
    pad_count_ = dls_count_ = dlplus_count_ = crc_errors_ = 0;
}

void PadDecoder::discontinuity() {
    // a data group and an X-PAD continuation do not go on over lost frames;
    // segments already checked stay (a label is sent again and again)
    dg_.clear();
    dg_need_ = 0;
    dg_active_ = false;
    last_type_ = 0;
    last_len_ = 0;
}

void PadDecoder::processAu(const uint8_t* au, size_t au_len) {
    // TS 102 563: the PAD is in a data stream element (ID_DSE = 4) at the start of the AU:
    // element_id (3 bits), element_instance_tag (4), data_byte_align_flag (1), count (8)
    // [esc_count (8) when count is 255], the data bytes
    if (au_len < 2 || (au[0] >> 5) != 4) return;
    size_t start = 2;
    size_t count = au[1];
    if (count == 255) {
        if (au_len < 3) return;
        count += au[2];
        start = 3;
    }
    if (count < 2 || start + count > au_len) return;
    process(au + start, count - 2, au + start + count - 2);
}

void PadDecoder::process(const uint8_t* xpad, size_t room, const uint8_t* fpad) {
    pad_count_++;
    // F-PAD type 00: byte L-1 has the X-PAD indicator; byte L the contents indicator flag
    if ((fpad[0] >> 6) != 0) return;
    uint8_t xpad_ind = (fpad[0] >> 4) & 0x03;
    bool ci_flag = (fpad[1] & 0x02) != 0;
    // byte k of the X-PAD (its bytes are in reverse order at the end of the room)
    auto xb = [&](size_t k) { return xpad[room - 1 - k]; };
    uint8_t buf[48];

    if (xpad_ind == 1) {
        // short X-PAD: 4 bytes, with a contents indicator the first of them
        if (room < 4) return;
        size_t at = 0;
        uint8_t app = continuation(last_type_);
        if (ci_flag) {
            app = xb(0) & 0x1F;
            at = 1;
        }
        size_t n = 4 - at;
        for (size_t k = 0; k < n; k++) buf[k] = xb(at + k);
        last_type_ = app;
        last_len_ = n;
        if (app) subfield(app, buf, n);
        return;
    }
    if (xpad_ind != 2) return;  // none (0) or reserved (3)

    // variable size X-PAD: with a contents indicator list (up to 4, an end
    // marker of type 0 after fewer), else one subfield continuing the last one
    struct Sub { uint8_t app; size_t len; };
    Sub subs[4];
    size_t nsubs = 0, at = 0, total = 0;
    if (ci_flag) {
        while (nsubs < 4 && at < room) {
            uint8_t ci = xb(at++);
            uint8_t app = ci & 0x1F;
            if (!app) break;
            subs[nsubs++] = {app, XPAD_SUBFIELD_LEN[ci >> 5]};
            total += XPAD_SUBFIELD_LEN[ci >> 5];
        }
    } else if (last_type_) {
        subs[nsubs++] = {continuation(last_type_), last_len_};
        total = last_len_;
    }
    if (!nsubs || at + total > room) {
        discontinuity();  // does not fit: the X-PAD of this frame is not what it says
        return;
    }
    for (size_t i = 0; i < nsubs; i++) {
        for (size_t k = 0; k < subs[i].len; k++) buf[k] = xb(at + k);
        subfield(subs[i].app, buf, subs[i].len);
        at += subs[i].len;
    }
    last_type_ = subs[nsubs - 1].app;
    last_len_ = subs[nsubs - 1].len;
}

void PadDecoder::subfield(uint8_t app_type, const uint8_t* data, size_t len) {
    if (app_type == APP_DL_START) {
        dg_.assign(data, data + len);
        dg_need_ = 0;
        dg_active_ = true;
    } else if (app_type == APP_DL_CONT && dg_active_) {
        dg_.insert(dg_.end(), data, data + len);
    } else {
        return;  // another application (MOT, ...): not read here
    }

    // the length of a dynamic label data group follows from its prefix (clause 7.4.5.2):
    // a segment or DL Plus command has a field of (low nibble + 1) bytes, "remove label" none;
    // 2 bytes prefix, the field, 2 bytes CRC
    if (!dg_need_ && dg_.size() >= 2) {
        uint8_t p0 = dg_[0];
        if (!(p0 & 0x10)) {
            dg_need_ = 2 + (p0 & 0x0F) + 1 + 2;
        } else if ((p0 & 0x0F) == 1) {
            dg_need_ = 4;
        } else if ((p0 & 0x0F) == 2) {
            dg_need_ = 2 + (dg_[1] & 0x0F) + 1 + 2;
        } else {
            dg_active_ = false;  // another command
            return;
        }
    }
    if (!dg_need_ || dg_.size() < dg_need_) return;
    dg_active_ = false;  // done; what follows in the subfield is padding
    uint16_t crc = static_cast<uint16_t>(dg_[dg_need_ - 2] << 8 | dg_[dg_need_ - 1]);
    if (crc16(dg_.data(), dg_need_ - 2) != crc) {
        crc_errors_++;
        return;
    }
    dataGroup(dg_.data(), dg_need_);
}

void PadDecoder::dataGroup(const uint8_t* dg, size_t len) {
    uint8_t p0 = dg[0];
    if (!(p0 & 0x10)) {
        segment(dg, len - 4);
    } else if ((p0 & 0x0F) == 1) {
        // remove label
        seg_toggle_ = -1;
        seg_have_ = 0;
        seg_last_ = -1;
        label_done_ = false;
        label_toggle_ = -1;
        if (!label_text_.empty()) {
            label_text_.clear();
            if (dls_callback_) dls_callback_(label_text_);
        }
    } else {
        dlPlus(dg, len - 4);
    }
}

void PadDecoder::segment(const uint8_t* dg, size_t field_len) {
    // prefix: toggle (b7), first (b6), last (b5), C = 0 (b4), field length - 1 (b3-0);
    // second byte: the character set (b7-4) of the first segment, else its number (b6-4)
    int toggle = dg[0] >> 7;
    bool first = (dg[0] & 0x40) != 0;
    bool last = (dg[0] & 0x20) != 0;
    int num = first ? 0 : (dg[1] >> 4) & 0x07;
    if (toggle != seg_toggle_) {
        seg_toggle_ = toggle;
        seg_have_ = 0;
        seg_last_ = -1;
        label_done_ = false;
    }
    if (first) seg_charset_ = dg[1] >> 4;
    std::vector<uint8_t> chars(dg + 2, dg + 2 + field_len);
    if ((seg_have_ & (1u << num)) && seg_[num] != chars) label_done_ = false;  // reused toggle
    seg_[num] = std::move(chars);
    seg_have_ |= static_cast<uint8_t>(1u << num);
    if (last) seg_last_ = num;
    uint8_t all = static_cast<uint8_t>((1u << (seg_last_ + 1)) - 1);
    if (!label_done_ && seg_last_ >= 0 && (seg_have_ & all) == all) labelComplete();
}

void PadDecoder::labelComplete() {
    label_done_ = true;
    std::vector<uint8_t> raw;
    for (int i = 0; i <= seg_last_; i++) raw.insert(raw.end(), seg_[i].begin(), seg_[i].end());
    std::string text;
    if (!dabLabelToUtf8(raw.data(), raw.size(), seg_charset_, text)) {
        if (!charset_warned_) {
            LOG_WARN(PAD, "dynamic label in character set " << (int)seg_charset_ << ", not read");
            charset_warned_ = true;
        }
        return;
    }
    while (!text.empty() && text.back() == ' ') text.pop_back();
    dls_count_++;
    if (label_toggle_ != seg_toggle_ || text != label_text_) {
        label_toggle_ = seg_toggle_;
        label_text_ = text;
        if (tags_link_ != label_toggle_) {
            tags_.clear();
            tags_link_ = -1;
        }
        tags_done_ = false;
        if (dls_callback_) dls_callback_(label_text_);
    }
    emitTags();
}

void PadDecoder::dlPlus(const uint8_t* dg, size_t field_len) {
    // TS 102 980: second prefix byte: link bit (b7) = the toggle of the label the
    // command is about; the field: CId (b7-4, 0 = DL Plus tags), CB = item toggle
    // (b3), item running (b2), number of tags - 1 (b1-0), then 3 bytes per tag:
    // content type, start marker, length marker (7 bits each)
    int link = dg[1] >> 7;
    const uint8_t* f = dg + 2;
    if (field_len < 1 || (f[0] >> 4) != 0) return;
    size_t nt = (f[0] & 0x03) + 1;
    if (field_len < 1 + 3 * nt) return;
    std::vector<DLPlusTag> tags;
    for (size_t i = 0; i < nt; i++) {
        DLPlusTag t;
        t.content_type = static_cast<DLPlusContentType>(f[1 + 3 * i] & 0x7F);
        t.start_marker = f[2 + 3 * i] & 0x7F;
        t.length_marker = f[3 + 3 * i] & 0x7F;
        if (t.content_type != DLPlusContentType::DUMMY) tags.push_back(t);
    }
    bool same = link == tags_link_ && tags.size() == tags_.size() &&
                std::equal(tags.begin(), tags.end(), tags_.begin(), [](const DLPlusTag& a, const DLPlusTag& b) {
                    return a.content_type == b.content_type && a.start_marker == b.start_marker &&
                           a.length_marker == b.length_marker;
                });
    if (same) return;
    tags_ = std::move(tags);
    tags_link_ = link;
    tags_done_ = false;
    emitTags();
}

void PadDecoder::emitTags() {
    // the tags go with the label they are linked to, once it is complete
    if (tags_done_ || tags_link_ < 0 || tags_link_ != label_toggle_ || label_text_.empty()) return;
    tags_done_ = true;
    dlplus_count_++;
    if (dlplus_callback_) dlplus_callback_(label_text_, tags_);
}

const char* dlPlusContentTypeToString(DLPlusContentType type) {
    switch (type) {
    case DLPlusContentType::DUMMY: return "DUMMY";
    case DLPlusContentType::ITEM_TITLE: return "TITLE";
    case DLPlusContentType::ITEM_ALBUM: return "ALBUM";
    case DLPlusContentType::ITEM_TRACKNUMBER: return "TRACK";
    case DLPlusContentType::ITEM_ARTIST: return "ARTIST";
    case DLPlusContentType::ITEM_COMPOSITION: return "COMPOSITION";
    case DLPlusContentType::ITEM_MOVEMENT: return "MOVEMENT";
    case DLPlusContentType::ITEM_CONDUCTOR: return "CONDUCTOR";
    case DLPlusContentType::ITEM_COMPOSER: return "COMPOSER";
    case DLPlusContentType::ITEM_BAND: return "BAND";
    case DLPlusContentType::ITEM_COMMENT: return "COMMENT";
    case DLPlusContentType::ITEM_GENRE: return "GENRE";
    case DLPlusContentType::INFO_NEWS: return "NEWS";
    case DLPlusContentType::INFO_NEWS_LOCAL: return "NEWS_LOCAL";
    case DLPlusContentType::INFO_STOCKMARKET: return "STOCK";
    case DLPlusContentType::INFO_SPORT: return "SPORT";
    case DLPlusContentType::INFO_LOTTERY: return "LOTTERY";
    case DLPlusContentType::INFO_HOROSCOPE: return "HOROSCOPE";
    case DLPlusContentType::INFO_DAILY_DIVERSION: return "DAILY_DIV";
    case DLPlusContentType::INFO_HEALTH: return "HEALTH";
    case DLPlusContentType::INFO_EVENT: return "EVENT";
    case DLPlusContentType::INFO_SCENE: return "SCENE";
    case DLPlusContentType::INFO_CINEMA: return "CINEMA";
    case DLPlusContentType::INFO_TV: return "TV";
    case DLPlusContentType::INFO_DATE_TIME: return "DATETIME";
    case DLPlusContentType::INFO_WEATHER: return "WEATHER";
    case DLPlusContentType::INFO_TRAFFIC: return "TRAFFIC";
    case DLPlusContentType::INFO_ALARM: return "ALARM";
    case DLPlusContentType::INFO_ADVERTISEMENT: return "AD";
    case DLPlusContentType::INFO_URL: return "URL";
    case DLPlusContentType::INFO_OTHER: return "INFO_OTHER";
    case DLPlusContentType::STATIONNAME_SHORT: return "STATION_SHORT";
    case DLPlusContentType::STATIONNAME_LONG: return "STATION_LONG";
    case DLPlusContentType::PROGRAMME_NOW: return "PROG_NOW";
    case DLPlusContentType::PROGRAMME_NEXT: return "PROG_NEXT";
    case DLPlusContentType::PROGRAMME_PART: return "PROG_PART";
    case DLPlusContentType::PROGRAMME_HOST: return "HOST";
    case DLPlusContentType::PROGRAMME_EDITORIAL_STAFF: return "STAFF";
    case DLPlusContentType::PROGRAMME_FREQUENCY: return "FREQ";
    case DLPlusContentType::PROGRAMME_HOMEPAGE: return "HOMEPAGE";
    case DLPlusContentType::PROGRAMME_SUBCHANNEL: return "SUBCHANNEL";
    case DLPlusContentType::PHONE_HOTLINE: return "PHONE_HOTLINE";
    case DLPlusContentType::PHONE_STUDIO: return "PHONE_STUDIO";
    case DLPlusContentType::PHONE_OTHER: return "PHONE_OTHER";
    case DLPlusContentType::SMS_STUDIO: return "SMS_STUDIO";
    case DLPlusContentType::SMS_OTHER: return "SMS_OTHER";
    case DLPlusContentType::EMAIL_HOTLINE: return "EMAIL_HOTLINE";
    case DLPlusContentType::EMAIL_STUDIO: return "EMAIL_STUDIO";
    case DLPlusContentType::EMAIL_OTHER: return "EMAIL_OTHER";
    case DLPlusContentType::MMS_OTHER: return "MMS_OTHER";
    case DLPlusContentType::CHAT: return "CHAT";
    case DLPlusContentType::CHAT_CENTER: return "CHAT_CENTER";
    case DLPlusContentType::VOTE_QUESTION: return "VOTE_Q";
    case DLPlusContentType::VOTE_CENTRE: return "VOTE_CENTER";
    case DLPlusContentType::PRIVATE_1: return "PRIVATE_1";
    case DLPlusContentType::PRIVATE_2: return "PRIVATE_2";
    case DLPlusContentType::PRIVATE_3: return "PRIVATE_3";
    default: return "UNKNOWN";
    }
}

} // namespace dvbdab
