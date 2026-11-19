#pragma once
// PAD (Programme Associated Data) of DAB and DAB+ audio: dynamic labels (DLS)
// and their DL Plus tags. References: ETSI EN 300 401 (clause 7.4: PAD, X-PAD,
// dynamic label data groups), ETSI TS 102 980 (DL Plus), ETSI TS 102 563 (the
// PAD of DAB+ in the data stream element of an AU).

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <array>

namespace dvbdab {

// DL Plus content types (ETSI TS 102 980, Table 1)
enum class DLPlusContentType : uint8_t {
    DUMMY = 0,
    ITEM_TITLE = 1,
    ITEM_ALBUM = 2,
    ITEM_TRACKNUMBER = 3,
    ITEM_ARTIST = 4,
    ITEM_COMPOSITION = 5,
    ITEM_MOVEMENT = 6,
    ITEM_CONDUCTOR = 7,
    ITEM_COMPOSER = 8,
    ITEM_BAND = 9,
    ITEM_COMMENT = 10,
    ITEM_GENRE = 11,
    INFO_NEWS = 12,
    INFO_NEWS_LOCAL = 13,
    INFO_STOCKMARKET = 14,
    INFO_SPORT = 15,
    INFO_LOTTERY = 16,
    INFO_HOROSCOPE = 17,
    INFO_DAILY_DIVERSION = 18,
    INFO_HEALTH = 19,
    INFO_EVENT = 20,
    INFO_SCENE = 21,
    INFO_CINEMA = 22,
    INFO_TV = 23,
    INFO_DATE_TIME = 24,
    INFO_WEATHER = 25,
    INFO_TRAFFIC = 26,
    INFO_ALARM = 27,
    INFO_ADVERTISEMENT = 28,
    INFO_URL = 29,
    INFO_OTHER = 30,
    STATIONNAME_SHORT = 31,
    STATIONNAME_LONG = 32,
    PROGRAMME_NOW = 33,
    PROGRAMME_NEXT = 34,
    PROGRAMME_PART = 35,
    PROGRAMME_HOST = 36,
    PROGRAMME_EDITORIAL_STAFF = 37,
    PROGRAMME_FREQUENCY = 38,
    PROGRAMME_HOMEPAGE = 39,
    PROGRAMME_SUBCHANNEL = 40,
    PHONE_HOTLINE = 41,
    PHONE_STUDIO = 42,
    PHONE_OTHER = 43,
    SMS_STUDIO = 44,
    SMS_OTHER = 45,
    EMAIL_HOTLINE = 46,
    EMAIL_STUDIO = 47,
    EMAIL_OTHER = 48,
    MMS_OTHER = 49,
    CHAT = 50,
    CHAT_CENTER = 51,
    VOTE_QUESTION = 52,
    VOTE_CENTRE = 53,
    // 54-55 RFU
    PRIVATE_1 = 56,
    PRIVATE_2 = 57,
    PRIVATE_3 = 58,
    // 59-63 reserved
};

// DL Plus tag extracted from PAD
struct DLPlusTag {
    DLPlusContentType content_type;
    uint8_t start_marker;   // Start position in DL text (0-127), in characters
    uint8_t length_marker;  // Length of tagged text - 1 (0-127), in characters
    // of the command the tag came in: the item toggle bit (changes with a new
    // item) and the item running bit (the item is on air)
    bool item_toggle{false};
    bool item_running{false};

    // Extract the tagged substring from a DL string (UTF-8: the markers count
    // characters, not bytes)
    std::string extract(const std::string& dl_text) const {
        size_t pos = 0, chars = 0, from = std::string::npos;
        while (pos < dl_text.size()) {
            if (chars == start_marker) from = pos;
            if (chars == static_cast<size_t>(start_marker) + length_marker + 1) break;
            pos++;
            while (pos < dl_text.size() && (static_cast<unsigned char>(dl_text[pos]) & 0xC0) == 0x80) pos++;
            chars++;
        }
        return from == std::string::npos ? "" : dl_text.substr(from, pos - from);
    }
};

// Callback for a complete dynamic label (UTF-8); an empty text: the label was removed
using DLSCallback = std::function<void(const std::string& text)>;

// Callback for the DL Plus tags of the current label
using DLPlusCallback = std::function<void(const std::string& text,
                                          const std::vector<DLPlusTag>& tags)>;

// PAD decoder: the PAD of each audio frame in order. The X-PAD data groups of
// dynamic labels (application types 2 and 3) are collected, checked by their
// CRC and put together into labels: a label is complete when all its segments
// of one toggle state came. Lost frames make an unfinished data group void
// (discontinuity()).
class PadDecoder {
public:
    PadDecoder();
    ~PadDecoder();

    void reset();

    void setDLSCallback(DLSCallback cb) { dls_callback_ = std::move(cb); }
    void setDLPlusCallback(DLPlusCallback cb) { dlplus_callback_ = std::move(cb); }

    /// The MSC data groups of the MOT application in the X-PAD (the
    /// slideshow of the service): each complete one, as it was sent, with
    /// its CRC still to be checked. Without a callback they are not collected.
    using DataGroupCallback = std::function<void(const uint8_t* data, size_t len)>;
    void setMotDataGroupCallback(DataGroupCallback cb) { mot_callback_ = std::move(cb); }

    // The PAD of a frame: the F-PAD (2 bytes) and the room the X-PAD ends at:
    // its bytes are the last ones of xpad_room bytes from xpad, in reverse
    // order (DAB+: the data stream element before its F-PAD; DAB: the MPEG
    // audio frame before its ScF-CRC). The contents indicators give the length.
    void process(const uint8_t* xpad, size_t xpad_room, const uint8_t* fpad);

    // The PAD of a DAB+ AU: in its data stream element, if it starts with one
    void processAu(const uint8_t* au, size_t au_len);

    // Frames were lost since the last PAD
    void discontinuity();

    // The current label and its tags
    const std::string& getDLSText() const { return label_text_; }
    const std::vector<DLPlusTag>& getDLPlusTags() const { return tags_; }

    // Statistics
    size_t getPadCount() const { return pad_count_; }
    size_t getDLSCount() const { return dls_count_; }
    size_t getDLPlusCount() const { return dlplus_count_; }
    size_t getCrcErrors() const { return crc_errors_; }

private:
    // X-PAD MOT: the data group being collected, its length from the data
    // group length indicator before it (0: none said)
    std::vector<uint8_t> mot_dg_;
    size_t mot_len_{0};
    bool mot_active_{false};
    DataGroupCallback mot_callback_;
    void motComplete();

    void subfield(uint8_t app_type, const uint8_t* data, size_t len);
    void dataGroup(const uint8_t* dg, size_t len);
    void segment(const uint8_t* dg, size_t field_len);
    void dlPlus(const uint8_t* dg, size_t field_len);
    void labelComplete();
    void emitTags();

    // X-PAD: the application type and length of the last data subfield (a
    // variable X-PAD without contents indicator continues it)
    uint8_t last_type_ = 0;
    size_t last_len_ = 0;

    // the dynamic label data group being collected
    std::vector<uint8_t> dg_;
    size_t dg_need_ = 0;     // its length once its prefix is there, 0 = not yet
    bool dg_active_ = false;

    // the label being put together: up to 8 segments of one toggle state
    int seg_toggle_ = -1;
    uint8_t seg_charset_ = 0;
    std::array<std::vector<uint8_t>, 8> seg_;
    uint8_t seg_have_ = 0;   // bit per segment
    int seg_last_ = -1;      // number of the last segment, -1 = not seen yet

    // the complete label
    int label_toggle_ = -1;
    std::string label_text_;
    bool label_done_ = false;   // the label of seg_toggle_ was put out

    // DL Plus tags and the toggle of the label they belong to (link bit)
    std::vector<DLPlusTag> tags_;
    int tags_link_ = -1;
    bool tags_done_ = false;

    DLSCallback dls_callback_;
    DLPlusCallback dlplus_callback_;

    size_t pad_count_ = 0;
    size_t dls_count_ = 0;
    size_t dlplus_count_ = 0;
    size_t crc_errors_ = 0;
    bool charset_warned_ = false;
};

// Helper: Convert DL Plus content type to string
const char* dlPlusContentTypeToString(DLPlusContentType type);

} // namespace dvbdab
