#pragma once
// PAD (Programme Associated Data) decoder for DAB+
// Extracts DLS (Dynamic Label Segment) text and DL Plus tags
// References: ETSI EN 300 401, ETSI TS 102 980
//
// Uses FDK-AAC to properly extract DSE (ancillary data) from AAC AU

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
    uint8_t start_marker;   // Start position in DL text (0-127)
    uint8_t length_marker;  // Length of tagged text (0-127)

    // Extract the tagged substring from a DL string
    std::string extract(const std::string& dl_text) const {
        if (start_marker >= dl_text.size()) return "";
        size_t len = std::min(static_cast<size_t>(length_marker + 1),
                              dl_text.size() - start_marker);
        return dl_text.substr(start_marker, len);
    }
};

// Callback for complete DLS text
using DLSCallback = std::function<void(const std::string& text)>;

// Callback for DL Plus update (text + tags)
using DLPlusCallback = std::function<void(const std::string& text,
                                          const std::vector<DLPlusTag>& tags)>;

// PAD decoder - processes F-PAD and X-PAD from DAB+ audio frames
// Uses FDK-AAC to extract ancillary data (DSE) like dablin does
class PadDecoder {
public:
    PadDecoder();
    ~PadDecoder();

    // Reset decoder state
    void reset();

    // Configure FDK-AAC decoder with DAB+ audio parameters
    // Must be called before processPad() for correct DSE extraction
    // These parameters come from the DAB+ superframe header (byte 2)
    void configure(bool dac_rate, bool sbr_flag, bool ps_flag, bool aac_channel_mode);

    // Set callbacks
    void setDLSCallback(DLSCallback cb) { dls_callback_ = std::move(cb); }
    void setDLPlusCallback(DLPlusCallback cb) { dlplus_callback_ = std::move(cb); }

    // Process PAD data from DAB+ AU
    // pad_data points to the PAD portion (last bytes of AU before CRC)
    // pad_len is the length of PAD (typically AU length - audio data - 2 CRC bytes)
    // In practice, we extract from the raw AU data
    void processPad(const uint8_t* au_data, size_t au_len);

    // Get current DLS text
    const std::string& getDLSText() const { return current_dls_; }

    // Get current DL Plus tags
    const std::vector<DLPlusTag>& getDLPlusTags() const { return current_tags_; }

    // Statistics
    size_t getPadCount() const { return pad_count_; }
    size_t getDLSCount() const { return dls_count_; }
    size_t getDLPlusCount() const { return dlplus_count_; }

private:
    // Process F-PAD (last 2 bytes)
    void processFPad(uint8_t fpad_type, uint8_t ci_flag);

    // Process X-PAD based on content indicator (legacy)
    void processXPad(const uint8_t* xpad, size_t len, uint8_t app_type);

    // Process X-PAD data (new implementation)
    void processXPadData(const uint8_t* xpad, size_t len, uint8_t app_type);

    // Try to process accumulated Data Group
    void tryProcessDataGroup();

    // Process DLS data from Data Group
    void processDLSData(const uint8_t* data, size_t len);

    // Process DLS segment (new dablin-style format)
    void processDLSSegmentNew(const uint8_t* data, size_t len, bool first, bool last, size_t field_len, bool toggle);

    // Process DL Plus command from Data Group
    void processDLPlusCommand(const uint8_t* data, size_t len, bool toggle);

    // Legacy methods (kept for compatibility)
    void processDataGroup(const uint8_t* data, size_t len);
    void processDLSSegment(const uint8_t* data, size_t len, bool first, bool last);
    void processDLPlus(const uint8_t* data, size_t len, bool toggle);
    bool isValidDLS(const std::string& text);
    bool isLikelyDLS(const std::string& text);

    // X-PAD state
    bool xpad_present_ = false;
    uint8_t xpad_ci_ = 0;          // Content Indicator
    uint8_t xpad_app_type_ = 0;    // Application Type
    size_t xpad_len_ = 0;          // Expected X-PAD length

    // Data group reassembly
    std::vector<uint8_t> dg_buffer_;
    bool dg_in_progress_ = false;
    uint8_t dg_type_ = 0;

    // DL Plus segment reassembly (for linked segments)
    std::vector<uint8_t> dlplus_buffer_;
    bool dlplus_link_pending_ = false;

    // DLS reassembly
    std::array<char, 129> dls_buffer_;  // 128 chars + null
    size_t dls_len_ = 0;
    uint8_t dls_charset_ = 0;      // 0=EBU Latin, 15=UTF-8
    bool dls_first_received_ = false;
    bool dls_toggle_ = false;      // Toggle bit for current DLS

    // Current state
    std::string current_dls_;
    std::vector<DLPlusTag> current_tags_;
    bool current_dls_toggle_ = false;  // Toggle of completed DLS

    // Callbacks
    DLSCallback dls_callback_;
    DLPlusCallback dlplus_callback_;

    // Statistics
    size_t pad_count_ = 0;
    size_t dls_count_ = 0;
    size_t dlplus_count_ = 0;

    // Note: PAD uses manual DSE parsing (like dablin), not FDK-AAC
};

// Helper: Convert DL Plus content type to string
const char* dlPlusContentTypeToString(DLPlusContentType type);

} // namespace dvbdab
