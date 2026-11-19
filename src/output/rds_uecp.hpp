#pragma once
// RDS RadioText in UECP frames (IEC 62106-10), as DVB carries RDS next to radio
// audio: a PES of stream type 0x89 with an ancillary_data_descriptor saying "RDS
// via UECP" (ETSI EN 300 468). tvheadend passes such a stream on as "RDS", Kodi
// shows its RadioText.

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace dvbdab {

// the longest RadioText (IEC 62106: 64 characters)
constexpr size_t RDS_RT_MAX = 64;

// A text for RadioText: in the RDS character set, at most RDS_RT_MAX
// characters - a longer one is cut at its last space within them (if that is
// not before the middle), else after RDS_RT_MAX
std::string rdsRadioText(const std::string& utf8);

// The same, and where each character of the source went: for character i
// (a code point of utf8) `at[i]` is its position in `text` and `width[i]` the
// number of RDS characters it became (usually 1); at[i] < 0 when it was cut
struct RdsText {
    std::string text;
    std::vector<int> at;
    std::vector<int> width;
};
RdsText rdsRadioTextMapped(const std::string& utf8);

// A text longer than a RadioText, whole: in parts of at most RDS_RT_MAX
// characters, cut at spaces, to be sent one after the other (at most
// RDS_RT_PARTS; a DAB label has up to 128 characters). Each part with the
// places of the characters of the source that are in it (-1 for the
// others), so the RT+ tags of a part come from rtPlusTags() as before. A
// text that fits has one part, an empty one none.
constexpr size_t RDS_RT_PARTS = 4;
std::vector<RdsText> rdsRadioTextParts(const std::string& utf8);

// A UECP frame with the whole label as it is, UTF-8, for receivers that
// know it: a manufacturer's specific command (MEC 0x2D) with the
// designation "dl" and the command 0x01, then the text - at most
// UECP_LABEL_MAX bytes of it, cut between two characters. RadioText has 64
// characters of the RDS character set; a DAB label has up to 128 of any.
// Empty without a text.
constexpr size_t UECP_LABEL_MAX = 250;
std::vector<uint8_t> uecpLabelFrame(const std::string& utf8);

// A UECP frame with a RadioText message (MEC 0x0A) of rds_text (from
// rdsRadioText; empty: no text); ab_flag: the A/B flag, changed with the text
std::vector<uint8_t> uecpRadioTextFrame(const std::string& rds_text, bool ab_flag);

// A slide of the slideshow of a service (an image file, JPEG or PNG), for
// receivers that know it: in pieces, each a manufacturer's specific command
// (MEC 0x2D) with the designation "dl" and the command 0x02 in a UECP frame
// of its own - the number of the slide (another one for another slide), the
// number of the piece and how many pieces there are (2 bytes each, high byte
// first), then up to UECP_SLIDE_PIECE bytes of the file. A receiver has the
// slide when it has all its pieces. No frames for an empty file or one of
// more than UECP_SLIDE_MAX bytes.
constexpr size_t UECP_SLIDE_PIECE = 240;
constexpr size_t UECP_SLIDE_MAX = 128 * 1024;
std::vector<std::vector<uint8_t>> uecpSlideFrames(uint8_t slide, const uint8_t* data, size_t len);

// A tag of RadioText Plus (RT+, IEC 62106-6): a part of the RadioText and
// what it is (the content types are those of DL Plus). start and length - 1
// in characters of the RadioText.
struct RtPlusTag {
    uint8_t content_type{0};   // 0 = dummy (no tag)
    uint8_t start{0};          // 0..63
    uint8_t length_minus_1{0}; // 0..63 in the first place of a group, 0..31 in the second
};

// The RT+ tags a RadioText can take from DL Plus tags of the label it was
// made of (`mapped` from rdsRadioTextMapped of that label): each as
// {content type, start, length - 1} in characters of the label. Tags that
// were cut off, or do not fit the fields of RT+, are left out.
std::vector<RtPlusTag> rtPlusTags(const RdsText& mapped,
                                  const std::vector<std::array<uint8_t, 3>>& dl_plus_tags);

// A UECP frame that announces RT+ (ODA configuration, MEC 0x40: application
// 0x4BD7 in group 11A) and carries the tags, two per ODA data message (MEC
// 0x46). Empty without tags.
std::vector<uint8_t> uecpRtPlusFrame(const std::vector<RtPlusTag>& tags, bool item_toggle, bool item_running);

} // namespace dvbdab
