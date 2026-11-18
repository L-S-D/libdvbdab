#pragma once
// RDS RadioText in UECP frames (IEC 62106-10), as DVB carries RDS next to radio
// audio: a PES of stream type 0x89 with an ancillary_data_descriptor saying "RDS
// via UECP" (ETSI EN 300 468). tvheadend passes such a stream on as "RDS", Kodi
// shows its RadioText.

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

// A UECP frame with a RadioText message (MEC 0x0A) of rds_text (from
// rdsRadioText; empty: no text); ab_flag: the A/B flag, changed with the text
std::vector<uint8_t> uecpRadioTextFrame(const std::string& rds_text, bool ab_flag);

} // namespace dvbdab
