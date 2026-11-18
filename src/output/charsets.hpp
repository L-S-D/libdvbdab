#pragma once
// Character sets of DAB labels (ETSI TS 101 756) and of RDS (IEC 62106, annex E)

#include <cstdint>
#include <cstddef>
#include <string>

namespace dvbdab {

// The DAB character set codes of a label (ETSI TS 101 756, table 1) this library reads
constexpr uint8_t DAB_CHARSET_EBU_LATIN = 0;  // complete EBU Latin based repertoire (table 19)
constexpr uint8_t DAB_CHARSET_UCS2_BE = 6;    // ISO/IEC 10646, UCS-2, big endian
constexpr uint8_t DAB_CHARSET_UTF8 = 15;      // ISO/IEC 10646, UTF-8

// A DAB label in its character set to UTF-8 into out; false for a character set
// it does not know. In EBU Latin a preferred line break and the end of a
// headline become a space, a preferred word break goes; a NUL ends the label.
bool dabLabelToUtf8(const uint8_t* data, size_t len, uint8_t charset, std::string& out);

// UTF-8 to the RDS character set (IEC 62106, annex E: the G0 code table); a
// character that set does not have becomes '?'
std::string utf8ToRds(const std::string& utf8);

} // namespace dvbdab
