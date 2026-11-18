#pragma once
/**
 * @file dab_tables.hpp
 * @brief Code tables of DAB (ETSI TS 101 756) put into what a DVB TS uses
 */

#include <cstdint>
#include <string>

namespace dvbdab {

/// The language of a service component (TS 101 756 tables 9 and 10, the
/// code of FIG 0/5) as an ISO 639-2 code of three letters; "" for a code
/// without a meaning or without an ISO 639-2 code of its own
const char* dabLanguageIso639(uint8_t language);

/// A language as two letters (ISO 639-1, as the programme guide of DAB says
/// it) or three (ISO 639-2) as the ISO 639-2 code a DVB descriptor has; ""
/// for one that is not known here
std::string iso639ForDvb(const std::string& language);

/// A programme type (the international code of FIG 0/17) as the two
/// nibbles of a DVB content_descriptor (EN 300 468 table 28); 0 for none.
/// Only for the international table 1 (the RDS types used in Europe):
/// others give 0.
uint8_t dabPtyToDvbContent(uint8_t pty, uint8_t international_table);

} // namespace dvbdab
