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

/// What a DVB AAC_descriptor (EN 300 468 annex H) says of DAB+ audio put
/// out as it is: profile_and_level (ISO/IEC 14496-3 table 1.14) and
/// AAC_type (the component types of stream_content 6)
struct AacSignalling {
    uint8_t profile;  ///< AAC, HE AAC or HE AAC v2 profile, level 2
    uint8_t type;     ///< mono, stereo or HE AAC v2 stereo
};

/// From the superframe header: SBR used, parametric stereo signalled, the
/// AAC core is stereo. Parametric stereo counts only with SBR. MPEG
/// Surround is not said: the descriptor is about the AAC core.
AacSignalling dabPlusAacSignalling(bool sbr, bool ps, bool stereo);

/// profile_and_level of AAC-LC of up to two channels and 48 kHz (what the
/// transcoder puts out): AAC profile, level 2
constexpr uint8_t AAC_PROFILE_LC_L2 = 0x29;

} // namespace dvbdab
