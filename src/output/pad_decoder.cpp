// PAD (Programme Associated Data) decoder for DAB+
// References: ETSI EN 300 401, ETSI TS 102 980, ETSI TS 102 563
//
// Key insight from dablin: X-PAD bytes in DAB+ DSE are stored in REVERSE order
// and must be reversed before parsing.

#include "pad_decoder.hpp"
#include <cstring>
#include <algorithm>
#include <cctype>

// Uncomment to enable debug output
// #define PAD_DEBUG

namespace dvbdab {

// X-PAD data field length table (ETSI EN 300 401, Table 9)
// Index from CI bits 7-5, gives data field length
static const size_t xpad_len_table[8] = {4, 6, 8, 12, 16, 24, 32, 48};

// X-PAD Application Type for Data Groups (Table 11)
// App Type 2 = DLS start, App Type 3 = DLS continuation
// App Type 12 = MOT (Multimedia Object Transfer)
// App Type 13 = MOT (continuation)

// EBU Latin (charset 0) to UTF-8 conversion table
// Based on ETSI TS 101 756 Annex C / ETSI EN 300 706 Table 36
// Complete EBU Latin character set for DAB
static std::string ebuLatinToUtf8(const char* src, size_t len) {
    std::string result;
    result.reserve(len * 2);  // UTF-8 may need more bytes

    for (size_t i = 0; i < len; i++) {
        uint8_t c = static_cast<uint8_t>(src[i]);
        if (c < 0x80) {
            // ASCII compatible (0x00-0x7F)
            result.push_back(static_cast<char>(c));
        } else {
            // EBU Latin extended characters (0x80-0xFF)
            // Based on ETSI TS 101 756 Annex C Table C.1
            switch (c) {
                // Row 8 (0x80-0x8F)
                case 0x80: result += " "; break;    // no-break space
                case 0x81: result += "¡"; break;
                case 0x82: result += "¢"; break;
                case 0x83: result += "£"; break;
                case 0x84: result += "$"; break;
                case 0x85: result += "¥"; break;
                case 0x86: result += "#"; break;
                case 0x87: result += "§"; break;
                case 0x88: result += "¤"; break;
                case 0x89: result += "'"; break;    // left single quote
                case 0x8A: result += "\""; break;   // left double quote
                case 0x8B: result += "«"; break;
                case 0x8C: result += "←"; break;
                case 0x8D: result += "ß"; break;    // sharp s (used in German)
                case 0x8E: result += "→"; break;
                case 0x8F: result += "↓"; break;

                // Row 9 (0x90-0x9F)
                // Note: DAB EBU Latin puts umlauts in this range
                case 0x90: result += "°"; break;
                case 0x91: result += "ä"; break;    // German a umlaut (lowercase)
                case 0x92: result += "²"; break;
                case 0x93: result += "³"; break;
                case 0x94: result += "×"; break;
                case 0x95: result += "µ"; break;
                case 0x96: result += "¶"; break;
                case 0x97: result += "ö"; break;    // German o umlaut
                case 0x98: result += "÷"; break;
                case 0x99: result += "ü"; break;    // German u umlaut
                case 0x9A: result += "'"; break;    // right single quote
                case 0x9B: result += "»"; break;
                case 0x9C: result += "¼"; break;
                case 0x9D: result += "½"; break;
                case 0x9E: result += "¾"; break;
                case 0x9F: result += "¿"; break;

                // Row A (0xA0-0xAF) - diacritical marks (combining)
                case 0xA0: result += " "; break;    // space
                case 0xA1: result += "`"; break;    // grave
                case 0xA2: result += "´"; break;    // acute
                case 0xA3: result += "^"; break;    // circumflex
                case 0xA4: result += "~"; break;    // tilde
                case 0xA5: result += "¯"; break;    // macron
                case 0xA6: result += "˘"; break;    // breve
                case 0xA7: result += "˙"; break;    // dot above
                case 0xA8: result += "¨"; break;    // diaeresis
                case 0xA9: result += "."; break;
                case 0xAA: result += "˚"; break;    // ring above
                case 0xAB: result += "¸"; break;    // cedilla
                case 0xAC: result += "_"; break;    // underscore
                case 0xAD: result += "˝"; break;    // double acute
                case 0xAE: result += "˛"; break;    // ogonek
                case 0xAF: result += "ˇ"; break;    // caron

                // Row B (0xB0-0xBF) - line drawing characters
                case 0xB0: result += "─"; break;
                case 0xB1: result += " "; break;
                case 0xB2: result += " "; break;
                case 0xB3: result += " "; break;
                case 0xB4: result += " "; break;
                case 0xB5: result += " "; break;
                case 0xB6: result += " "; break;
                case 0xB7: result += " "; break;
                case 0xB8: result += " "; break;
                case 0xB9: result += " "; break;
                case 0xBA: result += " "; break;
                case 0xBB: result += "°"; break;    // degree sign (also at 0x90)
                case 0xBC: result += " "; break;
                case 0xBD: result += " "; break;
                case 0xBE: result += " "; break;
                case 0xBF: result += " "; break;

                // Row C (0xC0-0xCF) - capital letters with diacritics
                case 0xC0: result += " "; break;
                case 0xC1: result += "À"; break;
                case 0xC2: result += "Á"; break;
                case 0xC3: result += "Â"; break;
                case 0xC4: result += "Ã"; break;
                case 0xC5: result += "Ä"; break;    // German A umlaut
                case 0xC6: result += "Ă"; break;
                case 0xC7: result += "Ç"; break;
                case 0xC8: result += "È"; break;
                case 0xC9: result += "É"; break;
                case 0xCA: result += "Ê"; break;
                case 0xCB: result += "Ë"; break;
                case 0xCC: result += "Ì"; break;
                case 0xCD: result += "Í"; break;
                case 0xCE: result += "Î"; break;
                case 0xCF: result += "Ï"; break;

                // Row D (0xD0-0xDF) - more capital letters
                case 0xD0: result += "Ð"; break;
                case 0xD1: result += "Ñ"; break;
                case 0xD2: result += "Ò"; break;
                case 0xD3: result += "Ó"; break;
                case 0xD4: result += "Ô"; break;
                case 0xD5: result += "Õ"; break;
                case 0xD6: result += "Ö"; break;    // German O umlaut
                case 0xD7: result += "Œ"; break;
                case 0xD8: result += "Ø"; break;
                case 0xD9: result += "Ü"; break;    // German U umlaut (NOT Ù!)
                case 0xDA: result += "Ù"; break;
                case 0xDB: result += "Ú"; break;
                case 0xDC: result += "Û"; break;
                case 0xDD: result += "Ý"; break;
                case 0xDE: result += "Þ"; break;
                case 0xDF: result += "ß"; break;

                // Row E (0xE0-0xEF) - small letters with diacritics
                case 0xE0: result += "à"; break;
                case 0xE1: result += "á"; break;
                case 0xE2: result += "â"; break;
                case 0xE3: result += "ã"; break;
                case 0xE4: result += "ä"; break;    // German a umlaut
                case 0xE5: result += "å"; break;
                case 0xE6: result += "æ"; break;
                case 0xE7: result += "ç"; break;
                case 0xE8: result += "è"; break;
                case 0xE9: result += "é"; break;
                case 0xEA: result += "ê"; break;
                case 0xEB: result += "ë"; break;
                case 0xEC: result += "ì"; break;
                case 0xED: result += "í"; break;
                case 0xEE: result += "î"; break;
                case 0xEF: result += "ï"; break;

                // Row F (0xF0-0xFF) - more small letters
                case 0xF0: result += "ð"; break;
                case 0xF1: result += "ñ"; break;
                case 0xF2: result += "ò"; break;
                case 0xF3: result += "ó"; break;
                case 0xF4: result += "ô"; break;
                case 0xF5: result += "õ"; break;
                case 0xF6: result += "ö"; break;
                case 0xF7: result += "œ"; break;
                case 0xF8: result += "ø"; break;
                case 0xF9: result += "ù"; break;
                case 0xFA: result += "ú"; break;
                case 0xFB: result += "û"; break;
                case 0xFC: result += "ü"; break;
                case 0xFD: result += "ý"; break;
                case 0xFE: result += "þ"; break;
                case 0xFF: result += "ÿ"; break;

                default:
                    // Unknown character - use space
                    result += " ";
                    break;
            }
        }
    }
    return result;
}

PadDecoder::PadDecoder() {
    // PAD decoder uses manual DSE parsing (like dablin's CheckForPAD)
    // No FDK-AAC initialization needed for PAD extraction
    reset();
}

void PadDecoder::configure(bool dac_rate, bool sbr_flag, bool ps_flag, bool aac_channel_mode) {
    // No longer needed - PAD uses manual DSE parsing, not FDK-AAC
    // Kept for API compatibility
    (void)dac_rate;
    (void)sbr_flag;
    (void)ps_flag;
    (void)aac_channel_mode;
}

PadDecoder::~PadDecoder() {
    // Nothing to clean up - no FDK-AAC resources used for PAD
}

void PadDecoder::reset() {
    xpad_present_ = false;
    xpad_ci_ = 0;
    xpad_app_type_ = 0;
    xpad_len_ = 0;

    dg_buffer_.clear();
    dg_in_progress_ = false;
    dg_type_ = 0;

    dlplus_buffer_.clear();
    dlplus_link_pending_ = false;

    std::memset(dls_buffer_.data(), 0, dls_buffer_.size());
    dls_len_ = 0;
    dls_charset_ = 0;
    dls_first_received_ = false;

    current_dls_.clear();
    current_tags_.clear();

    pad_count_ = 0;
    dls_count_ = 0;
    dlplus_count_ = 0;
}

void PadDecoder::processPad(const uint8_t* au_data, size_t au_len) {
    // Manually parse DSE from AU data like dablin does
    // The AU contains: [DSE header][PAD data (X-PAD reversed)][F-PAD (2 bytes)]
    //
    // DSE structure (ETSI TS 102 563):
    //   Byte 0: element_id (3 bits) | element_instance_tag (4 bits) | data_byte_align_flag (1 bit)
    //   Byte 1: count (length of data)
    //   If count == 255: Byte 2 = esc_count, total_len = 255 + esc_count
    //   Following bytes: PAD data

    if (au_len < 3) return;
    pad_count_++;

    // Check for DSE (Data Stream Element) at start of AU
    // element_id = 4 (bits 7-5)
    if ((au_data[0] >> 5) != 4) {
        // No DSE found - some AUs may not have PAD
#ifdef PAD_DEBUG
        if (pad_count_ <= 20) {
            fprintf(stderr, "[PAD] No DSE: first byte=0x%02x (element_id=%d)\n",
                    au_data[0], au_data[0] >> 5);
        }
#endif
        return;
    }

    // Parse DSE length
    size_t pad_start = 2;
    size_t pad_len = au_data[1];
    if (pad_len == 255) {
        if (au_len < 4) return;
        pad_len += au_data[2];
        pad_start = 3;
    }

    // F-PAD is always 2 bytes at the end of PAD data
    constexpr size_t FPAD_LEN = 2;
    if (pad_len < FPAD_LEN || au_len < pad_start + pad_len) {
#ifdef PAD_DEBUG
        if (pad_count_ <= 10) {
            fprintf(stderr, "[PAD] Invalid DSE length: pad_len=%zu au_len=%zu pad_start=%zu\n",
                    pad_len, au_len, pad_start);
        }
#endif
        return;
    }

    // Extract PAD data and F-PAD
    const uint8_t* pad_data = au_data + pad_start;
    size_t xpad_len = pad_len - FPAD_LEN;
    const uint8_t* fpad = pad_data + xpad_len;

#ifdef PAD_DEBUG
    if (pad_count_ <= 30) {
        fprintf(stderr, "[PAD] DSE found: pad_len=%zu xpad_len=%zu fpad=%02x%02x\n",
                pad_len, xpad_len, fpad[0], fpad[1]);
    }
#endif

    // Parse F-PAD (dablin's interpretation)
    // fpad[0] bits 7-6: F-PAD type
    // fpad[0] bits 5-4: X-PAD Indicator
    // fpad[1] bit 1: CI flag
    uint8_t fpad_type = (fpad[0] >> 6) & 0x03;
    uint8_t xpad_ind = (fpad[0] >> 4) & 0x03;
    bool ci_flag = (fpad[1] & 0x02) != 0;

    (void)fpad_type;

#ifdef PAD_DEBUG
    if (pad_count_ <= 50) {
        fprintf(stderr, "[PAD] F-PAD: %02x%02x xpad_ind=%d ci_flag=%d\n",
                fpad[0], fpad[1], xpad_ind, ci_flag);
    }
#endif

    if (xpad_ind == 0) {
        return;  // No X-PAD
    }

    // X-PAD is stored in REVERSE order in the PAD data (before F-PAD)
    // For Short X-PAD (xpad_ind=1): always 4 bytes
    // For Variable X-PAD (xpad_ind=2): length from DSE minus F-PAD
    size_t actual_xpad_len = xpad_len;  // xpad_len from DSE parsing
    if (xpad_ind == 1) {
        actual_xpad_len = 4;  // Short X-PAD is always 4 bytes
    }

    if (actual_xpad_len == 0 || actual_xpad_len > xpad_len) return;

    // Reverse X-PAD bytes (dablin: "undo reversed byte order")
    std::vector<uint8_t> xpad(actual_xpad_len);
    for (size_t i = 0; i < actual_xpad_len; i++) {
        xpad[i] = pad_data[actual_xpad_len - 1 - i];
    }

    // After reversal: CI(s) at start, data follows

    if (xpad_ind == 1) {
        // Short X-PAD (4 bytes): After reversal: [CI][D2][D1][D0]
        // CI is at the START, data follows
        if (actual_xpad_len < 4) return;

        uint8_t ci = xpad[0];  // CI at start after reversal
        uint8_t app_type = ci & 0x1F;

#ifdef PAD_DEBUG
        if (pad_count_ <= 50) {
            fprintf(stderr, "[PAD] Short X-PAD: CI=0x%02x app_type=%d data=%02x%02x%02x\n",
                    ci, app_type, xpad[1], xpad[2], xpad[3]);
        }
#endif

        xpad_app_type_ = app_type;
        if (app_type != 0) {
            processXPad(xpad.data() + 1, 3, app_type);  // Data starts after CI
        }
        return;
    }

    if (xpad_ind == 2 && ci_flag) {
        // Variable X-PAD with CI(s) at start after reversal
        // Can have multiple CIs, each describing a data subfield
        if (actual_xpad_len < 2) return;

        // Parse CI entries (up to 4) - dablin approach
        size_t ci_count = 0;
        std::vector<uint8_t> cis;
        for (size_t i = 0; i < 4 && i < actual_xpad_len; i++) {
            uint8_t ci = xpad[i];
            ci_count++;
            if ((ci & 0x1F) == 0) break;  // End marker
            cis.push_back(ci);
        }

        // Data starts after CIs
        size_t data_offset = ci_count;
        const uint8_t* data_ptr = xpad.data() + data_offset;
        size_t data_remaining = actual_xpad_len - data_offset;

        // Process each CI's data subfield
        for (auto ci : cis) {
            uint8_t len_idx = (ci >> 5) & 0x07;
            uint8_t app_type = ci & 0x1F;
            size_t subfield_len = xpad_len_table[len_idx];

            if (subfield_len > data_remaining) {
                subfield_len = data_remaining;
            }

#ifdef PAD_DEBUG
            if (pad_count_ <= 50) {
                fprintf(stderr, "[PAD] Variable X-PAD: CI=0x%02x len_idx=%d len=%zu app_type=%d\n",
                        ci, len_idx, subfield_len, app_type);
            }
#endif

            xpad_app_type_ = app_type;
            if (app_type != 0 && subfield_len > 0) {
                processXPad(data_ptr, subfield_len, app_type);
            }

            data_ptr += subfield_len;
            if (subfield_len <= data_remaining) {
                data_remaining -= subfield_len;
            } else {
                break;
            }
        }
        return;
    }

    if (xpad_ind == 2 && !ci_flag) {
        // Variable X-PAD without CI - use previous app_type
        if (xpad_app_type_ != 0 && actual_xpad_len > 0) {
#ifdef PAD_DEBUG
            if (pad_count_ <= 50) {
                fprintf(stderr, "[PAD] Variable X-PAD (no CI): prev app_type=%d len=%zu\n",
                        xpad_app_type_, actual_xpad_len);
            }
#endif
            processXPad(xpad.data(), actual_xpad_len, xpad_app_type_);
        }
    }
}

void PadDecoder::processFPad(uint8_t fpad_type, uint8_t ci_flag) {
    // F-PAD types (not commonly used for DLS):
    // Type 0: No audio-related data (most common)
    // Type 1: Audio-related data
    // Type 2: RFU
    // Type 3: RFU
    (void)fpad_type;
    (void)ci_flag;
}

void PadDecoder::processXPad(const uint8_t* xpad, size_t len, uint8_t app_type) {
    // X-PAD Application Types:
    // 0: Not used
    // 1: Data Group Length Indicator
    // 2: Data Group start
    // 3: Data Group continuation
    // 12: MOT (for SlideShow)
    // 13: MOT continuation

    if (app_type == 1) {
        // Data Group Length Indicator (DGLI)
        // Tells us the expected total length of the Data Group
        if (len >= 4) {
            // DGLI format: 4 bytes giving the length
            // Bits 0-1: RFU, Bits 2-13: Length (12 bits)
            size_t dg_len = ((xpad[0] & 0x3F) << 6) | ((xpad[1] >> 2) & 0x3F);
            xpad_len_ = dg_len;
#ifdef PAD_DEBUG
            fprintf(stderr, "[PAD] DGLI: expected length=%zu\n", dg_len);
#endif
        }
        return;
    }

    if (app_type == 2) {
        // Data Group start - first, process any pending Data Group
        if (dg_in_progress_ && dg_buffer_.size() >= 3) {
#ifdef PAD_DEBUG
            fprintf(stderr, "[PAD] Processing completed DG: size=%zu\n", dg_buffer_.size());
#endif
            processDataGroup(dg_buffer_.data(), dg_buffer_.size());
        }

        // Reset and start collecting new Data Group
        dg_buffer_.clear();
        dg_in_progress_ = true;
        xpad_len_ = 0;
    }

    if (app_type == 2 || app_type == 3) {
        // Data Group segment (start or continuation)
#ifdef PAD_DEBUG
        fprintf(stderr, "[PAD] DG segment: app_type=%d dg_in_progress=%d len=%zu buffer_size=%zu\n",
                app_type, dg_in_progress_, len, dg_buffer_.size());
#endif
        if (!dg_in_progress_) return;
        if (len == 0) return;

        dg_buffer_.insert(dg_buffer_.end(), xpad, xpad + len);

        // If we have expected length from DGLI and have reached it, process now
        if (xpad_len_ > 0 && dg_buffer_.size() >= xpad_len_) {
#ifdef PAD_DEBUG
            fprintf(stderr, "[PAD] DG complete (DGLI): size=%zu expected=%zu\n",
                    dg_buffer_.size(), xpad_len_);
#endif
            processDataGroup(dg_buffer_.data(), dg_buffer_.size());
            dg_buffer_.clear();
            dg_in_progress_ = false;
            xpad_len_ = 0;
        }

        return;
    }

    // Other application types (MOT, etc.) - not implemented yet
}

void PadDecoder::processDataGroup(const uint8_t* data, size_t len) {
    // DLS Data Group format (ETSI TS 102 980, simplified for PAD):
    // This matches dablin's DynamicLabelDecoder approach
    //
    // Byte 0: Prefix
    //   Bit 7: Toggle flag (changes when content updates)
    //   Bit 6: First segment flag
    //   Bit 5: Last segment flag
    //   Bit 4: Command flag (1=DL Plus command, 0=DL segment)
    //   Bits 3-0: If command=0: segment number (0-14) or charset (if first)
    //             If command=1: command type
    // Byte 1: (for segments) Additional info
    // Following bytes: Character data

    if (len < 2) return;

    uint8_t prefix = data[0];
    bool toggle = (prefix & 0x80) != 0;
    bool command = (prefix & 0x10) != 0;
    bool first = (prefix & 0x40) != 0;
    bool last = (prefix & 0x20) != 0;

#ifdef PAD_DEBUG
    fprintf(stderr, "[PAD] DG: len=%zu prefix=0x%02x toggle=%d cmd=%d first=%d last=%d\n",
            len, prefix, toggle, command, first, last);
    fprintf(stderr, "[PAD] DG raw: ");
    for (size_t i = 0; i < len && i < 24; i++) {
        fprintf(stderr, "%02x ", data[i]);
    }
    fprintf(stderr, "\n");
#endif

    if (command) {
        // DL Plus command
        uint8_t cmd_type = prefix & 0x0F;
        if (cmd_type == 0 || cmd_type == 2) {
            // DL Plus tags (cmd_type=0) or Item Running (cmd_type=2)
            // Both contain DL Plus tags in the same format (ETSI TS 102 980 Section 7.4.3)
            // Only apply if toggle matches current DLS
            if (len >= 2) {
                processDLPlus(data + 1, len - 1, toggle);
            }
        }
        // cmd_type=1 is Item Toggle (indicates new item started) - no tags
    } else {
        // DL segment
        // Calculate field length from lower nibble + 1
        size_t field_len = (prefix & 0x0F) + 1;
        if (len < 2 + field_len) {
            // Not enough data, might need to wait for CRC verification
            field_len = len - 2;
        }

        // Skip 2-byte prefix, extract character data
        if (len >= 2) {
            processDLSSegmentNew(data, len, first, last, field_len, toggle);
        }
    }
}

void PadDecoder::processDLSSegmentNew(const uint8_t* data, size_t len, bool first, bool last, size_t field_len, bool toggle) {
    // DLS segment structure (dablin format):
    // Byte 0: Prefix (toggle|first|last|cmd|field_len_minus_1)
    // Byte 1: Second prefix byte (rfu/charset info)
    // Bytes 2+: Character data (field_len bytes)
    // Final 2 bytes: CRC-16 (if present)

    if (len < 2) return;

    // Extract character data starting at byte 2
    const uint8_t* chars = data + 2;
    size_t char_len = field_len;

    // Ensure we don't read past the data (leave room for optional CRC)
    if (char_len > len - 2) {
        char_len = len - 2;
    }

    // For first segment, byte 1 contains charset info
    if (first) {
        dls_charset_ = data[1] & 0x0F;
        dls_len_ = 0;
        dls_first_received_ = true;
        dls_toggle_ = toggle;  // Track toggle for this DLS
    }

#ifdef PAD_DEBUG
    fprintf(stderr, "[PAD] DLS segment (new): first=%d last=%d field_len=%zu char_len=%zu charset=%d\n",
            first, last, field_len, char_len, dls_charset_);
    if (char_len > 0) {
        fprintf(stderr, "[PAD] DLS chars: '");
        for (size_t i = 0; i < char_len && i < 32; i++) {
            if (chars[i] >= 32 && chars[i] < 127) fprintf(stderr, "%c", chars[i]);
            else fprintf(stderr, "\\x%02x", static_cast<uint8_t>(chars[i]));
        }
        fprintf(stderr, "'\n");
    }
#endif

    if (!dls_first_received_) {
        return;
    }

    // Append character data
    size_t copy_len = std::min(char_len, static_cast<size_t>(128) - dls_len_);
    if (copy_len > 0) {
        std::memcpy(dls_buffer_.data() + dls_len_, chars, copy_len);
        dls_len_ += copy_len;
    }

    if (last) {
        // Complete DLS received
        dls_buffer_[dls_len_] = '\0';

        // Convert charset if needed
        if (dls_charset_ == 0) {
            // Convert EBU Latin to UTF-8
            current_dls_ = ebuLatinToUtf8(dls_buffer_.data(), dls_len_);
        } else {
            current_dls_ = std::string(dls_buffer_.data(), dls_len_);
        }

        current_dls_toggle_ = dls_toggle_;  // Store toggle of completed DLS

        // Trim trailing spaces/nulls
        while (!current_dls_.empty() &&
               (current_dls_.back() == ' ' || current_dls_.back() == '\0')) {
            current_dls_.pop_back();
        }

        // Clear tags when DLS changes (toggle changes)
        current_tags_.clear();

        dls_count_++;

#ifdef PAD_DEBUG
        fprintf(stderr, "[PAD] *** COMPLETE DLS #%zu (toggle=%d): '%s'\n",
                dls_count_, current_dls_toggle_, current_dls_.c_str());
#endif

        if (dls_callback_ && !current_dls_.empty()) {
            dls_callback_(current_dls_);
        }

        // Note: Don't call dlplus_callback here - wait for matching DL Plus tags

        dls_first_received_ = false;
    }
}

void PadDecoder::processDLSSegment(const uint8_t* data, size_t len, bool first, bool last) {
    if (len < 1) return;

    uint8_t prefix = data[0];
    data++;
    len--;

#ifdef PAD_DEBUG
    fprintf(stderr, "[PAD] DLS segment: first=%d last=%d len=%zu charset=%d prefix=0x%02x\n",
            first, last, len, prefix & 0x0F, prefix);
    if (len > 0 && len <= 32) {
        fprintf(stderr, "[PAD] DLS raw hex: ");
        for (size_t i = 0; i < len && i < 32; i++) {
            fprintf(stderr, "%02x ", data[i]);
        }
        fprintf(stderr, "\n[PAD] DLS text: '");
        for (size_t i = 0; i < len && i < 32; i++) {
            if (data[i] >= 32 && data[i] < 127) fprintf(stderr, "%c", data[i]);
            else fprintf(stderr, ".");
        }
        fprintf(stderr, "'\n");
    }
#endif

    if (first) {
        // First segment contains charset in bits 3-0 of prefix
        dls_charset_ = prefix & 0x0F;
        dls_len_ = 0;
        dls_first_received_ = true;
    }

    if (!dls_first_received_) {
        // Haven't seen first segment yet, ignore
        return;
    }

    // Copy text data
    size_t copy_len = std::min(len, static_cast<size_t>(128) - dls_len_);
    if (copy_len > 0) {
        std::memcpy(dls_buffer_.data() + dls_len_, data, copy_len);
        dls_len_ += copy_len;
    }

    if (last) {
        // Complete DLS received
        dls_buffer_[dls_len_] = '\0';

        // Convert charset if needed
        // Charset 0 = EBU Latin (similar to ISO 8859-15)
        // Charset 15 = UTF-8
        if (dls_charset_ == 0) {
            // Convert EBU Latin to UTF-8
            current_dls_ = ebuLatinToUtf8(dls_buffer_.data(), dls_len_);
        } else if (dls_charset_ == 15) {
            // Already UTF-8
            current_dls_ = std::string(dls_buffer_.data(), dls_len_);
        } else {
            // Unknown charset - use as-is
            current_dls_ = std::string(dls_buffer_.data(), dls_len_);
        }

        // Trim trailing spaces/nulls
        while (!current_dls_.empty() &&
               (current_dls_.back() == ' ' || current_dls_.back() == '\0')) {
            current_dls_.pop_back();
        }

        dls_count_++;

#ifdef PAD_DEBUG
        fprintf(stderr, "[PAD] *** COMPLETE DLS #%zu: '%s'\n", dls_count_, current_dls_.c_str());
#endif

        // Notify callback
        if (dls_callback_ && !current_dls_.empty()) {
            dls_callback_(current_dls_);
        }

        // Also notify DL Plus callback (text changed)
        if (dlplus_callback_ && !current_dls_.empty()) {
            dlplus_callback_(current_dls_, current_tags_);
        }

        // Reset for next DLS
        dls_first_received_ = false;
    }
}

void PadDecoder::processDLPlus(const uint8_t* data, size_t len, bool toggle) {
    // DL Plus structure (ETSI TS 102 980):
    // Byte 0: Header
    //   Bit 7: Link bit (1 = more segments follow)
    //   Bits 6-4: RFU or running state (for Item Running)
    //   Bits 3-0: Number of tags - 1 (nt, actual count = nt + 1)
    // Following bytes: Tags (3 bytes each)
    //   Byte 0 bits 6-0: Content type (7 bits)
    //   Byte 1 bits 6-0: Start marker (7 bits)
    //   Byte 2 bits 6-0: Length marker (7 bits, actual length = marker + 1)
    // Last 2 bytes: CRC-16

    // Only process if toggle matches current DLS
    if (toggle != current_dls_toggle_) {
#ifdef PAD_DEBUG
        fprintf(stderr, "[PAD] DL Plus: toggle mismatch (dlplus=%d, dls=%d), skipping\n",
                toggle, current_dls_toggle_);
#endif
        dlplus_buffer_.clear();
        dlplus_link_pending_ = false;
        return;
    }

    if (len < 3) return;

    uint8_t header = data[0];
    bool link_bit = (header & 0x80) != 0;
    int nt = header & 0x0F;
    int num_tags = nt + 1;

    // Handle linked segments: accumulate data until link bit is 0
    if (link_bit) {
        // This segment links to next - accumulate (skip header, include tag bytes)
        // CRC is only at the end of the final segment
        if (dlplus_buffer_.empty()) {
            // First segment - store header info
            dlplus_buffer_.push_back(header);
        }
        // Append tag data (skip header byte, keep rest except possible partial CRC)
        for (size_t i = 1; i < len; i++) {
            dlplus_buffer_.push_back(data[i]);
        }
        dlplus_link_pending_ = true;
#ifdef PAD_DEBUG
        fprintf(stderr, "[PAD] DL Plus: link segment, accumulated %zu bytes\n", dlplus_buffer_.size());
#endif
        return;
    }

    // Final segment (link bit = 0)
    std::vector<uint8_t> complete_data;
    if (dlplus_link_pending_ && !dlplus_buffer_.empty()) {
        // We have accumulated data from previous segments
        complete_data = std::move(dlplus_buffer_);
        // Append this final segment (skip header if we already have one)
        for (size_t i = 1; i < len; i++) {
            complete_data.push_back(data[i]);
        }
        dlplus_buffer_.clear();
        dlplus_link_pending_ = false;
        // Update header and num_tags from accumulated data
        header = complete_data[0];
        nt = header & 0x0F;
        num_tags = nt + 1;
    } else {
        // Single segment, no linking
        complete_data.assign(data, data + len);
    }

    // Remove CRC-16 (2 bytes) from the end
    if (complete_data.size() < 5) return;  // Need header + at least 1 tag + CRC
    size_t data_len = complete_data.size() - 2;

#ifdef PAD_DEBUG
    fprintf(stderr, "[PAD] DL Plus: complete len=%zu data_len=%zu header=0x%02x nt=%d num_tags=%d\n",
            complete_data.size(), data_len, header, nt, num_tags);
    fprintf(stderr, "[PAD] DL Plus raw: ");
    for (size_t i = 0; i < complete_data.size() && i < 24; i++) {
        fprintf(stderr, "%02x ", complete_data[i]);
    }
    fprintf(stderr, "\n");
#endif

    // Tags start at byte 1 (after header)
    size_t tag_offset = 1;
    size_t available_tag_bytes = data_len - 1;
    int max_tags = static_cast<int>(available_tag_bytes / 3);
    num_tags = std::min(num_tags, max_tags);

    if (num_tags <= 0 || num_tags > 4) {
        return;
    }

    // Parse tags
    current_tags_.clear();
    const uint8_t* tag_ptr = complete_data.data() + tag_offset;

    for (int i = 0; i < num_tags; i++) {
        if (tag_offset + (i + 1) * 3 > data_len) break;

        DLPlusTag tag;
        tag.content_type = static_cast<DLPlusContentType>(tag_ptr[0] & 0x7F);
        tag.start_marker = tag_ptr[1] & 0x7F;
        tag.length_marker = tag_ptr[2] & 0x7F;

        // Validate tag - skip dummy or clearly invalid tags
        if (tag.content_type != DLPlusContentType::DUMMY &&
            tag.start_marker < 128 && tag.length_marker < 128) {

#ifdef PAD_DEBUG
            fprintf(stderr, "[PAD] DL Plus tag %d: type=%d (%s) start=%d len=%d\n",
                    i, static_cast<int>(tag.content_type),
                    dlPlusContentTypeToString(tag.content_type),
                    tag.start_marker, tag.length_marker);
            if (!current_dls_.empty() && tag.start_marker < current_dls_.size()) {
                std::string extracted = tag.extract(current_dls_);
                fprintf(stderr, "[PAD] DL Plus tag %d text: '%s'\n", i, extracted.c_str());
            }
#endif
            // Only add tags for TITLE and ARTIST (the ones we care about for EIT)
            if (tag.content_type == DLPlusContentType::ITEM_TITLE ||
                tag.content_type == DLPlusContentType::ITEM_ARTIST ||
                tag.content_type == DLPlusContentType::ITEM_ALBUM ||
                tag.content_type == DLPlusContentType::PROGRAMME_NOW ||
                tag.content_type == DLPlusContentType::STATIONNAME_LONG) {
                current_tags_.push_back(tag);
            }
        }

        tag_ptr += 3;
    }

    if (!current_tags_.empty()) {
        dlplus_count_++;

        // Notify callback if we have DLS text
        if (dlplus_callback_ && !current_dls_.empty()) {
            dlplus_callback_(current_dls_, current_tags_);
        }
    }
}

bool PadDecoder::isValidDLS(const std::string& text) {
    if (text.size() < 8) return false;

    // Check for fill patterns (repeating characters)
    bool all_same = true;
    for (size_t i = 1; i < text.size() && all_same; i++) {
        if (text[i] != text[0]) all_same = false;
    }
    if (all_same) return false;

    // Check for alternating patterns like "iiiii" or "ZZZZZ"
    int repeat_count = 1;
    for (size_t i = 1; i < text.size(); i++) {
        if (text[i] == text[i-1]) {
            repeat_count++;
            if (repeat_count > 4) return false;  // Too many repeats
        } else {
            repeat_count = 1;
        }
    }

    // Filter out JPEG/binary patterns
    if (text.find("JFIF") != std::string::npos) return false;
    if (text.find("CREATOR") != std::string::npos) return false;
    if (text.find("gd-jpeg") != std::string::npos) return false;
    if (text.find("IJG") != std::string::npos) return false;

    // Filter out common ASCII sequences (like from binary data)
    if (text.find(")*456789") != std::string::npos) return false;
    if (text.find("CDEFGHIJ") != std::string::npos) return false;
    if (text.find("stuvwxyz") != std::string::npos) return false;

    // Check for valid DLS patterns (has spaces, dashes, or alphanumeric mix)
    int space_count = 0;
    int letter_count = 0;
    int digit_count = 0;
    int special_count = 0;

    for (char c : text) {
        if (c == ' ') space_count++;
        else if (std::isalpha(static_cast<unsigned char>(c))) letter_count++;
        else if (std::isdigit(static_cast<unsigned char>(c))) digit_count++;
        else special_count++;
    }

    // Valid DLS typically has:
    // - Some spaces (for "Artist - Title" format)
    // - Mostly letters
    // - Not too many special characters
    if (space_count == 0 && text.size() > 20) return false;  // Long text without spaces is suspicious
    if (letter_count < static_cast<int>(text.size()) / 3) return false;  // Too few letters
    if (special_count > static_cast<int>(text.size()) / 3) return false;  // Too many special chars

    return true;
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
