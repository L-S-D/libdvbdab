#include "dab_parser.h"
#include "logging.h"
#include "utils/crc_utils.hpp"
#include "utils/byte_utils.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace dvbdab {

// Bitrate tables from ETSI EN 300 401
static const int uep_bitrates[] = {
    32, 32, 32, 32, 32,   // indices 0-4
    48, 48, 48, 48, 48,   // indices 5-9
    56, 56, 56, 56,       // indices 10-13
    64, 64, 64, 64, 64, 64, 64,  // indices 14-20
    80, 80, 80, 80, 80, 80,      // indices 21-26
    96, 96, 96, 96, 96, 96,      // indices 27-32
    112, 112, 112, 112,   // indices 33-36
    128, 128, 128, 128, 128, 128, 128, // indices 37-43
    160, 160, 160, 160, 160, 160, // indices 44-49
    192, 192, 192, 192, 192, 192, 192, // indices 50-56
    224, 224, 224, 224, 224, // indices 57-61
    256, 256, 256          // indices 62-64
};

static int get_eep_bitrate(int subchsz, int protlvl) {
    int n = 0;
    switch (protlvl) {
        case 0: n = subchsz / 12; break;  // EEP-1A
        case 1: n = subchsz / 8; break;   // EEP-2A
        case 2: n = subchsz / 6; break;   // EEP-3A
        case 3: n = subchsz / 4; break;   // EEP-4A
        case 4: n = subchsz / 27; break;  // EEP-1B
        case 5: n = subchsz / 21; break;  // EEP-2B
        case 6: n = subchsz / 18; break;  // EEP-3B
        case 7: n = subchsz / 15; break;  // EEP-4B
        default: return 0;
    }
    return n * 8;
}

// EBU Latin character set to Unicode mapping (ETSI EN 300 401 Annex C)
// Characters 0x80-0x9F differ from ISO 8859-1
static const uint16_t ebu_latin_table[256] = {
    // 0x00-0x7F: Same as ASCII
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
    0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F,
    0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
    0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x001F,
    0x0020, 0x0021, 0x0022, 0x0023, 0x00A4, 0x0025, 0x0026, 0x0027,  // 0x24 = currency sign
    0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
    0x0058, 0x0059, 0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F,
    0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
    0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x007F,
    // 0x80-0x9F: EBU Latin special characters
    0x00E1, 0x00E0, 0x00E9, 0x00E8, 0x00ED, 0x00EC, 0x00F3, 0x00F2,  // áàéèíìóò
    0x00FA, 0x00F9, 0x00D1, 0x00C7, 0x015E, 0x00DF, 0x00A1, 0x0132,  // úùÑÇŞß¡Ĳ
    0x00E2, 0x00E4, 0x00EA, 0x00EB, 0x00EE, 0x00EF, 0x00F4, 0x00F6,  // âäêëîïôö
    0x00FB, 0x00FC, 0x00F1, 0x00E7, 0x015F, 0x011F, 0x0131, 0x0133,  // ûüñçşğıĳ
    // 0xA0-0xBF
    0x00AA, 0x03B1, 0x00A9, 0x2030, 0x011E, 0x011B, 0x0148, 0x0151,  // ªα©‰Ğěňő
    0x03C0, 0x20AC, 0x00A3, 0x0024, 0x2190, 0x2191, 0x2192, 0x2193,  // π€£$←↑→↓
    0x00BA, 0x00B9, 0x00B2, 0x00B3, 0x00B1, 0x0130, 0x0144, 0x0171,  // º¹²³±İńű
    0x00B5, 0x00BF, 0x00F7, 0x00B0, 0x00BC, 0x00BD, 0x00BE, 0x00A7,  // µ¿÷°¼½¾§
    // 0xC0-0xDF
    0x00C1, 0x00C0, 0x00C9, 0x00C8, 0x00CD, 0x00CC, 0x00D3, 0x00D2,  // ÁÀÉÈÍÌÓÒ
    0x00DA, 0x00D9, 0x0158, 0x010C, 0x0160, 0x017D, 0x00D0, 0x013F,  // ÚÙŘČŠŽÐĿ
    0x00C2, 0x00C4, 0x00CA, 0x00CB, 0x00CE, 0x00CF, 0x00D4, 0x00D6,  // ÂÄÊËÎÏÔÖ
    0x00DB, 0x00DC, 0x0159, 0x010D, 0x0161, 0x017E, 0x0111, 0x0140,  // ÛÜřčšžđŀ
    // 0xE0-0xFF
    0x00C3, 0x00C5, 0x00C6, 0x0152, 0x0177, 0x00DD, 0x00D5, 0x00D8,  // ÃÅÆŒŷÝÕØ
    0x00DE, 0x014A, 0x0154, 0x0106, 0x015A, 0x0179, 0x0166, 0x00F0,  // ÞŊŔĆŚŹŦð
    0x00E3, 0x00E5, 0x00E6, 0x0153, 0x0175, 0x00FD, 0x00F5, 0x00F8,  // ãåæœŵýõø
    0x00FE, 0x014B, 0x0155, 0x0107, 0x015B, 0x017A, 0x0167, 0x00FF   // þŋŕćśźŧÿ
};

// Append Unicode codepoint as UTF-8
static void append_utf8(std::string& result, uint16_t cp) {
    if (cp < 0x80) {
        result += static_cast<char>(cp);
    } else if (cp < 0x800) {
        result += static_cast<char>(0xC0 | (cp >> 6));
        result += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        result += static_cast<char>(0xE0 | (cp >> 12));
        result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        result += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

// Convert EBU Latin (charset 0) to UTF-8
static std::string ebu_latin_to_utf8(const char* src, size_t len) {
    std::string result;
    result.reserve(len * 3);

    for (size_t i = 0; i < len && src[i] != '\0'; i++) {
        unsigned char c = static_cast<unsigned char>(src[i]);
        uint16_t cp = ebu_latin_table[c];
        append_utf8(result, cp);
    }
    return result;
}

// Convert ISO 8859-1 (Latin-1) to UTF-8
static std::string latin1_to_utf8(const char* src, size_t len) {
    std::string result;
    result.reserve(len * 2);

    for (size_t i = 0; i < len && src[i] != '\0'; i++) {
        unsigned char c = static_cast<unsigned char>(src[i]);
        if (c < 0x80) {
            result += c;
        } else {
            result += static_cast<char>(0xC0 | (c >> 6));
            result += static_cast<char>(0x80 | (c & 0x3F));
        }
    }
    return result;
}

// Convert DAB label to UTF-8 based on charset
static std::string dab_label_to_utf8(const char* src, size_t len, int charset) {
    switch (charset) {
        case 0:  // Complete EBU Latin
        case 1:  // EBU Latin core
        case 2:  // EBU Latin
            return ebu_latin_to_utf8(src, len);
        case 6:  // ISO 8859-1 (Latin-1)
            return latin1_to_utf8(src, len);
        case 15: // UTF-8
            return std::string(src, strnlen(src, len));
        default:
            // Fall back to EBU Latin for unknown charsets
            return ebu_latin_to_utf8(src, len);
    }
}

DABParser::DABParser() : ensemble_id_(0), labelled_(false), basic_ready_(false),
    last_basic_service_count_(0), basic_stable_frames_(0),
    last_service_count_(0), stable_frames_(0), last_label_count_(0), label_stable_frames_(0) {
    reset();
}

DABParser::~DABParser() = default;

void DABParser::reset() {
    subchannels_.clear();
    pending_ascty_.clear();
    service_map_.clear();
    service_labels_.clear();
    ensemble_label_.clear();
    ensemble_id_ = 0;
    labelled_ = false;
    basic_ready_ = false;
    ensemble_ = DABEnsemble{};
    last_basic_service_count_ = 0;
    basic_stable_frames_ = 0;
    last_service_count_ = 0;
    stable_frames_ = 0;
    last_label_count_ = 0;
    label_stable_frames_ = 0;
    start_time_ = std::chrono::steady_clock::now();
    label_first_seen_ms_.clear();
    ensemble_label_first_seen_ms_ = -1;
}

bool DABParser::process_eti_frame(const uint8_t* frame, size_t len) {
    eti_call_count_++;

    if (labelled_) return true;

    if (len < 8) return false;

    uint32_t sync = (frame[0] << 24) | (frame[1] << 16) | (frame[2] << 8) | frame[3];
    if (eti_call_count_ <= 5 || eti_call_count_ % 100 == 0) {
        LOG_DEBUG(FIC, "process_eti_frame #" << eti_call_count_ << " sync=0x" << std::hex << sync
                 << " expect 0x" << ETI_NI_FSYNC0 << " or 0x" << ETI_NI_FSYNC1 << std::dec);
    }
    if (sync != ETI_NI_FSYNC0 && sync != ETI_NI_FSYNC1) {
        LOG_DEBUG(FIC, "sync mismatch! first 8 bytes: 0x" << std::hex
                 << (int)frame[0] << " 0x" << (int)frame[1] << " 0x" << (int)frame[2]
                 << " 0x" << (int)frame[3] << " 0x" << (int)frame[4] << " 0x" << (int)frame[5]
                 << " 0x" << (int)frame[6] << " 0x" << (int)frame[7] << std::dec);
        return false;
    }

    ETI_FC fc = parse_fc(frame + 4);

    if (fc.ficf == 0) {
        return labelled_;
    }

    int ficl = 24;
    if (fc.mid == 3) ficl = 32;

    int stc_end = 8 + (fc.nst * 4) + 4;
    const uint8_t* fic_data = frame + stc_end;
    int fic_len = ficl * 4;

    if ((size_t)(stc_end + fic_len) > len) {
        return labelled_;
    }

    process_fic(fic_data, fic_len, fc.mid);

    if (!service_map_.empty()) {
        build_ensemble();
    }

    // Check for basic ready - requires ALL audio subchannels have FIG 0/1 AND FIG 0/2
    if (!basic_ready_ && !service_map_.empty()) {
        size_t valid_services = 0;
        bool all_ready = true;

        for (const auto& [sid, info] : service_map_) {
            if (info.primary_subch >= 0) {
                auto it = subchannels_.find(info.primary_subch);
                if (it == subchannels_.end() || !it->second.codec_known) {
                    all_ready = false;  // Missing FIG 0/1 or FIG 0/2
                } else {
                    valid_services++;
                }
            }
        }

        if (valid_services > 0 && all_ready) {
            if (valid_services != last_basic_service_count_) {
                last_basic_service_count_ = valid_services;
                basic_stable_frames_ = 0;
            } else {
                basic_stable_frames_++;
            }

            if (basic_stable_frames_ >= 3) {
                basic_ready_ = true;
                LOG_INFO(FIC, "DAB BASIC READY: " << valid_services << " services, can start audio");
            }
        }
    }

    // Check for completion
    if (!service_map_.empty()) {
        size_t labelled_count = 0;
        for (const auto& [sid, _] : service_map_) {
            if (service_labels_.count(sid) > 0) {
                labelled_count++;
            }
        }

        bool has_ensemble_label = !ensemble_label_.empty();

        if (service_map_.size() != last_service_count_) {
            last_service_count_ = service_map_.size();
            stable_frames_ = 0;
        } else {
            stable_frames_++;
        }

        bool all_labelled = (labelled_count == service_map_.size() && has_ensemble_label);
        bool stable = (stable_frames_ >= 10);

        if (all_labelled && stable) {
            labelled_ = true;
            LOG_INFO(FIC, "DAB COMPLETE: " << service_map_.size() << " services with labels, ensemble='" << ensemble_label_ << "'");
            return true;
        }
    }

    return false;
}

void DABParser::process_fic(const uint8_t* fic_data, int fic_len, int /*mode_id*/) {
    int offset = 0;
    while (offset + 32 <= fic_len) {
        process_fib(fic_data + offset);
        offset += 32;
    }
}

static bool fib_crc_ok(const uint8_t* fib, bool debug = false) {
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < 30; i++) {
        crc = (crc << 8) ^ crc16_ccitt_table[(crc >> 8) ^ fib[i]];
    }
    crc ^= 0xFFFF;
    uint16_t stored_crc = (fib[30] << 8) | fib[31];
    if (debug) {
        LOG_DEBUG(FIC, "FIB CRC: calc=0x" << std::hex << crc << " stored=0x" << stored_crc
                 << " ok=" << (crc == stored_crc) << std::dec);
    }
    return crc == stored_crc;
}

void DABParser::process_fib(const uint8_t* fib) {
    fib_count_++;

    bool debug = fib_count_ <= 10;
    if (!fib_crc_ok(fib, debug)) {
        if (debug) {
            LOG_WARN(FIC, "FIB CRC fail - first 8 bytes: 0x" << std::hex
                     << (int)fib[0] << " 0x" << (int)fib[1] << " 0x" << (int)fib[2]
                     << " 0x" << (int)fib[3] << " 0x" << (int)fib[4] << " 0x" << (int)fib[5]
                     << " 0x" << (int)fib[6] << " 0x" << (int)fib[7] << std::dec);
        }
        return;
    }
    if (debug) {
        LOG_DEBUG(FIC, "FIB OK! Processing FIGs...");
    }

    int pos = 0;
    while (pos < 30) {
        uint8_t hdr = fib[pos];
        if (hdr == 0xFF) break;

        int fig_len = hdr & 0x1F;

        if (pos + 1 + fig_len > 30) break;

        process_fig(fib + pos + 1, fig_len);

        pos += 1 + fig_len;
    }
}

void DABParser::process_fig(const uint8_t* fig, int fig_len) {
    if (fig_len < 1) return;

    int fig_type = (fig[-1] >> 5) & 0x07;

    // FIG type 0 and 1 have different first data byte structures
    int ext, pd, charset;
    if (fig_type == 0) {
        // FIG 0: ext in bits 0-4, pd in bit 5, OE in bit 6, C/N in bit 7
        ext = fig[0] & 0x1F;
        pd = (fig[0] >> 5) & 0x01;
        charset = 0;
    } else if (fig_type == 1) {
        // FIG 1: ext in bits 0-2, OE in bit 3, charset in bits 4-7
        ext = fig[0] & 0x07;
        pd = 0;
        charset = (fig[0] >> 4) & 0x0F;
    } else {
        ext = 0;
        pd = 0;
        charset = 0;
    }

    fig_debug_count_++;

    LOG_DEBUG(FIC, "FIG: type=" << fig_type << " ext=" << ext << " pd=" << pd
             << " charset=" << charset
             << " len=" << fig_len << " hdr=0x" << std::hex << (int)fig[-1]
             << " first=0x" << (int)fig[0] << std::dec);

    switch (fig_type) {
        case 0:
            process_fig_0(fig + 1, fig_len - 1, ext, pd);
            break;
        case 1:
            process_fig_1(fig + 1, fig_len - 1, ext, charset);
            break;
    }
}

void DABParser::process_fig_0(const uint8_t* data, int len, int ext, int pd) {
    switch (ext) {
        case 0: {
            // FIG 0/0 - Ensemble Information
            if (len < 4) return;
            uint16_t eid = (data[0] << 8) | data[1];
            if (ensemble_id_ == 0 || ensemble_id_ != eid) {
                ensemble_id_ = eid;
                LOG_DEBUG(FIC, "FIG 0/0: Ensemble EID=0x" << std::hex << eid << std::dec);
            }
            break;
        }

        case 1: {
            // FIG 0/1 - Sub-channel organization
            int pos = 0;
            while (pos + 3 <= len) {
                int subchid = (data[pos] >> 2) & 0x3F;
                int startaddr = ((data[pos] & 0x03) << 8) | data[pos + 1];
                int form = (data[pos + 2] >> 7) & 0x01;

                SubChannel sc;
                sc.subchid = subchid;
                sc.startaddr = startaddr;
                if (subchannels_.count(subchid)) {
                    sc.dabplus = subchannels_[subchid].dabplus;
                    sc.codec_known = subchannels_[subchid].codec_known;
                } else if (pending_ascty_.count(subchid)) {
                    // FIG 0/2 arrived first - apply stored ASCTy
                    sc.dabplus = (pending_ascty_[subchid] == 63) ? 1 : 0;
                    sc.codec_known = true;
                    pending_ascty_.erase(subchid);
                } else {
                    sc.dabplus = 0;
                    sc.codec_known = false;
                }

                if (form == 0) {
                    int table_index = data[pos + 2] & 0x3F;
                    sc.eepprot = 0;
                    sc.uep_indx = table_index;
                    if (table_index < 64) {
                        sc.bitrate = uep_bitrates[table_index];
                    }
                    sc.subchsz = 0;
                    pos += 3;
                } else {
                    if (pos + 4 > len) break;
                    int subchsz = ((data[pos + 2] & 0x03) << 8) | data[pos + 3];
                    int protlvl = (data[pos + 2] >> 2) & 0x03;
                    int option = (data[pos + 2] >> 4) & 0x07;

                    sc.subchsz = subchsz;
                    sc.eepprot = 1;
                    sc.protlvl = protlvl + (option ? 4 : 0);
                    sc.bitrate = get_eep_bitrate(subchsz, sc.protlvl);
                    pos += 4;
                }

                subchannels_[subchid] = sc;
            }
            break;
        }

        case 2: {
            // FIG 0/2 - Basic service and component definition
            int pos = 0;
            int min_service_size = pd ? 5 : 3;
            while (pos + min_service_size <= len) {
                uint32_t sid;
                if (pd) {
                    sid = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos + 1] << 16) |
                          ((uint32_t)data[pos + 2] << 8) | data[pos + 3];
                    pos += 4;
                } else {
                    sid = (data[pos] << 8) | data[pos + 1];
                    pos += 2;
                }

                int num_components = data[pos] & 0x0F;
                pos++;

                ServiceInfo info;
                info.sid = sid;
                info.primary_subch = -1;
                info.secondary_subch = -1;

                for (int i = 0; i < num_components && pos + 2 <= len; i++) {
                    int tmid = (data[pos] >> 6) & 0x03;
                    if (tmid == 0) {
                        int ascty = data[pos] & 0x3F;
                        int subchid = (data[pos + 1] >> 2) & 0x3F;
                        int primary = (data[pos + 1] >> 1) & 0x01;

                        if (subchannels_.count(subchid)) {
                            subchannels_[subchid].dabplus = (ascty == 63) ? 1 : 0;
                            subchannels_[subchid].codec_known = true;
                            LOG_DEBUG(FIC, "FIG 0/2: SID=0x" << std::hex << sid
                                     << " subch=" << std::dec << subchid
                                     << " ASCTy=" << ascty
                                     << " -> " << ((ascty == 63) ? "DAB+" : "DAB"));
                        } else {
                            // Subchannel not yet created by FIG 0/1 - store for later
                            pending_ascty_[subchid] = ascty;
                            LOG_DEBUG(FIC, "FIG 0/2: SID=0x" << std::hex << sid
                                     << " subch=" << std::dec << subchid
                                     << " ASCTy=" << ascty << " (pending)");
                        }

                        if (primary && info.primary_subch < 0) {
                            info.primary_subch = subchid;
                        } else if (info.secondary_subch < 0) {
                            info.secondary_subch = subchid;
                        }
                    } else if (tmid == 1) {
                        int dscty = data[pos] & 0x3F;
                        int subchid = (data[pos + 1] >> 2) & 0x3F;
                        int primary = (data[pos + 1] >> 1) & 0x01;

                        LOG_DEBUG(FIC, "FIG 0/2: DATA SID=0x" << std::hex << sid << std::dec
                                 << " subch=" << subchid
                                 << " DSCTy=" << dscty
                                 << " primary=" << primary
                                 << " (packet mode)");

                        if (primary && info.primary_subch < 0) {
                            info.primary_subch = subchid;
                        }
                    }
                    pos += 2;
                }

                if (info.primary_subch >= 0) {
                    service_map_[sid] = info;
                    fig02_count_++;
                    LOG_DEBUG(FIC, "FIG 0/2: Found service SID=0x" << std::hex << sid
                             << " subch=" << std::dec << info.primary_subch
                             << " total=" << service_map_.size());
                }
            }
            break;
        }

        case 3: {
            // FIG 0/3 - Service Component in Packet Mode
            int pos = 0;
            while (pos + 5 <= len) {
                int scid = ((data[pos] & 0x0F) << 8) | data[pos + 1];
                pos += 2;

                int scca_flag = (data[pos] >> 4) & 0x01;
                int dg_flag = (data[pos] >> 3) & 0x01;
                pos++;

                int dscty = data[pos] & 0x3F;
                pos++;

                int subchid = data[pos] & 0x3F;
                pos++;

                if (scca_flag && pos + 2 <= len) {
                    pos += 2;
                }

                LOG_DEBUG(FIC, "FIG 0/3: SCId=" << scid
                         << " -> SubChId=" << subchid
                         << " DSCTy=" << dscty
                         << " DG=" << dg_flag
                         << " (packet mode data)");

                packet_mode_map_[scid] = {subchid, 0, dscty, dg_flag != 0};
            }
            break;
        }

        case 13: {
            // FIG 0/13 - User Application Information
            int pos = 0;
            while (pos < len) {
                uint32_t sid;
                if (pd) {
                    if (pos + 4 > len) break;
                    sid = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos + 1] << 16) |
                          ((uint32_t)data[pos + 2] << 8) | data[pos + 3];
                    pos += 4;
                } else {
                    if (pos + 2 > len) break;
                    sid = (data[pos] << 8) | data[pos + 1];
                    pos += 2;
                }

                if (pos >= len) break;
                int scids = (data[pos] >> 4) & 0x0F;
                int num_apps = data[pos] & 0x0F;
                pos++;

                for (int i = 0; i < num_apps && pos + 2 <= len; i++) {
                    uint16_t ua_word = (data[pos] << 8) | data[pos + 1];
                    int ua_type = (ua_word >> 5) & 0x7FF;
                    int ua_len = ua_word & 0x1F;
                    pos += 2;

                    const uint8_t* ua_data = (pos + ua_len <= len) ? &data[pos] : nullptr;

                    const char* ua_name = "unknown";
                    switch (ua_type) {
                        case 0x002: ua_name = "SlideShow"; break;
                        case 0x003: ua_name = "BWS"; break;
                        case 0x004: ua_name = "TPEG"; break;
                        case 0x005: ua_name = "DGPS"; break;
                        case 0x006: ua_name = "TMC"; break;
                        case 0x007: ua_name = "EPG"; break;
                        case 0x008: ua_name = "DABJava"; break;
                        case 0x009: ua_name = "DMB"; break;
                        case 0x00a: ua_name = "IPDC"; break;
                        case 0x00b: ua_name = "Voice"; break;
                        case 0x00c: ua_name = "Middleware"; break;
                        case 0x00d: ua_name = "Filecasting"; break;
                        case 0x44a: ua_name = "Journaline"; break;
                    }

                    LOG_DEBUG(FIC, "FIG 0/13: SID=0x" << std::hex << sid << std::dec
                             << " SCIdS=" << scids
                             << " UAType=0x" << std::hex << ua_type << std::dec
                             << " (" << ua_name << ")"
                             << " len=" << ua_len);

                    if (ua_type == 0x007 && ua_data && ua_len >= 2) {
                        LOG_INFO(FIC, "  -> EPG/SPI data service detected!");
                    }

                    pos += ua_len;
                }
            }
            break;
        }

        case 8: {
            // FIG 0/8 - Service Component Global Definition
            int pos = 0;
            while (pos < len) {
                uint32_t sid;
                if (pd) {
                    if (pos + 4 > len) break;
                    sid = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos + 1] << 16) |
                          ((uint32_t)data[pos + 2] << 8) | data[pos + 3];
                    pos += 4;
                } else {
                    if (pos + 2 > len) break;
                    sid = (data[pos] << 8) | data[pos + 1];
                    pos += 2;
                }

                if (pos >= len) break;
                int ext_flag = (data[pos] >> 7) & 0x01;
                int scids = data[pos] & 0x0F;
                pos++;

                if (pos >= len) break;
                int ls_flag = (data[pos] >> 7) & 0x01;

                if (ls_flag == 0) {
                    int subchid = data[pos] & 0x3F;
                    LOG_DEBUG(FIC, "FIG 0/8: SID=0x" << std::hex << sid << std::dec
                             << " SCIdS=" << scids
                             << " -> SubChId=" << subchid << " (MSC)");
                    pos++;
                } else {
                    if (pos + 1 >= len) break;
                    int scid = ((data[pos] & 0x0F) << 8) | data[pos + 1];
                    LOG_DEBUG(FIC, "FIG 0/8: SID=0x" << std::hex << sid << std::dec
                             << " SCIdS=" << scids
                             << " -> SCId=" << scid << " (long form)");
                    pos += 2;
                }

                if (ext_flag && pos < len) {
                    pos++;
                }
            }
            break;
        }
    }
}

void DABParser::process_fig_1(const uint8_t* data, int len, int ext, int charset) {
    if (len < 2) return;

    switch (ext) {
        case 0: {
            // FIG 1/0 - Ensemble label
            if (len < 18) return;
            ensemble_id_ = (data[0] << 8) | data[1];

            char label[17] = {0};
            std::copy(data + 2, data + 18, label);

            int end = 15;
            while (end >= 0 && (label[end] == ' ' || label[end] == 0)) {
                label[end--] = 0;
            }
            ensemble_label_ = dab_label_to_utf8(label, 16, charset);

            auto now = std::chrono::steady_clock::now();
            int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_).count();
            if (ensemble_label_first_seen_ms_ < 0) {
                ensemble_label_first_seen_ms_ = now_ms;
                LOG_DEBUG(FIC, "FIG 1/0: Ensemble EID=0x" << std::hex << ensemble_id_
                         << std::dec << " label='" << ensemble_label_ << "' @" << now_ms << "ms (NEW)");
            }
            break;
        }

        case 1: {
            // FIG 1/1 - Programme service label
            if (len < 20) return;
            uint32_t sid = (data[0] << 8) | data[1];

            char label[17] = {0};
            std::copy(data + 2, data + 18, label);

            int end = 15;
            while (end >= 0 && (label[end] == ' ' || label[end] == 0)) {
                label[end--] = 0;
            }
            service_labels_[sid] = dab_label_to_utf8(label, 16, charset);

            fig11_count_++;

            auto now = std::chrono::steady_clock::now();
            int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_).count();
            if (label_first_seen_ms_.count(sid) == 0) {
                label_first_seen_ms_[sid] = now_ms;
                LOG_DEBUG(FIC, "FIG 1/1: SID=0x" << std::hex << sid << std::dec
                         << " '" << service_labels_[sid] << "' @" << now_ms << "ms (NEW, total=" << label_first_seen_ms_.size() << ")");
            }
            break;
        }
    }
}

void DABParser::build_ensemble() {
    ensemble_.eid = ensemble_id_;
    ensemble_.label = ensemble_label_;
    ensemble_.services.clear();

    for (const auto& [sid, info] : service_map_) {
        if (info.primary_subch < 0) continue;

        DABService svc;
        svc.sid = sid;
        svc.label = service_labels_.count(sid) ? service_labels_[sid] : "";

        auto it = subchannels_.find(info.primary_subch);
        if (it != subchannels_.end()) {
            const SubChannel& sc = it->second;
            svc.subchannel_id = sc.subchid;
            svc.start_addr = sc.startaddr;
            svc.subchannel_size = sc.subchsz;
            svc.bitrate = sc.bitrate;
            svc.dabplus = (sc.dabplus == 1);
            svc.protection_level = sc.protlvl;
            svc.eep_protection = (sc.eepprot == 1);
        }

        ensemble_.services.push_back(svc);
    }

    std::sort(ensemble_.services.begin(), ensemble_.services.end(),
              [](const DABService& a, const DABService& b) { return a.sid < b.sid; });

    LOG_DEBUG(FIC, "Parsed ensemble '" << ensemble_.label << "' (0x"
             << std::hex << ensemble_.eid << std::dec << ") with "
             << ensemble_.services.size() << " services");
}

} // namespace dvbdab
