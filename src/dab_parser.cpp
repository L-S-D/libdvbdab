#include "dab_parser.h"
#include "logging.h"
#include "utils/crc_utils.hpp"
#include "utils/byte_utils.hpp"
#include "output/charsets.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace dvbdab {

// Short form of FIG 0/1 (UEP): size in capacity units, protection level and
// bitrate of each table index (ETSI EN 300 401, table 8)
static const int uep_sizes[64] = {
     16,  21,  24,  29,  35,  24,  29,  35,  42,  52,  29,  35,  42,  52,  32,  42,
     48,  58,  70,  40,  52,  58,  70,  84,  48,  58,  70,  84, 104,  58,  70,  84,
    104,  64,  84,  96, 116, 140,  80, 104, 116, 140, 168,  96, 116, 140, 168, 208,
    116, 140, 168, 208, 232, 128, 168, 192, 232, 280, 160, 208, 280, 192, 280, 416
};
static const int uep_levels[64] = {
    5, 4, 3, 2, 1, 5, 4, 3, 2, 1, 5, 4, 3, 2, 5, 4,
    3, 2, 1, 5, 4, 3, 2, 1, 5, 4, 3, 2, 1, 5, 4, 3,
    2, 5, 4, 3, 2, 1, 5, 4, 3, 2, 1, 5, 4, 3, 2, 1,
    5, 4, 3, 2, 1, 5, 4, 3, 2, 1, 5, 4, 2, 5, 3, 1
};
static const int uep_bitrates[64] = {
     32,  32,  32,  32,  32,  48,  48,  48,  48,  48,  56,  56,  56,  56,  64,  64,
     64,  64,  64,  80,  80,  80,  80,  80,  96,  96,  96,  96,  96, 112, 112, 112,
    112, 128, 128, 128, 128, 128, 160, 160, 160, 160, 160, 192, 192, 192, 192, 192,
    224, 224, 224, 224, 224, 256, 256, 256, 256, 256, 320, 320, 320, 384, 384, 384
};

// Long form (EEP): a subchannel of n times 8 kbit/s (set A) or 32 kbit/s (set B)
// has n times so many capacity units at its protection level
static int get_eep_bitrate(int subchsz, int protlvl) {
    int n = 0;
    switch (protlvl) {
        case 0: n = subchsz / 12; break;  // EEP-1A
        case 1: n = subchsz / 8; break;   // EEP-2A
        case 2: n = subchsz / 6; break;   // EEP-3A
        case 3: n = subchsz / 4; break;   // EEP-4A
        case 4: return subchsz / 27 * 32;  // EEP-1B
        case 5: return subchsz / 21 * 32;  // EEP-2B
        case 6: return subchsz / 18 * 32;  // EEP-3B
        case 7: return subchsz / 15 * 32;  // EEP-4B
        default: return 0;
    }
    return n * 8;
}

// A label of 16 bytes to UTF-8, by its character set (the same sets as
// dynamic labels: complete EBU Latin, UCS-2, UTF-8). A set that is not
// known is read as EBU Latin: a label with wrong letters is better than a
// service without a name.
static std::string dab_label_to_utf8(const char* src, size_t len, int charset) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(src);
    std::string out;
    if (!dabLabelToUtf8(data, len, static_cast<uint8_t>(charset), out)) {
        out.clear();
        dabLabelToUtf8(data, len, DAB_CHARSET_EBU_LATIN, out);
    }
    return out;
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
    fic_frame_ = 0;
    first_service_frame_ = -1;
    service_seen_.clear();
    subch_seen_.clear();
    subch_language_.clear();
    pty_static_.clear();
    pty_dynamic_.clear();
    has_country_ = false;
    ecc_ = 0;
    lto_half_hours_ = 0;
    international_table_ = 0;
    utc_ms_ = 0;
    utc_frame_ = -1;
    utc_long_ = false;
}

bool DABParser::process_eti_frame(const uint8_t* frame, size_t len) {
    eti_call_count_++;

    // (The FIC is read as long as the stream runs: an ensemble changes -
    // services come and go, move to another subchannel, get another name.)
    if (len < 8) return labelled_;

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
        return labelled_;
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

    fic_frame_++;
    process_fic(fic_data, fic_len, fc.mid);

    if (!service_map_.empty()) {
        drop_stale();
        build_ensemble();
    }

    // Check for basic ready - requires ALL audio subchannels have FIG 0/1 AND FIG 0/2
    if (!basic_ready_ && !service_map_.empty()) {
        size_t valid_services = 0;
        bool all_ready = true;
        // ... or, after a while, the ones that have: a service whose
        // subchannel never comes must not keep all the others silent
        if (first_service_frame_ < 0) first_service_frame_ = fic_frame_;
        bool waited = fic_frame_ - first_service_frame_ >= READY_WAIT_FRAMES;

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

        if (valid_services > 0 && (all_ready || waited)) {
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
        // Labels that do not come (a service without FIG 1/1) must not keep
        // the ensemble from ever being complete: after a while it is, with
        // the names that are there (a late one is a change like any other)
        bool waited = basic_ready_ && stable_frames_ >= READY_WAIT_FRAMES;

        if (!labelled_ && stable && (all_labelled || waited)) {
            labelled_ = true;
            LOG_INFO(FIC, "DAB COMPLETE: " << service_map_.size() << " services, " << labelled_count
                     << " with labels, ensemble='" << ensemble_label_ << "'");
        }
    }

    return labelled_;
}

// Services and subchannels the FIC no longer has: FIG 0/1 and 0/2 come ten
// times a second, what was not in them for STALE_FRAMES frames is gone
void DABParser::drop_stale() {
    for (auto it = service_map_.begin(); it != service_map_.end();) {
        auto seen = service_seen_.find(it->first);
        if (seen != service_seen_.end() && fic_frame_ - seen->second > STALE_FRAMES) {
            LOG_DEBUG(FIC, "service 0x" << std::hex << it->first << std::dec << " is gone");
            service_labels_.erase(it->first);
            pty_static_.erase(it->first);
            pty_dynamic_.erase(it->first);
            service_seen_.erase(seen);
            it = service_map_.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = subchannels_.begin(); it != subchannels_.end();) {
        auto seen = subch_seen_.find(it->first);
        if (seen != subch_seen_.end() && fic_frame_ - seen->second > STALE_FRAMES) {
            subch_seen_.erase(seen);
            subch_language_.erase(it->first);
            it = subchannels_.erase(it);
        } else {
            ++it;
        }
    }
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
    return !CHECKSUMS_CHECKED || crc == stored_crc;
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
    int ext, pd, charset, oe = 0;
    if (fig_type == 0) {
        // FIG 0: ext in bits 0-4, pd in bit 5, OE in bit 6, C/N in bit 7
        ext = fig[0] & 0x1F;
        pd = (fig[0] >> 5) & 0x01;
        oe = (fig[0] >> 6) & 0x01;
        charset = 0;
        // C/N = 1 in the FIGs of the multiplex configuration: the next
        // configuration, sent for six seconds before a reconfiguration. It
        // becomes the current one (C/N = 0) at the change; until then it
        // must not be mixed into what is on air.
        if ((fig[0] & 0x80) && (ext == 1 || ext == 2 || ext == 3 || ext == 4 || ext == 8)) return;
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
            process_fig_0(fig + 1, fig_len - 1, ext, pd, oe);
            break;
        case 1:
            process_fig_1(fig + 1, fig_len - 1, ext, charset);
            break;
    }
}

void DABParser::process_fig_0(const uint8_t* data, int len, int ext, int pd, int oe) {
    switch (ext) {
        case 5: {
            // FIG 0/5 - Service component language
            int pos = 0;
            while (pos < len) {
                if (data[pos] & 0x80) {
                    // long form (a component by its SCId): not what a
                    // programme service has its audio in
                    pos += 3;
                } else {
                    if (pos + 2 > len) break;
                    if (!(data[pos] & 0x40)) {   // in the MSC, in stream mode
                        subch_language_[data[pos] & 0x3F] = data[pos + 1];
                    }
                    pos += 2;
                }
            }
            break;
        }

        case 9: {
            // FIG 0/9 - Country, LTO and International table
            if (len < 3) return;
            has_country_ = true;
            lto_half_hours_ = static_cast<int8_t>((data[0] & 0x20 ? -1 : 1) * (data[0] & 0x1F));
            ecc_ = data[1];
            international_table_ = data[2];
            break;
        }

        case 10: {
            // FIG 0/10 - Date and time: MJD (17 bits), LSI, UTC flag, then
            // hours and minutes (short form), or with seconds and
            // milliseconds (long form)
            if (len < 4) return;
            bool long_form = data[2] & 0x08;
            if (long_form && len < 6) return;
            if (!long_form && utc_long_) return;   // the long form is the better one
            int64_t mjd = (data[0] & 0x7F) << 10 | data[1] << 2 | data[2] >> 6;
            int hours = (data[2] & 0x07) << 2 | data[3] >> 6;
            int minutes = data[3] & 0x3F;
            int seconds = long_form ? data[4] >> 2 : 0;
            int ms = long_form ? (data[4] & 0x03) << 8 | data[5] : 0;
            // 51544 is 2000-01-01; a seconds field of 60 is a leap second
            if (mjd < 51544 || hours > 23 || minutes > 59 || seconds > 60 || ms > 999) return;
            utc_ms_ = ((mjd - 40587) * 86400 + hours * 3600 + minutes * 60 + seconds) * 1000 + ms;
            utc_frame_ = fic_frame_;
            utc_long_ = long_form;
            break;
        }

        case 17: {
            // FIG 0/17 - Programme Type (of the services of this ensemble)
            if (pd || oe) return;
            int pos = 0;
            while (pos + 4 <= len) {
                uint32_t sid = (data[pos] << 8) | data[pos + 1];
                bool dynamic = data[pos + 2] & 0x80;
                bool with_language = data[pos + 2] & 0x20;
                bool with_coarse_code = data[pos + 2] & 0x10;
                pos += 3;
                if (with_language) pos++;
                if (pos >= len) break;
                uint8_t pty = data[pos] & 0x1F;
                pos++;
                if (with_coarse_code) pos++;
                (dynamic ? pty_dynamic_ : pty_static_)[sid] = pty;
            }
            break;
        }

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

                SubChannel sc{};
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
                    sc.bitrate = uep_bitrates[table_index];
                    sc.subchsz = uep_sizes[table_index];
                    sc.protlvl = uep_levels[table_index];
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
                subch_seen_[subchid] = fic_frame_;
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

                        // (not taken as the subchannel of the service: a
                        // data service is no radio programme, and waiting
                        // for its audio codec kept the whole ensemble silent)
                        (void)primary;
                    }
                    pos += 2;
                }

                if (info.primary_subch >= 0) {
                    service_map_[sid] = info;
                    service_seen_[sid] = fic_frame_;
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
    DABEnsemble e;
    e.eid = ensemble_id_;
    e.label = ensemble_label_;
    e.source_ip = ensemble_.source_ip;
    e.source_port = ensemble_.source_port;
    e.has_country = has_country_;
    e.ecc = ecc_;
    e.lto_half_hours = lto_half_hours_;
    e.international_table = international_table_;

    for (const auto& [sid, info] : service_map_) {
        if (info.primary_subch < 0) continue;

        // only with its subchannel and codec known (FIG 0/1 and 0/2)
        auto it = subchannels_.find(info.primary_subch);
        if (it == subchannels_.end() || !it->second.codec_known) continue;

        DABService svc;
        svc.sid = sid;
        svc.label = service_labels_.count(sid) ? service_labels_[sid] : "";

        const SubChannel& sc = it->second;
        svc.subchannel_id = sc.subchid;
        svc.start_addr = sc.startaddr;
        svc.subchannel_size = sc.subchsz;
        svc.bitrate = sc.bitrate;
        svc.dabplus = (sc.dabplus == 1);
        svc.protection_level = sc.protlvl;
        svc.eep_protection = (sc.eepprot == 1);
        auto lang = subch_language_.find(sc.subchid);
        if (lang != subch_language_.end()) svc.language = lang->second;
        // what the service is (static) before what is on right now (dynamic)
        if (auto st = pty_static_.find(sid); st != pty_static_.end()) svc.pty = st->second;
        if (svc.pty == 0) {
            if (auto dy = pty_dynamic_.find(sid); dy != pty_dynamic_.end()) svc.pty = dy->second;
        }

        e.services.push_back(svc);
    }

    std::sort(e.services.begin(), e.services.end(),
              [](const DABService& a, const DABService& b) { return a.sid < b.sid; });

    // A change of what a receiver must know (not of where in the frame a
    // subchannel lies): the revision goes up
    auto same = [](const DABService& a, const DABService& b) {
        return a.sid == b.sid && a.label == b.label && a.bitrate == b.bitrate &&
               a.subchannel_id == b.subchannel_id && a.dabplus == b.dabplus &&
               a.language == b.language && a.pty == b.pty;
    };
    bool changed = e.eid != ensemble_.eid || e.label != ensemble_.label ||
                   e.has_country != ensemble_.has_country || e.ecc != ensemble_.ecc ||
                   e.lto_half_hours != ensemble_.lto_half_hours ||
                   e.international_table != ensemble_.international_table ||
                   e.services.size() != ensemble_.services.size() ||
                   !std::equal(e.services.begin(), e.services.end(), ensemble_.services.begin(), same);
    ensemble_ = std::move(e);
    if (changed) revision_++;

    LOG_DEBUG(FIC, "Parsed ensemble '" << ensemble_.label << "' (0x"
             << std::hex << ensemble_.eid << std::dec << ") with "
             << ensemble_.services.size() << " services");
}

} // namespace dvbdab
