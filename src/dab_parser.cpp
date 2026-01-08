#include "dab_parser.h"
#include "logging.h"
#include "utils/crc_utils.hpp"
#include "utils/byte_utils.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

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

DABParser::DABParser() : ensemble_id_(0), labelled_(false), basic_ready_(false),
    last_basic_service_count_(0), basic_stable_frames_(0),
    last_service_count_(0), stable_frames_(0), last_label_count_(0), label_stable_frames_(0) {
    reset();
}

DABParser::~DABParser() = default;

void DABParser::reset() {
    subchannels_.clear();
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

    // Check for basic ready
    if (!basic_ready_ && !service_map_.empty()) {
        size_t valid_services = 0;
        for (const auto& [sid, info] : service_map_) {
            if (info.primary_subch >= 0 && subchannels_.count(info.primary_subch)) {
                valid_services++;
            }
        }

        if (valid_services > 0) {
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
    int ext = fig[0] & 0x1F;
    int pd = (fig[0] >> 5) & 0x01;

    fig_debug_count_++;

    LOG_DEBUG(FIC, "FIG: type=" << fig_type << " ext=" << ext << " pd=" << pd
             << " len=" << fig_len << " hdr=0x" << std::hex << (int)fig[-1]
             << " first=0x" << (int)fig[0] << std::dec);

    switch (fig_type) {
        case 0:
            process_fig_0(fig + 1, fig_len - 1, ext, pd);
            break;
        case 1:
            process_fig_1(fig + 1, fig_len - 1, ext);
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
                } else {
                    sc.dabplus = 0;
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
                            LOG_DEBUG(FIC, "FIG 0/2: SID=0x" << std::hex << sid
                                     << " subch=" << std::dec << subchid
                                     << " ASCTy=" << ascty
                                     << " -> " << ((ascty == 63) ? "DAB+" : "DAB"));
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

void DABParser::process_fig_1(const uint8_t* data, int len, int ext) {
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
            ensemble_label_ = latin1_to_utf8(label, 16);

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
            service_labels_[sid] = latin1_to_utf8(label, 16);

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
