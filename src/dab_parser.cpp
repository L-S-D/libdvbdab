#include "dab_parser.h"
#include "logging.h"
#include <cstring>
#include <algorithm>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

namespace lsdvb {

// CRC-16 CCITT lookup table
static const uint16_t crc16_table[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

// Helper functions for big-endian reads
static inline uint16_t read_16b(const uint8_t* p) {
    return (p[0] << 8) | p[1];
}

static inline uint32_t read_24b(const uint8_t* p) {
    return (p[0] << 16) | (p[1] << 8) | p[2];
}

static inline uint32_t read_32b(const uint8_t* p) {
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

// TS packet helpers
static inline bool ts_is_sync(const uint8_t* ts) { return ts[0] == 0x47; }
static inline bool ts_has_payload(const uint8_t* ts) { return (ts[3] & 0x10) != 0; }
static inline bool ts_is_payload_start(const uint8_t* ts) { return ts_has_payload(ts) && (ts[1] & 0x40); }
static inline bool ts_has_af(const uint8_t* ts) { return (ts[3] & 0x20) != 0; }
static inline uint16_t ts_get_pid(const uint8_t* ts) { return ((ts[1] & 0x1F) << 8) | ts[2]; }
static inline uint8_t ts_get_cc(const uint8_t* ts) { return ts[3] & 0x0F; }

static inline const uint8_t* ts_get_payload(const uint8_t* ts) {
    if (!ts_has_payload(ts)) return nullptr;
    if (!ts_has_af(ts)) return &ts[TS_HEADER_SIZE];
    if (ts[4] >= TS_PACKET_SIZE - TS_HEADER_SIZE - 1) return nullptr;
    return &ts[TS_HEADER_SIZE + 1 + ts[4]];
}

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
    // EEP bitrate calculation based on protection level and size
    // Protection levels: 0-3 = EEP-1A to EEP-4A, 4-7 = EEP-1B to EEP-4B
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
    return n * 8;  // Bitrate in kbps
}

// Convert ISO 8859-1 (Latin-1) to UTF-8
static std::string latin1_to_utf8(const char* src, size_t len) {
    std::string result;
    result.reserve(len * 2);  // Worst case: every char needs 2 bytes

    for (size_t i = 0; i < len && src[i] != '\0'; i++) {
        unsigned char c = static_cast<unsigned char>(src[i]);
        if (c < 0x80) {
            // ASCII: pass through
            result += c;
        } else {
            // Latin-1 0x80-0xFF -> UTF-8 two-byte sequence
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
    // Reset timestamp tracking
    start_time_ = std::chrono::steady_clock::now();
    label_first_seen_ms_.clear();
    ensemble_label_first_seen_ms_ = -1;
}

bool DABParser::process_eti_frame(const uint8_t* frame, size_t len) {
    eti_call_count_++;

    // Already complete - skip further processing
    if (labelled_) return true;

    if (len < 8) return false;

    // Check sync word (first 4 bytes)
    uint32_t sync = (frame[0] << 24) | (frame[1] << 16) | (frame[2] << 8) | frame[3];
    if (eti_call_count_ <= 5 || eti_call_count_ % 100 == 0) {
        LOG_DEBUG(SERVER, "FIC: process_eti_frame #" << eti_call_count_ << " sync=0x" << std::hex << sync
                 << " expect 0x" << ETI_NI_FSYNC0 << " or 0x" << ETI_NI_FSYNC1 << std::dec);
    }
    if (sync != ETI_NI_FSYNC0 && sync != ETI_NI_FSYNC1) {
        LOG_DEBUG(SERVER, "FIC: sync mismatch! first 8 bytes: 0x" << std::hex
                 << (int)frame[0] << " 0x" << (int)frame[1] << " 0x" << (int)frame[2]
                 << " 0x" << (int)frame[3] << " 0x" << (int)frame[4] << " 0x" << (int)frame[5]
                 << " 0x" << (int)frame[6] << " 0x" << (int)frame[7] << std::dec);
        return false;
    }

    // Parse FC word (bytes 4-7)
    ETI_FC fc = parse_fc(frame + 4);

    if (fc.ficf == 0) {
        // No FIC in this frame
        return labelled_;
    }

    // Calculate FIC length in words (each word is 4 bytes)
    int ficl = 24;  // Default for modes 1,2,4
    if (fc.mid == 3) ficl = 32;  // Mode 3

    // FIC data starts after STC (Stream Characterization) words
    // STC location: byte 8 + (nst * 4) + 4 (padding)
    int stc_end = 8 + (fc.nst * 4) + 4;
    const uint8_t* fic_data = frame + stc_end;
    int fic_len = ficl * 4;  // Convert words to bytes

    if ((size_t)(stc_end + fic_len) > len) {
        return labelled_;
    }

    process_fic(fic_data, fic_len, fc.mid);

    // Build ensemble on each frame
    if (!service_map_.empty()) {
        build_ensemble();
    }

    // Check for basic ready: services with valid subchannel info + stable count
    // This allows early audio start before labels are available (~150-300ms)
    if (!basic_ready_ && !service_map_.empty()) {
        // Count services with valid subchannel mapping
        size_t valid_services = 0;
        for (const auto& [sid, info] : service_map_) {
            if (info.primary_subch >= 0 && subchannels_.count(info.primary_subch)) {
                valid_services++;
            }
        }

        // Track stability of valid service count (need 3 frames stable)
        if (valid_services > 0) {
            if (valid_services != last_basic_service_count_) {
                last_basic_service_count_ = valid_services;
                basic_stable_frames_ = 0;
            } else {
                basic_stable_frames_++;
            }

            // Basic ready when service count stable for 3 frames (~72ms)
            if (basic_stable_frames_ >= 3) {
                basic_ready_ = true;
                LOG_INFO(SERVER, "DAB BASIC READY: " << valid_services << " services, can start audio");
            }
        }
    }

    // Check for completion: we have services AND ALL have labels AND ensemble has label
    // Also require service count to be stable for several frames to avoid premature completion
    if (!service_map_.empty()) {
        size_t labelled_count = 0;
        for (const auto& [sid, _] : service_map_) {
            if (service_labels_.count(sid) > 0) {
                labelled_count++;
            }
        }

        // Ensemble label is required for completion
        bool has_ensemble_label = !ensemble_label_.empty();

        // Track service count stability - require same count for 10 frames
        if (service_map_.size() != last_service_count_) {
            last_service_count_ = service_map_.size();
            stable_frames_ = 0;
        } else {
            stable_frames_++;
        }

        // Complete ONLY when ALL services have labels AND ensemble has label
        // AND service count has been stable for at least 10 frames
        bool all_labelled = (labelled_count == service_map_.size() && has_ensemble_label);
        bool stable = (stable_frames_ >= 10);

        if (all_labelled && stable) {
            labelled_ = true;
            LOG_INFO(SERVER, "DAB COMPLETE: " << service_map_.size() << " services with labels, ensemble='" << ensemble_label_ << "'");
            return true;
        }
    }

    return false;
}

void DABParser::process_fic(const uint8_t* fic_data, int fic_len, int /*mode_id*/) {
    // FIC consists of multiple FIBs (Fast Information Blocks)
    // Each FIB is 32 bytes: 30 bytes data + 2 bytes CRC

    int offset = 0;
    while (offset + 32 <= fic_len) {
        process_fib(fic_data + offset);
        offset += 32;
    }
}

// Check FIB CRC - CRC-16 CCITT over 30 data bytes, compared with 2 CRC bytes
static bool fib_crc_ok(const uint8_t* fib, bool debug = false) {
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < 30; i++) {
        crc = (crc << 8) ^ crc16_table[(crc >> 8) ^ fib[i]];
    }
    crc ^= 0xFFFF;  // Final XOR
    uint16_t stored_crc = (fib[30] << 8) | fib[31];
    if (debug) {
        LOG_DEBUG(SERVER, "FIB CRC: calc=0x" << std::hex << crc << " stored=0x" << stored_crc
                 << " ok=" << (crc == stored_crc) << std::dec);
    }
    return crc == stored_crc;
}

void DABParser::process_fib(const uint8_t* fib) {
    fib_count_++;

    // Check FIB CRC
    bool debug = fib_count_ <= 10;
    if (!fib_crc_ok(fib, debug)) {
        if (debug) {
            LOG_WARN(SERVER, "FIB CRC fail - first 8 bytes: 0x" << std::hex
                     << (int)fib[0] << " 0x" << (int)fib[1] << " 0x" << (int)fib[2]
                     << " 0x" << (int)fib[3] << " 0x" << (int)fib[4] << " 0x" << (int)fib[5]
                     << " 0x" << (int)fib[6] << " 0x" << (int)fib[7] << std::dec);
        }
        return;  // Skip corrupted FIB
    }
    if (debug) {
        LOG_DEBUG(SERVER, "FIB OK! Processing FIGs...");
    }

    // Process FIGs in the FIB
    int pos = 0;
    while (pos < 30) {
        // FIG header
        uint8_t hdr = fib[pos];
        if (hdr == 0xFF) break;  // End marker

        // fig_type extracted in process_fig() from first byte
        int fig_len = hdr & 0x1F;

        if (pos + 1 + fig_len > 30) break;

        process_fig(fib + pos + 1, fig_len);

        pos += 1 + fig_len;
    }
}

void DABParser::process_fig(const uint8_t* fig, int fig_len) {
    if (fig_len < 1) return;

    // FIG type 0 byte: CN/OE/PD + extension
    int fig_type = (fig[-1] >> 5) & 0x07;  // From header
    int ext = fig[0] & 0x1F;
    int pd = (fig[0] >> 5) & 0x01;

    fig_debug_count_++;

    // Log all FIG entries (DEBUG - very high frequency)
    LOG_DEBUG(SERVER, "FIG: type=" << fig_type << " ext=" << ext << " pd=" << pd
             << " len=" << fig_len << " hdr=0x" << std::hex << (int)fig[-1]
             << " first=0x" << (int)fig[0] << std::dec);

    switch (fig_type) {
        case 0:
            process_fig_0(fig + 1, fig_len - 1, ext, pd);
            break;
        case 1:
            process_fig_1(fig + 1, fig_len - 1, ext);
            break;
        // Other FIG types (2-7) not needed for basic service info
    }
}

void DABParser::process_fig_0(const uint8_t* data, int len, int ext, int pd) {
    // FIG 0 - Basic ensemble/service/component information
    // pd = Programme Data flag: 0 = audio (16-bit SID), 1 = data (32-bit SID)
    switch (ext) {
        case 0: {
            // FIG 0/0 - Ensemble Information (transmitted every 96ms)
            // Contains EID which is more frequent than FIG 1/0 ensemble label
            if (len < 4) return;
            uint16_t eid = (data[0] << 8) | data[1];
            // Bytes 2-3 contain ChgFlg, AlrmFlg, CIFCntH, CIFCntL
            if (ensemble_id_ == 0 || ensemble_id_ != eid) {
                ensemble_id_ = eid;
                LOG_DEBUG(SERVER, "FIG 0/0: Ensemble EID=0x" << std::hex << eid << std::dec);
            }
            break;
        }

        case 1: {
            // FIG 0/1 - Sub-channel organization (short form)
            int pos = 0;
            while (pos + 3 <= len) {
                int subchid = (data[pos] >> 2) & 0x3F;
                int startaddr = ((data[pos] & 0x03) << 8) | data[pos + 1];
                int form = (data[pos + 2] >> 7) & 0x01;

                SubChannel sc;
                sc.subchid = subchid;
                sc.startaddr = startaddr;
                // Preserve existing dabplus value if subchannel was already seen
                // (FIG 0/2 may have set it before FIG 0/1 repeats)
                if (subchannels_.count(subchid)) {
                    sc.dabplus = subchannels_[subchid].dabplus;
                } else {
                    sc.dabplus = 0;  // Initialize to DAB by default
                }

                if (form == 0) {
                    // Short form (UEP)
                    int table_index = data[pos + 2] & 0x3F;
                    sc.eepprot = 0;
                    sc.uep_indx = table_index;
                    // Size and bitrate from table
                    if (table_index < 64) {
                        sc.bitrate = uep_bitrates[table_index];
                    }
                    sc.subchsz = 0;  // TODO: lookup from table
                    pos += 3;
                } else {
                    // Long form (EEP)
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
            int min_service_size = pd ? 5 : 3;  // SID(4 or 2) + local(1)
            while (pos + min_service_size <= len) {
                // Service ID (2 or 4 bytes depending on PD flag)
                uint32_t sid;
                if (pd) {
                    // Data service: 32-bit SID (ECC + country + SId)
                    sid = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos + 1] << 16) |
                          ((uint32_t)data[pos + 2] << 8) | data[pos + 3];
                    pos += 4;
                } else {
                    // Audio service: 16-bit SID
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
                        // Audio stream (MSC stream mode)
                        int ascty = data[pos] & 0x3F;
                        int subchid = (data[pos + 1] >> 2) & 0x3F;
                        int primary = (data[pos + 1] >> 1) & 0x01;

                        // DAB+ uses ASCTy = 63
                        if (subchannels_.count(subchid)) {
                            subchannels_[subchid].dabplus = (ascty == 63) ? 1 : 0;
                            LOG_DEBUG(SERVER, "FIG 0/2: SID=0x" << std::hex << sid
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
                        // Data (MSC packet mode)
                        int dscty = data[pos] & 0x3F;  // Data Service Component Type
                        int subchid = (data[pos + 1] >> 2) & 0x3F;
                        int primary = (data[pos + 1] >> 1) & 0x01;

                        LOG_DEBUG(SERVER, "FIG 0/2: DATA SID=0x" << std::hex << sid << std::dec
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
                    LOG_DEBUG(SERVER, "FIG 0/2: Found service SID=0x" << std::hex << sid
                             << " subch=" << std::dec << info.primary_subch
                             << " total=" << service_map_.size());
                }
            }
            break;
        }

        case 3: {
            // FIG 0/3 - Service Component in Packet Mode
            // Links SCId (Service Component ID) to SubChId for packet-mode data services
            // Structure (5 bytes per entry):
            //   Bytes 0-1: Rfa(4) + SCId(12)
            //   Byte 2: Rfa(3) + SCCA_flag(1) + DG_flag(1) + Rfu(1) + DSCTy_high(2)
            //   Byte 3: DSCTy_low(4) + SubChId(4) or DSCTy in low 6 bits
            //   Byte 4: SubChId (low 6 bits)
            int pos = 0;
            while (pos + 5 <= len) {
                int scid = ((data[pos] & 0x0F) << 8) | data[pos + 1];
                pos += 2;

                // Flags byte
                int scca_flag = (data[pos] >> 4) & 0x01;
                int dg_flag = (data[pos] >> 3) & 0x01;
                pos++;

                // DSCTy in low 6 bits of next byte
                int dscty = data[pos] & 0x3F;
                pos++;

                // SubChId in low 6 bits of next byte
                int subchid = data[pos] & 0x3F;
                pos++;

                // Optional CA data if scca_flag
                if (scca_flag && pos + 2 <= len) {
                    pos += 2;
                }

                LOG_DEBUG(SERVER, "FIG 0/3: SCId=" << scid
                         << " -> SubChId=" << subchid
                         << " DSCTy=" << dscty
                         << " DG=" << dg_flag
                         << " (packet mode data)");

                // Store mapping for packet decoder
                packet_mode_map_[scid] = {subchid, 0, dscty, dg_flag != 0};
            }
            break;
        }

        case 13: {
            // FIG 0/13 - User Application Information
            // Signals which services have data applications (EPG, SlideShow, etc.)
            int pos = 0;
            while (pos < len) {
                // SId: 16 bits (audio, pd=0) or 32 bits (data, pd=1)
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
                int scids = (data[pos] >> 4) & 0x0F;  // Service Component ID within Service
                int num_apps = data[pos] & 0x0F;      // Number of user applications
                pos++;

                for (int i = 0; i < num_apps && pos + 2 <= len; i++) {
                    // User application type (11 bits) + data length (5 bits)
                    uint16_t ua_word = (data[pos] << 8) | data[pos + 1];
                    int ua_type = (ua_word >> 5) & 0x7FF;
                    int ua_len = ua_word & 0x1F;
                    pos += 2;

                    // User application data (optional)
                    const uint8_t* ua_data = (pos + ua_len <= len) ? &data[pos] : nullptr;

                    // Log user application types
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

                    LOG_DEBUG(SERVER, "FIG 0/13: SID=0x" << std::hex << sid << std::dec
                             << " SCIdS=" << scids
                             << " UAType=0x" << std::hex << ua_type << std::dec
                             << " (" << ua_name << ")"
                             << " len=" << ua_len);

                    // If EPG (0x007), log additional details
                    if (ua_type == 0x007 && ua_data && ua_len >= 2) {
                        // EPG data contains: SPI application version, etc.
                        LOG_INFO(SERVER, "  -> EPG/SPI data service detected!");
                    }

                    pos += ua_len;
                }
            }
            break;
        }

        case 8: {
            // FIG 0/8 - Service Component Global Definition
            // Links service components to subchannels (especially for data services)
            int pos = 0;
            while (pos < len) {
                // SId: 16 bits (audio, pd=0) or 32 bits (data, pd=1)
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
                int scids = data[pos] & 0x0F;  // Service Component ID within Service
                pos++;

                if (pos >= len) break;
                int ls_flag = (data[pos] >> 7) & 0x01;

                if (ls_flag == 0) {
                    // Short form: MSC subchannel
                    int subchid = data[pos] & 0x3F;
                    LOG_DEBUG(SERVER, "FIG 0/8: SID=0x" << std::hex << sid << std::dec
                             << " SCIdS=" << scids
                             << " -> SubChId=" << subchid << " (MSC)");
                    pos++;
                } else {
                    // Long form: FIDCId or SCId
                    if (pos + 1 >= len) break;
                    int scid = ((data[pos] & 0x0F) << 8) | data[pos + 1];
                    LOG_DEBUG(SERVER, "FIG 0/8: SID=0x" << std::hex << sid << std::dec
                             << " SCIdS=" << scids
                             << " -> SCId=" << scid << " (long form)");
                    pos += 2;
                }

                // Rfa field if ext_flag is set
                if (ext_flag && pos < len) {
                    pos++;  // Skip Rfa
                }
            }
            break;
        }

        // Other extensions not needed for basic parsing
    }
}

void DABParser::process_fig_1(const uint8_t* data, int len, int ext) {
    // FIG 1 - Labels
    if (len < 2) return;

    // Character set (first nibble)
    // For simplicity, assume charset 0 (EBU Latin)

    switch (ext) {
        case 0: {
            // FIG 1/0 - Ensemble label
            if (len < 18) return;
            ensemble_id_ = (data[0] << 8) | data[1];

            // Label is 16 bytes starting at offset 2, in ISO 8859-1
            char label[17] = {0};
            memcpy(label, data + 2, 16);

            // Trim trailing spaces before conversion
            int end = 15;
            while (end >= 0 && (label[end] == ' ' || label[end] == 0)) {
                label[end--] = 0;
            }
            // Convert ISO 8859-1 to UTF-8
            ensemble_label_ = latin1_to_utf8(label, 16);

            // Track when ensemble label was first seen
            auto now = std::chrono::steady_clock::now();
            int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_).count();
            if (ensemble_label_first_seen_ms_ < 0) {
                ensemble_label_first_seen_ms_ = now_ms;
                LOG_DEBUG(SERVER, "FIG 1/0: Ensemble EID=0x" << std::hex << ensemble_id_
                         << std::dec << " label='" << ensemble_label_ << "' @" << now_ms << "ms (NEW)");
            } else {
#if defined(LSDVB_LOG_DEBUG) || defined(LSDVB_LOG_TRACE)
                int64_t delta = now_ms - ensemble_label_first_seen_ms_;
                LOG_DEBUG(SERVER, "FIG 1/0: Ensemble EID=0x" << std::hex << ensemble_id_
                         << std::dec << " label='" << ensemble_label_ << "' @" << now_ms << "ms (REPEAT, delta=" << delta << "ms)");
#endif
            }
            break;
        }

        case 1: {
            // FIG 1/1 - Programme service label
            if (len < 20) return;  // 2 bytes SID + 16 bytes label + 2 bytes char flags
            uint32_t sid = (data[0] << 8) | data[1];

            // Label is 16 bytes at offset 2, in ISO 8859-1
            char label[17] = {0};
            memcpy(label, data + 2, 16);

            // Trim trailing spaces before conversion
            int end = 15;
            while (end >= 0 && (label[end] == ' ' || label[end] == 0)) {
                label[end--] = 0;
            }
            // Convert ISO 8859-1 to UTF-8
            service_labels_[sid] = latin1_to_utf8(label, 16);

            fig11_count_++;

            // Track when each label was first seen
            auto now = std::chrono::steady_clock::now();
            int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_).count();
            if (label_first_seen_ms_.count(sid) == 0) {
                label_first_seen_ms_[sid] = now_ms;
                LOG_DEBUG(SERVER, "FIG 1/1: SID=0x" << std::hex << sid << std::dec
                         << " '" << service_labels_[sid] << "' @" << now_ms << "ms (NEW, total=" << label_first_seen_ms_.size() << ")");
            } else {
#if defined(LSDVB_LOG_DEBUG) || defined(LSDVB_LOG_TRACE)
                int64_t delta = now_ms - label_first_seen_ms_[sid];
                LOG_DEBUG(SERVER, "FIG 1/1: SID=0x" << std::hex << sid << std::dec
                         << " '" << service_labels_[sid] << "' @" << now_ms << "ms (REPEAT, delta=" << delta << "ms)");
#endif
            }
            break;
        }

        // Other label types not needed for basic parsing
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

    // Sort by SID
    std::sort(ensemble_.services.begin(), ensemble_.services.end(),
              [](const DABService& a, const DABService& b) { return a.sid < b.sid; });

    LOG_DEBUG(SERVER, "DAB: Parsed ensemble '" << ensemble_.label << "' (0x"
             << std::hex << ensemble_.eid << std::dec << ") with "
             << ensemble_.services.size() << " services");
}

// =============================================================================
// PF_Reassembler - reassemble PF (Protocol Fragment) packets into AF packets
// Exact copy from verified test_eti_output.cpp PFReassembler
// =============================================================================

PF_Reassembler::PF_Reassembler() {
    reset();
}

void PF_Reassembler::reset() {
    collectors_.clear();
    af_buffer_.clear();
}

void PF_Reassembler::cleanup_old_collectors() {
    // Remove completed collectors when we have too many
    if (collectors_.size() > 16) {
        auto it = collectors_.begin();
        while (collectors_.size() > 8 && it != collectors_.end()) {
            if (it->second.processed) {
                it = collectors_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

bool PF_Reassembler::parse_pf_header(const uint8_t* pkt, size_t len, PF_Header& hdr) {
    // Exact copy from verified test_eti_output.cpp PFReassembler::parse_header
    if (len < 14 || pkt[0] != 'P' || pkt[1] != 'F') return false;

    hdr.pseq = (pkt[2] << 8) | pkt[3];
    hdr.findex = (pkt[4] << 16) | (pkt[5] << 8) | pkt[6];
    hdr.fcount = (pkt[7] << 16) | (pkt[8] << 8) | pkt[9];

    uint16_t fec_addr_plen = (pkt[10] << 8) | pkt[11];
    hdr.fec = (fec_addr_plen >> 15) & 1;
    hdr.addr = (fec_addr_plen >> 14) & 1;
    hdr.plen = fec_addr_plen & 0x3FFF;

    // HCRC validation disabled for now - need to verify correct algorithm
    // TODO: The HCRC calculation may use different polynomial or init value

    // Sanity check: plen should fit within the packet
    // Header is 14 bytes minimum, so payload can be at most len - 14
    if (hdr.plen > len - 14) {
        LOG_DEBUG(SERVER, "DAB: PF plen=" << hdr.plen << " > available=" << (len - 14));
        return false;
    }

    hdr.valid = true;
    return true;
}

const uint8_t* PF_Reassembler::add_fragment(const PF_Header& hdr, const uint8_t* pkt, size_t len, size_t& af_len) {
    // Match gse2dab: use map keyed by pseq, no collisions
    af_len = 0;

    // Calculate header size
    size_t hdr_size = 12;
    if (hdr.fec) hdr_size += 2;
    if (hdr.addr) hdr_size += 4;
    hdr_size += 2; // HCRC

    if (len < hdr_size + hdr.plen) return nullptr;

    const uint8_t* payload = pkt + hdr_size;

    // Get or create collector for this pseq (map auto-creates if not exists)
    PF_Collector& c = collectors_[hdr.pseq];

    // Initialize if new OR if this pseq was previously processed (pseq wrapped around)
    if (c.fcount == 0 || c.processed) {
        // Initialize/reinitialize collector
        c.pseq = hdr.pseq;
        c.fcount = hdr.fcount;
        c.fragments_collected = 0;
        c.processed = false;
        c.fragments.clear();
    }

    if (hdr.findex >= c.fcount) return nullptr;
    if (c.fragments.count(hdr.findex)) return nullptr;  // Already have this fragment

    // Store fragment
    c.fragments[hdr.findex].assign(payload, payload + hdr.plen);
    c.fragments_collected++;

    // Check if we have all fragments
    if (c.fragments_collected < c.fcount) {
        return nullptr;  // Not complete yet
    }

    // All fragments received - concatenate in order
    c.processed = true;
    af_buffer_.clear();

    for (uint32_t i = 0; i < c.fcount; i++) {
        auto it = c.fragments.find(i);
        if (it == c.fragments.end()) {
            return nullptr;  // Missing fragment
        }
        af_buffer_.insert(af_buffer_.end(), it->second.begin(), it->second.end());
    }

    // Cleanup old collectors
    cleanup_old_collectors();

    af_len = af_buffer_.size();
    return af_buffer_.data();
}

// =============================================================================
// MPESectionAccumulator - accumulates PSI/MPE sections from TS packets
// Uses queue-based approach from verified test_eti_output.cpp
// =============================================================================

MPESectionAccumulator::MPESectionAccumulator() {
    reset();
}

void MPESectionAccumulator::reset() {
    cc_ = 0;
    buffer_size_ = 0;
    buffer_skip_ = 0;
    completed_sections_.clear();
    completed_section_sizes_.clear();
}

void MPESectionAccumulator::emit_section() {
    if (buffer_size_ > 0 && buffer_skip_ >= buffer_size_) {
        completed_sections_.push_back(buffer_);
        completed_section_sizes_.push_back(buffer_size_);
    }
    buffer_skip_ = 0;
    buffer_size_ = 0;
}

void MPESectionAccumulator::process_ts_packet(const uint8_t* ts) {
    // Exact copy from verified test_eti_output.cpp MPEAccumulator::process_ts
    const uint8_t* payload = ts_get_payload(ts);
    if (!payload) return;

    uint8_t cc = ts_get_cc(ts);

    if (ts_is_payload_start(ts)) {
        uint8_t ptr = *payload++;

        // Complete previous section
        if (ptr > 0 && ptr < TS_BODY_SIZE && buffer_skip_ > 0) {
            if (((cc_ + 1) & 0x0F) == cc) {
                memcpy(&buffer_[buffer_skip_], payload, ptr);
                buffer_skip_ += ptr;
                if (buffer_size_ > 0 && buffer_skip_ >= buffer_size_) {
                    emit_section();
                }
            }
            buffer_skip_ = 0;
            buffer_size_ = 0;
        }
        payload += ptr;

        // Parse new sections
        while ((payload - ts) < TS_PACKET_SIZE && *payload != 0xFF) {
            size_t remain = (ts + TS_PACKET_SIZE) - payload;
            if (remain < 3) {
                memcpy(buffer_.data(), payload, remain);
                buffer_skip_ = remain;
                buffer_size_ = 0;
                break;
            }

            size_t psi_size = 3 + ((payload[1] & 0x0F) << 8 | payload[2]);
            if (psi_size <= 3 || psi_size > PSI_MAX_SIZE) break;

            buffer_size_ = psi_size;
            if (psi_size > remain) {
                memcpy(buffer_.data(), payload, remain);
                buffer_skip_ = remain;
                break;
            } else {
                memcpy(buffer_.data(), payload, psi_size);
                buffer_skip_ = psi_size;
                emit_section();
                payload += psi_size;
            }
        }
    } else {
        // Continuation
        if (buffer_skip_ > 0) {
            if (((cc_ + 1) & 0x0F) != cc) {
                buffer_skip_ = 0;
                buffer_size_ = 0;
            } else {
                size_t remain = (ts + TS_PACKET_SIZE) - payload;
                if (buffer_size_ == 0 && buffer_skip_ < 3) {
                    size_t needed = 3 - buffer_skip_;
                    memcpy(&buffer_[buffer_skip_], payload, needed);
                    buffer_skip_ += needed;
                    buffer_size_ = 3 + ((buffer_[1] & 0x0F) << 8 | buffer_[2]);
                    payload += needed;
                    remain -= needed;
                }
                size_t to_copy = std::min(remain, (size_t)(buffer_size_ - buffer_skip_));
                memcpy(&buffer_[buffer_skip_], payload, to_copy);
                buffer_skip_ += to_copy;

                if (buffer_size_ > 0 && buffer_skip_ >= buffer_size_) {
                    emit_section();
                }
            }
        }
    }
    cc_ = cc;
}

// =============================================================================
// DABStreamParser - complete TS → MPE → EDI → ETI → FIC pipeline
// =============================================================================

DABStreamParser::DABStreamParser(uint16_t target_pid, uint32_t target_ip, uint16_t target_port)
    : target_pid_(target_pid), target_ip_(target_ip), target_port_(target_port) {
    reset();
}

DABStreamParser::~DABStreamParser() = default;

void DABStreamParser::reset() {
    mpe_accum_.reset();
    pf_reassembler_.reset();
    fic_parser_.reset();
    edi_ = EDI_Builder{};
    last_af_seq_ = 0;
    pending_ring_buffer_.clear();
    ring_buffer_pending_ = false;
    ring_buffer_processed_ = false;
}

void DABStreamParser::set_pending_ring_buffer(std::vector<uint8_t>&& data) {
    // Process ring buffer immediately - no delay needed
    // The ring buffer contains old TS packets from before this parser was created
    // Process them first, then continue with live data as it arrives
    if (!data.empty()) {
        LOG_INFO(SERVER, "DAB: Processing " << data.size() / 188
                 << " ring buffer packets immediately");
        process_ts_data(data.data(), data.size());
        LOG_INFO(SERVER, "DAB: Ring buffer processing complete, services="
                 << fic_parser_.get_ensemble().services.size());
    }
    // No pending buffer - we processed it immediately
    pending_ring_buffer_.clear();
    ring_buffer_pending_ = false;
    ring_buffer_processed_ = true;
}

uint16_t DABStreamParser::crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc << 8) ^ crc16_table[(crc >> 8) ^ data[i]];
    }
    return crc ^ 0xFFFF;
}

bool DABStreamParser::check_crc(const uint8_t* data, size_t len) {
    if (len < 2) return false;

    // Get CRC from last 2 bytes of packet (big-endian)
    uint16_t crc_from_packet = (data[len - 2] << 8) | data[len - 1];

    // Calculate CRC over data (excluding CRC bytes)
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len - 2; i++) {
        crc = (crc << 8) ^ crc16_table[(crc >> 8) ^ data[i]];
    }
    crc ^= 0xFFFF;  // Final XOR

    crc_check_count_++;
    LOG_DEBUG(SERVER, "DAB: CRC check #" << crc_check_count_ << " len=" << len
             << " expected=0x" << std::hex << crc_from_packet
             << " calculated=0x" << crc << std::dec
             << (crc_from_packet == crc ? " OK" : " FAIL"));

    return crc_from_packet == crc;
}

bool DABStreamParser::process_ts_data(const uint8_t* data, size_t len) {
    // Track total bytes and timing per instance
    total_bytes_ += len;

    // Process TS packets
    for (size_t i = 0; i + TS_PACKET_SIZE <= len; i += TS_PACKET_SIZE) {
        const uint8_t* ts = data + i;
        if (!ts_is_sync(ts)) {
            non_sync_count_++;
            continue;
        }
        ts_count_++;

        uint16_t pid = ts_get_pid(ts);
        if (pid != target_pid_) {
            continue;  // Only process target PID
        }
        target_pid_count_++;

        // Log at first packet and periodically
        if (target_pid_count_ == 1) {
            LOG_INFO(SERVER, "DAB: First PID " << target_pid_ << " packet after " << total_bytes_ << " bytes");
        }

        // Process TS packet - may produce multiple MPE sections (queue-based)
        mpe_accum_.process_ts_packet(ts);

        // Process all queued sections
        while (mpe_accum_.has_section()) {
            mpe_count_++;
            LOG_DEBUG(SERVER, "DAB: MPE section #" << mpe_count_ << " size=" << mpe_accum_.get_section_size());
            handle_mpe_section(mpe_accum_.get_section(), mpe_accum_.get_section_size());
            mpe_accum_.pop_section();

            if (fic_parser_.is_complete()) {
                LOG_INFO(SERVER, "DAB: Complete after " << ts_count_ << " TS packets, " << mpe_count_ << " MPE, " << total_bytes_ << " bytes");
                return true;
            }
        }
    }
    return fic_parser_.is_complete();
}

void DABStreamParser::handle_mpe_section(const uint8_t* section, size_t len) {
    // Check MPE table_id
    if (section[0] != 0x3E) return;

    // Check LLC_SNAP_flag (bit 3 of byte 1) - ETSI EN 301 192
    // If set, there's an 8-byte LLC/SNAP header before IP datagram
    bool llc_snap = (section[1] & 0x08) != 0;
    size_t ip_offset = llc_snap ? 20 : 12;  // 12 + 8 LLC/SNAP header

    if (len < ip_offset + 28) return;  // Need at least IP + UDP headers

    const uint8_t* ip = section + ip_offset;

    mpe_debug_count_++;

    // Check IP version
    if ((ip[0] >> 4) != 4) return;

    // Check protocol (17 = UDP)
    if (ip[9] != 17) return;

    // Extract destination IP and port
    uint32_t dst_ip = (ip[16] << 24) | (ip[17] << 16) | (ip[18] << 8) | ip[19];
    const uint8_t* udp = ip + 20;
    uint16_t dst_port = (udp[2] << 8) | udp[3];
    uint16_t udp_len = (udp[4] << 8) | udp[5];

    // Filter by target IP:port
    // target_ip_ should be in MSB-first format (same as dst_ip extracted above)
    if (!logged_first_mpe_) {
        LOG_INFO(SERVER, "DAB: First MPE packet dst=" << ((dst_ip >> 24) & 0xFF) << "."
                 << ((dst_ip >> 16) & 0xFF) << "." << ((dst_ip >> 8) & 0xFF) << "." << (dst_ip & 0xFF)
                 << ":" << dst_port << " target=" << ((target_ip_ >> 24) & 0xFF) << "."
                 << ((target_ip_ >> 16) & 0xFF) << "." << ((target_ip_ >> 8) & 0xFF) << "."
                 << (target_ip_ & 0xFF) << ":" << target_port_);
        logged_first_mpe_ = true;
    }

    if (dst_ip != target_ip_ || dst_port != target_port_) return;

    // EDI payload starts after UDP header
    const uint8_t* edi_data = udp + 8;
    size_t edi_len = udp_len - 8;

    if (edi_len > 0 && edi_len <= len - 40) {
        edi_count_++;
        LOG_DEBUG(SERVER, "DAB: EDI packet #" << edi_count_ << " len=" << edi_len
                 << " type=" << (char)edi_data[0] << (char)edi_data[1]);
        handle_edi_packet(edi_data, edi_len);
    }
}

bool DABStreamParser::process_mpe_section(const uint8_t* section, size_t len) {
    // This method is called by the shared MPE dispatcher which already filtered by IP
    // Skip IP filtering - go directly to EDI extraction

    if (len < 40) return fic_parser_.is_complete();

    // Check MPE table_id
    if (section[0] != 0x3E) return fic_parser_.is_complete();

    // Check LLC_SNAP_flag (bit 3 of byte 1) - ETSI EN 301 192
    bool llc_snap = (section[1] & 0x08) != 0;
    size_t ip_offset = llc_snap ? 20 : 12;

    if (len < ip_offset + 28) return fic_parser_.is_complete();

    const uint8_t* ip = section + ip_offset;

    // Check IP version
    if ((ip[0] >> 4) != 4) return fic_parser_.is_complete();

    // Check protocol (17 = UDP)
    if (ip[9] != 17) return fic_parser_.is_complete();

    const uint8_t* udp = ip + 20;
    uint16_t udp_len = (udp[4] << 8) | udp[5];

    // EDI payload starts after UDP header
    const uint8_t* edi_data = udp + 8;
    size_t edi_len = udp_len - 8;

    mpe_count_++;

    // Debug: log first few calls and periodically
    if (mpe_count_ <= 3 || mpe_count_ % 500 == 0) {
        LOG_INFO(SERVER, "DAB process_mpe_section: mpe_count=" << mpe_count_
                 << " len=" << len << " ip_offset=" << ip_offset
                 << " udp_len=" << udp_len << " edi_len=" << edi_len
                 << " edi_type=" << (char)edi_data[0] << (char)edi_data[1]);
    }

    if (edi_len > 0 && edi_len <= len - ip_offset - 28) {
        edi_count_++;
        handle_edi_packet(edi_data, edi_len);
    }

    return fic_parser_.is_complete();
}

bool DABStreamParser::process_edi_packet(const uint8_t* edi_data, size_t len) {
    // Public method to process raw EDI data (PF or AF packets)
    // Used by GSE parser where IP/UDP is already extracted
    if (len > 0) {
        edi_count_++;
        handle_edi_packet(edi_data, len);
    }
    return fic_parser_.is_complete();
}

bool DABStreamParser::process_ip_packet(const uint8_t* ip, size_t len) {
    // Process raw IP packet from GSE stream (no MPE wrapper)
    // Same logic as process_mpe_section but without MPE table parsing

    if (len < 28) return fic_parser_.is_complete();  // Need IP + UDP header

    // Check IP version
    if ((ip[0] >> 4) != 4) return fic_parser_.is_complete();

    int ip_hdr_len = (ip[0] & 0x0F) * 4;
    if (ip_hdr_len < 20 || (size_t)ip_hdr_len > len) return fic_parser_.is_complete();

    // Check protocol (17 = UDP)
    if (ip[9] != 17) return fic_parser_.is_complete();

    // Extract UDP header
    if (len < (size_t)ip_hdr_len + 8) return fic_parser_.is_complete();
    const uint8_t* udp = ip + ip_hdr_len;
    uint16_t udp_len = (udp[4] << 8) | udp[5];

    // Validate UDP length - must be reasonable and fit within IP packet
    if (udp_len < 8 || udp_len > len - ip_hdr_len) {
        return fic_parser_.is_complete();  // Invalid UDP length
    }

    // EDI payload starts after UDP header
    const uint8_t* edi_data = udp + 8;
    size_t edi_len = udp_len - 8;

    mpe_count_++;

    // Debug: log first few calls and periodically
    if (mpe_count_ <= 3 || mpe_count_ % 500 == 0) {
        LOG_INFO(SERVER, "DAB process_ip_packet: mpe_count=" << mpe_count_
                 << " len=" << len << " ip_hdr_len=" << ip_hdr_len
                 << " udp_len=" << udp_len << " edi_len=" << edi_len
                 << " edi_type=" << (char)edi_data[0] << (char)edi_data[1]);
    }

    if (edi_len > 0 && edi_len <= len - ip_hdr_len - 8) {
        edi_count_++;
        handle_edi_packet(edi_data, edi_len);
    }

    return fic_parser_.is_complete();
}

int DABStreamParser::handle_edi_packet(const uint8_t* pkt, size_t len) {
    if (len < 2) return -1;

    // Check packet type
    if (pkt[0] == 'A' && pkt[1] == 'F') {
        int ret = handle_af_packet(pkt, len);
        if (ret > 0) {
            assemble_eti_frame();
        }
        return ret;
    } else if (pkt[0] == 'P' && pkt[1] == 'F') {
        int ret = handle_pf_packet(pkt, len);
        if (ret > 0) {
            assemble_eti_frame();
        }
        return ret;
    }

    return -1;
}

int DABStreamParser::handle_pf_packet(const uint8_t* pkt, size_t len) {
    // Exact copy of logic from verified test_eti_output.cpp
    PF_Header hdr;
    if (!pf_reassembler_.parse_pf_header(pkt, len, hdr)) {
        LOG_WARN(SERVER, "DAB: PF header parse failed, len=" << len);
        return -1;
    }

    pf_count_++;
    // Log first few and periodically (DEBUG level - high frequency)
    if (pf_count_ <= 5 || pf_count_ % 500 == 0) {
        LOG_DEBUG(SERVER, "DAB: PF packet #" << pf_count_ << " pseq=" << hdr.pseq
                  << " findex=" << hdr.findex << "/" << hdr.fcount
                  << " plen=" << hdr.plen << " len=" << len);
    }

    // Add fragment to reassembler - pass full packet, it extracts payload internally
    size_t af_len = 0;
    const uint8_t* af_data = pf_reassembler_.add_fragment(hdr, pkt, len, af_len);

    if (af_data && af_len > 0) {
        af_assembled_count_++;
        if (af_assembled_count_ <= 5 || af_assembled_count_ % 100 == 0) {
            LOG_DEBUG(SERVER, "DAB: PF reassembled AF packet #" << af_assembled_count_ << " len=" << af_len);
        }

        // Process the reassembled AF packet
        int ret = handle_af_packet(af_data, af_len);
        return ret;
    }

    return 0;  // Fragment received but AF not yet complete
}

int DABStreamParser::handle_af_packet(const uint8_t* pkt, size_t len) {
    // Exact copy from verified test_eti_output.cpp handle_af_packet
    constexpr size_t AFPACKET_HEADER_LEN = 10;

    if (len < AFPACKET_HEADER_LEN || pkt[0] != 'A' || pkt[1] != 'F') {
        af_process_count_++;
        LOG_DEBUG(SERVER, "DAB: AF bad sync or len=" << len);
        return -1;
    }

    // Read taglength - eti-tools treats this as BYTES (despite ETSI spec saying bits)
    uint32_t taglength = read_32b(pkt + 2);

    bool has_crc = (pkt[8] >> 7) & 1;
    char pt = pkt[9];

    af_process_count_++;
    // Log first few AF packets (DEBUG level - high frequency)
    if (af_process_count_ <= 5 || af_process_count_ % 100 == 0) {
        LOG_DEBUG(SERVER, "DAB: AF #" << af_process_count_ << " taglength=" << taglength
                 << " has_crc=" << has_crc << " pt=" << pt << " buflen=" << len);
    }

    if (pt != 'T') {
        LOG_DEBUG(SERVER, "DAB: AF pt=" << (int)pt << " not T");
        return -1;
    }

    size_t total_len = AFPACKET_HEADER_LEN + taglength + (has_crc ? 2 : 0);
    if (len < total_len) {
        LOG_DEBUG(SERVER, "DAB: AF len=" << len << " < total=" << total_len);
        return -1;
    }

    // CRC verification for AF packets
    if (has_crc) {
        uint16_t crc_from_pkt = read_16b(pkt + total_len - 2);
        // CRC calculation: crc16(0xFFFF, data, len) ^ 0xFFFF
        uint16_t crc = 0xFFFF;
        for (size_t i = 0; i < total_len - 2; i++) {
            crc = (crc << 8) ^ crc16_table[(crc >> 8) ^ pkt[i]];
        }
        crc ^= 0xFFFF;
        if (crc_from_pkt != crc) {
            LOG_DEBUG(SERVER, "DAB: AF CRC fail (got=0x" << std::hex << crc_from_pkt
                     << " calc=0x" << crc << std::dec << ")");
            return -1;
        }
    }

    // Decode tags - tags start at offset AFPACKET_HEADER_LEN (10)
    decode_tagpacket(pkt + AFPACKET_HEADER_LEN, taglength);

    // Log first few results (DEBUG level)
    if (af_process_count_ <= 5) {
        LOG_DEBUG(SERVER, "DAB: AF is_eti=" << edi_.is_eti << " fc_valid=" << edi_.m_fc_valid
                 << " fic_len=" << (int)edi_.fic_length << " nst=" << (int)edi_.m_fc.nst
                 << " mid=" << (int)edi_.m_fc.mid);
    }

    return 1;
}

bool DABStreamParser::decode_tagpacket(const uint8_t* pkt, size_t tagsize) {
    tagpkt_count_++;
    edi_.m_fc.nst = 0;
    int tag_count_local = 0;

    LOG_DEBUG(SERVER, "DAB: decode_tagpacket #" << tagpkt_count_ << " len=" << tagsize);

    // Hex dump first 32 bytes of tag packet for debugging
    if (tagpkt_count_ <= 3) {
        std::ostringstream ss;
        ss << "DAB: tagpkt hex: ";
        for (size_t j = 0; j < std::min(tagsize, (size_t)64); j++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)pkt[j] << " ";
            if ((j + 1) % 16 == 0) ss << "\n                   ";
        }
        LOG_DEBUG(SERVER, ss.str());
    }

    for (size_t i = 0; i + 8 <= tagsize; ) {
        uint32_t tagId = read_32b(pkt + i);
        uint32_t taglen_bits = read_32b(pkt + i + 4);

        // Debug first few tags
#if defined(LSDVB_LOG_DEBUG) || defined(LSDVB_LOG_TRACE)
        if (tagpkt_count_ <= 5 && tag_count_local < 3) {
            char id[5] = {(char)(tagId >> 24), (char)(tagId >> 16), (char)(tagId >> 8), (char)tagId, 0};
            LOG_DEBUG(SERVER, "  TAG[" << tag_count_local << "]: id='" << id << "' (0x"
                     << std::hex << tagId << ") len_bits=" << std::dec << taglen_bits);
        }
#endif

        if (taglen_bits % 8 != 0) break;
        uint32_t taglen = taglen_bits / 8;

        const uint8_t* val = pkt + i + 8;

        if (tagId == 0x2a707472) {  // "*ptr"
            decode_starptr(val, taglen);
        } else if (tagId == 0x64657469) {  // "deti"
            decode_deti(val, taglen);
        } else if ((tagId & 0xFFFFFF00) == 0x65737400) {  // "est?"
            decode_estn(val, taglen, tagId & 0xFF);
        }
        // Ignore other tags

        i += 8 + taglen;
        tag_count_local++;
        tag_count_++;
    }

    return true;
}

bool DABStreamParser::decode_starptr(const uint8_t* value, size_t len) {
    if (len != 8) return false;

    uint32_t proto = read_32b(value);
    uint16_t major = read_16b(value + 4);
    uint16_t minor = read_16b(value + 6);

    edi_.is_eti = (proto == 0x44455449 && major == 0 && minor == 0);  // "DETI"
    return true;
}

bool DABStreamParser::decode_deti(const uint8_t* val, size_t /*len*/) {
    // Based on eti-tools decode_deti - verified working implementation
    uint16_t detiHeader = read_16b(val);
    edi_.m_fc.atstf = (detiHeader >> 15) & 1;
    edi_.m_fc.ficf = (detiHeader >> 14) & 1;
    bool rfudf = (detiHeader >> 13) & 1;
    uint8_t fcth = (detiHeader >> 8) & 0x1F;
    uint8_t fct = detiHeader & 0xFF;
    edi_.m_fc.dflc = fcth * 250 + fct;

    uint32_t etiHeader = read_32b(val + 2);
    edi_.m_fc.mid = (etiHeader >> 22) & 0x03;
    edi_.m_fc.fp = (etiHeader >> 19) & 0x07;
    bool rfu = (etiHeader >> 16) & 1;
    edi_.m_mnsc = rfu ? 0xFFFF : etiHeader & 0xFFFF;

    uint32_t fic_length = edi_.m_fc.ficf ? (edi_.m_fc.mid == 3 ? 32 * 4 : 24 * 4) : 0;

    size_t i = 6;
    if (edi_.m_fc.atstf) {
        i++;  // utco
        i += 4;  // seconds
        edi_.m_fc.tsta = read_24b(val + i);
        i += 3;
    } else {
        edi_.m_fc.tsta = 0xFFFFFF;
    }

    if (edi_.m_fc.ficf) {
        edi_.fic_length = fic_length;
        memcpy(edi_.fic.data(), val + i, fic_length);
        i += fic_length;
    }

    edi_.m_rfu = 0xFFFF;
    if (rfudf) {
        uint32_t rfud = read_24b(val + i);
        edi_.m_rfu = rfud >> 8;
        i += 3;
    }

    edi_.m_fc_valid = true;
    return true;
}

bool DABStreamParser::decode_estn(const uint8_t* value, size_t len, uint8_t n) {
    if (len < 3 || n == 0 || n > 64) return false;

    uint32_t sstc = read_24b(value);

    EDI_STC& stc = edi_.m_stc[n - 1];
    stc.stream_index = n - 1;
    stc.scid = (sstc >> 18) & 0x3F;
    stc.sad = (sstc >> 8) & 0x3FF;
    stc.tpl = (sstc >> 2) & 0x3F;

    stc.mst.resize(len - 3);
    memcpy(stc.mst.data(), value + 3, len - 3);
    edi_.m_fc.nst++;

    return true;
}

bool DABStreamParser::assemble_eti_frame() {
    if (!edi_.is_eti || !edi_.m_fc_valid || !edi_.fic_length) {
        LOG_DEBUG(SERVER, "DAB: assemble_eti skip: is_eti=" << edi_.is_eti
                 << " fc_valid=" << edi_.m_fc_valid << " fic_len=" << (int)edi_.fic_length);
        return false;
    }

    // Validate FIC length (32*4=128 for mode 3, 24*4=96 for modes 1,2,4)
    if ((edi_.m_fc.mid == 3 && edi_.fic_length != 32 * 4) ||
        (edi_.m_fc.mid != 3 && edi_.fic_length != 24 * 4)) {
        LOG_WARN(SERVER, "DAB: ETI FIC length mismatch: mid=" << edi_.m_fc.mid << " fic_len=" << (int)edi_.fic_length);
        return false;
    }

    eti_count_++;
    if (eti_count_ <= 5 || eti_count_ % 100 == 0) {
        LOG_DEBUG(SERVER, "DAB: Assembling ETI frame #" << eti_count_ << " mid=" << edi_.m_fc.mid
                 << " nst=" << (int)edi_.m_fc.nst << " fic_len=" << (int)edi_.fic_length);
    }

    uint8_t* eti = eti_frame_.data();
    memset(eti, 0x55, ETI_NI_RAW_SIZE);  // Pre-fill with padding

    int idx = 0;

    // SYNC word: ERR (1 byte) + FSYNC (3 bytes)
    // Per ETSI EN 300 799 and eti-tools: ERR=0xFF first, FSYNC alternates each frame
    // Odd FCT: FSYNC = 0xF8C549, Even FCT: FSYNC = 0x073AB6
    uint8_t fct = edi_.m_fc.dflc % 250;
    eti[0] = 0xFF;  // ERR byte first
    if (fct % 2 == 1) {
        eti[1] = 0xF8; eti[2] = 0xC5; eti[3] = 0x49;
    } else {
        eti[1] = 0x07; eti[2] = 0x3A; eti[3] = 0xB6;
    }

    // FC
    eti[4] = fct;
    uint8_t nst = edi_.m_fc.nst;
    eti[5] = (edi_.m_fc.ficf ? 0x80 : 0) | nst;

    // Calculate FL
    uint16_t fl = nst + 1 + edi_.fic_length / 4;
    for (int i = 0; i < nst; i++) {
        fl += edi_.m_stc[i].mst.size() / 4;
    }

    uint16_t fp_mid_fl = (edi_.m_fc.fp << 13) | (edi_.m_fc.mid << 11) | fl;
    eti[6] = fp_mid_fl >> 8;
    eti[7] = fp_mid_fl & 0xFF;

    // STC
    for (int i = 0; i < nst; i++) {
        auto& stc = edi_.m_stc[i];
        eti[8 + i * 4] = (stc.scid << 2) | ((stc.sad >> 8) & 0x03);
        eti[8 + i * 4 + 1] = stc.sad & 0xFF;
        uint16_t stl = stc.mst.size() / 8;
        eti[8 + i * 4 + 2] = (stc.tpl << 2) | ((stl >> 8) & 0x03);
        eti[8 + i * 4 + 3] = stl & 0xFF;
    }

    idx = 8 + nst * 4;

    // EOH - MNSC
    eti[idx] = edi_.m_mnsc >> 8;
    eti[idx + 1] = edi_.m_mnsc & 0xFF;

    // EOH - CRC (over FC through MNSC, i.e., bytes 4 to idx+2)
    uint16_t hdr_crc = crc16(&eti[4], idx - 4 + 2);
    eti[idx + 2] = hdr_crc >> 8;
    eti[idx + 3] = hdr_crc & 0xFF;
    idx += 4;

    size_t mst_start = idx;

    // FIC
    memcpy(eti + idx, edi_.fic.data(), edi_.fic_length);
    idx += edi_.fic_length;

    // MST
    for (int i = 0; i < nst; i++) {
        memcpy(eti + idx, edi_.m_stc[i].mst.data(), edi_.m_stc[i].mst.size());
        idx += edi_.m_stc[i].mst.size();
    }

    // EOF - CRC
    uint16_t mst_crc = crc16(&eti[mst_start], idx - mst_start);
    eti[idx] = mst_crc >> 8;
    eti[idx + 1] = mst_crc & 0xFF;

    // RFU
    eti[idx + 2] = edi_.m_rfu >> 8;
    eti[idx + 3] = edi_.m_rfu & 0xFF;

    // TIST
    eti[idx + 4] = (edi_.m_fc.tsta >> 24) & 0xFF;
    eti[idx + 5] = (edi_.m_fc.tsta >> 16) & 0xFF;
    eti[idx + 6] = (edi_.m_fc.tsta >> 8) & 0xFF;
    eti[idx + 7] = edi_.m_fc.tsta & 0xFF;
    idx += 8;

    // Padding already done with 0x55 at start

    // Feed to FIC parser
    fic_parser_.process_eti_frame(eti, ETI_NI_RAW_SIZE);

    // Emit ETI frame to callback with DFLC for continuity checking
    if (eti_callback_) {
        eti_callback_(eti, ETI_NI_RAW_SIZE, edi_.m_fc.dflc);
    }

    return true;
}

const DABEnsemble& DABStreamParser::get_ensemble() const {
    return fic_parser_.get_ensemble();
}

bool DABStreamParser::is_complete() const {
    return fic_parser_.is_complete();
}

bool DABStreamParser::is_basic_ready() const {
    return fic_parser_.is_basic_ready();
}

bool DABStreamParser::has_data() const {
    // Check if we've received any ETI frames (useful data)
    return eti_count_ > 0;
}

} // namespace lsdvb
