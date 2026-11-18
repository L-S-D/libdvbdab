#pragma once
/**
 * @file ts_tables.hpp
 * @brief The PSI/SI sections of the TS that goes out
 *
 * Each function gives whole sections with their CRC, to be cut into TS
 * packets by the muxer. They keep no state: what a section says is all in
 * the arguments.
 *
 * References:
 *   ISO/IEC 13818-1 - MPEG-2 Systems (PAT, PMT)
 *   ETSI EN 300 468 - DVB SI (SDT, EIT)
 */

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include "../parsers/spi_parser.hpp"  // For EpgSchedule/EpgProgramme

namespace dvbdab {

/// @name TS Constants (ISO/IEC 13818-1)
/// @{
inline constexpr size_t TS_MUXER_PACKET_SIZE = 188;  ///< TS packet size in bytes
inline constexpr uint16_t PID_PAT = 0x0000;          ///< PAT always on PID 0
inline constexpr uint16_t PID_SDT = 0x0011;          ///< SDT/BAT PID
inline constexpr uint16_t PID_EIT = 0x0012;          ///< EIT PID
inline constexpr uint16_t PID_TDT = 0x0014;          ///< TDT/TOT PID
inline constexpr uint16_t PID_NULL = 0x1FFF;         ///< Null packet PID
/// @}

/// @name Stream Types (ISO/IEC 13818-1 Table 2-36)
/// @{
inline constexpr uint8_t STREAM_TYPE_AAC_ADTS = 0x0F;   ///< DAB+ (ISO/IEC 13818-7 AAC ADTS)
inline constexpr uint8_t STREAM_TYPE_AAC_LATM = 0x11;   ///< DAB+ (ISO/IEC 14496-3 LATM in LOAS)
inline constexpr uint8_t STREAM_TYPE_MPEG_AUDIO = 0x04; ///< DAB (ISO/IEC 13818-3 MPEG-2 Layer II)
/// @}

/**
 * @brief Service configuration for TS muxing
 *
 * Defines a single program/service within the transport stream.
 * Each service has its own PMT, audio PID, and metadata.
 */
struct TsService {
    uint16_t sid;           ///< Service ID (program_number in PAT/PMT)
    uint16_t pmt_pid;       ///< PID for this service's PMT
    uint16_t audio_pid;     ///< PID for audio elementary stream
    uint16_t rds_pid{0};    ///< PID for its dynamic label as RDS RadioText (UECP), 0 = none
    std::string name;       ///< Service name (SDT service_name descriptor)
    std::string provider;   ///< Provider name (SDT service_provider descriptor)
    bool dabplus;           ///< true=DAB+ (AAC-LC), false=DAB (MPEG Layer II)
    bool latm{false};       ///< DAB+ as LATM/LOAS (else ADTS)
    uint8_t subchannel_id;  ///< DAB subchannel ID (for feedAudioFrame lookup)
    int sample_rate{48000}; ///< Audio sample rate in Hz
    int bitrate{0};         ///< Audio bitrate in kbps
    std::string language;   ///< Language of the audio, ISO 639-2 (three letters); empty = not known
    uint8_t content{0};     ///< What it broadcasts, as the nibbles of a DVB content_descriptor; 0 = not known
};

/// The PAT: every service with the PID of its PMT
std::vector<uint8_t> buildPatSection(uint16_t tsid, uint8_t version, const std::vector<TsService>& services);

/// The PMT of a service: its audio (which carries the PCR; with the
/// language of the service, when that is known) and, with an rds_pid, its RadioText
std::vector<uint8_t> buildPmtSection(const TsService& service, uint8_t version);

/// The SDT (actual), in as many sections of at most 1024 bytes as the
/// services need. A service without a provider gets default_provider.
std::vector<std::vector<uint8_t>> buildSdtSections(uint16_t tsid, uint16_t onid, uint8_t version,
                                                   const std::vector<TsService>& services,
                                                   const std::string& default_provider);

/// The EIT schedule (table 0x50) of one service with these programmes, in
/// sections of at most 4096 bytes; none without programmes. The texts are
/// in `language` (ISO 639-2; "und" when empty), and every event has
/// `content` as its content_descriptor when that is not 0.
std::vector<std::vector<uint8_t>> buildEitScheduleSections(uint16_t service_id, uint16_t tsid, uint16_t onid,
                                                           uint8_t version,
                                                           const std::vector<EpgProgramme>& programmes,
                                                           const std::string& language = "",
                                                           uint8_t content = 0);

/// The TDT: UTC, in seconds since 1970
std::vector<uint8_t> buildTdtSection(int64_t utc_seconds);

} // namespace dvbdab
