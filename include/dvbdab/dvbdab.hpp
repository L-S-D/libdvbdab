#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace dvbdab {

// DAB Service Information
struct DABService {
    uint32_t sid{0};            // Service ID
    std::string label;          // Service label (up to 16 chars)
    int bitrate{0};             // Bitrate in kbps
    int subchannel_id{-1};      // Sub-channel ID
    int start_addr{0};          // Start address in CUs
    int subchannel_size{0};     // Size in CUs
    bool dabplus{false};        // true for DAB+, false for DAB
    int protection_level{0};    // Protection level
    bool eep_protection{false}; // EEP (true) or UEP (false)
    uint8_t language{0};        // Language of its audio (FIG 0/5, TS 101 756 tables 9/10), 0 = not said
    uint8_t pty{0};             // Programme type (FIG 0/17, international code), 0 = none
};

// DAB Ensemble Information
struct DABEnsemble {
    uint16_t eid{0};            // Ensemble ID
    std::string label;          // Ensemble label
    std::vector<DABService> services;

    // Stream identification (where this ensemble comes from)
    uint32_t source_ip{0};      // Multicast IP (e.g., 239.199.2.1)
    uint16_t source_port{0};    // UDP port (e.g., 1234)

    // Country, LTO and international table (FIG 0/9)
    bool has_country{false};    // FIG 0/9 was received
    uint8_t ecc{0};             // Extended country code
    int8_t lto_half_hours{0};   // Local time offset from UTC, in half hours
    uint8_t international_table{0};  // 1: RDS programme types, 2: RBDS
};

// Stream key for routing packets to per-ensemble parsers
struct StreamKey {
    uint32_t ip{0};
    uint16_t port{0};

    bool operator<(const StreamKey& other) const {
        if (ip != other.ip) return ip < other.ip;
        return port < other.port;
    }

    bool operator==(const StreamKey& other) const {
        return ip == other.ip && port == other.port;
    }
};

// IPv4 packet callback (DAB over IP: the caller takes the IPv4 packets out
// of their encapsulation, MPE or GSE)
using IpPacketCallback = std::function<void(const uint8_t* ip_packet, size_t len)>;

// UDP packet callback (extracted from IPv4 by shared UDP extractor)
using UdpPacketCallback = std::function<void(uint32_t dst_ip, uint16_t dst_port,
                                              const uint8_t* payload, size_t len)>;

// ETI frame callback (6144 bytes per frame)
// dflc = Data Flow Counter (0-7999) for continuity checking
using EtiFrameCallback = std::function<void(const StreamKey& stream,
                                             const uint8_t* frame, size_t len,
                                             uint16_t dflc)>;

// The same, also for frames from EDI packets of which fragments were lost:
// invalid_scids has the bit of each subchannel (SCID 0..63) whose data did not
// come (its bytes in the frame are zero). EtiFrameCallback only gets frames
// without such.
using EtiFrameExCallback = std::function<void(const StreamKey& stream,
                                               const uint8_t* frame, size_t len,
                                               uint16_t dflc, uint64_t invalid_scids)>;

// Subchannel data callback (raw MSC data for a service)
using SubchannelCallback = std::function<void(const StreamKey& stream,
                                               uint8_t subchannel_id,
                                               const uint8_t* data, size_t len)>;

// Audio frame callback (AAC or MP2)
using AudioFrameCallback = std::function<void(const StreamKey& stream,
                                               uint32_t sid,
                                               const uint8_t* frame, size_t len,
                                               bool is_aac)>;

// Ensemble discovery callback
using EnsembleFoundCallback = std::function<void(const DABEnsemble& ensemble)>;

// ETI frame constants
constexpr size_t ETI_FRAME_SIZE = 6144;
constexpr uint32_t ETI_FSYNC_ODD = 0xF8C549;   // Odd frames
constexpr uint32_t ETI_FSYNC_EVEN = 0x073AB6;  // Even frames

// TS packet constants
constexpr size_t TS_PACKET_SIZE = 188;
constexpr size_t TS_HEADER_SIZE = 4;

// Utility functions
inline std::string ipToString(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

inline uint32_t stringToIp(const std::string& s) {
    uint32_t a, b, c, d;
    if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
    return 0;
}

// Discovered service info (for discovery results)
struct DiscoveredService {
    uint32_t sid{0};             // Service ID
    std::string label;           // Service label (up to 16 chars)
    int bitrate{0};              // Bitrate in kbps
    uint8_t subchannel_id{0};    // Subchannel ID
    bool dabplus{false};         // true for DAB+, false for DAB
    uint8_t language{0};         // Language (FIG 0/5 code), 0 = not said
    uint8_t pty{0};              // Programme type (FIG 0/17), 0 = none
};

// ETI-NA detection info (for ETI-NA ensembles)
struct EtiNaInfo {
    int padding_bytes{0};      // Number of leading 0xFF bytes (typically 12)
    int sync_bit_offset{0};    // Bit position where E1 sync found (0-7)
    bool inverted{false};      // Signal is inverted
};

// Discovered ensemble info (with full service list)
struct DiscoveredEnsemble {
    uint32_t ip{0};              // Multicast IP address (0 for ETI-NA)
    uint16_t port{0};            // UDP port (0 for ETI-NA)
    uint16_t eid{0};             // Ensemble ID
    uint16_t pid{0};             // PID where ensemble was found
    std::string label;           // Ensemble label
    std::vector<DiscoveredService> services;  // Full service list

    // ETI-NA specific info (valid when is_etina is true)
    bool is_etina{false};        // True if this is an ETI-NA ensemble
    EtiNaInfo etina_info;        // ETI-NA detection parameters

    // TS NI V.11 format (satellite DAB via section-like framing)
    bool is_tsni{false};         // True if this is a TS NI V.11 ensemble

    size_t service_count() const { return services.size(); }

    // Convenience: formatted IP:port string
    std::string address() const {
        if (is_etina) {
            return "ETI-NA PID " + std::to_string(pid);
        }
        if (is_tsni) {
            return "TSNI PID " + std::to_string(pid);
        }
        return ipToString(ip) + ":" + std::to_string(port);
    }
};

/**
 * Callback-fed ensemble discovery (for integration with table filter systems).
 *
 * This class allows feeding section data incrementally rather than reading
 * from a file descriptor. Useful when data comes via callbacks from an
 * existing demultiplexer (e.g., tvheadend's table filter system).
 *
 * Two-tier timeout:
 * - early_timeout_ms: Fail fast if no multicast UDP within this time
 * - total_timeout_ms: Max time to wait for ensemble discovery once multicast found
 */
class EnsembleDiscovery {
public:
    /**
     * Create discovery context with two-tier timeout.
     *
     * @param early_timeout_ms  Fail fast if no multicast UDP seen (e.g., 1000ms)
     * @param total_timeout_ms  Max time for ensemble discovery (e.g., 10000ms)
     */
    EnsembleDiscovery(unsigned int early_timeout_ms, unsigned int total_timeout_ms);
    ~EnsembleDiscovery();

    // Non-copyable
    EnsembleDiscovery(const EnsembleDiscovery&) = delete;
    EnsembleDiscovery& operator=(const EnsembleDiscovery&) = delete;

    /**
     * Feed an IPv4 packet (the caller took it out of its encapsulation:
     * an MPE datagram section, table_id 0x3E, or a GSE PDU), UDP with EDI
     * data.
     *
     * @param ip_data   IPv4 packet data
     * @param len       Length of IP packet
     * @return          0=continue feeding, 1=done (found ensembles), -1=failed/timeout
     */
    int feedIpPacket(const uint8_t* ip_data, size_t len);

    /**
     * Get discovered ensembles (call after feedIpPacket returns 1).
     */
    std::vector<DiscoveredEnsemble> getResults();

    /**
     * Check if discovery is complete (found ensembles or timeout).
     */
    bool isDone() const;

    /**
     * Check if any ensembles were discovered.
     */
    bool hasEnsembles() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace dvbdab
