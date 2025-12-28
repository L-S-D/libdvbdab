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
};

// DAB Ensemble Information
struct DABEnsemble {
    uint16_t eid{0};            // Ensemble ID
    std::string label;          // Ensemble label
    std::vector<DABService> services;

    // Stream identification (where this ensemble comes from)
    uint32_t source_ip{0};      // Multicast IP (e.g., 239.199.2.1)
    uint16_t source_port{0};    // UDP port (e.g., 1234)
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

// IPv4 packet callback (common convergence point for all input sources)
// All input formats (GSE-in-TS, BBF-in-PseudoTS, MPE-in-TS) produce IPv4 packets
using IpPacketCallback = std::function<void(const uint8_t* ip_packet, size_t len)>;

// UDP packet callback (extracted from IPv4 by shared UDP extractor)
using UdpPacketCallback = std::function<void(uint32_t dst_ip, uint16_t dst_port,
                                              const uint8_t* payload, size_t len)>;

// ETI frame callback (6144 bytes per frame)
// dflc = Data Flow Counter (0-7999) for continuity checking
using EtiFrameCallback = std::function<void(const StreamKey& stream,
                                             const uint8_t* frame, size_t len,
                                             uint16_t dflc)>;

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

// GSE constants
constexpr size_t MAX_GSE_FRAGMENT_SIZE = 4096;
constexpr int GSE_FRAGMENT_ID_COUNT = 256;

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

    size_t service_count() const { return services.size(); }

    // Convenience: formatted IP:port string
    std::string address() const {
        if (is_etina) {
            return "ETI-NA PID " + std::to_string(pid);
        }
        return ipToString(ip) + ":" + std::to_string(port);
    }
};

// Input format for ensemble discovery
enum class InputFormat {
    MPE,    // MPE-in-TS (Astra, etc.) - requires PID
    BBF,    // BBF-in-pseudoTS (NRK GSE via DVB-S2)
    GSE     // GSE-in-TS
};

/**
 * Discover all DAB ensembles in a transport stream file.
 *
 * Scans the input file for DAB ensembles carried via EDI-over-UDP and returns
 * information about each discovered ensemble including IP:port, EID, and label.
 *
 * @param file_path     Path to input transport stream file
 * @param format        Input format (MPE, BBF, or GSE)
 * @param pid           PID to filter (only used for MPE format, default 3000)
 * @param timeout_ms    Maximum time to scan in milliseconds (default 20000 = 20 seconds)
 * @return              Vector of discovered ensembles (may be empty if none found)
 */
std::vector<DiscoveredEnsemble> discoverEnsembles(
    const std::string& file_path,
    InputFormat format,
    uint16_t pid = 3000,
    unsigned int timeout_ms = 20000
);

/**
 * Discover all DAB ensembles from a file descriptor (e.g., DVB DVR device).
 *
 * Reads from the fd and scans for DAB ensembles carried via EDI-over-UDP.
 * Returns information about each discovered ensemble including IP:port, EID, and label.
 *
 * @param fd            File descriptor to read from (must be open and readable)
 * @param format        Input format (MPE, BBF, or GSE)
 * @param pid           PID to filter (only used for MPE format)
 * @param timeout_ms    Maximum time to scan in milliseconds
 * @return              Vector of discovered ensembles (may be empty if none found)
 */
std::vector<DiscoveredEnsemble> discoverEnsemblesFromFd(
    int fd,
    InputFormat format,
    uint16_t pid,
    unsigned int timeout_ms
);

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
     * Feed an IP packet (extracted from MPE section, table_id 0x3E).
     *
     * The section data should be the payload of the MPE section, which is
     * a raw IPv4 packet containing UDP with EDI data.
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
