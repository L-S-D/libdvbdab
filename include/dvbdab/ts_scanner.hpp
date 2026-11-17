#pragma once

#include <dvbdab/dvbdab.hpp>
#include <memory>
#include <string>
#include <vector>

namespace dvbdab {

/**
 * ETI-NA detection result (for UK satellite DAB feeds).
 * ETI-NA streams use continuous mode (no PUSI), stream type 0x87,
 * with E1/G.704 framing and bit-level sync.
 */
struct EtiNaDetectionInfo {
    uint16_t pid{0};           // PID where ETI-NA was detected
    int padding_bytes{0};      // Number of leading 0xFF bytes (typically 12)
    int sync_bit_offset{0};    // Bit position where E1 sync found (0-7)
    bool inverted{false};      // Signal is inverted
};

/**
 * Transport Stream Scanner for DAB detection.
 *
 * Scans raw TS packets to automatically detect DAB ensembles carried via:
 *   - ETI-NA (G.704/E1) - continuous mode, no PUSI, UK satellite feeds
 *   - TS NI V.11 - ETI-NI frames with an incrementing sequence byte
 *
 * DAB over IP (EDI in UDP, in MPE or GSE) is the caller's: it takes the
 * IPv4 packets out of their encapsulation and gives them to a streamer of
 * DVBDAB_FORMAT_IPV4 (or to EnsembleDiscovery).
 *
 * Detection flow for ETI-NA:
 *   1. Detect PIDs with no PUSI (continuous data)
 *   2. Analyze for consistent 0xFF padding
 *   3. Search for E1 sync pattern (0x1B every 32 bytes)
 *   4. Verify ETI block structure inside E1 frames
 *
 * Usage:
 *   TsScanner scanner;
 *   scanner.setTimeout(5000);  // 5 seconds
 *   while (have_data && !scanner.isDone()) {
 *       scanner.feed(data, len);
 *   }
 *   auto results = scanner.getResults();
 *   auto etina_pids = scanner.getEtiNaResults();  // For ETI-NA streams
 */
class TsScanner {
public:
    TsScanner();
    ~TsScanner();

    // Non-copyable
    TsScanner(const TsScanner&) = delete;
    TsScanner& operator=(const TsScanner&) = delete;

    /**
     * Set timeout in milliseconds.
     * After this time, scanning stops and partial results are returned.
     * Default: 500ms (suitable for file scanning).
     */
    void setTimeout(unsigned int timeout_ms);

    /**
     * Feed raw TS data to the scanner.
     * Can be called with any amount of data (handles partial packets).
     *
     * @param data  Raw TS data (must start at sync byte 0x47)
     * @param len   Length of data in bytes
     * @return      0 = continue feeding, 1 = done (timeout or all complete)
     */
    int feed(const uint8_t* data, size_t len);

    /**
     * Get discovered ensembles.
     * Call after feed() returns 1 or isDone() returns true.
     */
    std::vector<DiscoveredEnsemble> getResults();

    /**
     * Check if scanning is complete.
     */
    bool isDone() const;

    /**
     * Check if any traffic was received.
     */
    bool hadTraffic() const;

    /**
     * Get ETI-NA detection results.
     * Returns information about PIDs detected as carrying ETI-NA data
     * (UK satellite DAB feeds using continuous E1/G.704 framing).
     */
    std::vector<EtiNaDetectionInfo> getEtiNaResults() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * Scan a TS file for DAB ensembles.
 *
 * Convenience function that reads a file and returns all discovered ensembles.
 *
 * @param file_path   Path to TS file
 * @param timeout_ms  Maximum scan time (default: 30 seconds)
 * @return            Vector of discovered ensembles (may be empty)
 */
std::vector<DiscoveredEnsemble> scanTsFile(
    const std::string& file_path,
    unsigned int timeout_ms = 30000
);

} // namespace dvbdab
