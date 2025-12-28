// TS Scanner - Auto-detect DAB ensembles from raw transport stream

#include <dvbdab/ts_scanner.hpp>
#include "parsers/mpe_parser.hpp"
#include "parsers/udp_extractor.hpp"
#include "etina_pipeline.hpp"
#include "ensemble_manager.hpp"
#include "dab_parser.h"
#include <array>
#include <chrono>
#include <fstream>
#include <map>
#include <vector>

namespace dvbdab {

// Per-PID state
struct PidState {
    bool active{false};          // Have we seen any packets on this PID?
    bool checked{false};         // Have we checked first PUSI for table_id?
    bool is_mpe{false};          // Confirmed as MPE (table_id 0x3E)?
    uint8_t last_cc{0xFF};       // Last continuity counter (0xFF = unknown)
    std::unique_ptr<MpeParser> mpe_parser;  // MPE section parser (created if MPE detected)

    // ETI-NA detection state
    int packet_count{0};         // Total packets seen on this PID
    int pusi_count{0};           // PUSI packets seen on this PID
    bool etina_candidate{false}; // True if no PUSI after threshold
    bool etina_checked{false};   // True if ETI-NA detection has been attempted
    std::unique_ptr<EtinaPipelineState> etina_pipeline;  // Modular ETI-NA pipeline

    // ETI-NA streaming state (after detection, parse FIC for ensemble discovery)
    bool etina_streaming{false};  // True when pipeline confirmed and streaming ETI-NI
    bool etina_detection_reported{false};  // True when detection info has been recorded
    std::unique_ptr<lsdvb::DABParser> etina_fic_parser;  // FIC parser for ensemble discovery
};

struct TsScanner::Impl {
    // Hybrid PID tracking: static array for O(1) lookup
    std::array<PidState, 8192> pids;

    // List of PIDs that are confirmed MPE
    std::vector<uint16_t> mpe_pids;

    // ETI-NA detection results
    std::vector<EtiNaDetectionInfo> etina_results;
    static constexpr int ETINA_PACKET_THRESHOLD = 100;  // Check for no-PUSI after this many packets

    // ETI-NA ensemble results (by PID)
    std::map<uint16_t, DiscoveredEnsemble> etina_ensembles;
    std::vector<uint16_t> etina_streaming_pids;  // PIDs currently streaming ETI-NA

    // Early exit tracking
    size_t total_packets{0};
    static constexpr unsigned int EARLY_EXIT_MS = 1000;  // Exit early after 1 second if no DAB found

    // Shared destination management
    UdpExtractor udp_extractor;
    EnsembleManager ensemble_manager;

    // Track which PID each stream (IP:port) came from
    std::map<StreamKey, uint16_t> stream_pid_map;
    uint16_t current_pid{0};  // PID currently being processed (for UDP callback)

    // Results storage - map by stream key for updates
    std::map<StreamKey, DiscoveredEnsemble> results_map;
    std::vector<DiscoveredEnsemble> results;  // Built from map on getResults()

    // Timing
    std::chrono::steady_clock::time_point start_time;
    unsigned int timeout_ms{500};
    bool started{false};
    bool done{false};

    // Partial TS packet buffer
    std::vector<uint8_t> partial_ts;

    // Helper to convert MPE ensemble to DiscoveredEnsemble
    DiscoveredEnsemble toDiscovered(const StreamKey& key, const lsdvb::DABEnsemble& ens) {
        DiscoveredEnsemble de;
        de.ip = key.ip;
        de.port = key.port;
        de.eid = ens.eid;
        de.label = ens.label;

        // Look up which PID this stream came from
        auto pid_it = stream_pid_map.find(key);
        if (pid_it != stream_pid_map.end()) {
            de.pid = pid_it->second;
        }

        for (const auto& svc : ens.services) {
            DiscoveredService ds;
            ds.sid = svc.sid;
            ds.label = svc.label;
            ds.bitrate = svc.bitrate;
            ds.subchannel_id = static_cast<uint8_t>(svc.subchannel_id);
            ds.dabplus = svc.dabplus;
            de.services.push_back(ds);
        }
        return de;
    }

    // Helper to convert ETI-NA ensemble to DiscoveredEnsemble
    DiscoveredEnsemble toDiscoveredEtina(uint16_t pid, const lsdvb::DABEnsemble& ens,
                                          const EtiNaDetectionInfo& info) {
        DiscoveredEnsemble de;
        de.ip = 0;  // No IP for ETI-NA
        de.port = 0;
        de.pid = pid;
        de.eid = ens.eid;
        de.label = ens.label;
        de.is_etina = true;
        de.etina_info.padding_bytes = info.padding_bytes;
        de.etina_info.sync_bit_offset = info.sync_bit_offset;
        de.etina_info.inverted = info.inverted;

        for (const auto& svc : ens.services) {
            DiscoveredService ds;
            ds.sid = svc.sid;
            ds.label = svc.label;
            ds.bitrate = svc.bitrate;
            ds.subchannel_id = static_cast<uint8_t>(svc.subchannel_id);
            ds.dabplus = svc.dabplus;
            de.services.push_back(ds);
        }
        return de;
    }

    Impl()
        : udp_extractor([this](uint32_t ip, uint16_t port, const uint8_t* payload, size_t len) {
              onUdp(ip, port, payload, len);
          })
    {
        partial_ts.reserve(TS_PACKET_SIZE);

        // Set up basic_ready callback - store partial results immediately
        ensemble_manager.setBasicReadyCallback([this](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
            results_map[key] = toDiscovered(key, ens);
        });

        // Set up complete callback - update with full labels
        ensemble_manager.setCompleteCallback([this](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
            results_map[key] = toDiscovered(key, ens);
        });
    }

    void onUdp(uint32_t ip, uint16_t port, const uint8_t* payload, size_t len) {
        // Check for multicast IP (224.x.x.x - 239.x.x.x)
        uint8_t first_octet = (ip >> 24) & 0xFF;
        if (first_octet >= 224 && first_octet <= 239) {
            // Record which PID this stream came from
            StreamKey key{ip, port};
            if (stream_pid_map.find(key) == stream_pid_map.end()) {
                stream_pid_map[key] = current_pid;
            }
            ensemble_manager.processUdp(ip, port, payload, len);
        }
    }

    void onIpPacket(uint16_t pid, const uint8_t* ip_data, size_t len) {
        current_pid = pid;  // Track which PID this IP packet came from
        udp_extractor.process(ip_data, len);
    }

    void processTsPacket(const uint8_t* ts) {
        // Verify sync byte
        if (ts[0] != 0x47) {
            return;
        }

        // Count valid packets for early exit
        total_packets++;

        // Extract header fields
        bool tei = (ts[1] >> 7) & 1;      // Transport Error Indicator
        bool pusi = (ts[1] >> 6) & 1;     // Payload Unit Start Indicator
        uint16_t pid = ((ts[1] & 0x1F) << 8) | ts[2];
        uint8_t adapt_ctrl = (ts[3] >> 4) & 3;
        uint8_t cc = ts[3] & 0x0F;

        // Skip packets with errors or null PID
        if (tei || pid == 0x1FFF) {
            return;
        }

        // Get PID state
        PidState& state = pids[pid];

        // Initialize on first packet
        if (!state.active) {
            state.active = true;
            state.last_cc = cc;
        }

        // Check continuity
        if (state.last_cc != 0xFF) {
            uint8_t expected = (state.last_cc + 1) & 0x0F;
            if (cc != expected && adapt_ctrl != 0 && adapt_ctrl != 2) {
                // CC discontinuity - reset MPE parser if exists
                if (state.mpe_parser) {
                    state.mpe_parser->reset();
                }
            }
        }
        state.last_cc = cc;

        // Determine payload start
        size_t payload_start = TS_HEADER_SIZE;
        if (adapt_ctrl == 2) {
            // Adaptation field only, no payload
            return;
        } else if (adapt_ctrl == 3) {
            // Adaptation field + payload
            if (4 >= TS_PACKET_SIZE) return;
            uint8_t adapt_len = ts[4];
            payload_start = 5 + adapt_len;
            if (payload_start >= TS_PACKET_SIZE) {
                return;  // No payload
            }
        }
        // adapt_ctrl == 1 or 0: Payload only (payload_start = 4)

        size_t payload_len = TS_PACKET_SIZE - payload_start;
        const uint8_t* payload = ts + payload_start;

        // MPE detection: check first PUSI packet for table_id 0x3E
        if (!state.checked && pusi && payload_len > 1) {
            state.checked = true;

            // First byte after PUSI is pointer_field
            uint8_t pointer = payload[0];
            if (pointer < payload_len - 1) {
                // Check table_id at pointer position
                uint8_t table_id = payload[1 + pointer];
                if (table_id == 0x3E) {
                    state.is_mpe = true;
                    mpe_pids.push_back(pid);

                    // Create MPE parser for this PID
                    state.mpe_parser = std::make_unique<MpeParser>(
                        [this, pid](const uint8_t* ip_data, size_t len) {
                            onIpPacket(pid, ip_data, len);
                        }
                    );
                }
            }
        }

        // Feed to MPE parser if this PID is MPE
        if (state.is_mpe && state.mpe_parser) {
            state.mpe_parser->feedTsPayload(payload, payload_len, pusi);
        }

        // Track packet/PUSI counts for ETI-NA detection
        state.packet_count++;
        if (pusi) {
            state.pusi_count++;
        }

        // ETI-NA detection: check PIDs with no PUSI after threshold
        if (!state.etina_checked && !state.is_mpe &&
            state.packet_count >= ETINA_PACKET_THRESHOLD) {

            if (state.pusi_count == 0) {
                // No PUSI at all - candidate for ETI-NA
                state.etina_candidate = true;
                state.etina_pipeline = std::make_unique<EtinaPipelineState>();
                state.etina_fic_parser = std::make_unique<lsdvb::DABParser>();
            }
            state.etina_checked = true;
        }

        // Feed to ETI-NA pipeline if this is a candidate or streaming
        if ((state.etina_candidate || state.etina_streaming) && state.etina_pipeline) {
            etina_feed_payload(*state.etina_pipeline, payload, payload_len,
                [this, &state, pid](const uint8_t* eti_ni, size_t len) {
                    // Got an ETI frame - pipeline is working
                    if (!state.etina_streaming) {
                        // First ETI frame - transition to streaming
                        state.etina_streaming = true;
                        state.etina_candidate = false;
                        etina_streaming_pids.push_back(pid);
                    }

                    // Record detection info once
                    if (!state.etina_detection_reported) {
                        state.etina_detection_reported = true;
                        EtiNaDetectionInfo info;
                        info.pid = pid;
                        info.padding_bytes = state.etina_pipeline->offset.detected_offset;
                        info.sync_bit_offset = state.etina_pipeline->e1.bit_offset;
                        info.inverted = state.etina_pipeline->e1.inverted;
                        etina_results.push_back(info);
                    }

                    // Feed to FIC parser
                    if (state.etina_fic_parser) {
                        state.etina_fic_parser->process_eti_frame(eti_ni, len);

                        // Check if FIC parser has all labels (full discovery complete)
                        if (state.etina_fic_parser->is_complete()) {
                            const auto& ens = state.etina_fic_parser->get_ensemble();
                            EtiNaDetectionInfo det;
                            det.pid = pid;
                            det.padding_bytes = state.etina_pipeline->offset.detected_offset;
                            det.sync_bit_offset = state.etina_pipeline->e1.bit_offset;
                            det.inverted = state.etina_pipeline->e1.inverted;
                            etina_ensembles[pid] = toDiscoveredEtina(pid, ens, det);
                        }
                    }
                });

            // Check for failed detection (too much data without sync)
            if (state.etina_candidate && !state.etina_streaming &&
                state.etina_pipeline->e1.buffer.size() > 16384) {
                // Too much data without producing ETI - not ETI-NA
                state.etina_candidate = false;
                state.etina_pipeline.reset();
                state.etina_fic_parser.reset();
            }
        }
    }

    int feed(const uint8_t* data, size_t len) {
        if (done) {
            return 1;
        }

        // Start timing on first feed
        if (!started) {
            started = true;
            start_time = std::chrono::steady_clock::now();
        }

        size_t pos = 0;

        // Handle partial TS packet from previous feed
        if (!partial_ts.empty()) {
            size_t needed = TS_PACKET_SIZE - partial_ts.size();
            if (len < needed) {
                partial_ts.insert(partial_ts.end(), data, data + len);
                return 0;
            }

            partial_ts.insert(partial_ts.end(), data, data + needed);
            pos = needed;
            processTsPacket(partial_ts.data());
            partial_ts.clear();
        }

        // Process complete TS packets
        while (pos + TS_PACKET_SIZE <= len) {
            processTsPacket(data + pos);
            pos += TS_PACKET_SIZE;
        }

        // Save remaining partial TS packet
        if (pos < len) {
            partial_ts.assign(data + pos, data + len);
        }

        // Check timeout
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        if (static_cast<unsigned int>(elapsed_ms) >= timeout_ms) {
            done = true;
            return 1;
        }

        // Check if all discovered MPE ensembles are complete (all labels received)
        size_t mpe_complete_count = ensemble_manager.getCompleteCount();
        size_t mpe_basic_count = results_map.size();
        bool mpe_complete = (mpe_basic_count == 0) ||
                           (mpe_complete_count > 0 && mpe_complete_count >= mpe_basic_count);

        // Check if all discovered ETI-NA ensembles are complete
        size_t etina_streaming_count = etina_streaming_pids.size();
        size_t etina_complete_count = etina_ensembles.size();
        bool etina_complete = (etina_streaming_count == 0) ||
                             (etina_complete_count >= etina_streaming_count);

        // If we have any DAB content and all are complete, we're done
        bool has_content = (mpe_basic_count > 0) || (etina_streaming_count > 0);
        if (has_content && mpe_complete && etina_complete) {
            done = true;
            return 1;
        }

        // Early exit if no DAB found after 1 second
        // This avoids waiting for full timeout on streams with no DAB traffic
        if (static_cast<unsigned int>(elapsed_ms) >= EARLY_EXIT_MS &&
            mpe_pids.empty() &&
            etina_streaming_pids.empty() &&
            results_map.empty()) {
            // No MPE sections, no ETI-NA, no ensembles after 1 second - no DAB here
            done = true;
            return 1;
        }

        return 0;
    }
};

TsScanner::TsScanner()
    : impl_(std::make_unique<Impl>())
{
}

TsScanner::~TsScanner() = default;

void TsScanner::setTimeout(unsigned int timeout_ms) {
    impl_->timeout_ms = timeout_ms;
}

int TsScanner::feed(const uint8_t* data, size_t len) {
    return impl_->feed(data, len);
}

std::vector<DiscoveredEnsemble> TsScanner::getResults() {
    // Build results from MPE ensembles
    std::vector<DiscoveredEnsemble> results;
    results.reserve(impl_->results_map.size() + impl_->etina_ensembles.size());
    for (const auto& [key, ens] : impl_->results_map) {
        results.push_back(ens);
    }
    // Add ETI-NA ensembles
    for (const auto& [pid, ens] : impl_->etina_ensembles) {
        results.push_back(ens);
    }
    return results;
}

bool TsScanner::isDone() const {
    return impl_->done;
}

bool TsScanner::hadTraffic() const {
    return impl_->total_packets > 0;
}

std::vector<uint16_t> TsScanner::getMpePids() const {
    return impl_->mpe_pids;
}

std::vector<EtiNaDetectionInfo> TsScanner::getEtiNaResults() const {
    return impl_->etina_results;
}

// File-based scanning
std::vector<DiscoveredEnsemble> scanTsFile(
    const std::string& file_path,
    unsigned int timeout_ms)
{
    TsScanner scanner;
    scanner.setTimeout(timeout_ms);

    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        return {};
    }

    std::vector<uint8_t> buffer(65536);

    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount()) {
        size_t bytes_read = file.gcount();
        if (scanner.feed(buffer.data(), bytes_read) != 0) {
            break;
        }
    }

    return scanner.getResults();
}

} // namespace dvbdab
