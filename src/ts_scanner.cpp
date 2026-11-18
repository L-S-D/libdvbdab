// TS Scanner - Auto-detect DAB ensembles from raw transport stream

#include <dvbdab/ts_scanner.hpp>
#include "etina_pipeline.hpp"
#include "dab_parser.h"
#include "ensemble_manager.hpp"
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
    bool is_mpe{false};          // MPE (table_id 0x3E): no ETI-NA, no TSNI
    bool is_bbf{false};          // BBF (0xB8 sync byte): no ETI-NA

    // ETI-NA detection state
    int packet_count{0};         // Total packets seen on this PID
    int pusi_count{0};           // PUSI packets seen on this PID
    int bbf_sync_count{0};       // Count of 0xB8 sync bytes seen (BBF detection)
    bool etina_candidate{false}; // True if no PUSI after threshold
    bool etina_checked{false};   // True if ETI-NA detection has been attempted
    std::unique_ptr<EtinaPipelineState> etina_pipeline;  // Modular ETI-NA pipeline

    // ETI-NA streaming state (after detection, parse FIC for ensemble discovery)
    bool etina_streaming{false};  // True when pipeline confirmed and streaming ETI-NI
    bool etina_detection_reported{false};  // True when detection info has been recorded
    std::unique_ptr<DABParser> etina_fic_parser;  // FIC parser for ensemble discovery

    // TS NI V.11 detection state
    bool tsni_checked{false};     // Have we checked for TSNI pattern?
    bool is_tsni{false};          // Confirmed as TS NI V.11?
    uint8_t tsni_last_seq{0xFF};  // Last sequence byte (the incrementing "table_id")
    int tsni_seq_count{0};        // Count of sequential increments seen
    std::vector<uint8_t> tsni_buffer;  // Frame accumulation buffer
    bool tsni_streaming{false};   // True when TSNI confirmed and streaming ETI-NI
    bool tsni_detection_reported{false};
    std::unique_ptr<DABParser> tsni_fic_parser;
};

struct TsScanner::Impl {
    // Hybrid PID tracking: static array for O(1) lookup
    std::array<PidState, 8192> pids;

    // ETI-NA detection results
    std::vector<EtiNaDetectionInfo> etina_results;
    static constexpr int ETINA_PACKET_THRESHOLD = 100;  // Check for no-PUSI after this many packets

    // ETI-NA ensemble results (by PID)
    std::map<uint16_t, DiscoveredEnsemble> etina_ensembles;
    std::vector<uint16_t> etina_streaming_pids;  // PIDs currently streaming ETI-NA

    // TS NI V.11 ensemble results (by PID)
    std::map<uint16_t, DiscoveredEnsemble> tsni_ensembles;
    std::vector<uint16_t> tsni_streaming_pids;  // PIDs currently streaming TSNI
    static constexpr int TSNI_SEQ_THRESHOLD = 4;  // Require 4 sequential increments to confirm
    static constexpr size_t TSNI_FRAME_SIZE = 6140;  // ETI-NI frame size for TSNI

    // Early exit tracking
    size_t total_packets{0};
    static constexpr unsigned int EARLY_EXIT_MS = 1000;  // Exit early after 1 second if no DAB found

    // Timing
    std::chrono::steady_clock::time_point start_time;
    unsigned int timeout_ms{500};
    bool started{false};
    bool done{false};

    // Partial TS packet buffer
    std::vector<uint8_t> partial_ts;

    // Helper to convert ETI-NA ensemble to DiscoveredEnsemble
    DiscoveredEnsemble toDiscoveredEtina(uint16_t pid, const DABEnsemble& ens,
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

    // Helper to convert TS NI V.11 ensemble to DiscoveredEnsemble
    DiscoveredEnsemble toDiscoveredTsni(uint16_t pid, const DABEnsemble& ens) {
        DiscoveredEnsemble de;
        de.ip = 0;  // No IP for TSNI
        de.port = 0;
        de.pid = pid;
        de.eid = ens.eid;
        de.label = ens.label;
        de.is_tsni = true;  // Mark as TSNI format

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
    {
        partial_ts.reserve(TS_PACKET_SIZE);
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

        // Skip packets with errors or null PID
        if (tei || pid == 0x1FFF) {
            return;
        }

        // Get PID state
        PidState& state = pids[pid];

        state.active = true;

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

        // MPE: the first PUSI packet has table_id 0x3E. The library does not
        // take MPE apart (the caller does: DVBDAB_FORMAT_IPV4), such a PID
        // is just no ETI-NA or TSNI one.
        if (!state.checked && pusi && payload_len > 1) {
            state.checked = true;

            // First byte after PUSI is pointer_field
            uint8_t pointer = payload[0];
            if (pointer < payload_len - 1) {
                // Check table_id at pointer position
                uint8_t table_id = payload[1 + pointer];
                if (table_id == 0x3E) {
                    state.is_mpe = true;
                }
            }
        }

        // TS NI V.11 detection: check for incrementing sequence byte on PUSI packets
        // Format: pointer_field=0, then incrementing "table_id" as frame sequence
        // Skip for BBF PIDs (BBF has no PUSI anyway, but be explicit)
        if (!state.is_mpe && !state.is_bbf && !state.tsni_checked && pusi && payload_len > 1) {
            uint8_t pointer = payload[0];
            if (pointer == 0) {
                uint8_t seq_byte = payload[1];  // The "table_id" is actually frame sequence
                if (state.tsni_last_seq != 0xFF) {
                    // Check if sequence increments (with wraparound)
                    uint8_t expected = state.tsni_last_seq + 1;
                    if (seq_byte == expected) {
                        state.tsni_seq_count++;
                        if (state.tsni_seq_count >= TSNI_SEQ_THRESHOLD) {
                            // Confirmed as TSNI
                            state.is_tsni = true;
                            state.tsni_checked = true;
                            state.tsni_fic_parser = std::make_unique<DABParser>();
                            state.tsni_buffer.reserve(TSNI_FRAME_SIZE + 188);
                            tsni_streaming_pids.push_back(pid);
                        }
                    } else {
                        // Not sequential, reset count
                        state.tsni_seq_count = 0;
                    }
                }
                state.tsni_last_seq = seq_byte;
            }
        }

        // TS NI V.11 streaming: accumulate frames and parse
        if (state.is_tsni) {
            if (pusi && payload_len > 1) {
                // Frame boundary - output previous frame if we have data
                if (state.tsni_buffer.size() >= 4) {
                    // Prepend sync word based on first byte (even/odd)
                    uint8_t seq_byte = state.tsni_buffer[0];
                    std::vector<uint8_t> frame;
                    frame.reserve(TSNI_FRAME_SIZE);

                    // ETI-NI sync: ff 07 3a b6 (even) or ff f8 c5 49 (odd)
                    if (seq_byte % 2 == 0) {
                        frame.insert(frame.end(), {0xff, 0x07, 0x3a, 0xb6});
                    } else {
                        frame.insert(frame.end(), {0xff, 0xf8, 0xc5, 0x49});
                    }
                    // Include full buffer (seq byte is part of the ETI data)
                    frame.insert(frame.end(), state.tsni_buffer.begin(), state.tsni_buffer.end());

                    // Pad to frame size if needed
                    if (frame.size() < TSNI_FRAME_SIZE) {
                        frame.resize(TSNI_FRAME_SIZE, 0x55);
                    }

                    // Report detection once
                    if (!state.tsni_detection_reported) {
                        state.tsni_detection_reported = true;
                        state.tsni_streaming = true;
                    }

                    // Feed to FIC parser
                    if (state.tsni_fic_parser) {
                        // (only frames whose CRCs are right: see EnsembleManager::processEtiFrame)
                        if (EnsembleManager::checkEtiFrame(frame.data(), frame.size()) == 0)
                            state.tsni_fic_parser->process_eti_frame(frame.data(), frame.size());

                        if (state.tsni_fic_parser->is_complete()) {
                            const auto& ens = state.tsni_fic_parser->get_ensemble();
                            tsni_ensembles[pid] = toDiscoveredTsni(pid, ens);
                        }
                    }
                }

                // Start new frame - skip pointer_field (byte 0), include seq byte and rest
                state.tsni_buffer.clear();
                state.tsni_buffer.insert(state.tsni_buffer.end(),
                                         payload + 1, payload + payload_len);
            } else {
                // Continuation - append payload
                state.tsni_buffer.insert(state.tsni_buffer.end(),
                                         payload, payload + payload_len);
            }
        }

        // Track packet/PUSI counts for ETI-NA detection
        state.packet_count++;
        if (pusi) {
            state.pusi_count++;
        }

        // BBF detection: check for 0xB8 sync byte (BBF pseudo-TS). The library
        // does not take BBFrames apart (the caller does: DVBDAB_FORMAT_IPV4).
        // BBF also has no PUSI, but first payload byte is 0xB8 for frame start
        if (!state.is_bbf && !pusi && payload_len > 0 && payload[0] == 0xB8) {
            state.bbf_sync_count++;
            if (state.bbf_sync_count >= 3) {
                // Multiple 0xB8 sync bytes seen - this is BBF, not ETI-NA
                state.is_bbf = true;
            }
        }

        // ETI-NA detection: check PIDs after threshold
        // ETI-NA streams have no PUSI flags - skip if any PUSI or BBF detected
        if (!state.etina_checked && !state.is_mpe && !state.is_tsni && !state.is_bbf &&
            state.packet_count >= ETINA_PACKET_THRESHOLD &&
            state.pusi_count == 0) {

            // Try ETI-NA detection - will fail quickly if not ETI-NA format
            state.etina_candidate = true;
            state.etina_pipeline = std::make_unique<EtinaPipelineState>();
            state.etina_fic_parser = std::make_unique<DABParser>();
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
                        if (EnsembleManager::checkEtiFrame(eti_ni, len) == 0)
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

            // Check for failed detection (too much data without sync). The E1 buffer
            // itself never gets this large: without sync it drops 4 KB whenever more
            // than 8 KB are waiting, so the bytes fed without sync are counted instead.
            if (state.etina_candidate && !state.etina_streaming &&
                !state.etina_pipeline->e1.sync_found &&
                state.etina_pipeline->e1.unsynced_bytes > 16384) {
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

        // Check if all discovered ETI-NA ensembles are complete
        size_t etina_streaming_count = etina_streaming_pids.size();
        size_t etina_complete_count = etina_ensembles.size();
        bool etina_complete = (etina_streaming_count == 0) ||
                             (etina_complete_count >= etina_streaming_count);

        // Check if all discovered TSNI ensembles are complete
        size_t tsni_streaming_count = tsni_streaming_pids.size();
        size_t tsni_complete_count = tsni_ensembles.size();
        bool tsni_complete = (tsni_streaming_count == 0) ||
                            (tsni_complete_count >= tsni_streaming_count);

        // If we have any DAB content and all are complete, we're done
        bool has_content = (etina_streaming_count > 0) || (tsni_streaming_count > 0);
        if (has_content && etina_complete && tsni_complete) {
            done = true;
            return 1;
        }

        // Early exit if no DAB found after 1 second
        // This avoids waiting for full timeout on streams with no DAB traffic
        if (static_cast<unsigned int>(elapsed_ms) >= EARLY_EXIT_MS &&
            etina_streaming_pids.empty() &&
            tsni_streaming_pids.empty()) {
            // No ETI-NA, no TSNI after 1 second - no DAB here
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
    std::vector<DiscoveredEnsemble> results;
    results.reserve(impl_->etina_ensembles.size() + impl_->tsni_ensembles.size());
    // ETI-NA ensembles
    for (const auto& [pid, ens] : impl_->etina_ensembles) {
        results.push_back(ens);
    }
    // Add TSNI ensembles
    for (const auto& [pid, ens] : impl_->tsni_ensembles) {
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
