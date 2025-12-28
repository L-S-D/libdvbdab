#pragma once

#include <dvbdab/dvbdab.hpp>
#include "../src/dab_parser.h"
#include <map>
#include <memory>
#include <functional>

namespace dvbdab {

// Callback when basic service info is ready (can start audio before labels)
using EnsembleBasicReadyCallback = std::function<void(const StreamKey& key, const lsdvb::DABEnsemble& ensemble)>;

// Callback when an ensemble is complete (all services have labels)
using EnsembleCompleteCallback = std::function<void(const StreamKey& key, const lsdvb::DABEnsemble& ensemble)>;

// Callback for ETI frames (optional, for output)
// dflc = Data Flow Counter (0-7999) for continuity checking
using EtiFrameCallback = std::function<void(const StreamKey& key, const uint8_t* data, size_t len, uint16_t dflc)>;

// Subchannel change info for dynamic PMT updates
struct SubchannelChange {
    uint32_t sid;              // Service ID that changed
    uint8_t old_subchannel_id; // Previous subchannel (0xFF if new service)
    uint8_t new_subchannel_id; // New subchannel (0xFF if service removed)
};

// Callback for subchannel mapping changes (for dynamic PMT updates)
using SubchannelChangeCallback = std::function<void(const StreamKey& key, const std::vector<SubchannelChange>& changes)>;

// Manages multiple DAB ensembles, routing UDP packets by destination ip:port
class EnsembleManager {
public:
    EnsembleManager();

    // Set callback for when basic service info is ready (for early audio start)
    void setBasicReadyCallback(EnsembleBasicReadyCallback callback) {
        basic_ready_callback_ = std::move(callback);
    }

    // Set callback for when an ensemble is complete (all labels available)
    void setCompleteCallback(EnsembleCompleteCallback callback) {
        complete_callback_ = std::move(callback);
    }

    // Set callback for ETI frames (optional)
    void setEtiCallback(EtiFrameCallback callback) {
        eti_callback_ = std::move(callback);
    }

    // Set callback for subchannel mapping changes (for dynamic PMT updates)
    void setSubchannelChangeCallback(SubchannelChangeCallback callback) {
        subchannel_change_callback_ = std::move(callback);
    }

    // Process a UDP packet (dst_ip, dst_port, payload)
    // Routes to the appropriate per-stream parser
    void processUdp(uint32_t dst_ip, uint16_t dst_port, const uint8_t* payload, size_t len);

    // Process a raw IPv4 packet (extracts UDP and routes)
    void processIpPacket(const uint8_t* ip_data, size_t len);

    // Process a raw ETI-NI frame directly (for ETI-NA where we already have ETI frames)
    void processEtiFrame(uint16_t pid, const uint8_t* eti_ni, size_t len);

    // Get all complete ensembles
    const std::map<StreamKey, lsdvb::DABEnsemble>& getEnsembles() const { return ensembles_; }

    // Get all ensembles (complete or not) - for iterating all discovered streams
    std::map<StreamKey, lsdvb::DABEnsemble> getAllEnsembles() const;

    // Check if a specific stream is complete
    bool isComplete(const StreamKey& key) const;

    // Check if all discovered streams are complete
    bool allComplete() const;

    // Get count of complete ensembles
    size_t getCompleteCount() const { return complete_count_; }

    // Get count of total streams seen
    size_t getStreamCount() const { return parsers_.size(); }

    // Reset all state
    void reset();

private:
    // Get or create parser for a stream
    lsdvb::DABStreamParser& getParser(const StreamKey& key);

    std::map<StreamKey, std::unique_ptr<lsdvb::DABStreamParser>> parsers_;
    std::map<StreamKey, lsdvb::DABEnsemble> ensembles_;
    std::map<StreamKey, bool> basic_ready_flags_;
    std::map<StreamKey, bool> complete_flags_;

    EnsembleBasicReadyCallback basic_ready_callback_;
    EnsembleCompleteCallback complete_callback_;
    EtiFrameCallback eti_callback_;
    SubchannelChangeCallback subchannel_change_callback_;

    // Track previous subchannel mappings for change detection
    std::map<StreamKey, std::map<uint32_t, uint8_t>> last_subchannel_map_;  // key -> (sid -> subchannel_id)

    // ETI-NA parsers (keyed by PID) - for direct ETI-NI frame processing
    std::map<uint16_t, std::unique_ptr<lsdvb::DABParser>> etina_parsers_;

    size_t complete_count_{0};
};

} // namespace dvbdab
