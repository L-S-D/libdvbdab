#pragma once

#include <dvbdab/dvbdab.hpp>
#include "dab_stream_parser.h"
#include <map>
#include <memory>
#include <functional>

namespace dvbdab {

// Callback when basic service info is ready (can start audio before labels)
using EnsembleBasicReadyCallback = std::function<void(const StreamKey& key, const DABEnsemble& ensemble)>;

// Callback when an ensemble is complete (all services have labels)
using EnsembleCompleteCallback = std::function<void(const StreamKey& key, const DABEnsemble& ensemble)>;

// Callback for an ensemble that changed after it was "basic ready": a service
// added or gone, on another subchannel, with another codec, bitrate or label,
// another ensemble label. Called once the change has settled (the FIGs of a
// new configuration come one after the other).
using EnsembleChangedCallback = std::function<void(const StreamKey& key, const DABEnsemble& ensemble)>;

// Callback for ETI frames (optional, for output)
// dflc = Data Flow Counter (0-7999) for continuity checking
using EtiFrameCallback = std::function<void(const StreamKey& key, const uint8_t* data, size_t len, uint16_t dflc)>;

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

    // Set callback for changes of an ensemble after it was basic ready
    void setChangedCallback(EnsembleChangedCallback callback) {
        changed_callback_ = std::move(callback);
    }

    // Set callback for ETI frames (optional)
    void setEtiCallback(EtiFrameCallback callback) {
        eti_callback_ = std::move(callback);
    }

    // Set callback for ETI frames, also those from EDI packets with lost
    // fragments (see EtiFrameExCallback; optional)
    void setEtiExCallback(EtiFrameExCallback callback) {
        eti_ex_callback_ = std::move(callback);
    }


    // Process a UDP packet (dst_ip, dst_port, payload)
    // Routes to the appropriate per-stream parser
    void processUdp(uint32_t dst_ip, uint16_t dst_port, const uint8_t* payload, size_t len);

    // Process a raw IPv4 packet (extracts UDP and routes)
    void processIpPacket(const uint8_t* ip_data, size_t len);

    // Process a raw ETI-NI frame directly (for ETI-NA and TS NI, where we
    // already have ETI frames). Returns what checkEtiFrame() says of it:
    // 0 taken, 1 dropped (header wrong), 2 its subchannels lost (data wrong).
    int processEtiFrame(uint16_t pid, const uint8_t* eti_ni, size_t len);

    // Frames checked, and how many had a wrong header or wrong data
    size_t getEtiFramesChecked() const { return eti_checked_; }
    size_t getEtiBadHeaders() const { return eti_bad_header_; }
    size_t getEtiBadData() const { return eti_bad_data_; }

    // Get all complete ensembles
    const std::map<StreamKey, DABEnsemble>& getEnsembles() const { return ensembles_; }

    // Get all ensembles (complete or not) - the discovered streams whose FIC
    // gave an ensemble id; other UDP streams (no DAB) are not in it
    std::map<StreamKey, DABEnsemble> getAllEnsembles() const;

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

    // An ETI(NI) frame by its CRCs: 0 right, 1 header wrong, 2 data wrong
    static int checkEtiFrame(const uint8_t* frame, size_t len);

private:
    // Get or create parser for a stream
    DABStreamParser& getParser(const StreamKey& key);

    static constexpr size_t MAX_STREAMS = 64;   // EDI streams (ensembles) at a time
    size_t eti_checked_ = 0, eti_bad_header_ = 0, eti_bad_data_ = 0;
    std::map<StreamKey, std::unique_ptr<DABStreamParser>> parsers_;
    std::map<StreamKey, DABEnsemble> ensembles_;
    std::map<StreamKey, bool> basic_ready_flags_;
    std::map<StreamKey, bool> complete_flags_;

    EnsembleBasicReadyCallback basic_ready_callback_;
    EnsembleCompleteCallback complete_callback_;
    EnsembleChangedCallback changed_callback_;

    // per stream: the revision of the ensemble that was reported, the one
    // seen last and for how many frames it has been that
    struct Reported {
        uint32_t revision = 0;
        uint32_t seen = 0;
        int64_t since = 0;    // the frame `seen` was first seen at
        int64_t frames = 0;   // frame count of streams that come as ETI frames
    };
    std::map<StreamKey, Reported> reported_;
    static constexpr int64_t CHANGE_SETTLE_FRAMES = 12;
    void noteRevision(const StreamKey& key, uint32_t revision, const DABEnsemble& ensemble, int64_t frame,
                      bool report_now);
    EtiFrameCallback eti_callback_;
    EtiFrameExCallback eti_ex_callback_;


    // ETI-NA parsers (keyed by PID) - for direct ETI-NI frame processing
    std::map<uint16_t, std::unique_ptr<DABParser>> etina_parsers_;

    size_t complete_count_{0};
};

} // namespace dvbdab
