#include "ensemble_manager.hpp"
#include <arpa/inet.h>

namespace dvbdab {

EnsembleManager::EnsembleManager() = default;

void EnsembleManager::reset() {
    parsers_.clear();
    etina_parsers_.clear();
    ensembles_.clear();
    basic_ready_flags_.clear();
    complete_flags_.clear();
    last_subchannel_map_.clear();
    complete_count_ = 0;
}

lsdvb::DABStreamParser& EnsembleManager::getParser(const StreamKey& key) {
    auto it = parsers_.find(key);
    if (it != parsers_.end()) {
        return *it->second;
    }

    // Create new parser for this stream
    // Use dummy PID (0) since we're feeding EDI directly
    // IP is already in MSB-first format (same as extracted from packets)
    auto parser = std::make_unique<lsdvb::DABStreamParser>(0, key.ip, key.port);

    // Wire up ETI callback to forward frames to our callback
    parser->setEtiCallback([this, key](const uint8_t* data, size_t len, uint16_t dflc) {
        if (eti_callback_) {
            eti_callback_(key, data, len, dflc);
        }
    });

    auto& ref = *parser;
    parsers_[key] = std::move(parser);
    basic_ready_flags_[key] = false;
    complete_flags_[key] = false;

    return ref;
}

void EnsembleManager::processUdp(uint32_t dst_ip, uint16_t dst_port, const uint8_t* payload, size_t len) {
    StreamKey key{dst_ip, dst_port};

    auto& parser = getParser(key);

    // Feed EDI packet directly (payload is PF or AF)
    bool complete = parser.process_edi_packet(payload, len);

    // Check for basic ready (can start audio before labels)
    if (parser.is_basic_ready() && !basic_ready_flags_[key]) {
        basic_ready_flags_[key] = true;

        // Notify basic ready callback (for early audio start)
        if (basic_ready_callback_) {
            basic_ready_callback_(key, parser.get_ensemble());
        }
    }

    // Check for full completion (all labels available)
    if (complete && !complete_flags_[key]) {
        complete_flags_[key] = true;
        complete_count_++;

        // Store ensemble
        ensembles_[key] = parser.get_ensemble();

        // Initialize subchannel tracking
        auto& subch_map = last_subchannel_map_[key];
        for (const auto& svc : ensembles_[key].services) {
            subch_map[svc.sid] = static_cast<uint8_t>(svc.subchannel_id);
        }

        // Notify complete callback (for SDT update with labels)
        if (complete_callback_) {
            complete_callback_(key, ensembles_[key]);
        }
    }

    // After completion, continuously monitor for subchannel changes
    if (complete_flags_[key] && subchannel_change_callback_) {
        const auto& current_ensemble = parser.get_ensemble();
        auto& prev_map = last_subchannel_map_[key];
        std::vector<SubchannelChange> changes;

        // Build current mapping
        std::map<uint32_t, uint8_t> current_map;
        for (const auto& svc : current_ensemble.services) {
            current_map[svc.sid] = static_cast<uint8_t>(svc.subchannel_id);
        }

        // Check for changes: new services or subchannel changes
        for (const auto& [sid, new_subch] : current_map) {
            auto prev_it = prev_map.find(sid);
            if (prev_it == prev_map.end()) {
                // New service
                changes.push_back({sid, 0xFF, new_subch});
            } else if (prev_it->second != new_subch) {
                // Subchannel changed
                changes.push_back({sid, prev_it->second, new_subch});
            }
        }

        // Check for removed services
        for (const auto& [sid, old_subch] : prev_map) {
            if (current_map.find(sid) == current_map.end()) {
                changes.push_back({sid, old_subch, 0xFF});
            }
        }

        // Notify if there are changes
        if (!changes.empty()) {
            prev_map = current_map;  // Update tracking
            subchannel_change_callback_(key, changes);
        }
    }
}

void EnsembleManager::processIpPacket(const uint8_t* ip_data, size_t len) {
    if (len < 28) return;  // Need at least IP + UDP header

    // Verify IPv4
    if ((ip_data[0] >> 4) != 4) return;

    // Get IP header length
    int ip_hdr_len = (ip_data[0] & 0x0F) * 4;
    if (ip_hdr_len < 20 || static_cast<size_t>(ip_hdr_len) > len) return;

    // Check protocol (17 = UDP)
    if (ip_data[9] != 17) return;

    // Extract destination IP (bytes 16-19)
    uint32_t dst_ip = (static_cast<uint32_t>(ip_data[16]) << 24) |
                      (static_cast<uint32_t>(ip_data[17]) << 16) |
                      (static_cast<uint32_t>(ip_data[18]) << 8) |
                      ip_data[19];

    // Extract UDP header
    if (len < static_cast<size_t>(ip_hdr_len) + 8) return;
    const uint8_t* udp = ip_data + ip_hdr_len;

    uint16_t dst_port = (static_cast<uint16_t>(udp[2]) << 8) | udp[3];
    uint16_t udp_len = (static_cast<uint16_t>(udp[4]) << 8) | udp[5];

    // Validate UDP length
    if (udp_len < 8 || udp_len > len - ip_hdr_len) return;

    // EDI payload starts after UDP header
    const uint8_t* payload = udp + 8;
    size_t payload_len = udp_len - 8;

    if (payload_len > 0) {
        processUdp(dst_ip, dst_port, payload, payload_len);
    }
}

std::map<StreamKey, lsdvb::DABEnsemble> EnsembleManager::getAllEnsembles() const {
    std::map<StreamKey, lsdvb::DABEnsemble> result;
    for (const auto& [key, parser] : parsers_) {
        result[key] = parser->get_ensemble();
    }
    return result;
}

bool EnsembleManager::isComplete(const StreamKey& key) const {
    auto it = complete_flags_.find(key);
    return it != complete_flags_.end() && it->second;
}

bool EnsembleManager::allComplete() const {
    if (parsers_.empty()) return false;

    for (const auto& [key, complete] : complete_flags_) {
        if (!complete) return false;
    }
    return true;
}

void EnsembleManager::processEtiFrame(uint16_t pid, const uint8_t* eti_ni, size_t len) {
    // Use PID as key (ip=pid, port=0) for ETI-NA streams
    StreamKey key{static_cast<uint32_t>(pid), 0};

    // Get or create FIC parser for this PID
    auto it = etina_parsers_.find(pid);
    if (it == etina_parsers_.end()) {
        etina_parsers_[pid] = std::make_unique<lsdvb::DABParser>();
        basic_ready_flags_[key] = false;
        complete_flags_[key] = false;
    }
    auto& parser = *etina_parsers_[pid];

    // Feed to FIC parser
    parser.process_eti_frame(eti_ni, len);

    // Check for basic ready FIRST - muxer must be initialized before audio processing
    if (parser.is_basic_ready() && !basic_ready_flags_[key]) {
        basic_ready_flags_[key] = true;
        if (basic_ready_callback_) {
            basic_ready_callback_(key, parser.get_ensemble());
        }
    }

    // THEN fire ETI callback (muxer_initialized will be true on the frame basic_ready becomes true)
    if (eti_callback_) {
        eti_callback_(key, eti_ni, len, 0);
    }

    // Check for complete
    if (parser.is_complete() && !complete_flags_[key]) {
        complete_flags_[key] = true;
        complete_count_++;
        ensembles_[key] = parser.get_ensemble();
        if (complete_callback_) {
            complete_callback_(key, ensembles_[key]);
        }
    }
}

} // namespace dvbdab
