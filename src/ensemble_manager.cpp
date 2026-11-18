#include "ensemble_manager.hpp"
#include "parsers/udp_extractor.hpp"
#include "utils/crc_utils.hpp"
#include "logging.h"
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
    reported_.clear();
    complete_count_ = 0;
}

// The ensemble of a stream after it was reported as basic ready: a revision
// that has stayed the same for a few frames and is not the one reported goes
// to the changed callback. report_now: this state was just reported.
void EnsembleManager::noteRevision(const StreamKey& key, uint32_t revision, const DABEnsemble& ensemble,
                                   int64_t frame, bool report_now) {
    Reported& r = reported_[key];
    if (report_now) {
        r.revision = r.seen = revision;
        r.since = frame;
        return;
    }
    if (revision != r.seen) {
        r.seen = revision;
        r.since = frame;
        return;
    }
    if (revision == r.revision || frame - r.since < CHANGE_SETTLE_FRAMES) return;
    r.revision = revision;
    ensembles_[key] = ensemble;
    if (changed_callback_) changed_callback_(key, ensemble);
}

DABStreamParser& EnsembleManager::getParser(const StreamKey& key) {
    auto it = parsers_.find(key);
    if (it != parsers_.end()) {
        return *it->second;
    }

    // Create new parser for this stream
    // Use dummy PID (0) since we're feeding EDI directly
    // IP is already in MSB-first format (same as extracted from packets)
    auto parser = std::make_unique<DABStreamParser>(key.ip, key.port);

    // Wire up ETI callback to forward frames to our callback
    parser->setEtiCallback([this](const StreamKey& key, const uint8_t* data, size_t len, uint16_t dflc) {
        if (eti_callback_) {
            eti_callback_(key, data, len, dflc);
        }
    });
    parser->setEtiExCallback([this](const StreamKey& key, const uint8_t* data, size_t len,
                                    uint16_t dflc, uint64_t invalid_scids) {
        if (eti_ex_callback_) {
            eti_ex_callback_(key, data, len, dflc, invalid_scids);
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

    // A destination gets a parser when it sends what starts like EDI ("AF" or
    // "PF"), and only so many do: without a filter every UDP stream of a
    // transponder comes here
    if (!parsers_.count(key)) {
        bool edi = len >= 10 && (payload[0] == 'A' || payload[0] == 'P') && payload[1] == 'F';
        if (!edi || parsers_.size() >= MAX_STREAMS) {
            return;
        }
    }

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
        noteRevision(key, parser.ensemble_revision(), parser.get_ensemble(), parser.eti_frame_count(), true);
    } else if (basic_ready_flags_[key]) {
        noteRevision(key, parser.ensemble_revision(), parser.get_ensemble(), parser.eti_frame_count(), false);
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

    // A damaged header: its destination is not the stream's
    if (!ipv4HeaderChecksumOk(ip_data, static_cast<size_t>(ip_hdr_len))) return;

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

std::map<StreamKey, DABEnsemble> EnsembleManager::getAllEnsembles() const {
    std::map<StreamKey, DABEnsemble> result;
    for (const auto& [key, parser] : parsers_) {
        // a parser is made for every UDP destination seen: only the ones
        // whose FIC gave an ensemble id carry DAB (not some other data, and
        // not a destination from a damaged header)
        const DABEnsemble& ens = parser->get_ensemble();
        if (ens.eid != 0)
            result[key] = ens;
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

// An ETI(NI) frame by its two CRCs (EN 300 799): 0 = right; 1 = the header
// (frame characterization and stream characterization, up to the EOH CRC) is
// damaged or says lengths the frame cannot have; 2 = the header is right, the
// data (FIC and streams, up to the EOF CRC) is damaged
int EnsembleManager::checkEtiFrame(const uint8_t* f, size_t len) {
    if (len < 12) return 1;
    size_t nst = f[5] & 0x7F;
    size_t fl = static_cast<size_t>((f[6] & 0x07) << 8 | f[7]);  // in words: STC, EOH, MST
    size_t eoh = 8 + nst * 4;                                      // MNSC, then the header CRC
    if (eoh + 4 > len || fl < nst + 1) return 1;
    if (CHECKSUMS_CHECKED && crc16_ccitt_xor(f + 4, eoh + 2 - 4) != static_cast<uint16_t>(f[eoh + 2] << 8 | f[eoh + 3])) return 1;
    size_t mst = eoh + 4, mst_len = (fl - nst - 1) * 4;
    if (mst + mst_len + 2 > len) return 1;
    if (CHECKSUMS_CHECKED && crc16_ccitt_xor(f + mst, mst_len) != static_cast<uint16_t>(f[mst + mst_len] << 8 | f[mst + mst_len + 1])) return 2;
    return 0;
}

int EnsembleManager::processEtiFrame(uint16_t pid, const uint8_t* eti_ni, size_t len) {
    // Use PID as key (ip=pid, port=0) for ETI-NA streams
    StreamKey key{static_cast<uint32_t>(pid), 0};

    // A frame that came through ETI-NA or TS NI is what the TS packets
    // made of it: with a packet lost it is too short, two frames in one, or
    // out of step. Its CRCs say so. With a wrong header nothing in it can
    // be trusted: dropped. With a right header and wrong data its
    // subchannels count as lost in this frame (the decoders keep their time
    // line), and its FIC is not read.
    int check = checkEtiFrame(eti_ni, len);
    eti_checked_++;
    if (check == 1) {
        eti_bad_header_++;
        return check;
    }
    if (check == 2) {
        eti_bad_data_++;
        if (eti_ex_callback_ && basic_ready_flags_[key]) {
            eti_ex_callback_(key, eti_ni, len, 0, ~uint64_t(0));
        }
        return check;
    }

    // Get or create FIC parser for this PID
    auto it = etina_parsers_.find(pid);
    if (it == etina_parsers_.end()) {
        etina_parsers_[pid] = std::make_unique<DABParser>();
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
        noteRevision(key, parser.revision(), parser.get_ensemble(), ++reported_[key].frames, true);
    } else if (basic_ready_flags_[key]) {
        noteRevision(key, parser.revision(), parser.get_ensemble(), ++reported_[key].frames, false);
    }

    // THEN fire ETI callback (muxer_initialized will be true on the frame basic_ready becomes true)
    if (eti_callback_) {
        eti_callback_(key, eti_ni, len, 0);
    }
    if (eti_ex_callback_) {
        eti_ex_callback_(key, eti_ni, len, 0, 0);
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
    return 0;
}

} // namespace dvbdab
