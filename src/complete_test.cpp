// Complete test: TS -> BBF -> UDP -> EDI -> ETI with completeness tracking
// Reads pseudo-TS from stdin, outputs service discovery stats

#include "bbf2udp.hpp"
#include "udp2edi.hpp"
#include <iostream>
#include <iomanip>
#include <map>
#include <set>
#include <algorithm>

// Per-stream completeness state
struct StreamState {
    std::size_t udp_packets{0};
    std::size_t eti_frames{0};

    // Labels
    std::string ensemble_label;
    std::uint16_t ensemble_id{0};
    std::map<std::uint16_t, std::string> service_labels;

    // Tracking
    std::size_t ensemble_found_at{0};
    std::size_t all_services_found_at{0};
    std::size_t last_service_count{0};

    bool is_complete() const {
        return !ensemble_label.empty() && !service_labels.empty() &&
               all_services_found_at > 0;
    }
};

std::string trimRight(const std::string& s) {
    auto end = s.find_last_not_of(' ');
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

std::string ipToString(std::uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

// Parse ETI frame for labels - returns true if new labels found
bool parseEtiForLabels(StreamState& state, const std::uint8_t* frame, std::size_t len) {
    if (len < 6144) return false;

    bool new_label = false;

    std::uint8_t ficf = (frame[5] >> 7) & 1;
    std::uint8_t nst = frame[5] & 0x7F;
    std::uint8_t mid = (frame[6] >> 3) & 0x03;

    if (!ficf) return false;

    std::size_t stc_end = 8 + nst * 4;
    std::size_t fic_offset = stc_end + 4;
    std::size_t fic_length = (mid == 3) ? 128 : 96;

    if (fic_offset + fic_length > 6144) return false;

    const std::uint8_t* fic = frame + fic_offset;
    int num_fibs = (mid == 3) ? 4 : 3;

    for (int fib_idx = 0; fib_idx < num_fibs; fib_idx++) {
        const std::uint8_t* fib_data = fic + fib_idx * 32;
        std::size_t pos = 0;

        while (pos < 30) {
            std::uint8_t type = fib_data[pos] >> 5;
            std::uint8_t length = fib_data[pos] & 0x1F;

            if (type == 7 && length == 31) break;
            if (length == 0 || pos + 1 + length > 30) break;

            std::uint8_t ext = fib_data[pos + 1] & 0x07;
            bool oe = (fib_data[pos + 1] >> 3) & 0x01;
            const std::uint8_t* fig_data = fib_data + pos + 2;
            std::size_t fig_len = length - 1;

            if (type == 1) {
                if (ext == 0 && !oe && fig_len >= 19) {
                    // FIG 1/0 - Ensemble label
                    if (state.ensemble_label.empty()) {
                        state.ensemble_id = (fig_data[0] << 8) | fig_data[1];
                        char label[17] = {0};
                        std::copy(fig_data + 2, fig_data + 18, label);
                        state.ensemble_label = trimRight(std::string(label, 16));
                        state.ensemble_found_at = state.eti_frames;
                        new_label = true;
                    }
                }
                else if (ext == 1 && !oe && fig_len >= 19) {
                    // FIG 1/1 - Service label
                    std::uint16_t sid = (fig_data[0] << 8) | fig_data[1];
                    if (state.service_labels.find(sid) == state.service_labels.end()) {
                        char label[17] = {0};
                        std::copy(fig_data + 2, fig_data + 18, label);
                        state.service_labels[sid] = trimRight(std::string(label, 16));
                        new_label = true;
                    }
                }
            }

            pos += 1 + length;
        }
    }

    // Check if service count stabilized (no new services for 10 frames)
    if (state.all_services_found_at == 0 && !state.service_labels.empty()) {
        if (state.service_labels.size() == state.last_service_count) {
            // Same count as last time - mark complete
            state.all_services_found_at = state.eti_frames;
        }
        state.last_service_count = state.service_labels.size();
    }

    return new_label;
}

int main() {
    std::map<std::pair<std::uint32_t, std::uint16_t>, StreamState> streams;
    std::size_t total_ts_packets = 0;
    std::size_t total_udp = 0;
    std::size_t total_eti = 0;

    // Discovery phase tracking
    std::size_t discovery_packets = 0;
    std::size_t packets_since_new_stream = 0;
    bool discovery_closed = false;
    const std::size_t STABLE_THRESHOLD = 500;  // Close discovery after 500 packets with no new stream

    // Create UDP->EDI handler
    Udp2Edi udp_handler([&](std::uint32_t ip, std::uint16_t port,
                            const std::uint8_t* data, std::size_t len,
                            std::uint16_t /*dflc*/) {
        auto key = std::make_pair(ip, port);
        auto& state = streams[key];
        state.eti_frames++;
        total_eti++;

        parseEtiForLabels(state, data, len);
    });

    // Create BBF parser
    Bbf2Udp bbf_parser([&](std::uint32_t ip, std::uint16_t port,
                           const std::uint8_t* data, std::size_t len) {
        auto key = std::make_pair(ip, port);

        // Track discovery
        if (!discovery_closed) {
            if (streams.find(key) == streams.end()) {
                packets_since_new_stream = 0;
                std::cerr << "Discovered: " << ipToString(ip) << ":" << port
                          << " (total: " << (streams.size() + 1) << ")\n";
            } else {
                packets_since_new_stream++;
            }
            discovery_packets++;

            if (packets_since_new_stream >= STABLE_THRESHOLD) {
                discovery_closed = true;
                std::cerr << "Discovery closed with " << streams.size() << " streams\n";
            }
        }

        auto& state = streams[key];
        state.udp_packets++;
        total_udp++;

        udp_handler.feed(ip, port, data, len);
    });

    // Read TS packets from stdin
    std::array<std::uint8_t, 188> ts_packet;
    std::vector<std::uint8_t> bbf_buffer;
    bbf_buffer.reserve(8192);

    while (std::cin.read(reinterpret_cast<char*>(ts_packet.data()), 188)) {
        total_ts_packets++;

        // Extract PID
        std::uint16_t pid = ((ts_packet[1] & 0x1F) << 8) | ts_packet[2];
        if (pid != 0x010e) continue;  // NRK GSE PID

        // Get payload length and start indicator
        std::uint8_t payload_len = ts_packet[7];
        bool is_start = (ts_packet[8] == 0xb8);

        if (is_start) {
            // Output bytes[8..8+len]
            bbf_buffer.assign(ts_packet.data() + 8, ts_packet.data() + 8 + payload_len);
        } else {
            // Output bytes[9..9+len-1]
            if (payload_len > 1) {
                bbf_buffer.assign(ts_packet.data() + 9, ts_packet.data() + 9 + payload_len - 1);
            }
        }

        bbf_parser.feed(bbf_buffer.data(), bbf_buffer.size());

        // Check if all streams complete
        if (discovery_closed && !streams.empty()) {
            bool all_complete = true;
            for (const auto& [key, state] : streams) {
                if (!state.is_complete()) {
                    all_complete = false;
                    break;
                }
            }
            if (all_complete) {
                std::cerr << "All " << streams.size() << " streams complete!\n";
                break;
            }
        }
    }

    // Print results
    std::cout << "\n=== Summary ===\n";
    std::cout << "TS packets: " << total_ts_packets << "\n";
    std::cout << "UDP packets: " << total_udp << "\n";
    std::cout << "ETI frames: " << total_eti << "\n";
    std::cout << "Streams: " << streams.size() << "\n";
    std::cout << "Discovery closed: " << (discovery_closed ? "yes" : "no") << "\n\n";

    std::size_t complete_count = 0;
    for (const auto& [key, state] : streams) {
        std::cout << "=== " << ipToString(key.first) << ":" << key.second << " ===\n";
        std::cout << "  UDP: " << state.udp_packets << ", ETI: " << state.eti_frames << "\n";
        std::cout << "  Complete: " << (state.is_complete() ? "YES" : "no") << "\n";
        std::cout << "  Ensemble: " << state.ensemble_label
                  << " (0x" << std::hex << state.ensemble_id << std::dec << ")"
                  << " found at frame " << state.ensemble_found_at << "\n";
        std::cout << "  Services: " << state.service_labels.size()
                  << " (all found by frame " << state.all_services_found_at << ")\n";

        for (const auto& [sid, label] : state.service_labels) {
            std::cout << "    - " << label << " (0x" << std::hex << sid << std::dec << ")\n";
        }
        std::cout << "\n";

        if (state.is_complete()) complete_count++;
    }

    std::cout << "Complete streams: " << complete_count << "/" << streams.size() << "\n";

    return (complete_count == streams.size()) ? 0 : 1;
}
