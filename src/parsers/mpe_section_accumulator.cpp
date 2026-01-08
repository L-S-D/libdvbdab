#include "mpe_section_accumulator.hpp"
#include "../utils/byte_utils.hpp"
#include <dvbdab/dvbdab.hpp>
#include <algorithm>

namespace dvbdab {

MPESectionAccumulator::MPESectionAccumulator() {
    reset();
}

void MPESectionAccumulator::reset() {
    cc_ = 0;
    buffer_size_ = 0;
    buffer_skip_ = 0;
    completed_sections_.clear();
}

void MPESectionAccumulator::emit_section() {
    if (buffer_size_ > 0 && buffer_skip_ >= buffer_size_) {
        // Only copy the actual section size, not the full 4KB buffer
        completed_sections_.emplace_back(buffer_.begin(), buffer_.begin() + buffer_size_);
    }
    buffer_skip_ = 0;
    buffer_size_ = 0;
}

// Local TS helper with null return
static inline const uint8_t* ts_get_payload_local(const uint8_t* ts) {
    if (!ts_has_payload(ts)) return nullptr;
    if (!ts_has_adaptation(ts)) return &ts[TS_HEADER_SIZE];
    if (ts[4] >= TS_PACKET_SIZE - TS_HEADER_SIZE - 1) return nullptr;
    return &ts[TS_HEADER_SIZE + 1 + ts[4]];
}

void MPESectionAccumulator::process_ts_packet(const uint8_t* ts) {
    const uint8_t* payload = ts_get_payload_local(ts);
    if (!payload) return;

    uint8_t cc = ts_get_cc(ts);

    if (ts_payload_start(ts)) {
        uint8_t ptr = *payload++;

        // Complete previous section
        if (ptr > 0 && ptr < 184 && buffer_skip_ > 0) {
            if (((cc_ + 1) & 0x0F) == cc) {
                std::copy(payload, payload + ptr, &buffer_[buffer_skip_]);
                buffer_skip_ += ptr;
                if (buffer_size_ > 0 && buffer_skip_ >= buffer_size_) {
                    emit_section();
                }
            }
            buffer_skip_ = 0;
            buffer_size_ = 0;
        }
        payload += ptr;

        // Parse new sections
        while ((payload - ts) < TS_PACKET_SIZE && *payload != 0xFF) {
            size_t remain = (ts + TS_PACKET_SIZE) - payload;
            if (remain < 3) {
                std::copy(payload, payload + remain, buffer_.data());
                buffer_skip_ = remain;
                buffer_size_ = 0;
                break;
            }

            size_t psi_size = 3 + ((payload[1] & 0x0F) << 8 | payload[2]);
            if (psi_size <= 3 || psi_size > PSI_MAX_SIZE) break;

            buffer_size_ = psi_size;
            if (psi_size > remain) {
                std::copy(payload, payload + remain, buffer_.data());
                buffer_skip_ = remain;
                break;
            } else {
                std::copy(payload, payload + psi_size, buffer_.data());
                buffer_skip_ = psi_size;
                emit_section();
                payload += psi_size;
            }
        }
    } else {
        // Continuation
        if (buffer_skip_ > 0) {
            if (((cc_ + 1) & 0x0F) != cc) {
                buffer_skip_ = 0;
                buffer_size_ = 0;
            } else {
                size_t remain = (ts + TS_PACKET_SIZE) - payload;
                if (buffer_size_ == 0 && buffer_skip_ < 3) {
                    size_t needed = 3 - buffer_skip_;
                    std::copy(payload, payload + needed, &buffer_[buffer_skip_]);
                    buffer_skip_ += needed;
                    buffer_size_ = 3 + ((buffer_[1] & 0x0F) << 8 | buffer_[2]);
                    payload += needed;
                    remain -= needed;
                }
                size_t to_copy = std::min(remain, (size_t)(buffer_size_ - buffer_skip_));
                std::copy(payload, payload + to_copy, &buffer_[buffer_skip_]);
                buffer_skip_ += to_copy;

                if (buffer_size_ > 0 && buffer_skip_ >= buffer_size_) {
                    emit_section();
                }
            }
        }
    }
    cc_ = cc;
}

} // namespace dvbdab
