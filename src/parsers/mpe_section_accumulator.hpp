#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <deque>
#include <vector>

namespace dvbdab {

constexpr int PSI_MAX_SIZE = 4096;

// MPE/PSI section accumulator with queue for back-to-back sections
// Based on eti-tools fedi2eti.c which correctly handles multiple sections per PUSI packet
class MPESectionAccumulator {
public:
    MPESectionAccumulator();
    void reset();

    // Process a TS packet
    void process_ts_packet(const uint8_t* ts);

    // Check if there are sections ready
    bool has_section() const { return !completed_sections_.empty(); }

    // Get next section (caller should copy data before calling pop_section)
    const uint8_t* get_section() const {
        return completed_sections_.empty() ? nullptr : completed_sections_.front().data();
    }
    size_t get_section_size() const {
        return completed_sections_.empty() ? 0 : completed_sections_.front().size();
    }

    // Remove the current section from queue
    void pop_section() {
        if (!completed_sections_.empty()) {
            completed_sections_.pop_front();
        }
    }

private:
    uint8_t cc_ = 0;

    // Working buffer for section being accumulated (fixed size for accumulation)
    std::array<uint8_t, PSI_MAX_SIZE> buffer_{};
    uint16_t buffer_size_ = 0;   // Expected total size of current section
    uint16_t buffer_skip_ = 0;   // Bytes accumulated so far

    // Queue of completed sections (dynamic size - only allocates actual section size)
    std::deque<std::vector<uint8_t>> completed_sections_;

    void emit_section();
};

} // namespace dvbdab
