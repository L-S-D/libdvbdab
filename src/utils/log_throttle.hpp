#pragma once
// Log throttle helper - reduces log spam in hot paths
// Logs first N messages, then every Nth message

#include <cstdint>

namespace dvbdab {

// Simple log throttle: logs first `initial` messages, then every `interval` messages
class LogThrottle {
public:
    constexpr LogThrottle(uint32_t initial = 5, uint32_t interval = 100)
        : initial_(initial), interval_(interval) {}

    // Increment counter and return true if this message should be logged
    bool should_log() {
        ++count_;
        return count_ <= initial_ || (count_ % interval_) == 0;
    }

    // Get current count (for including in log message)
    uint32_t count() const { return count_; }

    // Reset counter
    void reset() { count_ = 0; }

private:
    uint32_t count_ = 0;
    uint32_t initial_;
    uint32_t interval_;
};

// Macro for conditional logging with throttle
// Usage: LOG_THROTTLE_DEBUG(throttle_, TAG, "message " << value)
#define LOG_THROTTLE_DEBUG(throttle, tag, msg) \
    do { if ((throttle).should_log()) { LOG_DEBUG(tag, msg); } } while(0)

#define LOG_THROTTLE_INFO(throttle, tag, msg) \
    do { if ((throttle).should_log()) { LOG_INFO(tag, msg); } } while(0)

} // namespace dvbdab
