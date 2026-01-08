#pragma once

#include <dvbdab/dvbdab.hpp>
#include <array>
#include <cstdint>
#include <memory>

namespace dvbdab {

// Base class for all input sources
// Input sources convert their specific format to IPv4 packets
class InputSource {
public:
    virtual ~InputSource() = default;

    // Set callback for IPv4 packets produced by this source
    void setIpCallback(IpPacketCallback callback) {
        ip_callback_ = std::move(callback);
    }

    // Feed raw data to the source
    // The source will parse the data and emit IPv4 packets via the callback
    virtual void feed(const uint8_t* data, size_t len) = 0;

    // Reset parser state
    virtual void reset() = 0;

    // Get source description
    virtual const char* description() const = 0;

    // Statistics (common to all sources)
    size_t getDiscontinuityCount() const { return discontinuity_count_; }

protected:
    void emitIpPacket(const uint8_t* data, size_t len) {
        if (ip_callback_) {
            ip_callback_(data, len);
        }
    }

    // Check continuity counter and return true if continuous
    // Returns false on discontinuity (caller should handle appropriately)
    bool checkContinuity(uint16_t pid, uint8_t cc) {
        auto& state = cc_state_[pid];
        if (state.initialized) {
            uint8_t expected = (state.last_cc + 1) & 0x0f;
            if (cc != expected) {
                discontinuity_count_++;
                state.last_cc = cc;
                return false;
            }
        }
        state.last_cc = cc;
        state.initialized = true;
        return true;
    }

    IpPacketCallback ip_callback_;
    size_t discontinuity_count_{0};

private:
    struct CcState {
        uint8_t last_cc{0};
        bool initialized{false};
    };
    std::array<CcState, 8192> cc_state_{};  // Max 13-bit PID
};

} // namespace dvbdab
