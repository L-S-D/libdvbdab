#pragma once
// DAB MP2 Decoder - extracts MPEG-1 Layer II frames from DAB subchannel data
// DAB audio (non-DAB+) uses raw MP2 frames without any wrapper

#include <cstdint>
#include <cstddef>
#include <vector>
#include <functional>
#include <array>

namespace dvbdab {

// Callback for MP2 frames
using Mp2FrameCallback = std::function<void(const uint8_t* data, size_t len)>;

// MP2 frame parameters
struct Mp2Params {
    int version;          // 1=MPEG1, 2=MPEG2, 0=MPEG2.5
    int layer;            // 1, 2, or 3
    bool protection;      // Has CRC
    int bitrate;          // kbps
    int sample_rate;      // Hz
    bool padding;
    int channel_mode;     // 0=stereo, 1=joint, 2=dual, 3=mono
    int frame_size;       // bytes
};

class DabMp2Decoder {
public:
    explicit DabMp2Decoder(int bitrate);
    ~DabMp2Decoder() = default;

    // Set callback for decoded MP2 frames
    void setCallback(Mp2FrameCallback cb) { callback_ = std::move(cb); }

    // Feed subchannel frame data (24ms worth)
    // Returns number of MP2 frames extracted
    int feedFrame(const uint8_t* data, size_t len);

    // Reset decoder state
    void reset();

    // Get current parameters (valid after first frame)
    const Mp2Params& getParams() const { return params_; }

    // Statistics
    size_t getFrameCount() const { return frame_count_; }
    size_t getMp2FrameCount() const { return mp2_frame_count_; }
    size_t getSyncErrors() const { return sync_errors_; }

private:
    // Parse MP2 header and return frame size, or 0 if invalid
    int parseHeader(const uint8_t* header);

    // Check if bytes form valid MP2 sync
    static bool isSync(const uint8_t* data);

    int bitrate_;
    size_t frame_size_;           // Expected subchannel frame size
    bool synced_ = false;
    size_t sync_offset_ = 0;      // Offset within accumulated data to next frame

    // Buffer for incomplete frames
    std::vector<uint8_t> buffer_;

    Mp2Params params_{};
    Mp2FrameCallback callback_;

    // Statistics
    size_t frame_count_ = 0;
    size_t mp2_frame_count_ = 0;
    size_t sync_errors_ = 0;
};

} // namespace dvbdab
