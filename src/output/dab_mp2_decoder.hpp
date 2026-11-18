#pragma once
// DAB MP2 Decoder - extracts MPEG-1 Layer II frames from DAB subchannel data
// DAB audio (non-DAB+) uses raw MP2 frames without any wrapper

#include <cstdint>
#include <cstddef>
#include <vector>
#include <functional>
#include <array>
#include <memory>
#include <string>

namespace dvbdab {

// Callback for MP2 frames
using Mp2FrameCallback = std::function<void(const uint8_t* data, size_t len)>;

class PadDecoder;
struct DLPlusTag;

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
    ~DabMp2Decoder();  // in the .cpp, where PadDecoder is complete

    // Set callback for decoded MP2 frames
    void setCallback(Mp2FrameCallback cb) { callback_ = std::move(cb); }

    // The same with the time the frame began at, in 1/90000 s from frame
    // number 0 of feedFrame(data, len, frame_no): frames of the subchannel
    // last 24 ms, an MPEG frame begins where its bytes are in them (lost
    // frames leave a gap; a frame of 48 ms starts in every second one)
    using TimedCallback = std::function<void(const uint8_t* data, size_t len, int64_t time90k)>;
    void setTimedCallback(TimedCallback cb) { timed_callback_ = std::move(cb); }

    // The dynamic label and its DL Plus tags from the PAD at the end of each frame
    void setDLSCallback(std::function<void(const std::string& text)> cb);
    void setDLPlusCallback(std::function<void(const std::string& text, const std::vector<DLPlusTag>& tags)> cb);

    // Feed subchannel frame data (24ms worth)
    // Returns number of MP2 frames extracted
    int feedFrame(const uint8_t* data, size_t len);
    // with the number of the frame (24 ms each; lost frames: resync() first)
    int feedFrame(const uint8_t* data, size_t len, int64_t frame_no);

    // Reset decoder state
    void reset();

    // Frames were lost: drop what is buffered of a frame, find the sync again
    void resync();

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

    std::unique_ptr<PadDecoder> pad_;

    Mp2Params params_{};
    Mp2FrameCallback callback_;
    TimedCallback timed_callback_;

    // where the first byte of buffer_ is in the stream: the frame it came
    // in and its place in that frame (frames of feed_len_ bytes)
    int64_t buf_frame_ = 0;
    size_t buf_off_ = 0;
    size_t feed_len_ = 0;
    int64_t next_frame_ = 0;      // frame number for feedFrame() without one
    void consumed(size_t bytes);

    // Statistics
    size_t frame_count_ = 0;
    size_t mp2_frame_count_ = 0;
    size_t sync_errors_ = 0;
};

} // namespace dvbdab
