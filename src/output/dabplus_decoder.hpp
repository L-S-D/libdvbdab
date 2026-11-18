#pragma once
// DAB+ Audio Decoder - ported from eti-tools ni2out.c
// Original Copyright (C) 2008 David Crawley (OpenDAB)
// Extracts AAC audio units from DAB+ subchannel data

#include <cstdint>
#include <cstddef>
#include <vector>
#include <functional>
#include <array>
#include <memory>

namespace dvbdab {

// Forward declaration
class PadDecoder;

// Callback for decoded AAC frames with ADTS headers
using AacFrameCallback = std::function<void(const uint8_t* data, size_t len)>;

// The same with the position of the AU on the time line of the subchannel:
// au_slot counts the AUs from frame 0 (num_aus per superframe of 5 frames),
// lost frames and superframes leave their slots out
using AacTimedFrameCallback = std::function<void(const uint8_t* data, size_t len, int64_t au_slot)>;

// Forward declare DL Plus types
struct DLPlusTag;

// Callback for DLS text updates
using DLSUpdateCallback = std::function<void(const std::string& text)>;

// Callback for DL Plus updates (text + parsed tags)
using DLPlusUpdateCallback = std::function<void(const std::string& text, const std::vector<DLPlusTag>& tags)>;

// DAB+ stream parameters from superframe header
struct DabPlusParams {
    bool dac_rate;          // 0=32kHz, 1=48kHz
    bool sbr_flag;          // SBR used
    bool aac_channel_mode;  // 0=mono, 1=stereo
    bool ps_flag;           // Parametric stereo
    int mpeg_surround;      // MPEG surround config (0-7)
    int num_aus;            // Number of Access Units (2, 3, 4, or 6)
};

class DabPlusDecoder {
public:
    explicit DabPlusDecoder(int bitrate);
    ~DabPlusDecoder();  // Defined in .cpp for PadDecoder incomplete type

    // Set callback for decoded AAC frames
    void setCallback(AacFrameCallback cb) { callback_ = std::move(cb); }

    // Set callback for decoded AAC frames with their AU slot (see above)
    void setTimedCallback(AacTimedFrameCallback cb) { timed_callback_ = std::move(cb); }

    // Put the AUs out as LATM in LOAS (AudioSyncStream, a StreamMuxConfig in
    // every frame) instead of ADTS: its AudioSpecificConfig says 960 samples
    // per AU (frameLengthFlag), SBR and PS explicitly
    void setLatm(bool latm) { latm_ = latm; }

    // The time of an AU in 90 kHz units (valid after the first superframe):
    // 960 samples (LATM) or the 1024 an ADTS header stands for, at the
    // sampling rate of the AAC core
    int64_t getAuDuration90k() const;

    // The real length of an AU in 90 kHz units (960 samples of the core)
    int64_t getRealAuDuration90k() const;

    // Set callback for DLS text updates
    void setDLSCallback(DLSUpdateCallback cb);

    // Set callback for DL Plus updates (includes parsed artist/title tags)
    void setDLPlusCallback(DLPlusUpdateCallback cb);

    // Get current DLS text (if any)
    const std::string& getDLSText() const;

    // Feed one subchannel frame (called 5 times to build superframe)
    // Returns true if a complete superframe was processed
    bool feedFrame(const uint8_t* data, size_t len);

    // The same with the number of the frame (24 ms each, consecutive numbers
    // for consecutive frames): a gap is a lost frame. The frames go to their
    // place in the superframe; of a superframe with lost frames the AUs that
    // came complete (and pass their CRC) are still put out, one without its
    // first frame (the header) is lost.
    bool feedFrame(const uint8_t* data, size_t len, int64_t frame_no);

    // Reset decoder state
    void reset();

    // Get current parameters (valid after first superframe)
    const DabPlusParams& getParams() const { return params_; }

    /// Get output sample rate in Hz (32000 or 48000 per ETSI TS 102 563)
    int getOutputSampleRate() const {
        return params_.dac_rate ? 48000 : 32000;
    }

    /// Get samples per frame (2048 for SBR, 1024 otherwise)
    int getSamplesPerFrame() const {
        return params_.sbr_flag ? 2048 : 1024;
    }

    // Statistics
    size_t getFrameCount() const { return frame_count_; }
    size_t getSuperframeCount() const { return superframe_count_; }
    size_t getAuCount() const { return au_count_; }
    size_t getCrcErrors() const { return crc_errors_; }
    size_t getAusLost() const { return aus_lost_; }               // AUs in lost frames
    size_t getSuperframesNoHeader() const { return sf_no_header_; } // first frame lost
    size_t getSyncLosses() const { return sync_losses_; }

private:
    // FireCode CRC check (bytes 0-1 vs bytes 2-10)
    static bool checkFireCode(const uint8_t* buf);

    // AU CRC check (CRC-16 CCITT)
    static bool checkAuCrc(const uint8_t* buf, size_t len);

    // Build ADTS header for AAC frame
    void buildAdtsHeader(uint8_t* header, size_t au_len);

    // The LOAS frame of an AU into out (room for len + 32 bytes); its length
    size_t buildLatmFrame(uint8_t* out, const uint8_t* au, size_t len);

    // Process the superframe collected so far (sf_mask_: the frames it has)
    void processSuperframe();

    // Frame idx (0-4) of the superframe being collected
    void storeFrame(const uint8_t* data, int idx);

    // Process the superframe being collected, if it has a frame
    void finishSuperframe();

    int bitrate_;
    size_t frame_size_;           // Single frame size in bytes
    bool synced_ = false;         // FireCode sync acquired
    int64_t next_frame_ = 0;      // frame number for feedFrame() without one
    int64_t sf_start_ = 0;        // frame number of the first frame of the superframe
    uint8_t sf_mask_ = 0;         // frames of it collected (bit 0..4)

    // Superframe buffer (5 frames)
    std::vector<uint8_t> superframe_buf_;

    DabPlusParams params_{};
    AacFrameCallback callback_;
    AacTimedFrameCallback timed_callback_;
    bool latm_ = false;
    DLSUpdateCallback dls_callback_;
    DLPlusUpdateCallback dlplus_callback_;

    // PAD decoder for DLS/DL Plus extraction
    std::unique_ptr<PadDecoder> pad_decoder_;

    // Statistics
    size_t frame_count_ = 0;
    size_t superframe_count_ = 0;
    size_t au_count_ = 0;
    size_t crc_errors_ = 0;
    size_t aus_lost_ = 0;
    size_t sf_no_header_ = 0;
    size_t sync_losses_ = 0;

    // Output buffer for ADTS frame
    std::array<uint8_t, 2048> output_buf_;
};

} // namespace dvbdab
