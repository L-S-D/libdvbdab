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

    // Set callback for DLS text updates
    void setDLSCallback(DLSUpdateCallback cb);

    // Set callback for DL Plus updates (includes parsed artist/title tags)
    void setDLPlusCallback(DLPlusUpdateCallback cb);

    // Get current DLS text (if any)
    const std::string& getDLSText() const;

    // Feed one subchannel frame (called 5 times to build superframe)
    // Returns true if a complete superframe was processed
    bool feedFrame(const uint8_t* data, size_t len);

    // Reset decoder state
    void reset();

    // Get current parameters (valid after first superframe)
    const DabPlusParams& getParams() const { return params_; }

    // Statistics
    size_t getFrameCount() const { return frame_count_; }
    size_t getSuperframeCount() const { return superframe_count_; }
    size_t getAuCount() const { return au_count_; }
    size_t getCrcErrors() const { return crc_errors_; }

private:
    // FireCode CRC check (bytes 0-1 vs bytes 2-10)
    static bool checkFireCode(const uint8_t* buf);

    // AU CRC check (CRC-16 CCITT)
    static bool checkAuCrc(const uint8_t* buf, size_t len);

    // Build ADTS header for AAC frame
    void buildAdtsHeader(uint8_t* header, size_t au_len);

    // Process complete superframe (5 frames accumulated)
    void processSuperframe();

    int bitrate_;
    size_t frame_size_;           // Single frame size in bytes
    int frame_index_ = 0;         // 0-4 for superframe accumulation
    bool synced_ = false;         // FireCode sync acquired

    // Superframe buffer (5 frames)
    std::vector<uint8_t> superframe_buf_;

    DabPlusParams params_{};
    AacFrameCallback callback_;
    DLSUpdateCallback dls_callback_;
    DLPlusUpdateCallback dlplus_callback_;

    // PAD decoder for DLS/DL Plus extraction
    std::unique_ptr<PadDecoder> pad_decoder_;

    // Statistics
    size_t frame_count_ = 0;
    size_t superframe_count_ = 0;
    size_t au_count_ = 0;
    size_t crc_errors_ = 0;

    // Output buffer for ADTS frame
    std::array<uint8_t, 2048> output_buf_;
};

} // namespace dvbdab
