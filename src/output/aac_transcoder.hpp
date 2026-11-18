#pragma once

#include "dabplus_decoder.hpp"
#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>

namespace dvbdab {

/**
 * @brief DAB+ audio decoded and encoded again as AAC-LC in ADTS
 *
 * DAB+ codes AAC with 960-sample frames; ADTS cannot say so, and decoders
 * take 1024 samples per AU (the audio plays 6.7 % slow and about a semitone
 * low), while few decoders do SBR with 960 samples (FFmpeg does not). This
 * decodes the AUs with faad2 (960 with SBR and PS) and encodes the audio
 * again as AAC-LC with 1024 samples per frame (libavcodec), at the output
 * rate of the subchannel. AUs that were lost become silence of their length:
 * the output runs on in real time.
 *
 * Built only with faad2 and libavcodec (DVBDAB_WITH_TRANSCODE); available()
 * says so.
 */
class AacTranscoder {
public:
    // an ADTS frame of AAC-LC and its PTS (90 kHz)
    using Output = std::function<void(const uint8_t* adts, size_t len, int64_t pts)>;

    // bitrate: of the DAB+ subchannel (kbit/s; the output is AAC-LC at
    // 128 kbit/s per channel)
    AacTranscoder(int bitrate, Output out);
    ~AacTranscoder();

    AacTranscoder(const AacTranscoder&) = delete;
    AacTranscoder& operator=(const AacTranscoder&) = delete;

    // One AU of DabPlusDecoder (its ADTS frame) at its slot, with the
    // parameters of its superframe
    void feed(const uint8_t* adts, size_t len, int64_t au_slot, const DabPlusParams& params);

    // Whether the library has it
    static bool available();

    // Statistics
    size_t getDecodeErrors() const { return decode_errors_; }
    size_t getSilentAus() const { return silent_aus_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    size_t decode_errors_ = 0;
    size_t silent_aus_ = 0;
};

} // namespace dvbdab
