// DAB+ Audio Decoder - ported from eti-tools ni2out.c
// Original Copyright (C) 2008 David Crawley (OpenDAB)
// License: GPLv3

#include "dabplus_decoder.hpp"
#include "pad_decoder.hpp"
#include "../utils/crc_utils.hpp"
#include "../logging.h"
#include <algorithm>

namespace dvbdab {

DabPlusDecoder::DabPlusDecoder(int bitrate)
    : bitrate_(bitrate)
    , frame_size_(0)  // Will be set from first feedFrame call
    , pad_decoder_(std::make_unique<PadDecoder>())
{
    // Reserve space will be done when frame_size is known
}

// Destructor must be in .cpp where PadDecoder is complete
DabPlusDecoder::~DabPlusDecoder() = default;

void DabPlusDecoder::setDLSCallback(DLSUpdateCallback cb) {
    dls_callback_ = std::move(cb);
    if (pad_decoder_) {
        pad_decoder_->setDLSCallback([this](const std::string& text) {
            if (dls_callback_) {
                dls_callback_(text);
            }
        });
    }
}

void DabPlusDecoder::setDLPlusCallback(DLPlusUpdateCallback cb) {
    dlplus_callback_ = std::move(cb);
    if (pad_decoder_) {
        pad_decoder_->setDLPlusCallback([this](const std::string& text, const std::vector<DLPlusTag>& tags) {
            if (dlplus_callback_) {
                dlplus_callback_(text, tags);
            }
        });
    }
}

const std::string& DabPlusDecoder::getDLSText() const {
    static const std::string empty;
    return pad_decoder_ ? pad_decoder_->getDLSText() : empty;
}

void DabPlusDecoder::reset() {
    synced_ = false;
    next_frame_ = 0;
    sf_start_ = 0;
    sf_mask_ = 0;
    superframe_buf_.clear();
    frame_count_ = 0;
    superframe_count_ = 0;
    au_count_ = 0;
    crc_errors_ = 0;
    aus_lost_ = 0;
    sf_no_header_ = 0;
    sync_losses_ = 0;
    if (pad_decoder_) {
        pad_decoder_->reset();
    }
}

bool DabPlusDecoder::checkFireCode(const uint8_t* buf) {
    return firecode_check(buf);
}

bool DabPlusDecoder::checkAuCrc(const uint8_t* buf, size_t len) {
    return crc16_ccitt_verify(buf, len);
}

namespace {

// MSB first into a buffer
class BitWriter {
public:
    explicit BitWriter(uint8_t* out) : out_(out) {}
    void put(uint32_t value, int bits) {
        for (int i = bits - 1; i >= 0; i--) {
            if ((pos_ & 7) == 0) out_[pos_ >> 3] = 0;
            if ((value >> i) & 1) out_[pos_ >> 3] |= 0x80 >> (pos_ & 7);
            pos_++;
        }
    }
    size_t bytes() const { return (pos_ + 7) / 8; }
private:
    uint8_t* out_;
    size_t pos_ = 0;
};

} // namespace

int64_t DabPlusDecoder::getAuDuration90k() const {
    int out_rate = params_.dac_rate ? 48000 : 32000;
    int core_rate = params_.sbr_flag ? out_rate / 2 : out_rate;
    return static_cast<int64_t>(latm_ ? 960 : 1024) * 90000 / core_rate;
}

int64_t DabPlusDecoder::getRealAuDuration90k() const {
    int out_rate = params_.dac_rate ? 48000 : 32000;
    int core_rate = params_.sbr_flag ? out_rate / 2 : out_rate;
    return static_cast<int64_t>(960) * 90000 / core_rate;
}

size_t DabPlusDecoder::buildLatmFrame(uint8_t* out, const uint8_t* au, size_t len) {
    // sampling frequency indices: 48000 3, 32000 5, 24000 6, 16000 8
    int out_rate_idx = params_.dac_rate ? 3 : 5;
    int core_rate_idx = params_.sbr_flag ? (params_.dac_rate ? 6 : 8) : out_rate_idx;
    bool ps = params_.sbr_flag && params_.ps_flag;
    // PS: a mono core; MPEG Surround is left to its core as with ADTS
    int channels = (params_.aac_channel_mode && !ps) ? 2 : 1;

    BitWriter b(out + 3);
    // AudioMuxElement(muxConfigPresent = 1): the config in every frame
    b.put(0, 1);                     // useSameStreamMux
    // StreamMuxConfig
    b.put(0, 1);                     // audioMuxVersion
    b.put(1, 1);                     // allStreamsSameTimeFraming
    b.put(0, 6);                     // numSubFrames
    b.put(0, 4);                     // numProgram
    b.put(0, 3);                     // numLayer
    // AudioSpecificConfig (ISO/IEC 14496-3 1.6.2.1), SBR/PS explicit
    if (params_.sbr_flag) {
        b.put(ps ? 29 : 5, 5);       // audioObjectType: PS / SBR
        b.put(core_rate_idx, 4);     // samplingFrequencyIndex (core)
        b.put(channels, 4);          // channelConfiguration
        b.put(out_rate_idx, 4);      // extensionSamplingFrequencyIndex
        b.put(2, 5);                 // audioObjectType: AAC LC
    } else {
        b.put(2, 5);
        b.put(core_rate_idx, 4);
        b.put(channels, 4);
    }
    b.put(1, 1);                     // GASpecificConfig: frameLengthFlag, 960
    b.put(0, 1);                     // dependsOnCoreCoder
    b.put(0, 1);                     // extensionFlag
    b.put(0, 3);                     // frameLengthType 0
    b.put(0xff, 8);                  // latmBufferFullness
    b.put(0, 1);                     // otherDataPresent
    b.put(0, 1);                     // crcCheckPresent
    // PayloadLengthInfo: 255s, then the rest; PayloadMux
    size_t n = len;
    while (n >= 255) {
        b.put(255, 8);
        n -= 255;
    }
    b.put(static_cast<uint32_t>(n), 8);
    for (size_t i = 0; i < len; i++) b.put(au[i], 8);

    // AudioSyncStream: syncword 0x2B7, audioMuxLengthBytes
    size_t ame = b.bytes();
    out[0] = 0x56;
    out[1] = 0xe0 | ((ame >> 8) & 0x1f);
    out[2] = ame & 0xff;
    return 3 + ame;
}

void DabPlusDecoder::buildAdtsHeader(uint8_t* header, size_t au_len) {
    // Sample rate index for ADTS - uses core rates for implicit SBR signaling
    // Decoders detect SBR in bitstream and upsample automatically
    // Index: 32k=0x5, 16k=0x8, 48k=0x3, 24k=0x6
    static const uint8_t sample_rate_table[4] = {0x5, 0x8, 0x3, 0x6};
    uint8_t sfi = sample_rate_table[(params_.dac_rate ? 2 : 0) | (params_.sbr_flag ? 1 : 0)];

    // Channel config
    uint8_t channel_config;
    if (params_.mpeg_surround == 0) {
        if (params_.sbr_flag && !params_.aac_channel_mode && params_.ps_flag) {
            channel_config = 2;  // Parametric stereo
        } else {
            channel_config = params_.aac_channel_mode ? 2 : 1;
        }
    } else if (params_.mpeg_surround == 1) {
        channel_config = 6;
    } else {
        channel_config = params_.aac_channel_mode ? 2 : 1;
    }

    size_t frame_len = au_len + 7;  // Include 7-byte header

    // ADTS header (7 bytes)
    // DAB+ uses HE-AAC = AAC-LC + SBR, so profile should be 1 (LC), not 0 (Main)
    header[0] = 0xff;  // Syncword high
    header[1] = 0xf1;  // Syncword low + ID=0 (MPEG-4) + layer=0 + protection_absent=1
    header[2] = (1 << 6) | (sfi << 2) | ((channel_config >> 2) & 0x01);  // profile=1 (AAC-LC for HE-AAC)
    header[3] = ((channel_config & 0x03) << 6) | ((frame_len >> 11) & 0x03);
    header[4] = (frame_len >> 3) & 0xff;
    header[5] = ((frame_len & 0x07) << 5) | 0x1f;  // buffer fullness high (0x7ff = VBR)
    header[6] = 0xfc;  // buffer fullness low + num_raw_data_blocks=0
}

bool DabPlusDecoder::feedFrame(const uint8_t* data, size_t len) {
    return feedFrame(data, len, next_frame_);
}

void DabPlusDecoder::storeFrame(const uint8_t* data, int idx) {
    size_t offset = idx * frame_size_;
    if (superframe_buf_.size() < frame_size_ * 5) {
        superframe_buf_.resize(frame_size_ * 5);
    }
    std::copy(data, data + frame_size_, superframe_buf_.data() + offset);
    sf_mask_ |= 1u << idx;
}

void DabPlusDecoder::finishSuperframe() {
    if (sf_mask_) {
        processSuperframe();
    }
    sf_mask_ = 0;
}

bool DabPlusDecoder::feedFrame(const uint8_t* data, size_t len, int64_t frame_no) {
    // Auto-detect frame size from first call
    if (frame_size_ == 0) {
        frame_size_ = len;
        bitrate_ = len / 3;  // Recalculate bitrate from actual frame size
        superframe_buf_.reserve(frame_size_ * 5);
        LOG_DEBUG(DABPLUS, "Auto-detected frame_size=" << frame_size_ << " bitrate=" << bitrate_);
    }

    if (len != frame_size_) {
        return false;
    }

    frame_count_++;
    next_frame_ = frame_no + 1;
    bool done = false;

    if (synced_) {
        int64_t idx = frame_no - sf_start_;
        if (idx < 0) {
            return false;  // older than the superframe being collected
        }
        if (idx >= 5) {
            // the superframe is over (frames of it were lost), and the ones
            // after it that are entirely missing
            finishSuperframe();
            done = true;
            sf_start_ += idx / 5 * 5;
            idx %= 5;
        }
        // The first frame of a superframe starts with its header: a FireCode
        // that does not match there means the alignment is lost
        if (idx == 0 && !checkFireCode(data)) {
            synced_ = false;
            sync_losses_++;
        } else {
            storeFrame(data, static_cast<int>(idx));
        }
    }

    // Not synced: look for the header of a superframe (its FireCode)
    if (!synced_) {
        if (!checkFireCode(data)) {
            return done;
        }
        synced_ = true;
        sf_start_ = frame_no;
        sf_mask_ = 0;
        storeFrame(data, 0);
        if (frame_count_ <= 10) {
            LOG_DEBUG(DABPLUS, "FireCode SYNC at frame " << frame_count_);
        }
    }

    // Complete: process it at once
    if (sf_mask_ == 0x1f) {
        finishSuperframe();
        sf_start_ += 5;
        done = true;
    }

    return done;
}

void DabPlusDecoder::processSuperframe() {
    // Without its first frame there is no header (format, AU positions)
    if (!(sf_mask_ & 1)) {
        sf_no_header_++;
        aus_lost_ += params_.num_aus;
        return;
    }

    superframe_count_++;

    uint8_t* sf = superframe_buf_.data();
    int s = bitrate_ / 8;  // RS columns
    size_t audio_super_frame_size = frame_size_ * 5 - s * 10;  // Exclude RS parity

    if (superframe_count_ <= 3) {
        LOG_TRACE(DABPLUS, "Superframe #" << superframe_count_ << ": bitrate=" << bitrate_
                  << " s=" << s << " audio_size=" << audio_super_frame_size
                  << " first8: " << std::hex << (int)sf[0] << " " << (int)sf[1] << " "
                  << (int)sf[2] << " " << (int)sf[3] << " " << (int)sf[4] << " "
                  << (int)sf[5] << " " << (int)sf[6] << " " << (int)sf[7] << std::dec);
    }

    // NOTE: RS de-interleaving is NOT needed here.
    // The subchannel data from ETI-NI is already in sequential (de-interleaved) format.
    // RS interleaving is only applied at the transmission layer, not in ETI storage.
    // Attempting to de-interleave causes CRC errors - do not try again!
    // (Tested: WDR stream works without de-interleaving, AU offsets are valid)

    // Parse format byte (byte 2, after 2-byte FireCode CRC)
    // Bit 7: rfa (reserved)
    // Bit 6: dac_rate
    // Bit 5: sbr_flag
    // Bit 4: aac_channel_mode
    // Bit 3: ps_flag
    // Bits 2-0: mpeg_surround
    params_.dac_rate = (sf[2] & 0x40) != 0;
    params_.sbr_flag = (sf[2] & 0x20) != 0;
    params_.aac_channel_mode = (sf[2] & 0x10) != 0;
    params_.ps_flag = (sf[2] & 0x08) != 0;
    params_.mpeg_surround = sf[2] & 0x07;

    // Configure PAD decoder with audio parameters (for FDK-AAC DSE extraction)
    if (pad_decoder_ && superframe_count_ == 1) {
        pad_decoder_->configure(params_.dac_rate, params_.sbr_flag,
                                params_.ps_flag, params_.aac_channel_mode);
    }

    // Number of AUs based on dac_rate and sbr_flag
    static const int au_count_table[4] = {4, 2, 6, 3};
    params_.num_aus = au_count_table[(params_.dac_rate ? 2 : 0) | (params_.sbr_flag ? 1 : 0)];

    // Parse AU start offsets
    uint16_t au_start[6] = {0, 0, 0, 0, 0, 0};
    int16_t au_size[6] = {0, 0, 0, 0, 0, 0};

    switch (params_.num_aus) {
    case 2:
        au_start[0] = 5;  // Header: 2 (CRC) + 1 (format) + 2 (offsets) = 5
        au_start[1] = (sf[3] << 4) | (sf[4] >> 4);
        if (au_start[1]) {
            au_size[0] = au_start[1] - au_start[0];
            au_size[1] = audio_super_frame_size - au_start[1];
        }
        break;

    case 3:
        au_start[0] = 6;  // Header: 2 + 1 + 3 = 6
        au_start[1] = (sf[3] << 4) | (sf[4] >> 4);
        au_start[2] = ((sf[4] & 0x0f) << 8) | sf[5];
        if (au_start[1] && au_start[2]) {
            au_size[0] = au_start[1] - au_start[0];
            au_size[1] = au_start[2] - au_start[1];
            au_size[2] = audio_super_frame_size - au_start[2];
        }
        break;

    case 4:
        au_start[0] = 8;  // Header: 2 + 1 + 5 = 8
        au_start[1] = (sf[3] << 4) | (sf[4] >> 4);
        au_start[2] = ((sf[4] & 0x0f) << 8) | sf[5];
        au_start[3] = (sf[6] << 4) | (sf[7] >> 4);
        if (au_start[1] && au_start[2] && au_start[3]) {
            au_size[0] = au_start[1] - au_start[0];
            au_size[1] = au_start[2] - au_start[1];
            au_size[2] = au_start[3] - au_start[2];
            au_size[3] = audio_super_frame_size - au_start[3];
        }
        break;

    case 6:
        au_start[0] = 11;  // Header: 2 + 1 + 8 = 11
        au_start[1] = (sf[3] << 4) | (sf[4] >> 4);
        au_start[2] = ((sf[4] & 0x0f) << 8) | sf[5];
        au_start[3] = (sf[6] << 4) | (sf[7] >> 4);
        au_start[4] = ((sf[7] & 0x0f) << 8) | sf[8];
        au_start[5] = (sf[9] << 4) | (sf[10] >> 4);
        if (au_start[1] && au_start[2] && au_start[3] && au_start[4] && au_start[5]) {
            au_size[0] = au_start[1] - au_start[0];
            au_size[1] = au_start[2] - au_start[1];
            au_size[2] = au_start[3] - au_start[2];
            au_size[3] = au_start[4] - au_start[3];
            au_size[4] = au_start[5] - au_start[4];
            au_size[5] = audio_super_frame_size - au_start[5];
        }
        break;
    }

    if (superframe_count_ <= 3) {
        LOG_TRACE(DABPLUS, "SF params: num_aus=" << params_.num_aus
                  << " dac=" << params_.dac_rate << " sbr=" << params_.sbr_flag
                  << " ch=" << params_.aac_channel_mode << " ps=" << params_.ps_flag
                  << " mpeg=" << params_.mpeg_surround);
        std::ostringstream oss;
        oss << "AU offsets:";
        for (int i = 0; i < params_.num_aus; i++)
            oss << " [" << i << "]=" << au_start[i] << "/" << au_size[i];
        LOG_TRACE(DABPLUS, oss.str());
    }

    // Process each AU. After a lost AU the rest of the superframe is left
    // out too: SBR codes its envelopes relative to the AU before, a decoder
    // would take them against the wrong one; the first AU of a superframe
    // is a safe start again.
    bool lost_before = false;
    for (int i = 0; i < params_.num_aus; i++) {
        if (lost_before) {
            aus_lost_++;
            continue;
        }
        if (au_size[i] <= 0 || au_start[i] + au_size[i] < 2 ||
            static_cast<size_t>(au_start[i] + au_size[i]) > audio_super_frame_size) {
            if (superframe_count_ <= 3) {
                LOG_TRACE(DABPLUS, "AU" << i << " skipped: size=" << au_size[i] << " start=" << au_start[i]);
            }
            continue;
        }

        // An AU in a lost frame is lost
        size_t first_frame = au_start[i] / frame_size_;
        size_t last_frame = (au_start[i] + au_size[i] - 1) / frame_size_;
        bool complete = true;
        for (size_t f = first_frame; f <= last_frame; f++) {
            if (!(sf_mask_ & (1u << f))) {
                complete = false;
            }
        }
        if (!complete) {
            aus_lost_++;
            lost_before = true;
            continue;
        }

        // Invert CRC bits (DAB+ uses inverted CRC)
        sf[au_start[i] + au_size[i] - 2] ^= 0xff;
        sf[au_start[i] + au_size[i] - 1] ^= 0xff;

        // Check AU CRC
        if (!checkAuCrc(sf + au_start[i], au_size[i])) {
            crc_errors_++;
            lost_before = true;
            // Restore CRC bytes
            sf[au_start[i] + au_size[i] - 2] ^= 0xff;
            sf[au_start[i] + au_size[i] - 1] ^= 0xff;
            continue;
        }

        // AU data length excluding CRC
        size_t au_data_len = au_size[i] - 2;

        // Extract PAD from raw AU using FDK-AAC (like dablin)
        // FDK-AAC with TT_MP4_RAW expects raw AU data, not ADTS
        if (pad_decoder_ && au_data_len >= 2) {
            pad_decoder_->processPad(sf + au_start[i], au_data_len);
        }

        // Build ADTS frame and emit
        if ((callback_ || timed_callback_) && au_data_len > 0 && au_data_len + 32 < output_buf_.size()) {
            size_t out_len;
            if (latm_) {
                out_len = buildLatmFrame(output_buf_.data(), sf + au_start[i], au_data_len);
            } else {
                buildAdtsHeader(output_buf_.data(), au_data_len);
                std::copy(sf + au_start[i], sf + au_start[i] + au_data_len, output_buf_.data() + 7);
                out_len = au_data_len + 7;
            }
            if (callback_) {
                callback_(output_buf_.data(), out_len);
            }
            if (timed_callback_) {
                // num_aus slots per superframe of 5 frames
                timed_callback_(output_buf_.data(), out_len,
                                sf_start_ * params_.num_aus / 5 + i);
            }
            au_count_++;
            if (au_count_ <= 10) {
                LOG_TRACE(DABPLUS, "AU emitted #" << au_count_ << " len=" << (au_data_len + 7));
            }
        } else if (superframe_count_ <= 3) {
            LOG_TRACE(DABPLUS, "AU" << i << " NOT emitted: au_len=" << au_data_len);
        }
    }
}

} // namespace dvbdab
