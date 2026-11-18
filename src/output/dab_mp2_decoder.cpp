// DAB MP2 Decoder - extracts MPEG-1 Layer II frames from DAB subchannel data
// DAB audio uses raw MP2 frames without any superframe wrapper

#include "dab_mp2_decoder.hpp"
#include "pad_decoder.hpp"
#include "../logging.h"
#include <cstring>

namespace dvbdab {

// MPEG Audio bitrate tables (kbps)
// Index by [version][layer][bitrate_index]
// version: 0=MPEG2.5, 1=reserved, 2=MPEG2, 3=MPEG1
// layer: 0=reserved, 1=Layer3, 2=Layer2, 3=Layer1
static const int bitrate_table[4][4][16] = {
    // MPEG2.5
    {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // reserved
        {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},  // L3
        {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},  // L2
        {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0}  // L1
    },
    // Reserved
    {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    },
    // MPEG2
    {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // reserved
        {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},  // L3
        {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},  // L2
        {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0}  // L1
    },
    // MPEG1
    {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // reserved
        {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0},  // L3
        {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0},  // L2
        {0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0}  // L1
    }
};

// Sample rate table (Hz)
// Index by [version][sample_rate_index]
static const int sample_rate_table[4][4] = {
    {11025, 12000, 8000, 0},   // MPEG2.5
    {0, 0, 0, 0},              // Reserved
    {22050, 24000, 16000, 0},  // MPEG2
    {44100, 48000, 32000, 0}   // MPEG1
};

// Samples per frame
// Index by [version][layer]
static const int samples_per_frame[4][4] = {
    {0, 576, 1152, 384},   // MPEG2.5: reserved, L3, L2, L1
    {0, 0, 0, 0},          // Reserved
    {0, 576, 1152, 384},   // MPEG2
    {0, 1152, 1152, 384}   // MPEG1
};

DabMp2Decoder::DabMp2Decoder(int bitrate)
    : frame_size_(bitrate * 3)  // bitrate * 24ms / 8 = bitrate * 3 bytes
    , pad_(std::make_unique<PadDecoder>())
{
    buffer_.reserve(frame_size_ * 2);  // Reserve space for buffering
}

DabMp2Decoder::~DabMp2Decoder() = default;

size_t DabMp2Decoder::getLabelCount() const { return pad_->getDLSCount(); }
size_t DabMp2Decoder::getPadCrcErrors() const { return pad_->getCrcErrors(); }

void DabMp2Decoder::setDLSCallback(std::function<void(const std::string& text)> cb) {
    pad_->setDLSCallback(std::move(cb));
}

void DabMp2Decoder::setDLPlusCallback(
    std::function<void(const std::string& text, const std::vector<DLPlusTag>& tags)> cb) {
    pad_->setDLPlusCallback(std::move(cb));
}

void DabMp2Decoder::reset() {
    synced_ = false;
    sync_offset_ = 0;
    buffer_.clear();
    pad_->reset();
    frame_count_ = 0;
    mp2_frame_count_ = 0;
    sync_errors_ = 0;
}

void DabMp2Decoder::resync() {
    synced_ = false;
    sync_offset_ = 0;
    buffer_.clear();
    pad_->discontinuity();
}

bool DabMp2Decoder::isSync(const uint8_t* data) {
    // Check for MPEG audio sync word: 11 bits set
    // First byte is 0xFF, second byte starts with 111
    return data[0] == 0xFF && (data[1] & 0xE0) == 0xE0;
}

int DabMp2Decoder::parseHeader(const uint8_t* header) {
    // Parse MPEG audio header (4 bytes)
    // Byte 0: 0xFF (sync)
    // Byte 1: sync + version + layer + protection
    // Byte 2: bitrate + sample_rate + padding + private
    // Byte 3: mode + mode_ext + copyright + original + emphasis

    if (!isSync(header)) return 0;

    int version_id = (header[1] >> 3) & 3;  // 00=MPEG2.5, 01=reserved, 10=MPEG2, 11=MPEG1
    int layer_id = (header[1] >> 1) & 3;     // 00=reserved, 01=L3, 10=L2, 11=L1
    bool protection = (header[1] & 1) == 0;   // 0=protected, 1=not protected

    if (version_id == 1 || layer_id == 0) return 0;  // Reserved values

    int bitrate_idx = (header[2] >> 4) & 0x0F;
    int sample_rate_idx = (header[2] >> 2) & 0x03;
    bool padding = (header[2] >> 1) & 1;
    int mode = (header[3] >> 6) & 3;

    int bitrate = bitrate_table[version_id][layer_id][bitrate_idx];
    int sample_rate = sample_rate_table[version_id][sample_rate_idx];
    int samples = samples_per_frame[version_id][layer_id];

    if (bitrate == 0 || sample_rate == 0) return 0;

    // Calculate frame size
    int frame_size;
    if (layer_id == 3) {  // Layer 1
        frame_size = (12 * bitrate * 1000 / sample_rate + (padding ? 1 : 0)) * 4;
    } else {  // Layer 2 or 3
        int slot_size = (layer_id == 1) ? 1 : 1;  // Layer 3: 1 byte, Layer 2: 1 byte
        frame_size = samples / 8 * bitrate * 1000 / sample_rate + (padding ? slot_size : 0);
    }

    // Store parameters
    params_.version = (version_id == 3) ? 1 : ((version_id == 2) ? 2 : 0);
    params_.layer = (layer_id == 3) ? 1 : ((layer_id == 2) ? 2 : 3);
    params_.protection = protection;
    params_.bitrate = bitrate;
    params_.sample_rate = sample_rate;
    params_.padding = padding;
    params_.channel_mode = mode;
    params_.frame_size = frame_size;

    return frame_size;
}

int DabMp2Decoder::feedFrame(const uint8_t* data, size_t len) {
    return feedFrame(data, len, next_frame_);
}

// the first `bytes` of the buffer go: where its new first byte is
void DabMp2Decoder::consumed(size_t bytes) {
    if (!feed_len_) return;
    size_t at = buf_off_ + bytes;
    buf_frame_ += static_cast<int64_t>(at / feed_len_);
    buf_off_ = at % feed_len_;
}

int DabMp2Decoder::feedFrame(const uint8_t* data, size_t len, int64_t frame_no) {
    frame_count_++;
    next_frame_ = frame_no + 1;
    int frames_extracted = 0;
    if (len == 0) return 0;

    // Where the buffer begins: with nothing in it, at this frame; a
    // subchannel of another size than before starts anew
    if (len != feed_len_ && !buffer_.empty()) {
        resync();
    }
    feed_len_ = len;
    if (buffer_.empty()) {
        buf_frame_ = frame_no;
        buf_off_ = 0;
    }

    // Append to buffer
    buffer_.insert(buffer_.end(), data, data + len);

    // Find and extract MP2 frames
    size_t pos = 0;

    while (pos + 4 <= buffer_.size()) {
        // Look for sync
        if (!isSync(buffer_.data() + pos)) {
            if (synced_) {
                sync_errors_++;
                synced_ = false;
            }
            pos++;
            continue;
        }

        // Parse header to get frame size
        int frame_size = parseHeader(buffer_.data() + pos);
        if (frame_size == 0) {
            pos++;
            continue;
        }

        // Check if we have complete frame
        if (pos + frame_size > buffer_.size()) {
            break;  // Wait for more data
        }

        // Verify next frame sync (if available)
        bool next_valid = true;
        if (pos + frame_size + 2 <= buffer_.size()) {
            next_valid = isSync(buffer_.data() + pos + frame_size);
        }

        if (!synced_) {
            if (next_valid && pos + frame_size + 2 <= buffer_.size()) {
                synced_ = true;
                if (mp2_frame_count_ == 0) {
                    LOG_DEBUG(MP2, "Sync acquired: MPEG" << params_.version
                              << " Layer" << params_.layer << " " << params_.bitrate << "kbps "
                              << params_.sample_rate << "Hz "
                              << (params_.channel_mode == 3 ? "mono" : "stereo"));
                }
            } else if (!next_valid) {
                pos++;
                continue;
            }
        }

        // Emit frame
        if (callback_) {
            callback_(buffer_.data() + pos, frame_size);
        }
        if (timed_callback_) {
            size_t at = buf_off_ + pos;
            int64_t t = (buf_frame_ + static_cast<int64_t>(at / feed_len_)) * 2160 +
                        static_cast<int64_t>(at % feed_len_) * 2160 / static_cast<int64_t>(feed_len_);
            timed_callback_(buffer_.data() + pos, frame_size, t);
        }
        // the PAD at the end of the frame (EN 300 401 clause 7.4): the F-PAD
        // in the last 2 bytes, before them the ScF-CRC (MPEG-1 below 56 kbit/s
        // per channel 2 bytes, else 4), before that the X-PAD
        size_t scf_crc = (params_.version == 1 && params_.bitrate < (params_.channel_mode == 3 ? 56 : 112)) ? 2 : 4;
        if (static_cast<size_t>(frame_size) > 4 + scf_crc + 2) {
            const uint8_t* f = buffer_.data() + pos;
            pad_->process(f + 4, frame_size - 4 - scf_crc - 2, f + frame_size - 2);
        }
        mp2_frame_count_++;
        frames_extracted++;

        pos += frame_size;
    }

    // Remove consumed data
    if (pos > 0) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + pos);
        consumed(pos);
    }

    // Prevent buffer from growing too large
    if (buffer_.size() > frame_size_ * 4) {
        size_t drop = buffer_.size() - frame_size_ * 2;
        buffer_.erase(buffer_.begin(), buffer_.begin() + drop);
        consumed(drop);
        synced_ = false;
    }

    return frames_extracted;
}

} // namespace dvbdab
