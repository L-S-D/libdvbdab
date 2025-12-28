// DAB+ Audio Decoder - ported from eti-tools ni2out.c
// Original Copyright (C) 2008 David Crawley (OpenDAB)
// License: GPLv3

#include "dabplus_decoder.hpp"
#include "pad_decoder.hpp"
#include <cstring>

// Define DABPLUS_DEBUG to enable verbose debug output
// #define DABPLUS_DEBUG

namespace dvbdab {

// FireCode CRC table - G(x) = x^16 + x^14 + x^13 + x^12 + x^11 + x^5 + x^3 + x^2 + x + 1
static const uint16_t fire_crc_table[256] = {
    0x0000, 0x782f, 0xf05e, 0x8871, 0x9893, 0xe0bc, 0x68cd, 0x10e2,
    0x4909, 0x3126, 0xb957, 0xc178, 0xd19a, 0xa9b5, 0x21c4, 0x59eb,
    0x9212, 0xea3d, 0x624c, 0x1a63, 0x0a81, 0x72ae, 0xfadf, 0x82f0,
    0xdb1b, 0xa334, 0x2b45, 0x536a, 0x4388, 0x3ba7, 0xb3d6, 0xcbf9,
    0x5c0b, 0x2424, 0xac55, 0xd47a, 0xc498, 0xbcb7, 0x34c6, 0x4ce9,
    0x1502, 0x6d2d, 0xe55c, 0x9d73, 0x8d91, 0xf5be, 0x7dcf, 0x05e0,
    0xce19, 0xb636, 0x3e47, 0x4668, 0x568a, 0x2ea5, 0xa6d4, 0xdefb,
    0x8710, 0xff3f, 0x774e, 0x0f61, 0x1f83, 0x67ac, 0xefdd, 0x97f2,
    0xb816, 0xc039, 0x4848, 0x3067, 0x2085, 0x58aa, 0xd0db, 0xa8f4,
    0xf11f, 0x8930, 0x0141, 0x796e, 0x698c, 0x11a3, 0x99d2, 0xe1fd,
    0x2a04, 0x522b, 0xda5a, 0xa275, 0xb297, 0xcab8, 0x42c9, 0x3ae6,
    0x630d, 0x1b22, 0x9353, 0xeb7c, 0xfb9e, 0x83b1, 0x0bc0, 0x73ef,
    0xe41d, 0x9c32, 0x1443, 0x6c6c, 0x7c8e, 0x04a1, 0x8cd0, 0xf4ff,
    0xad14, 0xd53b, 0x5d4a, 0x2565, 0x3587, 0x4da8, 0xc5d9, 0xbdf6,
    0x760f, 0x0e20, 0x8651, 0xfe7e, 0xee9c, 0x96b3, 0x1ec2, 0x66ed,
    0x3f06, 0x4729, 0xcf58, 0xb777, 0xa795, 0xdfba, 0x57cb, 0x2fe4,
    0x0803, 0x702c, 0xf85d, 0x8072, 0x9090, 0xe8bf, 0x60ce, 0x18e1,
    0x410a, 0x3925, 0xb154, 0xc97b, 0xd999, 0xa1b6, 0x29c7, 0x51e8,
    0x9a11, 0xe23e, 0x6a4f, 0x1260, 0x0282, 0x7aad, 0xf2dc, 0x8af3,
    0xd318, 0xab37, 0x2346, 0x5b69, 0x4b8b, 0x33a4, 0xbbd5, 0xc3fa,
    0x5408, 0x2c27, 0xa456, 0xdc79, 0xcc9b, 0xb4b4, 0x3cc5, 0x44ea,
    0x1d01, 0x652e, 0xed5f, 0x9570, 0x8592, 0xfdbd, 0x75cc, 0x0de3,
    0xc61a, 0xbe35, 0x3644, 0x4e6b, 0x5e89, 0x26a6, 0xaed7, 0xd6f8,
    0x8f13, 0xf73c, 0x7f4d, 0x0762, 0x1780, 0x6faf, 0xe7de, 0x9ff1,
    0xb015, 0xc83a, 0x404b, 0x3864, 0x2886, 0x50a9, 0xd8d8, 0xa0f7,
    0xf91c, 0x8133, 0x0942, 0x716d, 0x618f, 0x19a0, 0x91d1, 0xe9fe,
    0x2207, 0x5a28, 0xd259, 0xaa76, 0xba94, 0xc2bb, 0x4aca, 0x32e5,
    0x6b0e, 0x1321, 0x9b50, 0xe37f, 0xf39d, 0x8bb2, 0x03c3, 0x7bec,
    0xec1e, 0x9431, 0x1c40, 0x646f, 0x748d, 0x0ca2, 0x84d3, 0xfcfc,
    0xa517, 0xdd38, 0x5549, 0x2d66, 0x3d84, 0x45ab, 0xcdda, 0xb5f5,
    0x7e0c, 0x0623, 0x8e52, 0xf67d, 0xe69f, 0x9eb0, 0x16c1, 0x6eee,
    0x3705, 0x4f2a, 0xc75b, 0xbf74, 0xaf96, 0xd7b9, 0x5fc8, 0x27e7
};

// CRC-16 CCITT table - G(x) = x^16 + x^12 + x^5 + 1
static const uint16_t crc16_table[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

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
    frame_index_ = 0;
    synced_ = false;
    superframe_buf_.clear();
    frame_count_ = 0;
    superframe_count_ = 0;
    au_count_ = 0;
    crc_errors_ = 0;
    if (pad_decoder_) {
        pad_decoder_->reset();
    }
}

bool DabPlusDecoder::checkFireCode(const uint8_t* buf) {
    // Check if FireCode CRC in bytes 0-1 matches bytes 2-10
    uint16_t crc = 0;
    const uint8_t* ptr = buf + 2;

    for (int i = 0; i < 9; i++) {
        crc = (crc << 8) ^ fire_crc_table[((crc >> 8) ^ ptr[i]) & 0xff];
    }

    return ((crc >> 8) == buf[0]) && ((crc & 0xff) == buf[1]);
}

bool DabPlusDecoder::checkAuCrc(const uint8_t* buf, size_t len) {
    // CRC-16 CCITT check - result should be 0 if valid
    uint16_t crc = 0xffff;

    for (size_t i = 0; i < len; i++) {
        crc = (crc << 8) ^ crc16_table[((crc >> 8) ^ buf[i]) & 0xff];
    }

    return crc == 0;
}

void DabPlusDecoder::buildAdtsHeader(uint8_t* header, size_t au_len) {
    // Sample rate index: 32k=0x5, 16k=0x8, 48k=0x3, 24k=0x6
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
    // Auto-detect frame size from first call
    if (frame_size_ == 0) {
        frame_size_ = len;
        bitrate_ = len / 3;  // Recalculate bitrate from actual frame size
        superframe_buf_.reserve(frame_size_ * 5);
#ifdef DABPLUS_DEBUG
        fprintf(stderr, "[DEBUG] Auto-detected frame_size=%zu bitrate=%d\n", frame_size_, bitrate_);
#endif
    }

    if (len != frame_size_) {
        return false;
    }

    frame_count_++;

    // Check FireCode on potential first frame of superframe
    // The first frame of a superframe should pass FireCode CRC check
    bool fire_ok = checkFireCode(data);

    // If we haven't synced yet, look for FireCode match
    if (!synced_) {
        if (fire_ok) {
            synced_ = true;
            frame_index_ = 0;
#ifdef DABPLUS_DEBUG
            if (frame_count_ <= 10) {
                fprintf(stderr, "[DEBUG] FireCode SYNC at frame %d\n", frame_count_);
            }
#endif
        } else {
            // Keep looking for sync
            return false;
        }
    } else if (frame_index_ == 0 && !fire_ok && frame_count_ > 10) {
        // Lost sync - resync
        synced_ = false;
        return false;
    }

    // Accumulate frame
    size_t offset = frame_index_ * frame_size_;
    if (superframe_buf_.size() < offset + len) {
        superframe_buf_.resize(offset + len);
    }
    std::memcpy(superframe_buf_.data() + offset, data, len);
    frame_index_++;

    // Process when we have 5 frames
    if (frame_index_ >= 5) {
        processSuperframe();
        frame_index_ = 0;
        return true;
    }

    return false;
}

void DabPlusDecoder::processSuperframe() {
    superframe_count_++;

    uint8_t* sf = superframe_buf_.data();
    int s = bitrate_ / 8;  // RS columns
    size_t audio_super_frame_size = frame_size_ * 5 - s * 10;  // Exclude RS parity

#ifdef DABPLUS_DEBUG
    if (superframe_count_ <= 3) {
        fprintf(stderr, "[DEBUG] Superframe #%d: bitrate=%d s=%d audio_size=%zu first16: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                superframe_count_, bitrate_, s, audio_super_frame_size,
                sf[0], sf[1], sf[2], sf[3], sf[4], sf[5], sf[6], sf[7]);
    }
#endif

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

#ifdef DABPLUS_DEBUG
    if (superframe_count_ <= 3) {
        fprintf(stderr, "[DEBUG] SF params: num_aus=%d dac=%d sbr=%d ch=%d ps=%d mpeg=%d\n",
                params_.num_aus, params_.dac_rate, params_.sbr_flag,
                params_.aac_channel_mode, params_.ps_flag, params_.mpeg_surround);
        fprintf(stderr, "[DEBUG] AU offsets: ");
        for (int i = 0; i < params_.num_aus; i++)
            fprintf(stderr, "[%d]=%d/%d ", i, au_start[i], au_size[i]);
        fprintf(stderr, "\n");
    }
#endif

    // Process each AU
    for (int i = 0; i < params_.num_aus; i++) {
        if (au_size[i] <= 0 || au_start[i] + au_size[i] < 2 ||
            static_cast<size_t>(au_start[i] + au_size[i]) > audio_super_frame_size) {
#ifdef DABPLUS_DEBUG
            if (superframe_count_ <= 3)
                fprintf(stderr, "[DEBUG] AU%d skipped: size=%d start=%d\n", i, au_size[i], au_start[i]);
#endif
            continue;
        }

        // Invert CRC bits (DAB+ uses inverted CRC)
        sf[au_start[i] + au_size[i] - 2] ^= 0xff;
        sf[au_start[i] + au_size[i] - 1] ^= 0xff;

        // Check AU CRC
        if (!checkAuCrc(sf + au_start[i], au_size[i])) {
            crc_errors_++;
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
        if (callback_ && au_data_len > 0 && au_data_len < output_buf_.size() - 7) {
            buildAdtsHeader(output_buf_.data(), au_data_len);
            std::memcpy(output_buf_.data() + 7, sf + au_start[i], au_data_len);
            callback_(output_buf_.data(), au_data_len + 7);
            au_count_++;
#ifdef DABPLUS_DEBUG
            if (au_count_ <= 10)
                fprintf(stderr, "[DEBUG] AU emitted #%d len=%zu\n", au_count_, au_data_len + 7);
#endif
        }
#ifdef DABPLUS_DEBUG
        else if (superframe_count_ <= 3) {
            fprintf(stderr, "[DEBUG] AU%d NOT emitted: au_len=%zu\n", i, au_data_len);
        }
#endif
    }
}

} // namespace dvbdab
