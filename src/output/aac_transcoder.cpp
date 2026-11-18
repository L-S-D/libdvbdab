// DAB+ audio decoded (faad2) and encoded again as AAC-LC in ADTS (libavcodec)

#include "aac_transcoder.hpp"
#include "../logging.h"

#ifdef DVBDAB_WITH_TRANSCODE
#include <neaacdec.h>
extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/channel_layout.h>
#include <libavutil/mathematics.h>
}
#include <algorithm>
#include <array>
#include <vector>
#endif

namespace dvbdab {

#ifdef DVBDAB_WITH_TRANSCODE

namespace {

// sampling frequency index of a rate (ISO/IEC 14496-3)
int sfi_of(int rate) {
    static const int rates[] = {96000, 88200, 64000, 48000, 44100, 32000, 24000,
                                22050, 16000, 12000, 11025, 8000, 7350};
    for (int i = 0; i < 13; i++)
        if (rates[i] == rate) return i;
    return 3;
}

// MSB first into a buffer
struct Bits {
    uint8_t* p;
    int n = 0;
    void put(uint32_t value, int bits) {
        for (int i = bits - 1; i >= 0; i--, n++) {
            if ((n & 7) == 0) p[n >> 3] = 0;
            if ((value >> i) & 1) p[n >> 3] |= 0x80 >> (n & 7);
        }
    }
};

// a gap longer than this (AUs, 5 s at 40 ms) starts the time line anew
constexpr int64_t MAX_GAP_AUS = 125;

} // namespace

struct AacTranscoder::Impl {
    Output out;
    DabPlusParams params{};
    bool open = false;
    NeAACDecHandle dec = nullptr;
    AVCodecContext* enc = nullptr;
    AVFrame* frame = nullptr;
    AVPacket* pkt = nullptr;
    int rate = 0;                   // output sampling rate
    int channels = 0;               // output channels
    int au_samples = 0;             // samples (per channel) of an AU at the output rate
    int64_t next_slot = -1;         // the AU slot expected next
    int64_t next_pts = 0;           // sample number of the next sample into the encoder
    std::vector<std::vector<float>> fifo;   // per channel, waiting for a frame
    std::array<uint8_t, 8192> adts{};

    explicit Impl(Output o) : out(std::move(o)) {}
    ~Impl() { close(); }

    void close() {
        if (dec) NeAACDecClose(dec);
        dec = nullptr;
        if (enc) avcodec_free_context(&enc);
        av_frame_free(&frame);
        av_packet_free(&pkt);
        fifo.clear();
        next_slot = -1;
        open = false;
    }

    bool same(const DabPlusParams& p) const {
        return p.dac_rate == params.dac_rate && p.sbr_flag == params.sbr_flag &&
               p.aac_channel_mode == params.aac_channel_mode && p.ps_flag == params.ps_flag;
    }

    bool start(const DabPlusParams& p);
    void push_pcm(const float* pcm, size_t frames, int ch);
    void push_silence(int64_t frames);
    void encode_ready();
    void emit();
};

// faad2 with the AudioSpecificConfig of the subchannel (AAC LC with 960-sample
// frames, SBR and PS by their sync extensions), the AAC-LC encoder
bool AacTranscoder::Impl::start(const DabPlusParams& p) {
    close();
    params = p;
    int out_rate = p.dac_rate ? 48000 : 32000;
    int core_rate = p.sbr_flag ? out_rate / 2 : out_rate;
    bool ps = p.sbr_flag && p.ps_flag;
    int core_channels = (p.aac_channel_mode && !ps) ? 2 : 1;

    uint8_t asc[8] = {0};
    Bits b{asc};
    b.put(2, 5);                        // audioObjectType: AAC LC
    b.put(sfi_of(core_rate), 4);
    b.put(core_channels, 4);
    b.put(1, 1);                        // GASpecificConfig: frameLengthFlag, 960
    b.put(0, 1);                        // dependsOnCoreCoder
    b.put(0, 1);                        // extensionFlag
    if (p.sbr_flag) {
        b.put(0x2b7, 11);               // syncExtensionType: SBR
        b.put(5, 5);
        b.put(1, 1);                    // sbrPresentFlag
        b.put(sfi_of(out_rate), 4);     // extensionSamplingFrequencyIndex
        if (ps) {
            b.put(0x548, 11);           // syncExtensionType: PS
            b.put(1, 1);                // psPresentFlag
        }
    }

    dec = NeAACDecOpen();
    NeAACDecConfigurationPtr conf = NeAACDecGetCurrentConfiguration(dec);
    conf->outputFormat = FAAD_FMT_FLOAT;
    conf->downMatrix = 0;
    NeAACDecSetConfiguration(dec, conf);
    unsigned long r = 0;
    unsigned char ch = 0;
    if (NeAACDecInit2(dec, asc, (b.n + 7) / 8, &r, &ch) < 0 || r == 0 || ch == 0 || ch > 2) {
        LOG_WARN(DABPLUS, "transcoder: faad2 does not take the subchannel (rate " << r
                 << ", channels " << (int)ch << ")");
        close();
        return false;
    }
    rate = static_cast<int>(r);
    channels = ch;
    au_samples = 960 * rate / core_rate;

    const AVCodec* codec = avcodec_find_encoder(AV_CODEC_ID_AAC);
    if (!codec || !(enc = avcodec_alloc_context3(codec))) {
        LOG_WARN(DABPLUS, "transcoder: no AAC encoder in libavcodec");
        close();
        return false;
    }
    enc->sample_fmt = AV_SAMPLE_FMT_FLTP;
    enc->sample_rate = rate;
    av_channel_layout_default(&enc->ch_layout, channels);
    // AAC-LC at a rate that adds nothing audible to the (lossy) DAB+ audio:
    // 128 kbit/s per channel; lossless would be LPCM or FLAC, which TS players
    // and tvheadend do not take
    int kbps = channels > 1 ? 256 : 128;
    enc->bit_rate = kbps * 1000;
#ifdef AV_PROFILE_AAC_LOW
    enc->profile = AV_PROFILE_AAC_LOW;
#else
    enc->profile = FF_PROFILE_AAC_LOW;
#endif
    enc->time_base = AVRational{1, rate};
    enc->thread_count = 1;
    if (avcodec_open2(enc, codec, nullptr) < 0 || enc->frame_size <= 0) {
        LOG_WARN(DABPLUS, "transcoder: the AAC encoder does not open");
        close();
        return false;
    }
    frame = av_frame_alloc();
    pkt = av_packet_alloc();
    if (!frame || !pkt) {
        close();
        return false;
    }
    frame->format = AV_SAMPLE_FMT_FLTP;
    frame->sample_rate = rate;
    frame->nb_samples = enc->frame_size;
    av_channel_layout_copy(&frame->ch_layout, &enc->ch_layout);
    if (av_frame_get_buffer(frame, 0) < 0) {
        close();
        return false;
    }
    fifo.assign(channels, {});
    open = true;
    LOG_DEBUG(DABPLUS, "transcoder: " << rate << " Hz, " << channels << " channels, "
              << au_samples << " samples per AU, AAC-LC " << kbps << " kbit/s");
    return true;
}

void AacTranscoder::Impl::push_pcm(const float* pcm, size_t frames, int ch) {
    for (int c = 0; c < channels; c++) {
        auto& f = fifo[c];
        size_t at = f.size();
        f.resize(at + frames);
        for (size_t i = 0; i < frames; i++)
            f[at + i] = pcm[i * ch + std::min(c, ch - 1)];
    }
}

void AacTranscoder::Impl::push_silence(int64_t frames) {
    if (frames <= 0) return;
    for (auto& f : fifo)
        f.resize(f.size() + static_cast<size_t>(frames), 0.0f);
}

// a frame of the encoder for each frame_size samples there are
void AacTranscoder::Impl::encode_ready() {
    size_t fs = static_cast<size_t>(enc->frame_size);
    while (!fifo.empty() && fifo[0].size() >= fs) {
        if (av_frame_make_writable(frame) < 0) return;
        for (int c = 0; c < channels; c++) {
            std::copy(fifo[c].begin(), fifo[c].begin() + fs, reinterpret_cast<float*>(frame->data[c]));
            fifo[c].erase(fifo[c].begin(), fifo[c].begin() + fs);
        }
        frame->pts = next_pts;
        next_pts += fs;
        if (avcodec_send_frame(enc, frame) < 0) return;
        while (avcodec_receive_packet(enc, pkt) == 0) {
            emit();
            av_packet_unref(pkt);
        }
    }
}

// an encoded frame with its ADTS header
void AacTranscoder::Impl::emit() {
    size_t len = static_cast<size_t>(pkt->size) + 7;
    if (pkt->size <= 0 || len > adts.size() || len > 0x1fff) return;
    int sfi = sfi_of(rate);
    adts[0] = 0xff;
    adts[1] = 0xf1;                                 // MPEG-4, no CRC
    adts[2] = (1 << 6) | (sfi << 2) | ((channels >> 2) & 1);   // AAC LC
    adts[3] = ((channels & 3) << 6) | ((len >> 11) & 3);
    adts[4] = (len >> 3) & 0xff;
    adts[5] = ((len & 7) << 5) | 0x1f;
    adts[6] = 0xfc;
    std::copy(pkt->data, pkt->data + pkt->size, adts.begin() + 7);
    out(adts.data(), len, 90000 + av_rescale(pkt->pts, 90000, rate));
}

AacTranscoder::AacTranscoder(int /*bitrate*/, Output out)
    : impl_(std::make_unique<Impl>(std::move(out))) {}

AacTranscoder::~AacTranscoder() = default;

bool AacTranscoder::available() {
    return true;
}

void AacTranscoder::feed(const uint8_t* adts, size_t len, int64_t au_slot, const DabPlusParams& params) {
    Impl& m = *impl_;
    if ((!m.open || !m.same(params)) && !m.start(params)) return;
    if (len < 8 || adts[0] != 0xff) return;
    size_t hl = (adts[1] & 1) ? 7 : 9;
    if (len <= hl) return;

    // the AUs lost before it: silence of their length (after what the
    // decoder still has: faad2 puts out an AU one later); a long gap, or one
    // backwards, starts the time line anew
    int64_t lost = 0;
    if (m.next_slot < 0 || au_slot < m.next_slot || au_slot - m.next_slot > MAX_GAP_AUS) {
        if (m.next_slot >= 0 && !m.start(params)) return;
        m.next_pts = au_slot * m.au_samples;
    } else {
        lost = au_slot - m.next_slot;
    }
    m.next_slot = au_slot + 1;

    NeAACDecFrameInfo fi;
    void* pcm = NeAACDecDecode(m.dec, &fi, const_cast<uint8_t*>(adts + hl), len - hl);
    if (fi.error || (fi.samples && !pcm)) {
        decode_errors_++;
        m.push_silence(m.au_samples);
    } else if (fi.samples > 0 && fi.channels > 0) {
        m.push_pcm(static_cast<const float*>(pcm), fi.samples / fi.channels, fi.channels);
    }
    if (lost > 0) {
        silent_aus_ += lost;
        m.push_silence(lost * m.au_samples);
    }
    m.encode_ready();
}

#else  // without faad2 and libavcodec

struct AacTranscoder::Impl {};

AacTranscoder::AacTranscoder(int, Output) {}
AacTranscoder::~AacTranscoder() = default;

bool AacTranscoder::available() {
    return false;
}

void AacTranscoder::feed(const uint8_t*, size_t, int64_t, const DabPlusParams&) {}

#endif

} // namespace dvbdab
