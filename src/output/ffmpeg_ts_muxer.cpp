#include "ffmpeg_ts_muxer.hpp"
#include <cstring>
#include <ctime>
#include <algorithm>

namespace dvbdab {

// DVB CRC32 table (polynomial 0x04C11DB7)
static const uint32_t dvb_crc32_table[256] = {
    0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
    0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
    0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
    0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
    0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
    0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
    0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
    0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
    0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
    0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
    0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
    0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
    0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
    0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
    0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
    0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
    0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
    0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
    0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
    0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
    0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
    0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
    0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
    0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
    0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
    0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
    0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
    0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
    0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
    0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
    0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
    0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

// ADTS sample rate table
static const int adts_sample_rates[] = {
    96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
    16000, 12000, 11025, 8000, 7350
};

FfmpegTsMuxer::FfmpegTsMuxer() {
}

FfmpegTsMuxer::~FfmpegTsMuxer() {
    finalize();
}

void FfmpegTsMuxer::setEnsemble(uint16_t tsid, const std::string& name) {
    tsid_ = tsid;
    ensemble_name_ = name;
}

int FfmpegTsMuxer::addService(const FfmpegService& service) {
    // Check if this SID already exists (avoid duplicates)
    for (size_t i = 0; i < services_.size(); i++) {
        if (services_[i].sid == service.sid) {
            // Already have this service - update it instead
            services_[i] = service;
            // Update label cache if name is available
            if (!service.name.empty()) {
                service_labels_[service.sid] = service.name;
            }
            return static_cast<int>(i);
        }
    }
    services_.push_back(service);

    // Pre-populate label cache if name is available
    if (!service.name.empty()) {
        service_labels_[service.sid] = service.name;
    }

    return static_cast<int>(services_.size() - 1);
}

int FfmpegTsMuxer::writePacket(void* opaque, const uint8_t* buf, int buf_size) {
    auto* muxer = static_cast<FfmpegTsMuxer*>(opaque);
    if (muxer->output_ && buf_size > 0) {
        muxer->output_(buf, static_cast<size_t>(buf_size));
        muxer->packet_count_ += buf_size / 188;
    }
    return buf_size;
}

int FfmpegTsMuxer::getAdtsSampleRate(const uint8_t* data) {
    if (data[0] != 0xFF || (data[1] & 0xF0) != 0xF0) {
        return 48000;  // Default
    }
    int sr_idx = (data[2] >> 2) & 0xF;
    if (sr_idx < 13) {
        return adts_sample_rates[sr_idx];
    }
    return 48000;
}

bool FfmpegTsMuxer::initialize() {
    if (initialized_ || services_.empty()) {
        return false;
    }

    // Allocate AVIO buffer
    constexpr size_t avio_buffer_size = 188 * 7;  // 7 TS packets
    avio_buffer_ = static_cast<uint8_t*>(av_malloc(avio_buffer_size));
    if (!avio_buffer_) {
        fprintf(stderr, "[FfmpegTsMuxer] Failed to allocate AVIO buffer\n");
        return false;
    }

    // Create custom AVIO context
    avio_ctx_ = avio_alloc_context(
        avio_buffer_,
        avio_buffer_size,
        1,  // write flag
        this,
        nullptr,  // read
        writePacket,
        nullptr   // seek
    );
    if (!avio_ctx_) {
        fprintf(stderr, "[FfmpegTsMuxer] Failed to create AVIO context\n");
        av_free(avio_buffer_);
        avio_buffer_ = nullptr;
        return false;
    }

    // Allocate format context
    int ret = avformat_alloc_output_context2(&fmt_ctx_, nullptr, "mpegts", nullptr);
    if (ret < 0 || !fmt_ctx_) {
        fprintf(stderr, "[FfmpegTsMuxer] Failed to create format context\n");
        avio_context_free(&avio_ctx_);
        avio_buffer_ = nullptr;
        return false;
    }

    fmt_ctx_->pb = avio_ctx_;
    fmt_ctx_->flags |= AVFMT_FLAG_CUSTOM_IO;

    // First pass: create ONE stream per unique subchannel
    for (const auto& svc : services_) {
        // Skip if we already have a stream for this subchannel
        if (subch_to_stream_.count(svc.subchannel_id) > 0) {
            continue;
        }

        AVStream* stream = avformat_new_stream(fmt_ctx_, nullptr);
        if (!stream) {
            avformat_free_context(fmt_ctx_);
            fmt_ctx_ = nullptr;
            avio_context_free(&avio_ctx_);
            avio_buffer_ = nullptr;
            return false;
        }

        int stream_idx = fmt_ctx_->nb_streams - 1;

        // Use codec context to properly configure parameters
        const AVCodec* codec = nullptr;
        if (svc.dabplus) {
            codec = avcodec_find_encoder(AV_CODEC_ID_AAC);
        } else {
            codec = avcodec_find_encoder(AV_CODEC_ID_MP2);
        }

        if (!codec) {
            fprintf(stderr, "[FfmpegTsMuxer] Failed to find encoder for %s\n", svc.name.c_str());
            avformat_free_context(fmt_ctx_);
            fmt_ctx_ = nullptr;
            return false;
        }

        AVCodecContext* codec_ctx = avcodec_alloc_context3(codec);
        if (!codec_ctx) {
            fprintf(stderr, "[FfmpegTsMuxer] Failed to alloc codec context\n");
            avformat_free_context(fmt_ctx_);
            fmt_ctx_ = nullptr;
            return false;
        }

        codec_ctx->codec_type = AVMEDIA_TYPE_AUDIO;
        codec_ctx->codec_id = codec->id;
        codec_ctx->sample_rate = svc.sample_rate;
        codec_ctx->bit_rate = svc.bitrate * 1000;
        av_channel_layout_default(&codec_ctx->ch_layout, 2);
        codec_ctx->sample_fmt = AV_SAMPLE_FMT_FLTP;
        // Set frame_size for mpegts muxer timestamp calculation
        codec_ctx->frame_size = svc.dabplus ? 1024 : 1152;

        // Copy parameters to stream
        ret = avcodec_parameters_from_context(stream->codecpar, codec_ctx);
        int64_t saved_br = codec_ctx->bit_rate;
        avcodec_free_context(&codec_ctx);

        if (ret < 0) {
            fprintf(stderr, "[FfmpegTsMuxer] Failed to copy codec params\n");
            avformat_free_context(fmt_ctx_);
            fmt_ctx_ = nullptr;
            return false;
        }

        stream->codecpar->bit_rate = saved_br;
        // Explicitly set frame_size on codecpar (some FFmpeg versions don't copy it)
        int expected_frame_size = svc.dabplus ? 1024 : 1152;
        stream->codecpar->frame_size = expected_frame_size;
        stream->time_base = AVRational{1, 90000};

        fprintf(stderr, "[FfmpegTsMuxer] Stream %d: frame_size=%d (expected %d)\n",
                stream_idx, stream->codecpar->frame_size, expected_frame_size);

        // Map subchannel to this stream
        // PID will be: PID_AUDIO_BASE + stream_idx (sequential from 0x1000)
        subch_to_stream_[svc.subchannel_id] = stream_idx;
        stream_pts_[stream_idx] = 0;
    }

    // Second pass: create a program for EACH service, pointing to shared stream
    for (const auto& svc : services_) {
        int stream_idx = subch_to_stream_[svc.subchannel_id];

        AVProgram* program = av_new_program(fmt_ctx_, svc.sid);
        if (program) {
            av_dict_set(&program->metadata, "service_name", svc.name.c_str(), 0);
            av_dict_set(&program->metadata, "service_provider", ensemble_name_.c_str(), 0);
            av_dict_set(&program->metadata, "service_type", "0x02", 0);
            // All services sharing a subchannel point to the SAME stream
            av_program_add_stream_index(fmt_ctx_, svc.sid, stream_idx);
            // PCR PID = audio PID = PID_AUDIO_BASE + stream_idx (sequential)
            program->pcr_pid = PID_AUDIO_BASE + stream_idx;
        }

        // Track initial service-to-subchannel mapping for dynamic updates
        sid_to_subch_[svc.sid] = svc.subchannel_id;
    }

    fprintf(stderr, "[FfmpegTsMuxer] Created %d streams for %zu services\n",
            fmt_ctx_->nb_streams, services_.size());

    // Set TSID and ONID to match what we use in EIT
    // Use 1 if tsid_ is 0 since FFmpeg requires 1-65535
    AVDictionary* opts = nullptr;
    char tsid_str[16];
    uint16_t effective_tsid = (tsid_ == 0) ? 1 : tsid_;
    snprintf(tsid_str, sizeof(tsid_str), "%d", effective_tsid);
    av_dict_set(&opts, "mpegts_transport_stream_id", tsid_str, 0);
    av_dict_set(&opts, "mpegts_original_network_id", tsid_str, 0);
    // Set service type globally to radio
    av_dict_set(&opts, "mpegts_service_type", "0x02", 0);
    // Note: FFmpeg assigns PIDs as 0x100 + stream_index
    // To find PID for a subchannel: PID = 0x100 + subch_to_stream_[subchannel_id]

    // Debug: check frame_size right before write_header
    for (unsigned i = 0; i < fmt_ctx_->nb_streams; i++) {
        fprintf(stderr, "[FfmpegTsMuxer] Pre-header stream %u: frame_size=%d\n",
                i, fmt_ctx_->streams[i]->codecpar->frame_size);
    }

    // Write header
    ret = avformat_write_header(fmt_ctx_, &opts);
    av_dict_free(&opts);
    if (ret < 0) {
        char errbuf[128];
        av_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "[FfmpegTsMuxer] Failed to write header: %s\n", errbuf);
        avformat_free_context(fmt_ctx_);
        fmt_ctx_ = nullptr;
        avio_context_free(&avio_ctx_);
        avio_buffer_ = nullptr;
        return false;
    }

    initialized_ = true;

    // Don't inject SDT here - wait until ensemble discovery is complete with all labels
    // FFmpeg will emit its internal SDT, which we'll override later when complete

    fprintf(stderr, "[FfmpegTsMuxer] Initialized with %zu streams\n", services_.size());
    return true;
}

void FfmpegTsMuxer::feedAudioFrame(uint8_t subchannel_id, const uint8_t* data, size_t len, int64_t pts) {
    if (!initialized_ || len == 0) {
        return;
    }

    auto it = subch_to_stream_.find(subchannel_id);
    if (it == subch_to_stream_.end()) {
        return;
    }

    int stream_idx = it->second;

    // Periodic EIT repetition - every ~200 audio frames (~4-5 seconds)
    eit_repeat_counter_++;
    if (eit_repeat_counter_ >= 200) {
        eit_repeat_counter_ = 0;
        // Re-inject EIT for all services with cached metadata
        for (const auto& [sid, event_name] : eit_event_name_) {
            auto text_it = eit_event_text_.find(sid);
            std::string event_text = (text_it != eit_event_text_.end()) ? text_it->second : "";
            if (!event_name.empty()) {
                injectEit(sid, event_name, event_text);
            }
        }
    }

    AVStream* stream = fmt_ctx_->streams[stream_idx];

    // For ADTS, detect sample rate from first frame and update stream if needed
    int sample_rate = 48000;
    if (len >= 7 && data[0] == 0xFF && (data[1] & 0xF0) == 0xF0) {
        sample_rate = getAdtsSampleRate(data);
        if (stream->codecpar->sample_rate != sample_rate) {
            stream->codecpar->sample_rate = sample_rate;
        }
    }

    // Create packet
    AVPacket* pkt = av_packet_alloc();
    if (!pkt) {
        return;
    }

    // Allocate and copy data
    if (av_new_packet(pkt, static_cast<int>(len)) < 0) {
        av_packet_free(&pkt);
        return;
    }
    memcpy(pkt->data, data, len);

    pkt->stream_index = stream_idx;
    pkt->pts = pts;
    pkt->dts = pts;
    pkt->duration = (int64_t)1024 * 90000 / sample_rate;

    // Write packet - use av_write_frame (not interleaved) for immediate output
    // av_interleaved_write_frame buffers waiting for ALL streams which causes delays
    int ret = av_write_frame(fmt_ctx_, pkt);
    if (ret < 0 && ret != AVERROR(EAGAIN)) {
        if (write_error_count_++ < 5) {
            char errbuf[128];
            av_strerror(ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "[FfmpegTsMuxer] Write frame error: %s\n", errbuf);
        }
    }

    av_packet_free(&pkt);
}

void FfmpegTsMuxer::updateMetadata(uint8_t subchannel_id, const FfmpegMetadata& metadata) {
    if (!initialized_) {
        return;
    }

    // Check if metadata actually changed
    auto it = last_metadata_.find(subchannel_id);
    if (it != last_metadata_.end() &&
        it->second.text == metadata.text &&
        it->second.title == metadata.title &&
        it->second.artist == metadata.artist) {
        return;  // No change
    }

    // Store new metadata
    last_metadata_[subchannel_id] = metadata;

    // Find the audio stream for this subchannel
    auto stream_it = subch_to_stream_.find(subchannel_id);
    if (stream_it == subch_to_stream_.end()) {
        return;
    }

    int audio_stream_idx = stream_it->second;
    int64_t pts = stream_pts_[audio_stream_idx];

    // Build ID3v2 tag with timed metadata
    // ID3v2 header (10 bytes) + frames
    std::vector<uint8_t> id3_data;

    // Helper to add ID3v2 text frame
    auto addTextFrame = [&id3_data](const char* frame_id, const std::string& text) {
        if (text.empty()) return;

        // Frame header: 4-byte ID + 4-byte size + 2-byte flags
        id3_data.push_back(frame_id[0]);
        id3_data.push_back(frame_id[1]);
        id3_data.push_back(frame_id[2]);
        id3_data.push_back(frame_id[3]);

        // Size (syncsafe: 7 bits per byte) - text + encoding byte
        uint32_t frame_size = text.size() + 1;  // +1 for encoding byte
        id3_data.push_back((frame_size >> 21) & 0x7F);
        id3_data.push_back((frame_size >> 14) & 0x7F);
        id3_data.push_back((frame_size >> 7) & 0x7F);
        id3_data.push_back(frame_size & 0x7F);

        // Flags (2 bytes)
        id3_data.push_back(0);
        id3_data.push_back(0);

        // Encoding: 0x03 = UTF-8
        id3_data.push_back(0x03);

        // Text content
        for (char c : text) {
            id3_data.push_back(static_cast<uint8_t>(c));
        }
    };

    // Add frames: TIT2 (title), TPE1 (artist), TALB (album), TXXX (full text)
    addTextFrame("TIT2", metadata.title);
    addTextFrame("TPE1", metadata.artist);
    addTextFrame("TALB", metadata.album);

    // Add full DLS text as TXXX frame if we have it
    if (!metadata.text.empty() && metadata.text != metadata.title) {
        // TXXX: encoding + description (null-terminated) + value
        id3_data.push_back('T');
        id3_data.push_back('X');
        id3_data.push_back('X');
        id3_data.push_back('X');

        std::string desc = "DLS";
        uint32_t frame_size = 1 + desc.size() + 1 + metadata.text.size();
        id3_data.push_back((frame_size >> 21) & 0x7F);
        id3_data.push_back((frame_size >> 14) & 0x7F);
        id3_data.push_back((frame_size >> 7) & 0x7F);
        id3_data.push_back(frame_size & 0x7F);
        id3_data.push_back(0);
        id3_data.push_back(0);
        id3_data.push_back(0x03);  // UTF-8

        for (char c : desc) id3_data.push_back(static_cast<uint8_t>(c));
        id3_data.push_back(0);  // null terminator for description
        for (char c : metadata.text) id3_data.push_back(static_cast<uint8_t>(c));
    }

    if (id3_data.empty()) {
        return;
    }

    // Build complete ID3v2.4 tag
    std::vector<uint8_t> id3_tag;

    // ID3 header
    id3_tag.push_back('I');
    id3_tag.push_back('D');
    id3_tag.push_back('3');
    id3_tag.push_back(0x04);  // Version 2.4
    id3_tag.push_back(0x00);  // Revision 0
    id3_tag.push_back(0x00);  // Flags

    // Size (syncsafe)
    uint32_t tag_size = id3_data.size();
    id3_tag.push_back((tag_size >> 21) & 0x7F);
    id3_tag.push_back((tag_size >> 14) & 0x7F);
    id3_tag.push_back((tag_size >> 7) & 0x7F);
    id3_tag.push_back(tag_size & 0x7F);

    // Append frame data
    id3_tag.insert(id3_tag.end(), id3_data.begin(), id3_data.end());

    // Write as timed ID3 packet using the audio stream's PES
    // FFmpeg's mpegts muxer can handle ID3 as side data on audio packets
    // For now, we use a simpler approach: inject as PES private data

    // Create packet with ID3 data as side data
    AVPacket* pkt = av_packet_alloc();
    if (!pkt) {
        return;
    }

    // Allocate packet data
    if (av_new_packet(pkt, static_cast<int>(id3_tag.size())) < 0) {
        av_packet_free(&pkt);
        return;
    }
    memcpy(pkt->data, id3_tag.data(), id3_tag.size());

    // Use the audio stream - FFmpeg will handle the metadata
    pkt->stream_index = audio_stream_idx;
    pkt->pts = pts;
    pkt->dts = pts;

    // Set flags to indicate this is metadata, not audio
    pkt->flags |= AV_PKT_FLAG_KEY;

    av_packet_free(&pkt);

    // Find service ID for this subchannel
    uint16_t service_id = 0;
    for (const auto& svc : services_) {
        if (svc.subchannel_id == subchannel_id) {
            service_id = svc.sid;
            break;
        }
    }

    if (service_id == 0) {
        return;
    }

    // Build event name: "Artist - Title" or just the DLS text
    std::string event_name;
    if (!metadata.artist.empty() && !metadata.title.empty()) {
        event_name = metadata.artist + " - " + metadata.title;
    } else if (!metadata.title.empty()) {
        event_name = metadata.title;
    } else {
        event_name = metadata.text;
    }

    // Inject EIT p/f with the now playing info
    injectEit(service_id, event_name, metadata.text);

    fprintf(stderr, "[FfmpegTsMuxer] EIT update SID=0x%04x: %s\n",
            service_id, event_name.c_str());
}

uint32_t FfmpegTsMuxer::dvbCrc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xffffffff;
    for (size_t i = 0; i < len; i++) {
        crc = (crc << 8) ^ dvb_crc32_table[((crc >> 24) ^ data[i]) & 0xff];
    }
    return crc;
}

std::vector<uint8_t> FfmpegTsMuxer::buildEitSection(uint16_t service_id, uint8_t section_number,
                                                      const std::string& event_name, const std::string& event_text) {
    std::vector<uint8_t> section;

    // Limit strings to fit in descriptor (max 255 bytes total)
    // short_event_descriptor content: lang(3) + name_len(1) + name + text_len(1) + text
    // So name + text must be <= 250 bytes
    std::string name = event_name.substr(0, 120);
    std::string text;  // Skip text to keep it simple - name is enough for now-playing

    // Calculate descriptor length
    // short_event_descriptor: tag(1) + len(1) + lang(3) + name_len(1) + name + text_len(1) + text
    size_t short_event_len = 3 + 1 + name.size() + 1 + text.size();
    size_t descriptors_len = 2 + short_event_len;  // tag + length + content

    // Event loop: event_id(2) + start_time(5) + duration(3) + status/CA/desc_len(2) + descriptors
    size_t event_len = 12 + descriptors_len;

    // Section header: table_id(1) + flags/len(2) + service_id(2) + version(1) + section(1) + last_section(1)
    //                + tsid(2) + onid(2) + segment_last(1) + last_table_id(1) = 14 bytes
    // Plus event data and CRC(4)
    size_t section_len = 11 + event_len + 4;  // after section_length field

    // Build section
    section.push_back(0x4E);  // table_id: EIT actual p/f

    // section_syntax_indicator(1) + reserved_future_use(1) + reserved(2) + section_length(12)
    section.push_back(0xF0 | ((section_len >> 8) & 0x0F));
    section.push_back(section_len & 0xFF);

    // service_id
    section.push_back((service_id >> 8) & 0xFF);
    section.push_back(service_id & 0xFF);

    // reserved(2) + version_number(5) + current_next_indicator(1)
    uint8_t version = eit_version_[service_id] & 0x1F;
    section.push_back(0xC1 | (version << 1));  // reserved=11, version, current=1

    // section_number (0=present, 1=following)
    section.push_back(section_number);

    // last_section_number
    section.push_back(0x01);  // We have present and following

    // transport_stream_id
    section.push_back((tsid_ >> 8) & 0xFF);
    section.push_back(tsid_ & 0xFF);

    // original_network_id (use tsid for simplicity)
    section.push_back((tsid_ >> 8) & 0xFF);
    section.push_back(tsid_ & 0xFF);

    // segment_last_section_number
    section.push_back(0x01);

    // last_table_id
    section.push_back(0x4E);

    // === Event ===
    // event_id (use service_id + section as unique ID)
    uint16_t event_id = (service_id & 0xFFF0) | section_number;
    section.push_back((event_id >> 8) & 0xFF);
    section.push_back(event_id & 0xFF);

    // start_time: MJD(2 bytes) + UTC(3 bytes BCD)
    // Use current time for "present", current+1hour for "following"
    time_t now = time(nullptr);
    if (section_number == 1) {
        now += 3600;  // Following event: 1 hour from now
    }
    struct tm* utc = gmtime(&now);

    // Calculate MJD (Modified Julian Date)
    int y = utc->tm_year + 1900;
    int m = utc->tm_mon + 1;
    int d = utc->tm_mday;
    if (m <= 2) { y--; m += 12; }
    int mjd = 14956 + d + (int)((y - 1900) * 365.25) + (int)((m - 1 - (m > 14 ? 12 : 0) + 1) * 30.6001);

    section.push_back((mjd >> 8) & 0xFF);
    section.push_back(mjd & 0xFF);

    // UTC time in BCD: HHMMSS
    auto toBcd = [](int val) -> uint8_t { return ((val / 10) << 4) | (val % 10); };
    section.push_back(toBcd(utc->tm_hour));
    section.push_back(toBcd(utc->tm_min));
    section.push_back(toBcd(utc->tm_sec));

    // duration: 1 hour in BCD (01:00:00)
    section.push_back(0x01);  // 01 hours
    section.push_back(0x00);  // 00 minutes
    section.push_back(0x00);  // 00 seconds

    // running_status(3) + free_CA_mode(1) + descriptors_loop_length(12)
    // running_status: 4 = running (for present), 1 = not running (for following)
    uint8_t running = (section_number == 0) ? 4 : 1;
    section.push_back((running << 5) | ((descriptors_len >> 8) & 0x0F));
    section.push_back(descriptors_len & 0xFF);

    // === short_event_descriptor (0x4D) ===
    section.push_back(0x4D);  // descriptor_tag
    section.push_back(static_cast<uint8_t>(short_event_len));  // descriptor_length

    // ISO_639_language_code: "ger" (German)
    section.push_back('g');
    section.push_back('e');
    section.push_back('r');

    // event_name_length + event_name
    section.push_back(static_cast<uint8_t>(name.size()));
    for (char c : name) {
        section.push_back(static_cast<uint8_t>(c));
    }

    // text_length + text
    section.push_back(static_cast<uint8_t>(text.size()));
    for (char c : text) {
        section.push_back(static_cast<uint8_t>(c));
    }

    // CRC32
    uint32_t crc = dvbCrc32(section.data(), section.size());
    section.push_back((crc >> 24) & 0xFF);
    section.push_back((crc >> 16) & 0xFF);
    section.push_back((crc >> 8) & 0xFF);
    section.push_back(crc & 0xFF);

    return section;
}

void FfmpegTsMuxer::injectEit(uint16_t service_id, const std::string& event_name, const std::string& event_text) {
    if (!output_) {
        return;
    }

    // Check if content actually changed - only increment version on real changes
    bool content_changed = false;
    auto name_it = eit_event_name_.find(service_id);
    auto text_it = eit_event_text_.find(service_id);
    if (name_it == eit_event_name_.end() || name_it->second != event_name ||
        text_it == eit_event_text_.end() || text_it->second != event_text) {
        content_changed = true;
        // Increment EIT version only when content changes
        eit_version_[service_id] = (eit_version_[service_id] + 1) & 0x1F;
    }

    // Cache for periodic repetition
    eit_event_name_[service_id] = event_name;
    eit_event_text_[service_id] = event_text;

    // Build EIT section for "present" event (section 0)
    std::vector<uint8_t> section = buildEitSection(service_id, 0, event_name, event_text);

    // Wrap in TS packets (PID 0x12 for EIT)
    const uint16_t eit_pid = 0x0012;
    size_t section_offset = 0;
    bool first_packet = true;

    while (section_offset < section.size()) {
        uint8_t ts_packet[188];
        memset(ts_packet, 0xFF, 188);

        // TS header
        ts_packet[0] = 0x47;  // Sync byte
        ts_packet[1] = (first_packet ? 0x40 : 0x00) | ((eit_pid >> 8) & 0x1F);  // PUSI + PID high
        ts_packet[2] = eit_pid & 0xFF;  // PID low
        ts_packet[3] = 0x10 | (eit_cc_ & 0x0F);  // No adaptation, payload only, CC
        eit_cc_ = (eit_cc_ + 1) & 0x0F;

        size_t payload_start = 4;
        size_t payload_len = 184;

        if (first_packet) {
            // Pointer field for first packet
            ts_packet[4] = 0x00;  // Pointer field
            payload_start = 5;
            payload_len = 183;
            first_packet = false;
        }

        size_t copy_len = std::min(payload_len, section.size() - section_offset);
        memcpy(ts_packet + payload_start, section.data() + section_offset, copy_len);
        section_offset += copy_len;

        // Output the TS packet
        output_(ts_packet, 188);
        packet_count_++;
    }
}

int FfmpegTsMuxer::getStreamIndex(uint8_t subchannel_id) const {
    auto it = subch_to_stream_.find(subchannel_id);
    return (it != subch_to_stream_.end()) ? it->second : -1;
}

uint16_t FfmpegTsMuxer::getPid(uint8_t subchannel_id) const {
    auto it = subch_to_stream_.find(subchannel_id);
    if (it == subch_to_stream_.end()) return 0;
    return PID_AUDIO_BASE + it->second;
}

std::vector<uint8_t> FfmpegTsMuxer::updateSubchannelMapping(uint16_t service_id, uint8_t new_subchannel_id) {
    std::vector<uint8_t> new_subchannels;

    if (!initialized_) return new_subchannels;

    // Check if subchannel already exists
    if (subch_to_stream_.find(new_subchannel_id) == subch_to_stream_.end()) {
        // New subchannel - caller needs to create decoder
        new_subchannels.push_back(new_subchannel_id);
    }

    // Update service-to-subchannel mapping
    uint8_t old_subch = 0xFF;
    auto old_it = sid_to_subch_.find(service_id);
    if (old_it != sid_to_subch_.end()) {
        old_subch = old_it->second;
    }
    sid_to_subch_[service_id] = new_subchannel_id;

    // If subchannel changed, inject updated PMT
    if (old_subch != new_subchannel_id && subch_to_stream_.find(new_subchannel_id) != subch_to_stream_.end()) {
        int stream_idx = subch_to_stream_[new_subchannel_id];
        uint16_t audio_pid = PID_AUDIO_BASE + stream_idx;

        // Find service info
        for (const auto& svc : services_) {
            if (svc.sid == service_id) {
                // Build stream list for this program
                std::vector<std::pair<uint16_t, uint8_t>> streams;
                // 0x0F = ADTS AAC (for DAB+), 0x03 = MPEG-1 Audio Layer II (for DAB)
                uint8_t stream_type = svc.dabplus ? 0x0F : 0x03;
                streams.push_back({audio_pid, stream_type});

                // Inject PMT with new audio PID
                // PMT PID is typically 0x100 + program_number, but we use 0x1000 + program
                uint16_t pmt_pid = 0x1000 + (service_id & 0x0FFF);
                injectPmt(service_id, pmt_pid, audio_pid, streams);

                fprintf(stderr, "[FfmpegTsMuxer] Updated SID=0x%04x: SubCh %d -> %d, PID=0x%04x\n",
                        service_id, old_subch, new_subchannel_id, audio_pid);
                break;
            }
        }
    }

    return new_subchannels;
}

int FfmpegTsMuxer::addNewSubchannel(uint8_t subchannel_id, bool dabplus, int sample_rate, int bitrate) {
    // Cannot add streams after FFmpeg write_header - return existing or -1
    // This is a limitation of FFmpeg's mpegts muxer
    auto it = subch_to_stream_.find(subchannel_id);
    if (it != subch_to_stream_.end()) {
        return it->second;
    }

    fprintf(stderr, "[FfmpegTsMuxer] Cannot add new subchannel %d after initialization (FFmpeg limitation)\n",
            subchannel_id);
    return -1;
}

std::vector<uint8_t> FfmpegTsMuxer::buildPmtSection(uint16_t program_number, uint16_t pcr_pid,
                                                     const std::vector<std::pair<uint16_t, uint8_t>>& streams) {
    std::vector<uint8_t> section;

    // Calculate section length
    size_t descriptors_len = 0;  // No program-level descriptors
    size_t stream_info_len = streams.size() * 5;  // 5 bytes per stream (type + pid + es_info_len)
    size_t section_len = 9 + descriptors_len + stream_info_len + 4;  // +4 for CRC

    // Table ID = 0x02 (PMT)
    section.push_back(0x02);

    // Section syntax indicator (1) + reserved (1) + 0 (2) + section_length (12)
    section.push_back(0xB0 | ((section_len >> 8) & 0x0F));
    section.push_back(section_len & 0xFF);

    // Program number
    section.push_back((program_number >> 8) & 0xFF);
    section.push_back(program_number & 0xFF);

    // Reserved (2) + version (5) + current_next (1)
    section.push_back(0xC1);  // version 0, current

    // Section number
    section.push_back(0x00);

    // Last section number
    section.push_back(0x00);

    // Reserved (3) + PCR_PID (13)
    section.push_back(0xE0 | ((pcr_pid >> 8) & 0x1F));
    section.push_back(pcr_pid & 0xFF);

    // Reserved (4) + program_info_length (12)
    section.push_back(0xF0 | ((descriptors_len >> 8) & 0x0F));
    section.push_back(descriptors_len & 0xFF);

    // Stream info
    for (const auto& [pid, stream_type] : streams) {
        section.push_back(stream_type);
        section.push_back(0xE0 | ((pid >> 8) & 0x1F));
        section.push_back(pid & 0xFF);
        section.push_back(0xF0);  // ES_info_length = 0
        section.push_back(0x00);
    }

    // CRC32
    uint32_t crc = dvbCrc32(section.data(), section.size());
    section.push_back((crc >> 24) & 0xFF);
    section.push_back((crc >> 16) & 0xFF);
    section.push_back((crc >> 8) & 0xFF);
    section.push_back(crc & 0xFF);

    return section;
}

void FfmpegTsMuxer::injectPmt(uint16_t program_number, uint16_t pmt_pid, uint16_t pcr_pid,
                               const std::vector<std::pair<uint16_t, uint8_t>>& streams) {
    if (!output_) return;

    std::vector<uint8_t> section = buildPmtSection(program_number, pcr_pid, streams);

    // Get/update continuity counter for this program
    uint8_t& cc = pmt_cc_[program_number];

    // Wrap in TS packets
    size_t section_offset = 0;
    bool first_packet = true;

    while (section_offset < section.size()) {
        uint8_t ts_packet[188];
        memset(ts_packet, 0xFF, 188);

        // TS header
        ts_packet[0] = 0x47;
        ts_packet[1] = (first_packet ? 0x40 : 0x00) | ((pmt_pid >> 8) & 0x1F);
        ts_packet[2] = pmt_pid & 0xFF;
        ts_packet[3] = 0x10 | (cc & 0x0F);
        cc = (cc + 1) & 0x0F;

        size_t payload_start = 4;
        size_t payload_len = 184;

        if (first_packet) {
            ts_packet[4] = 0x00;  // Pointer field
            payload_start = 5;
            payload_len = 183;
            first_packet = false;
        }

        size_t copy_len = std::min(payload_len, section.size() - section_offset);
        memcpy(ts_packet + payload_start, section.data() + section_offset, copy_len);
        section_offset += copy_len;

        output_(ts_packet, 188);
        packet_count_++;
    }
}

std::vector<uint8_t> FfmpegTsMuxer::buildSdtSection() {
    std::vector<uint8_t> section;

    // SDT actual (table_id = 0x42)
    section.push_back(0x42);

    // Placeholder for section_length (will be filled later)
    size_t length_pos = section.size();
    section.push_back(0x00);
    section.push_back(0x00);

    // transport_stream_id
    section.push_back((tsid_ >> 8) & 0xFF);
    section.push_back(tsid_ & 0xFF);

    // reserved(2) + version_number(5) + current_next_indicator(1)
    section.push_back(0xC1 | ((sdt_version_ & 0x1F) << 1));

    // section_number
    section.push_back(0x00);

    // last_section_number
    section.push_back(0x00);

    // original_network_id
    section.push_back((onid_ >> 8) & 0xFF);
    section.push_back(onid_ & 0xFF);

    // reserved_future_use
    section.push_back(0xFF);

    // Service entries
    for (const auto& svc : services_) {
        // service_id
        section.push_back((svc.sid >> 8) & 0xFF);
        section.push_back(svc.sid & 0xFF);

        // reserved_future_use(6) + EIT_schedule_flag(1) + EIT_present_following_flag(1)
        section.push_back(0xFD);  // EIT p/f available

        // running_status(3) + free_CA_mode(1) + descriptors_loop_length(12)
        size_t desc_len_pos = section.size();
        section.push_back(0x00);  // placeholder
        section.push_back(0x00);  // placeholder

        size_t desc_start = section.size();

        // Service descriptor (tag 0x48)
        section.push_back(0x48);  // descriptor_tag
        size_t desc_length_pos = section.size();
        section.push_back(0x00);  // placeholder for descriptor_length

        // service_type: 0x02 = radio
        section.push_back(0x02);

        // Get current label (use cached or service name)
        std::string label;
        auto it = service_labels_.find(svc.sid);
        if (it != service_labels_.end() && !it->second.empty()) {
            label = it->second;
        } else {
            label = svc.name;
        }

        // service_provider_name_length + provider name
        std::string provider = ensemble_name_;
        if (provider.size() > 255) provider = provider.substr(0, 255);
        section.push_back(static_cast<uint8_t>(provider.size()));
        for (char c : provider) {
            section.push_back(static_cast<uint8_t>(c));
        }

        // service_name_length + service name
        if (label.size() > 255) label = label.substr(0, 255);
        section.push_back(static_cast<uint8_t>(label.size()));
        for (char c : label) {
            section.push_back(static_cast<uint8_t>(c));
        }

        // Fill in descriptor length
        section[desc_length_pos] = static_cast<uint8_t>(section.size() - desc_length_pos - 1);

        // Fill in descriptors_loop_length (running_status=4, free_CA=0)
        size_t desc_loop_len = section.size() - desc_start;
        section[desc_len_pos] = 0x80 | ((desc_loop_len >> 8) & 0x0F);
        section[desc_len_pos + 1] = desc_loop_len & 0xFF;
    }

    // Calculate section_length (from after length field to end including CRC)
    size_t section_length = section.size() - 3 + 4;  // +4 for CRC
    section[length_pos] = 0xF0 | ((section_length >> 8) & 0x0F);
    section[length_pos + 1] = section_length & 0xFF;

    // Add CRC32
    uint32_t crc = dvbCrc32(section.data(), section.size());
    section.push_back((crc >> 24) & 0xFF);
    section.push_back((crc >> 16) & 0xFF);
    section.push_back((crc >> 8) & 0xFF);
    section.push_back(crc & 0xFF);

    return section;
}

void FfmpegTsMuxer::injectSdt() {
    if (!output_) {
        return;
    }

    std::vector<uint8_t> section = buildSdtSection();

    // Wrap in TS packets (PID 0x11 for SDT)
    const uint16_t sdt_pid = 0x0011;
    size_t section_offset = 0;
    bool first_packet = true;

    while (section_offset < section.size()) {
        uint8_t ts_packet[188];
        memset(ts_packet, 0xFF, 188);

        // TS header
        ts_packet[0] = 0x47;  // Sync byte
        ts_packet[1] = (first_packet ? 0x40 : 0x00) | ((sdt_pid >> 8) & 0x1F);
        ts_packet[2] = sdt_pid & 0xFF;
        ts_packet[3] = 0x10 | (sdt_cc_ & 0x0F);
        sdt_cc_ = (sdt_cc_ + 1) & 0x0F;

        size_t payload_start = 4;
        size_t payload_len = 184;

        if (first_packet) {
            ts_packet[4] = 0x00;  // Pointer field
            payload_start = 5;
            payload_len = 183;
            first_packet = false;
        }

        size_t copy_len = std::min(payload_len, section.size() - section_offset);
        memcpy(ts_packet + payload_start, section.data() + section_offset, copy_len);
        section_offset += copy_len;

        output_(ts_packet, 188);
        packet_count_++;
    }
}

void FfmpegTsMuxer::updateServiceLabel(uint16_t service_id, const std::string& name) {
    if (!initialized_ || name.empty()) {
        return;
    }

    // Check if label actually changed
    auto it = service_labels_.find(service_id);
    if (it != service_labels_.end() && it->second == name) {
        return;  // No change
    }

    // Update cached label
    service_labels_[service_id] = name;

    // Increment SDT version
    sdt_version_ = (sdt_version_ + 1) & 0x1F;

    // Inject updated SDT
    injectSdt();

    fprintf(stderr, "[FfmpegTsMuxer] SDT update SID=0x%04x: %s\n", service_id, name.c_str());
}

void FfmpegTsMuxer::updateServiceLabelBySubch(uint8_t subchannel_id, const std::string& name) {
    // Find service ID for this subchannel
    for (const auto& svc : services_) {
        if (svc.subchannel_id == subchannel_id) {
            updateServiceLabel(svc.sid, name);
            return;
        }
    }
}

void FfmpegTsMuxer::updateEnsembleName(const std::string& name) {
    if (!initialized_ || name.empty() || name == ensemble_name_) {
        return;
    }

    ensemble_name_ = name;

    // Increment SDT version and inject
    sdt_version_ = (sdt_version_ + 1) & 0x1F;
    injectSdt();

    fprintf(stderr, "[FfmpegTsMuxer] SDT update ensemble: %s\n", name.c_str());
}

void FfmpegTsMuxer::finalize() {
    if (fmt_ctx_ && initialized_) {
        av_write_trailer(fmt_ctx_);
        initialized_ = false;
    }

    if (fmt_ctx_) {
        if (fmt_ctx_->pb && !(fmt_ctx_->flags & AVFMT_FLAG_CUSTOM_IO)) {
            avio_closep(&fmt_ctx_->pb);
        }
        avformat_free_context(fmt_ctx_);
        fmt_ctx_ = nullptr;
    }

    if (avio_ctx_) {
        avio_context_free(&avio_ctx_);
        avio_ctx_ = nullptr;
        avio_buffer_ = nullptr;
    }
}

} // namespace dvbdab
