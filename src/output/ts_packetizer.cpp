#include "ts_packetizer.hpp"
#include "pad_decoder.hpp"
#include <cstring>

namespace dvbdab {

TsPacketizer::TsPacketizer() {
}

TsPacketizer::~TsPacketizer() {
    finalize();
}

void TsPacketizer::setOutput(TsOutputCallback callback) {
    output_ = std::move(callback);
}

void TsPacketizer::finalize() {
    if (muxer_) {
        muxer_->finalize();
    }
}

void TsPacketizer::updateServiceLabel(uint16_t service_id, const std::string& name) {
    if (muxer_) {
        muxer_->updateServiceLabel(service_id, name);
    }
}

void TsPacketizer::updateEnsembleName(const std::string& name) {
    if (muxer_) {
        muxer_->updateEnsembleName(name);
    }
}

void TsPacketizer::configureFromEnsemble(const lsdvb::DABEnsemble& ensemble) {
    // Clear existing configuration
    services_.clear();
    subch_to_sid_.clear();
    pts_counter_.clear();
    decoders_.clear();
    mp2_decoders_.clear();

    // Create FFmpeg muxer
    muxer_ = std::make_unique<FfmpegTsMuxer>();
    muxer_->setOutput([this](const uint8_t* data, size_t len) {
        if (output_) {
            output_(data, len);
        }
    });

    muxer_->setEnsemble(ensemble.eid, ensemble.label);

    // Add services
    for (const auto& dab_svc : ensemble.services) {
        FfmpegService fs;
        fs.sid = dab_svc.sid;
        fs.name = dab_svc.label;
        fs.dabplus = dab_svc.dabplus;
        fs.subchannel_id = dab_svc.subchannel_id;
        fs.bitrate = dab_svc.bitrate;
        fs.sample_rate = 48000;  // DAB+ with SBR outputs 48kHz

        muxer_->addService(fs);

        // Store for ETI processing
        services_[dab_svc.sid] = dab_svc;
        subch_to_sid_[dab_svc.subchannel_id] = dab_svc.sid;
        pts_counter_[dab_svc.sid] = 90000;  // Start at 1 second

        // Create decoders
        if (dab_svc.dabplus) {
            auto decoder = std::make_unique<DabPlusDecoder>(dab_svc.bitrate);
            uint8_t scid = dab_svc.subchannel_id;

            // Audio callback
            decoder->setCallback([this, scid](const uint8_t* data, size_t len) {
                if (!muxer_ || len < 7) return;
                auto it = subch_to_sid_.find(scid);
                if (it == subch_to_sid_.end()) return;

                // Parse sample rate from ADTS header
                static const int adts_rates[] = {96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350};
                int sample_rate = 48000;
                if (data[0] == 0xFF && (data[1] & 0xF0) == 0xF0) {
                    int sr_idx = (data[2] >> 2) & 0xF;
                    if (sr_idx < 13) sample_rate = adts_rates[sr_idx];
                }

                int64_t pts = pts_counter_[it->second];
                pts_counter_[it->second] += (int64_t)1024 * 90000 / sample_rate;

                muxer_->feedAudioFrame(scid, data, len, pts);
            });

            // DL Plus callback - disabled due to parsing issues
            // Plain DLS callback below handles now-playing info
            (void)decoder;  // Suppress unused warning

            // DLS callback - triggers EIT update with now-playing text
            decoder->setDLSCallback([this, scid](const std::string& text) {
                if (dls_callback_) {
                    auto it = subch_to_sid_.find(scid);
                    if (it != subch_to_sid_.end()) {
                        dls_callback_(it->second, text);
                    }
                }
                // Update EIT with DLS text - filter out garbage
                if (muxer_ && text.size() >= 5) {
                    // Must start with uppercase letter (proper title/artist)
                    char c = text[0];
                    if (!std::isupper(static_cast<unsigned char>(c))) {
                        return;  // Skip garbage
                    }
                    // Skip promotional text (contains URLs or hotline numbers)
                    if (text.find("www.") != std::string::npos ||
                        text.find(".de") != std::string::npos ||
                        text.find("Hotline") != std::string::npos ||
                        text.find("0800") != std::string::npos ||
                        text.find("0221") != std::string::npos) {
                        return;  // Skip ads/info
                    }
                    FfmpegMetadata meta;
                    meta.text = text;
                    meta.title = text;
                    muxer_->updateMetadata(scid, meta);
                }
            });

            decoders_[scid] = std::move(decoder);
        } else {
            // DAB/MP2
            auto mp2_decoder = std::make_unique<DabMp2Decoder>(dab_svc.bitrate);
            uint8_t scid = dab_svc.subchannel_id;

            mp2_decoder->setCallback([this, scid](const uint8_t* data, size_t len) {
                if (!muxer_ || len < 4) return;
                auto it = subch_to_sid_.find(scid);
                if (it == subch_to_sid_.end()) return;

                int64_t pts = pts_counter_[it->second];
                pts_counter_[it->second] += 2160;  // 1152 samples / 48000 * 90000

                muxer_->feedAudioFrame(scid, data, len, pts);
            });

            mp2_decoders_[scid] = std::move(mp2_decoder);
        }
    }

    // Initialize muxer
    if (!muxer_->initialize()) {
        fprintf(stderr, "[ERROR] Failed to initialize FFmpeg muxer\n");
        return;
    }

    configured_ = true;
}

void TsPacketizer::feedEtiFrame(const uint8_t* data, size_t len) {
    if (!configured_ || len < 6144) {
        return;
    }

    // Check SYNC
    if (data[0] != 0xFF) return;

    // Frame info
    uint8_t ficf = (data[5] >> 7) & 0x01;
    uint8_t nst = data[5] & 0x7F;
    uint16_t fp_mid_fl = (data[6] << 8) | data[7];
    uint8_t mid = (fp_mid_fl >> 11) & 0x03;

    // Header size
    size_t header_size = 4 + 4 + nst * 4 + 4;

    // FIC size
    size_t fic_size = 0;
    if (ficf) {
        switch (mid) {
            case 1: fic_size = 96; break;
            case 2: fic_size = 32; break;
            case 3: fic_size = 128; break;
            case 4: fic_size = 96; break;
            default: fic_size = 96; break;
        }
    }

    size_t stream_offset = header_size + fic_size;

    // Process streams
    for (uint8_t i = 0; i < nst && i < 64; i++) {
        size_t stc_pos = 8 + i * 4;
        if (stc_pos + 4 > len) break;

        uint8_t scid = (data[stc_pos] >> 2) & 0x3F;
        uint16_t stl = ((data[stc_pos + 2] & 0x03) << 8) | data[stc_pos + 3];
        size_t stream_size = stl * 8;

        if (stream_offset + stream_size > len) break;

        // Feed to decoder
        auto dec_it = decoders_.find(scid);
        if (dec_it != decoders_.end()) {
            dec_it->second->feedFrame(data + stream_offset, stream_size);
        } else {
            auto mp2_it = mp2_decoders_.find(scid);
            if (mp2_it != mp2_decoders_.end()) {
                mp2_it->second->feedFrame(data + stream_offset, stream_size);
            }
        }

        stream_offset += stream_size;
    }

    frame_counter_++;
}

void TsPacketizer::processSubchannel(const lsdvb::DABService& service, const uint8_t* data, size_t len) {
    // Not used anymore - decoders handle this via callbacks
    (void)service;
    (void)data;
    (void)len;
}

} // namespace dvbdab
