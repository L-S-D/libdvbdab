#include "dab_stream_processor.hpp"
#include <algorithm>
#include <cctype>

namespace dvbdab {

DabStreamProcessor::DabStreamProcessor() {
    ehb_parser_.setScheduleCallback([this](const ServiceSchedule& schedule) {
        onScheduleParsed(schedule);
    });
}

EpgSchedule DabStreamProcessor::convertSchedule(const ServiceSchedule& schedule) {
    EpgSchedule epg_schedule;
    epg_schedule.service_id = schedule.service_id;
    epg_schedule.service_name = schedule.service_name;
    epg_schedule.last_update = time(nullptr);

    for (const auto& event : schedule.events) {
        EpgProgramme prog;
        prog.short_id = std::to_string(event.event_id);
        prog.name = event.title;
        prog.description = event.description;
        prog.start_time = event.start_time;
        prog.duration_seconds = event.duration_seconds;
        epg_schedule.programmes.push_back(prog);
    }
    return epg_schedule;
}

void DabStreamProcessor::onScheduleParsed(const ServiceSchedule& schedule) {
    epg_schedule_count_++;

    // Call external callback if set (for gap tracking etc.)
    if (external_schedule_callback_) {
        external_schedule_callback_(schedule);
    }

    EpgSchedule epg_schedule = convertSchedule(schedule);

    if (muxer_configured_) {
        muxer_.updateSchedule(schedule.service_id, epg_schedule);
    } else {
        // Buffer for later - merge events if we already have data for this service
        auto& existing = early_schedules_[schedule.service_id];
        if (existing.programmes.empty()) {
            existing = epg_schedule;
        } else {
            // Append new events
            for (const auto& prog : epg_schedule.programmes) {
                existing.programmes.push_back(prog);
            }
        }
    }
}

void DabStreamProcessor::setEnsemble(uint16_t eid, const std::string& name, const std::string& provider) {
    muxer_.setEnsemble(eid, name, provider);
}

void DabStreamProcessor::addService(const TsService& service) {
    services_.push_back(service);
    subch_to_sid_[service.subchannel_id] = service.sid;
    pts_counter_[service.sid] = 90000;  // Start at 1 second
    muxer_.addService(service);
}

void DabStreamProcessor::startService(uint8_t subchannel_id) {
    const TsService* svc = nullptr;
    for (const auto& s : services_) {
        if (s.subchannel_id == subchannel_id) {
            svc = &s;
            break;
        }
    }
    if (!svc) return;

    if (svc->dabplus) {
        if (dabplus_decoders_.find(subchannel_id) == dabplus_decoders_.end()) {
            auto decoder = std::make_unique<DabPlusDecoder>(svc->bitrate);

            decoder->setCallback([this, subchannel_id](const uint8_t* data, size_t len) {
                audio_frame_count_++;
                if (len < 7) return;

                auto it = subch_to_sid_.find(subchannel_id);
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

                muxer_.feedAudioFrame(it->second, data, len, pts);
            });

            decoder->setDLSCallback([this, subchannel_id](const std::string& text) {
                if (text.size() < 5) return;
                if (!std::isupper(static_cast<unsigned char>(text[0]))) return;

                auto it = subch_to_sid_.find(subchannel_id);
                if (it != subch_to_sid_.end()) {
                    muxer_.setNowPlaying(it->second, text);
                }
            });

            dabplus_decoders_[subchannel_id] = std::move(decoder);
        }
    } else {
        if (mp2_decoders_.find(subchannel_id) == mp2_decoders_.end()) {
            auto decoder = std::make_unique<DabMp2Decoder>(svc->bitrate);

            decoder->setCallback([this, subchannel_id](const uint8_t* data, size_t len) {
                audio_frame_count_++;
                if (len < 4) return;

                auto it = subch_to_sid_.find(subchannel_id);
                if (it == subch_to_sid_.end()) return;

                // Parse sample rate from MP2 header
                // Syncword(12) + ID(1) + Layer(2) + Protection(1) + Bitrate(4) + SampleRate(2) + ...
                int sample_rate = 48000;  // Default fallback
                if (data[0] == 0xFF && (data[1] & 0xE0) == 0xE0) {
                    int version = (data[1] >> 3) & 0x03;  // 0=MPEG2.5, 2=MPEG2, 3=MPEG1
                    int sr_idx = (data[2] >> 2) & 0x03;
                    static const int sr_table[4][4] = {
                        {11025, 12000, 8000, 0},   // MPEG2.5
                        {0, 0, 0, 0},              // Reserved
                        {22050, 24000, 16000, 0},  // MPEG2
                        {44100, 48000, 32000, 0}   // MPEG1
                    };
                    if (version != 1 && sr_idx < 3) {
                        sample_rate = sr_table[version][sr_idx];
                    }
                }

                // Safety check to prevent division by zero
                if (sample_rate == 0) sample_rate = 48000;

                int64_t pts = pts_counter_[it->second];
                // 1152 samples per MP2 Layer II frame
                pts_counter_[it->second] += (int64_t)1152 * 90000 / sample_rate;

                muxer_.feedAudioFrame(it->second, data, len, pts);
            });

            mp2_decoders_[subchannel_id] = std::move(decoder);
        }
    }

    muxer_configured_ = true;
}

void DabStreamProcessor::stopService(uint8_t subchannel_id) {
    dabplus_decoders_.erase(subchannel_id);
    mp2_decoders_.erase(subchannel_id);
}

void DabStreamProcessor::startAllServices() {
    for (const auto& svc : services_) {
        startService(svc.subchannel_id);
    }
    // Flush any early schedules now that muxer is configured
    flushEarlySchedules();
}

void DabStreamProcessor::flushEarlySchedules() {
    if (!early_schedules_.empty() && muxer_configured_) {
        for (const auto& [sid, schedule] : early_schedules_) {
            muxer_.updateSchedule(sid, schedule);
        }
        early_schedules_.clear();
    }
}

void DabStreamProcessor::updateServiceLabel(uint16_t sid, const std::string& name) {
    muxer_.updateServiceLabel(sid, name);
}

void DabStreamProcessor::feedEtiFrame(const uint8_t* eti_ni, size_t len) {
    if (len < 12) return;
    eti_frame_count_++;

    // Parse ETI frame header
    uint8_t nst = eti_ni[5] & 0x7F;
    uint8_t ficf = (eti_ni[5] >> 7) & 0x01;
    uint16_t fp_mid_fl = (eti_ni[6] << 8) | eti_ni[7];
    uint8_t mid = (fp_mid_fl >> 11) & 0x03;

    size_t header_size = 4 + 4 + nst * 4 + 4;
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

    for (uint8_t i = 0; i < nst && i < 64; i++) {
        size_t stc_pos = 8 + i * 4;
        if (stc_pos + 4 > len) break;

        uint8_t scid = (eti_ni[stc_pos] >> 2) & 0x3F;
        uint16_t stl = ((eti_ni[stc_pos + 2] & 0x03) << 8) | eti_ni[stc_pos + 3];
        size_t stream_size = stl * 8;

        if (stream_offset + stream_size > len) break;

        if (muxer_configured_) {
            auto dec_it = dabplus_decoders_.find(scid);
            if (dec_it != dabplus_decoders_.end()) {
                dec_it->second->feedFrame(eti_ni + stream_offset, stream_size);
                stream_offset += stream_size;
                continue;
            }
            auto mp2_it = mp2_decoders_.find(scid);
            if (mp2_it != mp2_decoders_.end()) {
                mp2_it->second->feedFrame(eti_ni + stream_offset, stream_size);
                stream_offset += stream_size;
                continue;
            }
        }

        // Process data subchannels for EPG accumulation
        if (data_subchannels_.insert(scid).second) {
            auto decoder = std::make_unique<PacketDecoder>();

            // Wire to EHB parser for EPG files
            decoder->setMotCallback([this](uint16_t tid,
                    const MOTHeaderInfo& hdr, const uint8_t* file_data, size_t file_len) {
                if (hdr.content_name.find(".EHB") != std::string::npos) {
                    if (processed_tids_.insert(tid).second) {
                        ehb_parser_.parse(hdr.content_name, file_data, file_len);
                    }
                }
            });

            epg_decoders_[scid] = std::move(decoder);
        }

        auto epg_it = epg_decoders_.find(scid);
        if (epg_it != epg_decoders_.end()) {
            epg_it->second->feedSubchannelData(eti_ni + stream_offset, stream_size);
        }

        stream_offset += stream_size;
    }
}

} // namespace dvbdab
