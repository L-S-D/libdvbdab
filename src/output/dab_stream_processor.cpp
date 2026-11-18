#include "dab_stream_processor.hpp"
#include "pad_decoder.hpp"
#include "../logging.h"
#include <algorithm>
#include <cctype>
#include <sstream>

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

void DabStreamProcessor::setAacOutput(int mode) {
    if (mode == 2 && !AacTranscoder::available()) {
        // said once per streamer: the audio then plays too slow on players
        // that take the 960 samples of an AU for 1024
        LOG_WARN(MUXER, "DAB+ transcoding was asked for and is not there (the library was built without it, "
                 "or another libavcodec is linked): the audio goes out as ADTS");
        mode = 0;
    }
    aac_output_ = mode;
}

void DabStreamProcessor::setWantedPids(const uint16_t* pids, int count) {
    wanted_all_ = count < 0;
    wanted_pids_.clear();
    for (int i = 0; i < count; i++) wanted_pids_.insert(pids[i]);
    if (aac_output_ != 2) return;
    for (const auto& svc : services_) {
        if (!svc.dabplus || dabplus_decoders_.count(svc.subchannel_id) == 0) continue;
        bool want = isWanted(svc);
        bool has = transcoders_.count(svc.subchannel_id) != 0;
        if (want && !has) {
            makeTranscoder(svc);
        } else if (!want && has) {
            transcoders_.erase(svc.subchannel_id);
            muxer_.dropAudio(svc.sid);  // what waited for a PES is of then, not of the next start
            LOG_DEBUG(DABPLUS, "transcoder of service 0x" << std::hex << svc.sid << std::dec
                      << " stopped: its PIDs are not wanted");
        }
    }
}

bool DabStreamProcessor::isWanted(const TsService& svc) const {
    return wanted_all_ || wanted_pids_.count(svc.pmt_pid) != 0 || wanted_pids_.count(svc.audio_pid) != 0;
}

// a transcoder for a DAB+ service: its output goes to the muxer
void DabStreamProcessor::makeTranscoder(const TsService& svc) {
    uint8_t subchannel_id = svc.subchannel_id;
    transcoders_[subchannel_id] = std::make_unique<AacTranscoder>(svc.bitrate,
        [this, subchannel_id](const uint8_t* data, size_t len, int64_t pts) {
            auto it = subch_to_sid_.find(subchannel_id);
            if (it != subch_to_sid_.end()) {
                muxer_.feedAudioFrame(it->second, data, len, pts);
            }
        });
}

void DabStreamProcessor::addService(const TsService& service) {
    TsService svc = service;
    svc.latm = aac_output_ == 1 && svc.dabplus;
    services_.push_back(svc);
    subch_to_sid_[svc.subchannel_id] = svc.sid;
    muxer_.addService(svc);
}

void DabStreamProcessor::removeService(uint16_t sid) {
    for (auto it = services_.begin(); it != services_.end(); ++it) {
        if (it->sid != sid) continue;
        uint8_t subch = it->subchannel_id;
        stopService(subch);
        subch_to_sid_.erase(subch);
        last_dls_.erase(subch);
        last_dlplus_.erase(subch);
        services_.erase(it);
        break;
    }
    muxer_.removeService(sid);
}

bool DabStreamProcessor::isStarted(uint8_t subchannel_id) const {
    return dabplus_decoders_.count(subchannel_id) != 0 || mp2_decoders_.count(subchannel_id) != 0;
}

bool DabStreamProcessor::getServiceStats(uint8_t subchannel_id, ServiceStats& st) const {
    const TsService* svc = nullptr;
    for (const auto& s : services_) {
        if (s.subchannel_id == subchannel_id) svc = &s;
    }
    if (!svc) return false;

    st = ServiceStats{};
    st.dabplus = svc->dabplus;
    st.started = isStarted(subchannel_id);
    st.output = !svc->dabplus ? 0 : aac_output_ == 1 ? 2 : aac_output_ == 2 ? 3 : 1;
    if (auto it = dabplus_decoders_.find(subchannel_id); it != dabplus_decoders_.end()) {
        const DabPlusDecoder& d = *it->second;
        st.frames = d.getFrameCount();
        st.audio_units = d.getAuCount();
        st.audio_units_lost = d.getAusLost();
        st.crc_errors = d.getCrcErrors();
        st.sync_losses = d.getSyncLosses();
        st.labels = d.getLabelCount();
        st.pad_crc_errors = d.getPadCrcErrors();
    }
    if (auto it = mp2_decoders_.find(subchannel_id); it != mp2_decoders_.end()) {
        const DabMp2Decoder& d = *it->second;
        st.frames = d.getFrameCount();
        st.audio_units = d.getMp2FrameCount();
        st.sync_losses = d.getSyncErrors();
        st.labels = d.getLabelCount();
        st.pad_crc_errors = d.getPadCrcErrors();
    }
    if (auto it = transcoders_.find(subchannel_id); it != transcoders_.end() && it->second) {
        st.transcoding = true;
        st.transcode_errors = it->second->getDecodeErrors();
        st.silent_units = it->second->getSilentAus();
    }
    return true;
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

            decoder->setLatm(aac_output_ == 1);
            DabPlusDecoder* dec = decoder.get();
            if (aac_output_ == 2 && isWanted(*svc)) makeTranscoder(*svc);
            decoder->setTimedCallback([this, subchannel_id, dec](const uint8_t* data, size_t len, int64_t au_slot) {
                audio_frame_count_++;
                if (len < 7) return;

                // decoded and encoded again while the service is wanted
                // (its output goes to the muxer); else not put out, but the
                // tables go on with its time line (the real one, that of
                // the transcoders)
                if (aac_output_ == 2) {
                    auto t = transcoders_.find(subchannel_id);
                    if (t != transcoders_.end()) {
                        t->second->feed(data, len, au_slot, dec->getParams());
                    } else {
                        muxer_.tick(90000 + au_slot * dec->getRealAuDuration90k());
                    }
                    return;
                }

                auto it = subch_to_sid_.find(subchannel_id);
                if (it == subch_to_sid_.end()) return;

                // The AU slot on the time line of the subchannel: lost AUs
                // leave a gap. A slot lasts an AU: 960 samples (LATM) or the
                // 1024 the ADTS headers stand for.
                int64_t pts = 90000 + au_slot * dec->getAuDuration90k();

                muxer_.feedAudioFrame(it->second, data, len, pts);
            });

            decoder->setDLSCallback([this, subchannel_id](const std::string& text) {
                onLabel(subchannel_id, text);
            });
            decoder->setDLPlusCallback([this, subchannel_id](const std::string& text,
                                                             const std::vector<DLPlusTag>& tags) {
                onDLPlus(subchannel_id, text, tags);
            });

            dabplus_decoders_[subchannel_id] = std::move(decoder);
        }
    } else {
        if (mp2_decoders_.find(subchannel_id) == mp2_decoders_.end()) {
            auto decoder = std::make_unique<DabMp2Decoder>(svc->bitrate);

            decoder->setTimedCallback([this, subchannel_id](const uint8_t* data, size_t len, int64_t time90k) {
                audio_frame_count_++;
                if (len < 4) return;

                auto it = subch_to_sid_.find(subchannel_id);
                if (it == subch_to_sid_.end()) return;

                // The time the frame began at on the time line of the
                // subchannel (as the AU slots of DAB+): lost frames leave a
                // gap, whatever the length of an MPEG frame
                muxer_.feedAudioFrame(it->second, data, len, 90000 + time90k);
            });

            decoder->setDLSCallback([this, subchannel_id](const std::string& text) {
                onLabel(subchannel_id, text);
            });
            decoder->setDLPlusCallback([this, subchannel_id](const std::string& text,
                                                             const std::vector<DLPlusTag>& tags) {
                onDLPlus(subchannel_id, text, tags);
            });

            mp2_decoders_[subchannel_id] = std::move(decoder);
        }
    }

    muxer_configured_ = true;
}

// the dynamic label of a service: as RDS RadioText with its audio
void DabStreamProcessor::onLabel(uint8_t subchannel_id, const std::string& text) {
    auto it = subch_to_sid_.find(subchannel_id);
    if (it == subch_to_sid_.end()) return;
    auto& last = last_dls_[subchannel_id];
    if (text != last) {
        last = text;
        LOG_DEBUG(DABPLUS, "dynamic label of service 0x" << std::hex << it->second << std::dec << ": \""
                  << text << "\"");
    }
    muxer_.setRadioText(it->second, text);
}

void DabStreamProcessor::onDLPlus(uint8_t subchannel_id, const std::string& text,
                                  const std::vector<DLPlusTag>& tags) {
    auto it = subch_to_sid_.find(subchannel_id);
    if (it == subch_to_sid_.end()) return;
    std::ostringstream o;
    for (const auto& t : tags)
        o << " " << dlPlusContentTypeToString(t.content_type) << "=\"" << t.extract(text) << "\"";
    auto& last = last_dlplus_[subchannel_id];
    if (o.str() != last) {
        last = o.str();
        LOG_DEBUG(DABPLUS, "DL Plus of service 0x" << std::hex << it->second << std::dec << ":" << o.str());
    }
    // with the RadioText of the label, as RT+
    std::vector<std::array<uint8_t, 3>> plain;
    for (const auto& t : tags) {
        plain.push_back({static_cast<uint8_t>(t.content_type), t.start_marker, t.length_marker});
    }
    muxer_.setRadioTextPlus(it->second, text, plain, !tags.empty() && tags[0].item_toggle,
                            !tags.empty() && tags[0].item_running);
}

void DabStreamProcessor::stopService(uint8_t subchannel_id) {
    dabplus_decoders_.erase(subchannel_id);
    transcoders_.erase(subchannel_id);
    mp2_decoders_.erase(subchannel_id);
    mp2_last_frame_.erase(subchannel_id);
    auto it = subch_to_sid_.find(subchannel_id);
    if (it != subch_to_sid_.end()) muxer_.dropAudio(it->second);
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

void DabStreamProcessor::updateServiceInfo(uint16_t sid, const std::string& language, uint8_t content) {
    for (auto& s : services_) {
        if (s.sid == sid) {
            s.language = language;
            s.content = content;
        }
    }
    muxer_.updateServiceInfo(sid, language, content);
}

void DabStreamProcessor::feedEtiFrame(const uint8_t* eti_ni, size_t len) {
    feedEtiFrame(eti_ni, len, 0);
}

void DabStreamProcessor::feedEtiFrame(const uint8_t* eti_ni, size_t len, uint64_t invalid_scids) {
    if (len < 12) return;

    // FCT (0..249): the frame number, a gap is a lost frame. The same FCT
    // again is the same frame again.
    int fct = eti_ni[4];
    if (fct >= 250) {
        frame_no_++;
    } else if (last_fct_ >= 0) {
        int d = (fct - last_fct_ + 250) % 250;
        if (d == 0) return;
        frame_no_ += d;
        eti_frames_lost_ += static_cast<size_t>(d - 1);
    }
    if (fct < 250) last_fct_ = fct;
    eti_frame_count_++;

    // Parse ETI frame header
    uint8_t nst = eti_ni[5] & 0x7F;
    uint8_t ficf = (eti_ni[5] >> 7) & 0x01;
    uint16_t fp_mid_fl = (eti_ni[6] << 8) | eti_ni[7];
    uint8_t mid = (fp_mid_fl >> 11) & 0x03;

    size_t header_size = 4 + 4 + nst * 4 + 4;
    size_t fic_size = 0;
    if (ficf) {
        // EN 300 799: the FIC of a frame is 24 words, in mode III 32
        fic_size = mid == 3 ? 128 : 96;
    }

    size_t stream_offset = header_size + fic_size;

    for (uint8_t i = 0; i < nst && i < 64; i++) {
        size_t stc_pos = 8 + i * 4;
        if (stc_pos + 4 > len) break;

        uint8_t scid = (eti_ni[stc_pos] >> 2) & 0x3F;
        uint16_t stl = ((eti_ni[stc_pos + 2] & 0x03) << 8) | eti_ni[stc_pos + 3];
        size_t stream_size = stl * 8;

        if (stream_offset + stream_size > len) break;

        // Not in this frame: lost for its decoder
        if ((invalid_scids >> scid) & 1) {
            stream_offset += stream_size;
            continue;
        }

        if (muxer_configured_) {
            auto dec_it = dabplus_decoders_.find(scid);
            if (dec_it != dabplus_decoders_.end()) {
                dec_it->second->feedFrame(eti_ni + stream_offset, stream_size, frame_no_);
                stream_offset += stream_size;
                continue;
            }
            auto mp2_it = mp2_decoders_.find(scid);
            if (mp2_it != mp2_decoders_.end()) {
                // Lost frames: what is buffered of an MPEG frame goes; the
                // time of the next one follows from the frame it begins in
                auto last = mp2_last_frame_.find(scid);
                if (last != mp2_last_frame_.end() && frame_no_ - last->second > 1) {
                    mp2_it->second->resync();
                }
                mp2_last_frame_[scid] = frame_no_;
                mp2_it->second->feedFrame(eti_ni + stream_offset, stream_size, frame_no_);
                stream_offset += stream_size;
                continue;
            }
        }

        // The subchannel of an audio service that is not started carries no
        // packets: its bytes would only now and then look like one
        if (subch_to_sid_.count(scid)) {
            if (data_subchannels_.erase(scid)) {
                epg_decoders_.erase(scid);
            }
            stream_offset += stream_size;
            continue;
        }

        // Process data subchannels for EPG accumulation
        if (epg_decoders_.size() < MAX_DATA_SUBCHANNELS && data_subchannels_.insert(scid).second) {
            auto decoder = std::make_unique<PacketDecoder>();

            // Wire to EHB parser for EPG files
            decoder->setMotCallback([this](uint16_t tid,
                    const MOTHeaderInfo& hdr, const uint8_t* file_data, size_t file_len) {
                if (hdr.content_name.find(".EHB") != std::string::npos) {
                    // again only when it is another file: a transport id
                    // comes again with new content (the counter wraps)
                    uint32_t h = 2166136261u;
                    for (unsigned char ch : hdr.content_name) h = (h ^ ch) * 16777619u;
                    for (size_t i = 0; i < file_len; i++) h = (h ^ file_data[i]) * 16777619u;
                    auto seen = processed_files_.find(tid);
                    if (seen == processed_files_.end() || seen->second != h) {
                        processed_files_[tid] = h;
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
