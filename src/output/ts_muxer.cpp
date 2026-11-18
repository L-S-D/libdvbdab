#include "ts_muxer.hpp"
#include "rds_uecp.hpp"
#include <algorithm>

namespace dvbdab {

TsMuxer::TsMuxer() = default;

void TsMuxer::setEnsemble(uint16_t tsid, const std::string& name, const std::string& provider) {
    // a new label of the ensemble is the provider of its services
    if (provider != provider_name_) {
        bool changed = false;
        for (auto& s : services_) {
            if (s.provider == provider_name_ && s.provider != provider) {
                s.provider = provider;
                changed = true;
            }
        }
        if (changed) sdt_version_ = (sdt_version_ + 1) & 0x1F;
    }
    tsid_ = tsid;
    ensemble_name_ = name;
    provider_name_ = provider;
    onid_ = tsid;  // Use same as TSID for simplicity
}

void TsMuxer::removeService(uint16_t sid) {
    auto it = sid_to_index_.find(sid);
    if (it == sid_to_index_.end()) return;
    services_.erase(services_.begin() + static_cast<std::ptrdiff_t>(it->second));
    sid_to_index_.clear();
    subch_to_sid_.clear();
    for (size_t i = 0; i < services_.size(); i++) {
        sid_to_index_[services_[i].sid] = i;
        subch_to_sid_[services_[i].subchannel_id] = services_[i].sid;
    }
    audio_buffers_.erase(sid);
    eit_pf_.erase(sid);
    frame_step_.erase(sid);
    last_audio_pts_.erase(sid);
    radio_text_.erase(sid);
    // the PAT and SDT no longer list it
    pat_version_ = (pat_version_ + 1) & 0x1F;
    sdt_version_ = (sdt_version_ + 1) & 0x1F;
}

void TsMuxer::addService(const TsService& service) {
    services_.push_back(service);
    sid_to_index_[service.sid] = services_.size() - 1;
    subch_to_sid_[service.subchannel_id] = service.sid;
    cc_[service.pmt_pid] = 0;
    cc_[service.audio_pid] = 0;

    // The PAT and SDT that went out earlier do not list this service: a new
    // version makes receivers read them again
    if (last_psi_pts_ >= 0) {
        pat_version_ = (pat_version_ + 1) & 0x1F;
        sdt_version_ = (sdt_version_ + 1) & 0x1F;
    }
}

void TsMuxer::updateServiceLabel(uint16_t sid, const std::string& name) {
    auto it = sid_to_index_.find(sid);
    if (it != sid_to_index_.end() && services_[it->second].name != name) {
        services_[it->second].name = name;
        sdt_version_ = (sdt_version_ + 1) & 0x1F;
    }
}

void TsMuxer::updateServiceInfo(uint16_t sid, const std::string& language, uint8_t content) {
    auto it = sid_to_index_.find(sid);
    if (it == sid_to_index_.end()) return;
    TsService& s = services_[it->second];
    if (s.language == language && s.content == content) return;
    if (s.language != language) pmt_version_ = (pmt_version_ + 1) & 0x1F;
    s.language = language;
    s.content = content;
    // its events say both
    if (service_schedules_.count(sid)) {
        schedule_changed_[sid] = true;
        eit_carousel_pending_ = true;
    }
}

void TsMuxer::setRadioText(uint16_t sid, const std::string& text) {
    std::string rds = rdsRadioText(text);
    auto& rt = radio_text_[sid];
    if (rds == rt.text && !rt.frame.empty()) return;
    rt.text = rds;
    rt.ab = !rt.ab;  // a new text: receivers start it anew
    rt.frame = uecpRadioTextFrame(rds, rt.ab);
    rt.plus_frame.clear();  // the tags were about the old text
    rt.sent_pts = -1;
}

void TsMuxer::setRadioTextPlus(uint16_t sid, const std::string& text, const std::vector<std::array<uint8_t, 3>>& tags,
                               bool item_toggle, bool item_running) {
    auto it = radio_text_.find(sid);
    if (it == radio_text_.end()) return;
    RadioText& rt = it->second;
    RdsText mapped = rdsRadioTextMapped(text);
    if (mapped.text != rt.text) return;  // not the text that is on
    std::vector<uint8_t> frame = uecpRtPlusFrame(rtPlusTags(mapped, tags), item_toggle, item_running);
    if (frame == rt.plus_frame) return;
    rt.plus_frame = std::move(frame);
    rt.sent_pts = -1;
}

void TsMuxer::setNowPlaying(uint16_t sid, const std::string& title, const std::string& artist) {
    setRadioText(sid, artist.empty() ? title : artist + " - " + title);
}

void TsMuxer::outputRadioTexts(int64_t pts) {
    for (auto& [sid, rt] : radio_text_) {
        if (rt.sent_pts >= 0 && pts - rt.sent_pts < RADIO_TEXT_REPEAT_PTS) continue;
        auto it = sid_to_index_.find(sid);
        if (it == sid_to_index_.end() || !services_[it->second].rds_pid) continue;
        // stamped with the time of its own audio (the services of an ensemble
        // need not be on one time line); when to send goes by the tick
        auto own = last_audio_pts_.find(sid);
        std::vector<uint8_t> frames = rt.frame;
        frames.insert(frames.end(), rt.plus_frame.begin(), rt.plus_frame.end());
        outputPes(services_[it->second].rds_pid, frames.data(), frames.size(),
                  own != last_audio_pts_.end() ? own->second : pts, false, 0, 0xBD);
        rt.sent_pts = pts;
    }
}

void TsMuxer::writePacket(const uint8_t* packet) {
    if (output_) {
        output_(packet, TS_MUXER_PACKET_SIZE);
        packet_count_++;
    }
}

void TsMuxer::outputSection(uint16_t pid, const std::vector<uint8_t>& section, bool set_discontinuity) {
    if (section.empty()) return;

    size_t offset = 0;
    bool first = true;

    while (offset < section.size()) {
        uint8_t packet[TS_MUXER_PACKET_SIZE];
        std::fill(packet, packet + TS_MUXER_PACKET_SIZE, 0xFF);

        // TS header
        packet[0] = 0x47;  // Sync byte
        packet[1] = (first ? 0x40 : 0x00) | ((pid >> 8) & 0x1F);
        packet[2] = pid & 0xFF;

        uint8_t& cc = cc_[pid];

        size_t payload_start;
        if (first && set_discontinuity) {
            // Add adaptation field with discontinuity_indicator for EIT version changes
            packet[3] = 0x30 | (cc & 0x0F);  // Adaptation + payload
            packet[4] = 1;  // Adaptation field length
            packet[5] = 0x80;  // discontinuity_indicator=1
            packet[6] = 0x00;  // Pointer field
            payload_start = 7;
            set_discontinuity = false;  // Only on first packet
        } else {
            packet[3] = 0x10 | (cc & 0x0F);  // Payload only, no adaptation
            payload_start = 4;
            if (first) {
                packet[4] = 0x00;  // Pointer field
                payload_start = 5;
            }
        }
        cc = (cc + 1) & 0x0F;

        if (first) first = false;

        size_t payload_len = TS_MUXER_PACKET_SIZE - payload_start;
        size_t to_copy = std::min(payload_len, section.size() - offset);
        std::copy(section.data() + offset, section.data() + offset + to_copy, packet + payload_start);
        offset += to_copy;

        writePacket(packet);
    }
}

void TsMuxer::outputPat() {
    outputSection(PID_PAT, buildPatSection(tsid_, pat_version_, services_));
}

void TsMuxer::outputPmt(const TsService& service) {
    outputSection(service.pmt_pid, buildPmtSection(service, pmt_version_));
}

void TsMuxer::outputSdt() {
    for (const auto& section : buildSdtSections(tsid_, onid_, sdt_version_, services_, provider_name_)) {
        outputSection(PID_SDT, section);
    }
}

// Helper to build one EIT p/f section
void TsMuxer::updateSchedule(uint16_t service_id, const EpgSchedule& schedule) {
    if (schedule.programmes.empty()) return;

    // The service id comes from a file name in the stream: only so many
    // schedules are kept (the ones of services this TS has go out)
    if (service_schedules_.size() >= MAX_SCHEDULES && !service_schedules_.count(service_id)) {
        return;
    }

    // Merge programmes into existing schedule (EHB sends partial schedules)
    auto& existing = service_schedules_[service_id];
    existing.service_id = schedule.service_id;
    existing.service_name = schedule.service_name;
    existing.last_update = schedule.last_update;

    // Add new programmes; one with the start time of one that is there
    // replaces it when it says something else (a corrected title or
    // duration). A duration of 86400 is the "all day" placeholder that is
    // cut to the next start below: not a change.
    for (const auto& prog : schedule.programmes) {
        bool found = false;
        for (auto& existing_prog : existing.programmes) {
            if (existing_prog.start_time == prog.start_time) {
                found = true;
                if (existing_prog.name != prog.name || existing_prog.description != prog.description ||
                    (prog.duration_seconds != 86400 && existing_prog.duration_seconds != prog.duration_seconds)) {
                    existing_prog = prog;
                    schedule_changed_[service_id] = true;
                }
                break;
            }
        }
        if (!found) {
            existing.programmes.push_back(prog);
            // Mark that this service has pending changes
            schedule_changed_[service_id] = true;
        }
    }

    // Sort by start_time for proper EPG ordering and duration adjustment
    std::sort(existing.programmes.begin(), existing.programmes.end(),
        [](const EpgProgramme& a, const EpgProgramme& b) {
            return a.start_time < b.start_time;
        });

    // What is over goes, or the schedule (and the EIT sent every few seconds)
    // grows as long as the stream runs. By the clock only when the schedule
    // is of now (not when a recording of last year is played); the oldest
    // when there are too many all the same.
    auto& progs = existing.programmes;
    size_t drop = 0;
    time_t now = time(nullptr);
    if (!progs.empty() && progs.back().start_time > now - SCHEDULE_PAST_SECONDS) {
        while (drop < progs.size() &&
               progs[drop].start_time + progs[drop].duration_seconds < now - SCHEDULE_PAST_SECONDS) {
            drop++;
        }
    }
    if (progs.size() - drop > MAX_PROGRAMMES) {
        drop = progs.size() - MAX_PROGRAMMES;
    }
    if (drop) {
        progs.erase(progs.begin(), progs.begin() + drop);
        schedule_changed_[service_id] = true;
    }

    // Adjust "all day" placeholder durations (86400 = 24 hours, mapped from DAB EPG max ~18:12)
    // to end at the start of the next event
    for (size_t i = 0; i < existing.programmes.size(); i++) {
        auto& prog = existing.programmes[i];
        if (prog.duration_seconds == 86400 && i + 1 < existing.programmes.size()) {
            // There's a next event - adjust duration to end at its start
            time_t next_start = existing.programmes[i + 1].start_time;
            if (next_start > prog.start_time) {
                prog.duration_seconds = static_cast<int>(next_start - prog.start_time);
                schedule_changed_[service_id] = true;
            }
        }
    }

    // Mark that we have pending changes - will be applied at next carousel cycle
    if (schedule_changed_[service_id]) {
        eit_carousel_pending_ = true;
    }
}

void TsMuxer::outputEitScheduleCarousel() {
    if (!output_ || service_schedules_.empty()) return;

    // First, apply any pending changes and increment versions
    if (eit_carousel_pending_) {
        for (auto& [service_id, changed] : schedule_changed_) {
            if (changed) {
                eit_schedule_version_[service_id] = (eit_schedule_version_[service_id] + 1) & 0x1F;
                changed = false;
            }
        }
        eit_carousel_pending_ = false;
    }

    // Output complete EIT table for ALL services
    // This ensures decoders see complete table before any version change
    for (const auto& [service_id, schedule] : service_schedules_) {
        if (schedule.programmes.empty() || !sid_to_index_.count(service_id)) continue;
        const TsService& svc = services_[sid_to_index_[service_id]];
        for (const auto& section : buildEitScheduleSections(service_id, tsid_, onid_,
                                                            eit_schedule_version_[service_id],
                                                            schedule.programmes, svc.language, svc.content)) {
            outputSection(PID_EIT, section);
        }
    }
}

void TsMuxer::outputPes(uint16_t pid, const uint8_t* data, size_t len, int64_t pts, bool insert_pcr, int64_t pcr,
                        uint8_t stream_id) {
    // PES packet length (6 bytes header + 5 PTS + data)
    // 0 = unbounded for large packets
    size_t pes_len = 3 + 5 + len;  // flags(2) + header_len(1) + PTS(5) + data
    if (pes_len > 0xFFFF) pes_len = 0;

    // PTS (33 bits in 5 bytes with markers)
    // Format: '0010' + PTS[32:30] + '1' + PTS[29:15] + '1' + PTS[14:0] + '1'
    int64_t pts33 = pts & 0x1FFFFFFFFLL;

    const uint8_t header[] = {
        0x00, 0x00, 0x01,                       // PES start code prefix
        stream_id,                              // 0xC0 = audio stream 0, 0xBD = private stream 1
        static_cast<uint8_t>(pes_len >> 8), static_cast<uint8_t>(pes_len),
        0x80,   // '10' + scrambling(2) + priority(1) + alignment(1) + copyright(1) + original(1)
        0x80,   // PTS_DTS_flags(2)=10 + other flags
        0x05,   // PES_header_data_length = 5 (PTS only)
        static_cast<uint8_t>(0x21 | ((pts33 >> 29) & 0x0E)),
        static_cast<uint8_t>(pts33 >> 22),
        static_cast<uint8_t>(0x01 | ((pts33 >> 14) & 0xFE)),
        static_cast<uint8_t>(pts33 >> 7),
        static_cast<uint8_t>(0x01 | ((pts33 << 1) & 0xFE)),
    };

    // Build PES packet: header and audio data, in a buffer of its final size
    std::vector<uint8_t> pes(sizeof(header) + len);
    std::copy(header, header + sizeof(header), pes.begin());
    std::copy(data, data + len, pes.begin() + sizeof(header));

    // Packetize into TS packets
    size_t offset = 0;
    bool first = true;

    while (offset < pes.size()) {
        uint8_t packet[TS_MUXER_PACKET_SIZE];
        std::fill(packet, packet + TS_MUXER_PACKET_SIZE, 0xFF);

        packet[0] = 0x47;
        packet[1] = (first ? 0x40 : 0x00) | ((pid >> 8) & 0x1F);
        packet[2] = pid & 0xFF;

        uint8_t& cc = cc_[pid];
        size_t remaining = pes.size() - offset;

        if (first && insert_pcr) {
            // First packet with adaptation field containing PCR
            // Adaptation field: length(1) + flags(1) + PCR(6) = 8 bytes
            packet[3] = 0x30 | (cc & 0x0F);  // adaptation + payload
            packet[4] = 7;  // adaptation_field_length
            packet[5] = 0x10;  // PCR_flag = 1

            // PCR (in 27 MHz units): base (33 bits, 90 kHz) + 6 reserved +
            // extension (9 bits, 0-299); pcr = base * 300 + extension
            int64_t pcr_base = (pcr / 300) & 0x1FFFFFFFFLL;
            uint16_t pcr_ext = static_cast<uint16_t>(pcr % 300);

            packet[6] = (pcr_base >> 25) & 0xFF;
            packet[7] = (pcr_base >> 17) & 0xFF;
            packet[8] = (pcr_base >> 9) & 0xFF;
            packet[9] = (pcr_base >> 1) & 0xFF;
            packet[10] = ((pcr_base & 1) << 7) | 0x7E | ((pcr_ext >> 8) & 0x01);
            packet[11] = pcr_ext & 0xFF;

            size_t payload_start = 12;
            size_t payload_len = TS_MUXER_PACKET_SIZE - payload_start;
            size_t to_copy = std::min(remaining, payload_len);
            std::copy(pes.data() + offset, pes.data() + offset + to_copy, packet + payload_start);
            offset += to_copy;
        } else if (remaining < TS_MUXER_PACKET_SIZE - 4) {
            // Need stuffing - use adaptation field
            size_t stuff_needed = (TS_MUXER_PACKET_SIZE - 4) - remaining;

            if (stuff_needed == 1) {
                // Just adaptation_field_length = 0
                packet[3] = 0x30 | (cc & 0x0F);
                packet[4] = 0x00;
                std::copy(pes.data() + offset, pes.data() + offset + remaining, packet + 5);
            } else {
                packet[3] = 0x30 | (cc & 0x0F);
                packet[4] = static_cast<uint8_t>(stuff_needed - 1);
                packet[5] = 0x00;  // flags
                if (stuff_needed > 2) {
                    std::fill(packet + 6, packet + 6 + stuff_needed - 2, 0xFF);
                }
                std::copy(pes.data() + offset, pes.data() + offset + remaining, packet + 4 + stuff_needed);
            }
            offset = pes.size();
        } else {
            // Full payload, no adaptation
            packet[3] = 0x10 | (cc & 0x0F);
            std::copy(pes.data() + offset, pes.data() + offset + TS_MUXER_PACKET_SIZE - 4, packet + 4);
            offset += TS_MUXER_PACKET_SIZE - 4;
        }

        cc = (cc + 1) & 0x0F;
        first = false;
        writePacket(packet);
    }
}

void TsMuxer::flushAudioBuffer(uint16_t sid) {
    auto it = sid_to_index_.find(sid);
    if (it == sid_to_index_.end()) return;

    const auto& svc = services_[it->second];
    uint16_t audio_pid = svc.audio_pid;
    auto& buf = audio_buffers_[sid];

    if (buf.data.empty()) return;

    // The PCR of a service is on its own time line (its PCR PID is its audio
    // PID), ahead of the PTS by a fixed time: what a decoder that goes by
    // the PCR has as buffer. Every PES has one.
    int64_t pcr = (buf.first_pts > PCR_LEAD_PTS ? buf.first_pts - PCR_LEAD_PTS : 0) * 300;

    outputPes(audio_pid, buf.data.data(), buf.data.size(), buf.first_pts, true, pcr);
    last_audio_pts_[sid] = buf.last_pts;

    buf.data.clear();
    buf.frame_count = 0;
}

void TsMuxer::feedAudioFrame(uint16_t sid, const uint8_t* data, size_t len, int64_t pts) {
    auto it = sid_to_index_.find(sid);
    if (it == sid_to_index_.end() || len == 0) return;

    tick(pts);

    // Buffer audio frames for PES aggregation (reduces overhead like FFmpeg)
    auto& buf = audio_buffers_[sid];

    // The time from one frame to the next: the smallest seen (lost frames
    // only make it longer)
    int64_t& step = frame_step_[sid];
    if (buf.last_pts >= 0 && pts > buf.last_pts && (step == 0 || pts - buf.last_pts < step)) {
        step = pts - buf.last_pts;
    }

    // A PES has the PTS of its first frame only, a receiver counts on from
    // it: frames that do not follow each other (lost ones between them, a
    // time line that starts anew) do not go into one PES
    if (!buf.data.empty() && (pts <= buf.last_pts || (step > 0 && pts - buf.last_pts > step + step / 8))) {
        flushAudioBuffer(sid);
    }

    // Store first PTS for this buffer
    if (buf.data.empty()) {
        buf.first_pts = pts;
    }

    // Append frame to buffer
    buf.data.insert(buf.data.end(), data, data + len);
    buf.frame_count++;
    buf.last_pts = pts;

    // A PES goes out when it is long enough in bytes or in time: by bytes
    // alone a service of 16 kbit/s got one a second, and with it its PCR
    // and the first sound after tuning to it
    if (buf.data.size() >= PES_TARGET_SIZE || pts + step - buf.first_pts >= PES_TARGET_PTS) {
        flushAudioBuffer(sid);
    }
}

void TsMuxer::dropAudio(uint16_t sid) {
    auto it = audio_buffers_.find(sid);
    if (it == audio_buffers_.end()) return;
    it->second.data.clear();
    it->second.frame_count = 0;
    it->second.last_pts = -1;
}

void TsMuxer::refreshEitFlags() {
    bool changed = false;
    for (auto& s : services_) {
        auto it = service_schedules_.find(s.sid);
        bool schedule = it != service_schedules_.end() && !it->second.programmes.empty();
        bool pf = schedule && utc_ms_ >= 0;
        if (s.eit_schedule != schedule || s.eit_pf != pf) {
            s.eit_schedule = schedule;
            s.eit_pf = pf;
            changed = true;
        }
    }
    if (changed) sdt_version_ = (sdt_version_ + 1) & 0x1F;
}

void TsMuxer::outputEitPresentFollowing() {
    if (utc_ms_ < 0) return;
    const time_t now = static_cast<time_t>(utc_ms_ / 1000);

    for (const auto& [service_id, schedule] : service_schedules_) {
        auto idx = sid_to_index_.find(service_id);
        if (schedule.programmes.empty() || idx == sid_to_index_.end()) continue;

        // the programmes are in the order of their start
        const EpgProgramme* present = nullptr;
        const EpgProgramme* following = nullptr;
        for (const auto& p : schedule.programmes) {
            if (p.start_time <= now && now < p.start_time + p.duration_seconds) {
                present = &p;
            } else if (p.start_time > now) {
                following = &p;
                break;
            }
        }

        // a new version when another programme is on, or the schedule said something new
        PresentFollowing& pf = eit_pf_[service_id];
        int64_t p_id = present ? static_cast<int64_t>(present->start_time) : 0;
        int64_t f_id = following ? static_cast<int64_t>(following->start_time) : 0;
        uint8_t sv = eit_schedule_version_[service_id];
        if (pf.sent && (pf.present != p_id || pf.following != f_id || pf.schedule_version != sv)) {
            pf.version = (pf.version + 1) & 0x1F;
        }
        pf.present = p_id;
        pf.following = f_id;
        pf.schedule_version = sv;
        pf.sent = true;

        const TsService& svc = services_[idx->second];
        for (const auto& section : buildEitPresentFollowingSections(service_id, tsid_, onid_, pf.version, present,
                                                                    following, svc.language, svc.content)) {
            outputSection(PID_EIT, section);
        }
    }
}

void TsMuxer::tick(int64_t pts) {
    outputRadioTexts(pts);
    refreshEitFlags();

    // Time-based PSI output (DVB compliant: PAT/PMT every 500ms, SDT every 2s)
    // Track maximum PTS seen to handle multi-service streams where each service has different PTS
    if (pts > last_psi_pts_) {
        bool output_psi = (last_psi_pts_ < 0) || (pts - last_psi_pts_ >= PSI_INTERVAL_PTS);
        if (output_psi) {
            last_psi_pts_ = pts;
            outputPat();
            for (const auto& s : services_) {
                outputPmt(s);
            }

            // SDT every 2 seconds (DVB max interval)
            if (last_sdt_pts_ < 0 || pts - last_sdt_pts_ >= SDT_INTERVAL_PTS) {
                last_sdt_pts_ = pts;
                outputSdt();
            }
        }
    }

    // The time of the ensemble, as long as it sends one
    if (utc_ms_ >= 0 && pts > last_tdt_pts_ && (last_tdt_pts_ < 0 || pts - last_tdt_pts_ >= TDT_INTERVAL_PTS)) {
        last_tdt_pts_ = pts;
        outputSection(PID_TDT, buildTdtSection(utc_ms_ / 1000));
    }

    // What is on now and next, every 2 s
    if (pts > last_pf_pts_ && (last_pf_pts_ < 0 || pts - last_pf_pts_ >= EIT_PF_INTERVAL_PTS)) {
        last_pf_pts_ = pts;
        outputEitPresentFollowing();
    }

    // EIT schedule carousel - output complete table periodically: by the
    // time of the stream, the same for one service as for forty
    if (pts > last_eit_pts_ && (last_eit_pts_ < 0 || pts - last_eit_pts_ >= EIT_INTERVAL_PTS)) {
        last_eit_pts_ = pts;
        outputEitScheduleCarousel();
    }
}

// FfmpegTsMuxer compatibility: feed by subchannel_id
void TsMuxer::feedAudioFrame(uint8_t subchannel_id, const uint8_t* data, size_t len, int64_t pts) {
    auto it = subch_to_sid_.find(subchannel_id);
    if (it != subch_to_sid_.end()) {
        feedAudioFrame(it->second, data, len, pts);
    }
}

// FfmpegTsMuxer compatibility: set now-playing by subchannel_id
void TsMuxer::setNowPlayingBySubch(uint8_t subchannel_id, const std::string& title, const std::string& artist) {
    auto it = subch_to_sid_.find(subchannel_id);
    if (it != subch_to_sid_.end()) {
        setNowPlaying(it->second, title, artist);
    }
}

// FfmpegTsMuxer compatibility: update service label by subchannel_id
void TsMuxer::updateServiceLabelBySubch(uint8_t subchannel_id, const std::string& name) {
    auto it = subch_to_sid_.find(subchannel_id);
    if (it != subch_to_sid_.end()) {
        updateServiceLabel(it->second, name);
    }
}

} // namespace dvbdab
