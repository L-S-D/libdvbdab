#pragma once
// EhbScheduleBridge - Connects PacketDecoder MOT output to EhbParser and TsMuxer
// Routes EHB binary EPG data to schedule parsing and EIT injection
//
// LIFETIME REQUIREMENTS:
// ----------------------
// This bridge stores raw pointers to TsMuxer and PacketDecoder objects.
// The bridge registers a MOT callback on the decoder. To avoid dangling pointers:
//
//   1. The TsMuxer MUST outlive the EhbScheduleBridge
//   2. The attached PacketDecoder MUST outlive the EhbScheduleBridge,
//      OR call detachDecoder() before destroying the decoder
//
// Recommended ownership pattern:
//   - Owner creates: muxer, decoder, then bridge
//   - Owner destroys: bridge, then decoder, then muxer
//   - The destructor automatically detaches the decoder

#include "../parsers/ehb_parser.hpp"
#include "../parsers/spi_parser.hpp"  // For EpgSchedule/EpgProgramme
#include "../parsers/packet_decoder.hpp"
#include "ts_muxer.hpp"
#include <map>
#include <set>

namespace dvbdab {

// Bridge class that wires:
// PacketDecoder -> EhbParser -> TsMuxer
//
// Converts EHB binary EPG format (ETSI TS 102 371) to EIT tables
// See LIFETIME REQUIREMENTS in file header
//
// Usage:
//   EhbScheduleBridge bridge;
//   bridge.setMuxer(&muxer);
//   bridge.attachPacketDecoder(&decoder);
//
class EhbScheduleBridge {
public:
    EhbScheduleBridge() {
        // Set up EhbParser callback to forward schedules to muxer
        ehb_parser_.setScheduleCallback([this](const ServiceSchedule& schedule) {
            onScheduleParsed(schedule);
        });
    }

    // Destructor detaches decoder to prevent dangling callback
    ~EhbScheduleBridge() { detachDecoder(); }

    // Non-copyable (prevents accidental copies with stale pointers)
    EhbScheduleBridge(const EhbScheduleBridge&) = delete;
    EhbScheduleBridge& operator=(const EhbScheduleBridge&) = delete;

    // Set the muxer to receive schedule updates
    void setMuxer(TsMuxer* muxer) { muxer_ = muxer; }

    // Attach a packet decoder
    // All EHB files will be processed automatically
    void attachPacketDecoder(PacketDecoder* decoder) {
        if (!decoder) return;

        // Set MOT callback to route EHB files to parser
        decoder->setMotCallback([this](uint16_t transport_id,
                                        const MOTHeaderInfo& header,
                                        const uint8_t* data, size_t len) {
            // Only process EHB files
            if (header.content_name.find(".EHB") != std::string::npos) {
                // Skip if we've already processed this TID
                if (processed_tids_.count(transport_id)) return;
                processed_tids_.insert(transport_id);

                ehb_parser_.parse(header.content_name, data, len);
            }
        });

        decoder_ = decoder;
    }

    // Detach decoder
    void detachDecoder() {
        if (decoder_) {
            decoder_->setMotCallback(nullptr);
            decoder_ = nullptr;
        }
    }

    // Clear processed TIDs (allows reprocessing)
    void reset() {
        processed_tids_.clear();
    }

    // Get parser for direct access
    EhbParser& getParser() { return ehb_parser_; }
    const EhbParser& getParser() const { return ehb_parser_; }

    // Statistics
    size_t getProcessedCount() const { return processed_tids_.size(); }
    size_t getScheduleCount() const { return schedule_count_; }

private:
    // Convert EHB ServiceSchedule to SPI-style EpgSchedule
    EpgSchedule convertSchedule(const ServiceSchedule& ehb_schedule) {
        EpgSchedule schedule;
        schedule.service_id = ehb_schedule.service_id;
        schedule.service_name = ehb_schedule.service_name;
        schedule.last_update = time(nullptr);

        for (const auto& event : ehb_schedule.events) {
            EpgProgramme prog;
            prog.short_id = std::to_string(event.event_id);
            prog.name = event.title;
            prog.description = event.description;
            prog.start_time = event.start_time;
            prog.duration_seconds = event.duration_seconds;
            schedule.programmes.push_back(prog);
        }

        return schedule;
    }

    // Called when EhbParser completes parsing a schedule
    void onScheduleParsed(const ServiceSchedule& ehb_schedule) {
        if (!muxer_) return;

        // Convert to EpgSchedule format
        EpgSchedule schedule = convertSchedule(ehb_schedule);

        // Forward to muxer using the service component ID from EHB filename
        // The service_id in EHB is actually the service component ID (like 0xdf95)
        muxer_->updateSchedule(ehb_schedule.service_id, schedule);

        schedule_count_++;
    }

    TsMuxer* muxer_ = nullptr;
    EhbParser ehb_parser_;
    PacketDecoder* decoder_ = nullptr;
    std::set<uint16_t> processed_tids_;  // Already processed transport IDs
    size_t schedule_count_ = 0;
};

} // namespace dvbdab
