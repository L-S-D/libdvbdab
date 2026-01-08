#pragma once
// SpiScheduleBridge - Connects PacketDecoder MOT output to SpiParser and TsMuxer
// Routes SPI XML data to schedule parsing and EIT injection
//
// LIFETIME REQUIREMENTS:
// ----------------------
// This bridge stores raw pointers to TsMuxer and PacketDecoder objects.
// The bridge registers MOT callbacks on decoders. To avoid dangling pointers:
//
//   1. The TsMuxer MUST outlive the SpiScheduleBridge
//   2. All attached PacketDecoders MUST outlive the SpiScheduleBridge,
//      OR call detachDecoder() for each before destroying
//   3. Call clear() before destroying the bridge if decoder lifetimes
//      are uncertain
//
// Recommended ownership pattern:
//   - Owner creates: muxer, decoders, then bridge
//   - Owner destroys: bridge.clear(), then bridge, then decoders, then muxer
//   - The destructor automatically calls clear()

#include "../parsers/spi_parser.hpp"
#include "../parsers/packet_decoder.hpp"
#include "ts_muxer.hpp"
#include <map>

namespace dvbdab {

// Bridge class that wires:
// PacketDecoder -> SpiParser -> TsMuxer
// See LIFETIME REQUIREMENTS in file header
//
// Usage:
//   SpiScheduleBridge bridge;
//   bridge.setMuxer(&muxer);
//   bridge.attachPacketDecoder(&decoder, service_id);
//
class SpiScheduleBridge {
public:
    SpiScheduleBridge() {
        // Set up SpiParser callback to forward schedules to muxer
        spi_parser_.setScheduleCallback([this](const EpgSchedule& schedule) {
            onScheduleParsed(schedule);
        });
    }

    // Destructor clears callbacks to prevent dangling references
    ~SpiScheduleBridge() { clear(); }

    // Non-copyable (prevents accidental copies with stale pointers)
    SpiScheduleBridge(const SpiScheduleBridge&) = delete;
    SpiScheduleBridge& operator=(const SpiScheduleBridge&) = delete;

    // Set the muxer to receive schedule updates
    void setMuxer(TsMuxer* muxer) { muxer_ = muxer; }

    // Attach a packet decoder for a specific service
    // The decoder's MOT callback will be wired to SPI parsing
    // service_id is used to map schedules to the correct EIT service
    void attachPacketDecoder(PacketDecoder* decoder, uint16_t service_id) {
        if (!decoder) return;

        // Set MOT callback to route to SPI parser
        decoder->setMotCallback([this, service_id](uint16_t transport_id,
                                                    const MOTHeaderInfo& header,
                                                    const uint8_t* data, size_t len) {
            // Forward to SPI parser
            spi_parser_.onMotObject(transport_id, header, data, len);

            // Track which transport_id maps to which service
            // (SPI XML may arrive from multiple transport IDs for the same service)
            transport_to_service_[transport_id] = service_id;
        });

        decoders_[service_id] = decoder;
    }

    // Feed MOT object directly (alternative to attaching decoder)
    void feedMotObject(uint16_t service_id, uint16_t transport_id,
                       const MOTHeaderInfo& header, const uint8_t* data, size_t len) {
        transport_to_service_[transport_id] = service_id;
        spi_parser_.onMotObject(transport_id, header, data, len);
    }

    // Detach a decoder
    void detachDecoder(uint16_t service_id) {
        auto it = decoders_.find(service_id);
        if (it != decoders_.end()) {
            if (it->second) {
                it->second->setMotCallback(nullptr);
            }
            decoders_.erase(it);
        }
    }

    // Clear all attachments
    void clear() {
        for (auto& [sid, decoder] : decoders_) {
            if (decoder) {
                decoder->setMotCallback(nullptr);
            }
        }
        decoders_.clear();
        transport_to_service_.clear();
    }

    // Get SPI parser for direct access to schedules
    SpiParser& getSpiParser() { return spi_parser_; }
    const SpiParser& getSpiParser() const { return spi_parser_; }

    // Statistics
    size_t getXmlCount() const { return spi_parser_.getXmlCount(); }
    size_t getScheduleCount() const { return spi_parser_.getScheduleCount(); }
    size_t getParseErrors() const { return spi_parser_.getParseErrors(); }

private:
    // Called when SpiParser completes parsing a schedule
    void onScheduleParsed(const EpgSchedule& schedule) {
        if (!muxer_) return;

        // The schedule already has service_id from the XML
        uint32_t service_id = schedule.service_id;

        // If we don't have a 32-bit SId, it might be a 16-bit one
        // DAB uses 16-bit or 32-bit service IDs depending on context
        uint16_t sid16 = static_cast<uint16_t>(service_id & 0xFFFF);

        // Forward to muxer
        muxer_->updateSchedule(sid16, schedule);
    }

    TsMuxer* muxer_ = nullptr;
    SpiParser spi_parser_;
    std::map<uint16_t, PacketDecoder*> decoders_;  // service_id -> decoder
    std::map<uint16_t, uint16_t> transport_to_service_;  // transport_id -> service_id
};

} // namespace dvbdab
