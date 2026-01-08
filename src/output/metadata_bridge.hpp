#pragma once
// MetadataBridge - Connects DabPlusDecoder DL Plus output to TsMuxer EIT
// Converts DL Plus tags (ITEM_TITLE, ITEM_ARTIST, etc.) to now-playing info
//
// LIFETIME REQUIREMENTS:
// ----------------------
// This bridge stores raw pointers to TsMuxer and DabPlusDecoder objects.
// The bridge registers callbacks on decoders that reference both the bridge
// and muxer. To avoid dangling pointers:
//
//   1. The TsMuxer MUST outlive the MetadataBridge
//   2. All attached DabPlusDecoders MUST outlive the MetadataBridge,
//      OR call detachDecoder() before destroying each decoder
//   3. Call clear() before destroying the bridge if decoder lifetimes
//      are uncertain
//
// Recommended ownership pattern:
//   - Owner creates: muxer, decoders, then bridge
//   - Owner destroys: bridge.clear(), then bridge, then decoders, then muxer
//
// Example:
//   TsMuxer muxer;
//   DabPlusDecoder decoder;
//   MetadataBridge bridge;
//   bridge.setMuxer(&muxer);
//   bridge.attachDecoder(&decoder, 0);
//   // ... use ...
//   bridge.clear();  // Safe cleanup before any destruction

#include "dabplus_decoder.hpp"
#include "ts_muxer.hpp"
#include "pad_decoder.hpp"
#include <map>
#include <memory>

namespace dvbdab {

// Helper class to wire DL Plus metadata from decoders to the TS muxer
// See LIFETIME REQUIREMENTS in file header
class MetadataBridge {
public:
    MetadataBridge() = default;

    // Destructor clears callbacks to prevent dangling references
    ~MetadataBridge() { clear(); }

    // Non-copyable (prevents accidental copies with stale pointers)
    MetadataBridge(const MetadataBridge&) = delete;
    MetadataBridge& operator=(const MetadataBridge&) = delete;

    // Set the muxer to receive metadata updates
    void setMuxer(TsMuxer* muxer) { muxer_ = muxer; }

    // Attach a decoder for a specific subchannel
    // This registers DLS and DL Plus callbacks on the decoder
    void attachDecoder(DabPlusDecoder* decoder, uint8_t subchannel_id) {
        if (!decoder || !muxer_) return;

        // Store reference for potential cleanup
        decoders_[subchannel_id] = decoder;

        // Set DLS callback - updates EIT when no DL Plus tags available
        decoder->setDLSCallback([this, subchannel_id](const std::string& text) {
            onDLS(subchannel_id, text);
        });

        // Set DL Plus callback - extracts artist/title for EIT
        decoder->setDLPlusCallback([this, subchannel_id](
            const std::string& text, const std::vector<DLPlusTag>& tags) {
            onDLPlus(subchannel_id, text, tags);
        });
    }

    // Detach a decoder (clears callbacks)
    void detachDecoder(uint8_t subchannel_id) {
        auto it = decoders_.find(subchannel_id);
        if (it != decoders_.end()) {
            if (it->second) {
                it->second->setDLSCallback(nullptr);
                it->second->setDLPlusCallback(nullptr);
            }
            decoders_.erase(it);
        }
        last_dls_.erase(subchannel_id);
    }

    // Clear all attachments
    void clear() {
        for (auto& [scid, decoder] : decoders_) {
            if (decoder) {
                decoder->setDLSCallback(nullptr);
                decoder->setDLPlusCallback(nullptr);
            }
        }
        decoders_.clear();
        last_dls_.clear();
    }

private:
    // Called when DLS text is received (without DL Plus tags)
    void onDLS(uint8_t subchannel_id, const std::string& text) {
        if (!muxer_ || text.empty()) return;

        // Filter out promotional/URL text
        if (isPromotionalText(text)) return;

        // Avoid duplicate updates
        auto it = last_dls_.find(subchannel_id);
        if (it != last_dls_.end() && it->second == text) return;
        last_dls_[subchannel_id] = text;

        std::string title, artist;

        // Try to parse "Artist - Title" format from DLS text
        size_t sep = text.find(" - ");
        if (sep != std::string::npos && sep > 0 && sep < text.size() - 3) {
            artist = text.substr(0, sep);
            title = text.substr(sep + 3);
        } else {
            title = text;
        }

        muxer_->setNowPlayingBySubch(subchannel_id, title, artist);
    }

    // Called when DL Plus tags are received
    void onDLPlus(uint8_t subchannel_id, const std::string& text,
                  const std::vector<DLPlusTag>& tags) {
        if (!muxer_ || tags.empty()) return;

        std::string title, artist;

        // Extract structured metadata from tags
        for (const auto& tag : tags) {
            std::string value = tag.extract(text);
            if (value.empty()) continue;

            switch (tag.content_type) {
                case DLPlusContentType::ITEM_TITLE:
                    title = value;
                    break;
                case DLPlusContentType::ITEM_ARTIST:
                    artist = value;
                    break;
                default:
                    break;
            }
        }

        // Only update if we have meaningful data
        if (!title.empty() || !artist.empty()) {
            muxer_->setNowPlayingBySubch(subchannel_id, title, artist);
        }
    }

    // Check if text is promotional (URLs, hotlines, etc.)
    static bool isPromotionalText(const std::string& text) {
        // Common promotional patterns
        if (text.find(".de") != std::string::npos &&
            text.find("http") == std::string::npos &&
            text.find(" - ") == std::string::npos) {
            // Likely a URL mention without artist-title format
            if (text.find("Playlist") != std::string::npos ||
                text.find("App") != std::string::npos ||
                text.find("Stream") != std::string::npos) {
                return true;
            }
        }
        if (text.find("Hotline") != std::string::npos) return true;
        if (text.find("0800") != std::string::npos) return true;
        if (text.find("0221") != std::string::npos) return true;
        return false;
    }

    TsMuxer* muxer_ = nullptr;
    std::map<uint8_t, DabPlusDecoder*> decoders_;
    std::map<uint8_t, std::string> last_dls_;  // Deduplication
};

} // namespace dvbdab
