#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <functional>
#include <array>

namespace dvbdab {

// ETI-NA detector for continuous stream DAB feeds (e.g., UK satellite feeds)
// These streams use stream type 0x87 with no PUSI, 12-byte 0xFF padding,
// and E1/G.704 framing with bit-level sync

struct EtiNaDetectionResult {
    bool detected{false};           // ETI confirmed (not just E1)
    bool e1_sync_found{false};      // E1 framing detected
    bool eti_sync_found{false};     // ETI block structure confirmed
    int padding_bytes{0};           // Number of leading 0xFF bytes (typically 12)
    int sync_bit_offset{0};         // Bit position where sync was found (0-7)
    bool inverted{false};           // Signal is inverted
    uint16_t pid{0};                // PID where detected
};

class EtiNaDetector {
public:
    // Callback when ETI-NI frame is ready (6144 bytes)
    using EtiNiCallback = std::function<void(const uint8_t* eti_ni, size_t len)>;

    EtiNaDetector();

    // Set callback for ETI-NI frames
    void setCallback(EtiNiCallback callback) { callback_ = std::move(callback); }

    // Feed TS packet payload (after stripping TS header)
    // Returns true if this looks like ETI-NA data
    void feedPayload(const uint8_t* payload, size_t len);

    // Get detection result
    const EtiNaDetectionResult& getResult() const { return result_; }

    // Check if detection is complete (either found or ruled out)
    bool isDetectionComplete() const { return detection_complete_; }

    // Check if ETI-NA was detected
    bool isDetected() const { return result_.detected; }

    // Reset state
    void reset();

private:
    // Detection phases
    enum class Phase {
        ANALYZING_PADDING,    // Checking for consistent 0xFF padding
        SEARCHING_E1_SYNC,    // Looking for E1 sync pattern (0x1B every 32 bytes)
        VERIFYING_ETI,        // Verifying ETI block structure inside E1
        STREAMING,            // ETI confirmed, producing ETI-NI frames
        FAILED                // Not ETI-NA
    };

    Phase phase_{Phase::ANALYZING_PADDING};

    // Padding analysis
    static constexpr size_t PADDING_SAMPLES_NEEDED = 10;
    size_t padding_samples_{0};
    int detected_padding_{-1};  // -1 = not yet determined

    // Sync search
    std::vector<uint8_t> sync_buffer_;
    // Need enough for sync search: 8 sync positions * 64 bytes + search margin
    static constexpr size_t SYNC_BUFFER_SIZE = 8192;

    // E1 frame constants (G.704)
    // Sync byte is 0x1B but only lower 7 bits are checked
    static constexpr uint8_t E1_SYNC_VAL = 0x1B;
    static constexpr uint8_t E1_SYNC_MASK = 0x7F;
    static constexpr size_t E1_FRAME_SIZE = 32;
    // Sync appears every 2 frames (even/odd pair) = 64 bytes
    static constexpr size_t E1_SYNC_INTERVAL = E1_FRAME_SIZE * 2;
    static constexpr size_t E1_FRAMES_FOR_SYNC = 8;  // Check 8 consecutive sync positions

    // ETI-NI output
    std::vector<uint8_t> eti_buffer_;
    static constexpr size_t ETI_NI_FRAME_SIZE = 6144;

    EtiNaDetectionResult result_;
    bool detection_complete_{false};

    EtiNiCallback callback_;

    // E1 sync state (after E1 sync found)
    size_t e1_sync_start_{0};       // Byte offset where E1 sync was found

    // ETI verification
    std::vector<uint8_t> aligned_buffer_;  // Bit-aligned E1 frames
    static constexpr size_t ETI_VERIFY_FRAMES = 64;  // Need enough frames to see block pattern

    // ETI-NA constants (from ETSI EN 300 799)
    static constexpr size_t FRAMES_IN_BLOCK = 8;
    static constexpr size_t BLOCKS_IN_SUPERBLOCK = 8;
    static constexpr size_t SUPERBLOCKS_IN_MULTIFRAME = 3;
    static constexpr size_t FRAMES_IN_MULTIFRAME = FRAMES_IN_BLOCK * BLOCKS_IN_SUPERBLOCK * SUPERBLOCKS_IN_MULTIFRAME;  // 192
    static constexpr size_t INTERLEAVE_ROWS = 8;
    static constexpr size_t INTERLEAVE_COLS = 240;

    // Streaming state
    std::vector<uint8_t> stream_buffer_;     // Raw incoming data (after padding skip)
    std::vector<uint8_t> frame_buffer_;      // Bit-aligned E1 frames
    uint8_t carry_bits_{0};                  // Bits carried over between packets
    size_t multiframe_pos_{0};               // Current position in multiframe
    bool multiframe_synced_{false};          // Have we found multiframe sync?
    int even_frame_{1};                      // Alternating sync word

    // Analysis methods
    int countLeadingFF(const uint8_t* data, size_t len);
    void analyzePadding(const uint8_t* payload, size_t len);
    void searchForE1Sync();
    bool checkE1SyncAtBitOffset(int bit_offset, bool inverted, size_t& sync_start);
    void extractAlignedFrames();
    bool verifyEtiStructure();
    void processEtiNa(const uint8_t* data, size_t len);

    // Streaming methods
    void alignAndAccumulate(const uint8_t* data, size_t len);
    int findMultiframeSync();
    void deinterleave(const uint8_t* frames, uint8_t* deint);
    void outputEtiNi(const uint8_t* deint);
};

} // namespace dvbdab
