#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <functional>

namespace dvbdab {

// Constants
constexpr size_t E1_FRAME_SIZE = 32;
constexpr uint8_t E1_SYNC_VAL = 0x1B;
constexpr uint8_t E1_SYNC_MASK = 0x7F;
constexpr size_t E1_SYNC_INTERVAL = E1_FRAME_SIZE * 2;  // 64 bytes
constexpr size_t FRAMES_IN_BLOCK = 8;
constexpr size_t BLOCKS_IN_SUPERBLOCK = 8;
constexpr size_t SUPERBLOCKS_IN_MULTIFRAME = 3;
constexpr size_t FRAMES_IN_MULTIFRAME = FRAMES_IN_BLOCK * BLOCKS_IN_SUPERBLOCK * SUPERBLOCKS_IN_MULTIFRAME;  // 192
constexpr size_t INTERLEAVE_ROWS = 8;
constexpr size_t INTERLEAVE_COLS = 240;
constexpr size_t ETI_NI_FRAME_SIZE = 6144;
constexpr int OFFSET_DETECTION_PACKET_COUNT = 5;

// Step 1: Strip FF padding
struct EtinaOffsetState {
    int packet_count = 0;
    int min_ff_count = 255;
    int detected_offset = -1;  // -1 = not yet detected
};

// Returns pointer to stripped payload, sets out_len
// Returns nullptr if still in detection phase
const uint8_t* etina_strip_padding(
    EtinaOffsetState& state,
    const uint8_t* payload, size_t len,
    size_t& out_len
);

// Step 2: Find E1 sync and extract aligned frames
struct EtinaE1State {
    std::vector<uint8_t> buffer;
    std::vector<uint8_t> aligned_frame;  // holds current 32-byte frame
    int bit_offset = -1;      // -1 = not found yet
    bool inverted = false;
    bool sync_found = false;
    size_t sync_start = 0;    // byte position where sync was found
};

// Feed data and extract aligned E1 frames
// Returns pointer to 32-byte aligned frame, or nullptr if none ready
// Call with data=nullptr, len=0 to drain remaining frames from buffer
const uint8_t* etina_extract_e1_frame(
    EtinaE1State& state,
    const uint8_t* data, size_t len
);

// Step 3: Accumulate E1 frames into multiframe
struct EtinaMultiframeState {
    std::vector<uint8_t> frame_buffer;
    bool multiframe_synced = false;
};

// Feed E1 frames and get complete multiframes
// Returns pointer to 192*32 byte multiframe, or nullptr if not ready
const uint8_t* etina_accumulate_multiframe(
    EtinaMultiframeState& state,
    const uint8_t* e1_frame  // 32 bytes, or nullptr to just check
);

// Step 4: Deinterleave multiframe to ETI-NI
struct EtinaDeintState {
    bool even_frame = true;
};

// Deinterleave multiframe into ETI-NI frame
// out must point to buffer of at least ETI_NI_FRAME_SIZE bytes
void etina_deinterleave_to_eti(
    EtinaDeintState& state,
    const uint8_t* multiframe,  // 192 * 32 bytes
    uint8_t* out                // 6144 bytes
);

// Combined pipeline state
struct EtinaPipelineState {
    EtinaOffsetState offset;
    EtinaE1State e1;
    EtinaMultiframeState multiframe;
    EtinaDeintState deint;
};

// Convenience function: feed payload, get ETI frames via callback
void etina_feed_payload(
    EtinaPipelineState& state,
    const uint8_t* payload, size_t len,
    std::function<void(const uint8_t* eti, size_t len)> callback
);

} // namespace dvbdab
