#include "etina_pipeline.hpp"
#include <algorithm>
#include <cstring>

namespace dvbdab {

// Helper: count leading 0xFF bytes
static int count_leading_ff(const uint8_t* data, size_t len) {
    int count = 0;
    for (size_t i = 0; i < len && data[i] == 0xFF; i++) {
        count++;
    }
    return count;
}

// Step 1: Strip FF padding
const uint8_t* etina_strip_padding(
    EtinaOffsetState& state,
    const uint8_t* payload, size_t len,
    size_t& out_len)
{
    out_len = 0;

    if (state.detected_offset >= 0) {
        // Already detected - just strip and return
        size_t offset = static_cast<size_t>(state.detected_offset);
        if (offset >= len) return nullptr;
        out_len = len - offset;
        return payload + offset;
    }

    // Still detecting
    int ff_count = count_leading_ff(payload, len);
    if (ff_count < state.min_ff_count) {
        state.min_ff_count = ff_count;
    }

    state.packet_count++;

    if (state.packet_count >= OFFSET_DETECTION_PACKET_COUNT) {
        // Detection complete
        state.detected_offset = state.min_ff_count;
        size_t offset = static_cast<size_t>(state.detected_offset);
        if (offset >= len) return nullptr;
        out_len = len - offset;
        return payload + offset;
    }

    // Still detecting, don't output yet
    return nullptr;
}

// Step 2: Find E1 sync and extract aligned frames
const uint8_t* etina_extract_e1_frame(
    EtinaE1State& state,
    const uint8_t* data, size_t len)
{
    // Add new data to buffer
    if (data && len > 0) {
        state.buffer.insert(state.buffer.end(), data, data + len);
    }

    // If sync not found yet, search for it
    if (!state.sync_found) {
        // Need enough data to verify sync pattern
        size_t bytes_needed = E1_SYNC_INTERVAL * 4 + 1;  // Check 4 sync positions
        if (state.buffer.size() < bytes_needed) {
            return nullptr;
        }

        // Try each bit offset and inversion
        for (int bit_offset = 0; bit_offset < 8; bit_offset++) {
            for (int inv = 0; inv < 2; inv++) {
                bool inverted = (inv == 1);

                // Lambda to extract byte at position with bit offset and inversion
                auto extract_byte = [&](size_t pos) -> uint8_t {
                    if (pos + 1 >= state.buffer.size()) return 0;
                    uint8_t result;
                    if (bit_offset == 0) {
                        result = state.buffer[pos];
                    } else {
                        result = (state.buffer[pos] << bit_offset) |
                                 (state.buffer[pos + 1] >> (8 - bit_offset));
                    }
                    if (inverted) result ^= 0xFF;
                    return result;
                };

                // Search for sync pattern
                for (size_t start = 0; start < 1024 && start + bytes_needed < state.buffer.size(); start++) {
                    bool all_sync = true;
                    for (size_t frame = 0; frame < 4; frame++) {
                        size_t pos = start + frame * E1_SYNC_INTERVAL;
                        uint8_t byte_at_pos = extract_byte(pos) & E1_SYNC_MASK;
                        if (byte_at_pos != E1_SYNC_VAL) {
                            all_sync = false;
                            break;
                        }
                    }
                    if (all_sync) {
                        state.sync_found = true;
                        state.bit_offset = bit_offset;
                        state.inverted = inverted;
                        state.sync_start = start;
                        // Remove bytes before sync start
                        state.buffer.erase(state.buffer.begin(),
                                          state.buffer.begin() + start);
                        break;
                    }
                }
                if (state.sync_found) break;
            }
            if (state.sync_found) break;
        }

        if (!state.sync_found) {
            // No sync found - discard old data to prevent infinite growth
            if (state.buffer.size() > 8192) {
                state.buffer.erase(state.buffer.begin(),
                                  state.buffer.begin() + 4096);
            }
            return nullptr;
        }
    }

    // Sync found - extract aligned frames
    // Need E1_FRAME_SIZE bytes + 1 extra for bit shifting
    if (state.buffer.size() < E1_FRAME_SIZE + 1) {
        return nullptr;
    }

    // Extract one aligned frame
    state.aligned_frame.resize(E1_FRAME_SIZE);
    for (size_t i = 0; i < E1_FRAME_SIZE; i++) {
        uint8_t result;
        if (state.bit_offset == 0) {
            result = state.buffer[i];
        } else {
            result = (state.buffer[i] << state.bit_offset) |
                     (state.buffer[i + 1] >> (8 - state.bit_offset));
        }
        if (state.inverted) result ^= 0xFF;
        state.aligned_frame[i] = result;
    }

    // Remove processed bytes
    state.buffer.erase(state.buffer.begin(),
                      state.buffer.begin() + E1_FRAME_SIZE);

    return state.aligned_frame.data();
}

// Step 3: Accumulate E1 frames into multiframe
const uint8_t* etina_accumulate_multiframe(
    EtinaMultiframeState& state,
    const uint8_t* e1_frame)
{
    // Add frame to buffer
    if (e1_frame) {
        state.frame_buffer.insert(state.frame_buffer.end(),
                                  e1_frame, e1_frame + E1_FRAME_SIZE);
    }

    // Need at least FRAMES_IN_MULTIFRAME + some extra for sync search
    size_t frames_needed = FRAMES_IN_MULTIFRAME + FRAMES_IN_BLOCK;
    if (state.frame_buffer.size() < frames_needed * E1_FRAME_SIZE) {
        return nullptr;
    }

    // Find multiframe sync if not already synced
    if (!state.multiframe_synced) {
        // Look for block 0, superblock 0 in management byte
        size_t max_search = FRAMES_IN_BLOCK * BLOCKS_IN_SUPERBLOCK;
        for (size_t frame_offset = 0; frame_offset < max_search; frame_offset++) {
            bool valid = true;
            for (size_t block = 0; block < BLOCKS_IN_SUPERBLOCK && valid; block++) {
                size_t frame_idx = frame_offset + block * FRAMES_IN_BLOCK;
                if (frame_idx * E1_FRAME_SIZE + 1 >= state.frame_buffer.size()) {
                    valid = false;
                    break;
                }

                uint8_t mgmt = state.frame_buffer[frame_idx * E1_FRAME_SIZE + 1];
                uint8_t block_num = (mgmt >> 5) & 0x07;
                uint8_t superblock_num = (mgmt >> 3) & 0x03;

                if (block == 0) {
                    if (block_num != 0 || superblock_num != 0) {
                        valid = false;
                    }
                } else {
                    if (block_num != block || superblock_num != 0) {
                        valid = false;
                    }
                }
            }
            if (valid) {
                // Found sync - remove preceding frames
                if (frame_offset > 0) {
                    state.frame_buffer.erase(state.frame_buffer.begin(),
                                            state.frame_buffer.begin() + frame_offset * E1_FRAME_SIZE);
                }
                state.multiframe_synced = true;
                break;
            }
        }

        if (!state.multiframe_synced) {
            // No sync found - discard some old frames
            if (state.frame_buffer.size() > FRAMES_IN_BLOCK * E1_FRAME_SIZE * 2) {
                state.frame_buffer.erase(state.frame_buffer.begin(),
                                        state.frame_buffer.begin() + FRAMES_IN_BLOCK * E1_FRAME_SIZE);
            }
            return nullptr;
        }
    }

    // Check if we have a complete multiframe
    if (state.frame_buffer.size() >= FRAMES_IN_MULTIFRAME * E1_FRAME_SIZE) {
        return state.frame_buffer.data();
    }

    return nullptr;
}

// Step 4: Deinterleave multiframe to ETI-NI
void etina_deinterleave_to_eti(
    EtinaDeintState& state,
    const uint8_t* multiframe,
    uint8_t* out)
{
    // ETI-NI sync words
    static constexpr uint32_t FSYNC0 = 0xb63a07ff;
    static constexpr uint32_t FSYNC1 = 0x49c5f8ff;

    // Write sync word (little-endian)
    uint32_t sync = state.even_frame ? FSYNC0 : FSYNC1;
    out[0] = sync & 0xff;
    out[1] = (sync >> 8) & 0xff;
    out[2] = (sync >> 16) & 0xff;
    out[3] = (sync >> 24) & 0xff;

    // Step 1: Deinterleave all 3 superblocks into one contiguous buffer
    // (matching na2ni.c structure)
    std::vector<uint8_t> deint(INTERLEAVE_ROWS * INTERLEAVE_COLS * SUPERBLOCKS_IN_MULTIFRAME);
    const uint8_t* superblock = multiframe;
    uint8_t* deint_ptr = deint.data();

    for (size_t sb = 0; sb < SUPERBLOCKS_IN_MULTIFRAME; sb++) {
        size_t in_ptr = 0;

        for (size_t col = 0; col < INTERLEAVE_COLS; col++) {
            for (size_t row = 0; row < INTERLEAVE_ROWS; row++) {
                // Skip sync byte every 16 bytes
                if ((in_ptr % 16) == 0) {
                    in_ptr++;
                }
                size_t out_idx = col + row * INTERLEAVE_COLS;
                deint_ptr[out_idx] = superblock[in_ptr];
                in_ptr++;
            }
        }

        superblock += FRAMES_IN_BLOCK * BLOCKS_IN_SUPERBLOCK * E1_FRAME_SIZE;
        deint_ptr += INTERLEAVE_ROWS * INTERLEAVE_COLS;
    }

    // Step 2: Extract type bit from M01 (once, from first superblock)
    uint8_t mgmt = deint[30];  // M01 byte position
    uint8_t type_bit = (mgmt >> 1) & 0x01;
    size_t max_read = type_bit ? 226 : 235;

    // Step 3: Copy to output, processing all rows of all superblocks
    uint8_t* out_ptr = out + 4;
    size_t total_rows = INTERLEAVE_ROWS * SUPERBLOCKS_IN_MULTIFRAME;  // 24

    for (size_t row = 0; row < total_rows; row++) {
        const uint8_t* row_data = deint.data() + row * INTERLEAVE_COLS;

        if ((row % INTERLEAVE_ROWS) < 2) {
            // Rows 0,1 of each superblock: skip first byte of each 30-byte segment
            size_t read_ptr = 0;
            while (read_ptr < max_read) {
                size_t to_read = 29;
                if (read_ptr + to_read > max_read)
                    to_read = max_read - read_ptr - 1;
                read_ptr++;  // Skip management byte
                memcpy(out_ptr, row_data + read_ptr, to_read);
                out_ptr += to_read;
                read_ptr += to_read;
            }
        } else {
            memcpy(out_ptr, row_data, max_read);
            out_ptr += max_read;
        }
    }

    // Pad remainder with 0x55
    while (out_ptr < out + ETI_NI_FRAME_SIZE) {
        *out_ptr++ = 0x55;
    }

    state.even_frame = !state.even_frame;
}

// Convenience function: feed payload, get ETI frames via callback
void etina_feed_payload(
    EtinaPipelineState& state,
    const uint8_t* payload, size_t len,
    std::function<void(const uint8_t* eti, size_t len)> callback)
{
    // Step 1: Strip padding
    size_t stripped_len;
    const uint8_t* stripped = etina_strip_padding(state.offset, payload, len, stripped_len);
    if (!stripped) return;

    // Step 2: Extract E1 frames
    const uint8_t* e1_frame = etina_extract_e1_frame(state.e1, stripped, stripped_len);
    while (e1_frame) {
        // Step 3: Accumulate into multiframe
        const uint8_t* multiframe = etina_accumulate_multiframe(state.multiframe, e1_frame);
        if (multiframe) {
            // Step 4: Deinterleave to ETI
            std::vector<uint8_t> eti_out(ETI_NI_FRAME_SIZE);
            etina_deinterleave_to_eti(state.deint, multiframe, eti_out.data());

            // Remove processed multiframe
            state.multiframe.frame_buffer.erase(
                state.multiframe.frame_buffer.begin(),
                state.multiframe.frame_buffer.begin() + FRAMES_IN_MULTIFRAME * E1_FRAME_SIZE);

            // Callback with ETI frame
            if (callback) {
                callback(eti_out.data(), ETI_NI_FRAME_SIZE);
            }
        }

        // Try to get more E1 frames from buffer
        e1_frame = etina_extract_e1_frame(state.e1, nullptr, 0);
    }
}

} // namespace dvbdab
