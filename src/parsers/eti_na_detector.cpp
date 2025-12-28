#include "eti_na_detector.hpp"
#include <cstring>
#include <algorithm>

namespace dvbdab {

EtiNaDetector::EtiNaDetector() {
    sync_buffer_.reserve(SYNC_BUFFER_SIZE);
    eti_buffer_.reserve(ETI_NI_FRAME_SIZE * 2);
    aligned_buffer_.reserve(E1_FRAME_SIZE * ETI_VERIFY_FRAMES);
    stream_buffer_.reserve(8192);
    frame_buffer_.reserve(FRAMES_IN_MULTIFRAME * E1_FRAME_SIZE * 2);
}

void EtiNaDetector::reset() {
    phase_ = Phase::ANALYZING_PADDING;
    padding_samples_ = 0;
    detected_padding_ = -1;
    sync_buffer_.clear();
    eti_buffer_.clear();
    aligned_buffer_.clear();
    e1_sync_start_ = 0;
    result_ = EtiNaDetectionResult{};
    detection_complete_ = false;

    // Streaming state
    stream_buffer_.clear();
    frame_buffer_.clear();
    carry_bits_ = 0;
    multiframe_pos_ = 0;
    multiframe_synced_ = false;
    even_frame_ = 1;
}

int EtiNaDetector::countLeadingFF(const uint8_t* data, size_t len) {
    int count = 0;
    for (size_t i = 0; i < len && data[i] == 0xFF; i++) {
        count++;
    }
    return count;
}

void EtiNaDetector::analyzePadding(const uint8_t* payload, size_t len) {
    int ff_count = countLeadingFF(payload, len);

    if (padding_samples_ == 0) {
        // First sample - record the padding amount
        detected_padding_ = ff_count;
    } else {
        // Check consistency - allow small variation (within 2 bytes)
        if (std::abs(ff_count - detected_padding_) > 2) {
            // Inconsistent padding - not ETI-NA
            phase_ = Phase::FAILED;
            detection_complete_ = true;
            return;
        }
    }

    padding_samples_++;

    // After enough samples, move to sync search
    if (padding_samples_ >= PADDING_SAMPLES_NEEDED) {
        if (detected_padding_ >= 8 && detected_padding_ <= 16) {
            // Reasonable padding (typically 12 bytes)
            result_.padding_bytes = detected_padding_;
            phase_ = Phase::SEARCHING_E1_SYNC;
        } else if (detected_padding_ == 0) {
            // No padding - might still be ETI-NA with offset 0
            result_.padding_bytes = 0;
            phase_ = Phase::SEARCHING_E1_SYNC;
        } else {
            // Unusual padding - not ETI-NA
            phase_ = Phase::FAILED;
            detection_complete_ = true;
        }
    }
}

void EtiNaDetector::feedPayload(const uint8_t* payload, size_t len) {
    if (detection_complete_ && phase_ != Phase::STREAMING) {
        return;
    }

    switch (phase_) {
        case Phase::ANALYZING_PADDING:
            analyzePadding(payload, len);
            if (phase_ == Phase::SEARCHING_E1_SYNC) {
                // Start accumulating data for sync search (skip padding)
                size_t skip = static_cast<size_t>(result_.padding_bytes);
                if (skip < len) {
                    sync_buffer_.insert(sync_buffer_.end(),
                                       payload + skip, payload + len);
                }
            }
            break;

        case Phase::SEARCHING_E1_SYNC: {
            // Accumulate data (skip padding)
            size_t skip = static_cast<size_t>(result_.padding_bytes);
            if (skip < len) {
                sync_buffer_.insert(sync_buffer_.end(),
                                   payload + skip, payload + len);
            }

            // Try to find E1 sync when we have enough data
            if (sync_buffer_.size() >= SYNC_BUFFER_SIZE) {
                searchForE1Sync();
            }
            break;
        }

        case Phase::VERIFYING_ETI: {
            // Continue accumulating for ETI verification
            size_t skip = static_cast<size_t>(result_.padding_bytes);
            if (skip < len) {
                sync_buffer_.insert(sync_buffer_.end(),
                                   payload + skip, payload + len);
            }

            // Try to verify ETI structure
            if (sync_buffer_.size() >= E1_FRAME_SIZE * ETI_VERIFY_FRAMES + e1_sync_start_) {
                extractAlignedFrames();
                if (verifyEtiStructure()) {
                    result_.detected = true;
                    result_.eti_sync_found = true;
                    phase_ = Phase::STREAMING;
                    detection_complete_ = true;

                    // Transfer remaining sync_buffer_ data to streaming buffer
                    // Start from e1_sync_start_ to preserve alignment
                    if (e1_sync_start_ < sync_buffer_.size()) {
                        stream_buffer_.insert(stream_buffer_.end(),
                                             sync_buffer_.begin() + e1_sync_start_,
                                             sync_buffer_.end());
                    }
                    sync_buffer_.clear();

                    // Process the transferred data immediately
                    alignAndAccumulate(nullptr, 0);
                } else {
                    // E1 sync found but not ETI - could be other E1 data
                    phase_ = Phase::FAILED;
                    detection_complete_ = true;
                }
            }
            break;
        }

        case Phase::STREAMING:
            processEtiNa(payload, len);
            break;

        case Phase::FAILED:
            break;
    }
}

void EtiNaDetector::searchForE1Sync() {
    // Try each bit offset (0-7) and both normal/inverted
    for (int bit_offset = 0; bit_offset < 8; bit_offset++) {
        size_t sync_start = 0;
        if (checkE1SyncAtBitOffset(bit_offset, false, sync_start)) {
            result_.e1_sync_found = true;
            result_.sync_bit_offset = bit_offset;
            result_.inverted = false;
            e1_sync_start_ = sync_start;
            phase_ = Phase::VERIFYING_ETI;
            return;
        }
        if (checkE1SyncAtBitOffset(bit_offset, true, sync_start)) {
            result_.e1_sync_found = true;
            result_.sync_bit_offset = bit_offset;
            result_.inverted = true;
            e1_sync_start_ = sync_start;
            phase_ = Phase::VERIFYING_ETI;
            return;
        }
    }

    // If we've accumulated a lot of data and still no E1 sync, give up
    phase_ = Phase::FAILED;
    detection_complete_ = true;
}

bool EtiNaDetector::checkE1SyncAtBitOffset(int bit_offset, bool inverted, size_t& sync_start) {
    auto extractByte = [this, bit_offset, inverted](size_t byte_pos) -> uint8_t {
        if (byte_pos + 1 >= sync_buffer_.size()) return 0;

        uint8_t result;
        if (bit_offset == 0) {
            result = sync_buffer_[byte_pos];
        } else {
            uint8_t b1 = sync_buffer_[byte_pos];
            uint8_t b2 = sync_buffer_[byte_pos + 1];
            result = (b1 << bit_offset) | (b2 >> (8 - bit_offset));
        }

        if (inverted) {
            result ^= 0xFF;
        }
        return result;
    };

    // Search for first sync byte (masked to 7 bits)
    // Sync appears every 64 bytes (every 2 E1 frames - even/odd pair)
    size_t bytes_needed = E1_SYNC_INTERVAL * E1_FRAMES_FOR_SYNC + 1;
    if (sync_buffer_.size() < bytes_needed) return false;

    size_t max_search = std::min(sync_buffer_.size() - bytes_needed,
                                  static_cast<size_t>(1024));

    for (size_t start = 0; start < max_search; start++) {
        uint8_t first = extractByte(start) & E1_SYNC_MASK;
        if (first != E1_SYNC_VAL) continue;

        // Check for sync pattern at 64-byte intervals (every 2 E1 frames)
        bool all_sync = true;
        for (size_t frame = 1; frame < E1_FRAMES_FOR_SYNC; frame++) {
            size_t pos = start + frame * E1_SYNC_INTERVAL;
            uint8_t byte_at_pos = extractByte(pos) & E1_SYNC_MASK;
            if (byte_at_pos != E1_SYNC_VAL) {
                all_sync = false;
                break;
            }
        }

        if (all_sync) {
            sync_start = start;
            return true;
        }
    }

    return false;
}

void EtiNaDetector::extractAlignedFrames() {
    // Extract bit-aligned E1 frames starting from e1_sync_start_
    aligned_buffer_.clear();

    int bit_offset = result_.sync_bit_offset;
    bool inverted = result_.inverted;

    size_t num_frames = ETI_VERIFY_FRAMES;
    size_t bytes_needed = e1_sync_start_ + num_frames * E1_FRAME_SIZE + 1;

    if (sync_buffer_.size() < bytes_needed) {
        num_frames = (sync_buffer_.size() - e1_sync_start_ - 1) / E1_FRAME_SIZE;
    }

    for (size_t frame = 0; frame < num_frames; frame++) {
        for (size_t byte_in_frame = 0; byte_in_frame < E1_FRAME_SIZE; byte_in_frame++) {
            size_t byte_pos = e1_sync_start_ + frame * E1_FRAME_SIZE + byte_in_frame;

            uint8_t result;
            if (bit_offset == 0) {
                result = sync_buffer_[byte_pos];
            } else {
                if (byte_pos + 1 >= sync_buffer_.size()) break;
                uint8_t b1 = sync_buffer_[byte_pos];
                uint8_t b2 = sync_buffer_[byte_pos + 1];
                result = (b1 << bit_offset) | (b2 >> (8 - bit_offset));
            }

            if (inverted) {
                result ^= 0xFF;
            }

            aligned_buffer_.push_back(result);
        }
    }
}

bool EtiNaDetector::verifyEtiStructure() {
    // After E1 alignment, we have 32-byte frames.
    // ETI uses an interleaving scheme: 8 blocks × 240 E1 frames = 1 superframe
    // Each superframe produces one ETI-NI frame (6144 bytes)
    //
    // To verify it's ETI (not just any E1 data), we check:
    // 1. First byte of each frame should be 0x1B (E1 sync) - already verified
    // 2. Management bytes should show consistent block numbering pattern
    // 3. After deinterleaving, we should see valid ETI structure

    if (aligned_buffer_.size() < E1_FRAME_SIZE * 32) {
        return false;  // Not enough data
    }

    // Quick sanity check: verify E1 sync bytes are present
    // Sync appears every 64 bytes (every 2 E1 frames), NOT every frame
    int sync_count = 0;
    int non_sync_count = 0;
    for (size_t i = 0; i < aligned_buffer_.size(); i += E1_SYNC_INTERVAL) {
        if ((aligned_buffer_[i] & E1_SYNC_MASK) == E1_SYNC_VAL) {
            sync_count++;
        } else {
            non_sync_count++;
        }
    }

    // Should have mostly sync bytes (allow some errors due to transmission)
    size_t total_sync_positions = aligned_buffer_.size() / E1_SYNC_INTERVAL;
    if (total_sync_positions > 0 &&
        sync_count < static_cast<int>(total_sync_positions) * 80 / 100) {
        return false;  // Too many sync errors
    }

    // Check for ETI block structure
    // In ETI-NA, byte 1 of each E1 frame contains management info
    // Bits contain block number (1-8) and other flags
    // We look for a repeating pattern that indicates block numbering

    // Extract management bytes (byte 1 of each frame)
    std::vector<uint8_t> mgmt_bytes;
    for (size_t i = 0; i + 1 < aligned_buffer_.size(); i += E1_FRAME_SIZE) {
        mgmt_bytes.push_back(aligned_buffer_[i + 1]);
    }

    if (mgmt_bytes.size() < 32) {
        return false;
    }

    // Look for repeating pattern in lower bits (block number)
    // Block numbers should cycle 1-8 (or 0-7 depending on encoding)
    int pattern_matches = 0;
    for (size_t i = 8; i < mgmt_bytes.size(); i++) {
        // Check if lower 4 bits show some kind of cycling pattern
        uint8_t current = mgmt_bytes[i] & 0x0F;
        uint8_t prev_cycle = mgmt_bytes[i - 8] & 0x0F;
        if (current == prev_cycle) {
            pattern_matches++;
        }
    }

    // If we see a repeating pattern every 8 frames, likely ETI
    double match_ratio = static_cast<double>(pattern_matches) / (mgmt_bytes.size() - 8);

    // Also check that data isn't all zeros or all ones (would indicate no actual content)
    int nonzero_count = 0;
    for (size_t i = 0; i < std::min(aligned_buffer_.size(), static_cast<size_t>(1024)); i++) {
        if (aligned_buffer_[i] != 0x00 && aligned_buffer_[i] != 0xFF &&
            (aligned_buffer_[i] & E1_SYNC_MASK) != E1_SYNC_VAL) {
            nonzero_count++;
        }
    }

    // Need reasonable amount of actual data content
    if (nonzero_count < 100) {
        return false;  // Mostly empty/padding
    }

    // Accept if we have good sync and some pattern consistency
    // (Real ETI will have ~100% pattern match, but allow some tolerance)
    return match_ratio > 0.5 || nonzero_count > 500;
}

void EtiNaDetector::processEtiNa(const uint8_t* data, size_t len) {
    // Skip padding
    size_t skip = static_cast<size_t>(result_.padding_bytes);
    if (skip >= len) return;

    // Accumulate raw data
    stream_buffer_.insert(stream_buffer_.end(), data + skip, data + len);

    // Process complete E1 frames
    alignAndAccumulate(nullptr, 0);

    // Check if we have enough frames for a multiframe
    while (frame_buffer_.size() >= (FRAMES_IN_MULTIFRAME + FRAMES_IN_BLOCK) * E1_FRAME_SIZE) {
        if (!multiframe_synced_) {
            int sync_offset = findMultiframeSync();
            if (sync_offset < 0) {
                // No sync found, discard some data and try again
                frame_buffer_.erase(frame_buffer_.begin(),
                                   frame_buffer_.begin() + FRAMES_IN_BLOCK * E1_FRAME_SIZE);
                continue;
            }
            // Found sync, align to it
            if (sync_offset > 0) {
                frame_buffer_.erase(frame_buffer_.begin(),
                                   frame_buffer_.begin() + sync_offset * E1_FRAME_SIZE);
            }
            multiframe_synced_ = true;
        }

        if (frame_buffer_.size() >= FRAMES_IN_MULTIFRAME * E1_FRAME_SIZE) {
            // Deinterleave and output
            std::vector<uint8_t> deint(INTERLEAVE_ROWS * INTERLEAVE_COLS * SUPERBLOCKS_IN_MULTIFRAME);
            deinterleave(frame_buffer_.data(), deint.data());
            outputEtiNi(deint.data());

            // Remove processed frames
            frame_buffer_.erase(frame_buffer_.begin(),
                               frame_buffer_.begin() + FRAMES_IN_MULTIFRAME * E1_FRAME_SIZE);
        } else {
            break;
        }
    }
}

void EtiNaDetector::alignAndAccumulate(const uint8_t* /*data*/, size_t /*len*/) {
    int bit_offset = result_.sync_bit_offset;
    bool inverted = result_.inverted;

    // Process stream_buffer_ into aligned E1 frames
    while (stream_buffer_.size() >= E1_FRAME_SIZE + 1) {
        uint8_t frame[E1_FRAME_SIZE];

        for (size_t i = 0; i < E1_FRAME_SIZE; i++) {
            uint8_t b;
            if (bit_offset == 0) {
                b = stream_buffer_[i];
            } else {
                b = (stream_buffer_[i] << bit_offset) |
                    (stream_buffer_[i + 1] >> (8 - bit_offset));
            }
            if (inverted) b ^= 0xFF;
            frame[i] = b;
        }

        frame_buffer_.insert(frame_buffer_.end(), frame, frame + E1_FRAME_SIZE);
        stream_buffer_.erase(stream_buffer_.begin(),
                            stream_buffer_.begin() + E1_FRAME_SIZE);
    }
}

int EtiNaDetector::findMultiframeSync() {
    // Look for block 0 of superblock 0 (management byte pattern)
    // Management byte is byte 1 of E1 frame: bits 7-5 = block#, bits 4-3 = superblock#

    size_t max_search = std::min(frame_buffer_.size() / E1_FRAME_SIZE,
                                  FRAMES_IN_BLOCK * BLOCKS_IN_SUPERBLOCK);

    for (size_t frame_offset = 0; frame_offset < max_search; frame_offset++) {
        bool valid = true;

        // Check pattern over multiple blocks
        for (size_t block = 0; block < BLOCKS_IN_SUPERBLOCK && valid; block++) {
            size_t frame_idx = frame_offset + block * FRAMES_IN_BLOCK;
            if (frame_idx * E1_FRAME_SIZE + 1 >= frame_buffer_.size()) {
                valid = false;
                break;
            }

            uint8_t mgmt = frame_buffer_[frame_idx * E1_FRAME_SIZE + 1];
            uint8_t block_num = (mgmt >> 5) & 0x07;
            uint8_t superblock_num = (mgmt >> 3) & 0x03;

            if (block == 0) {
                // First block should be block 0, superblock 0
                if (block_num != 0 || superblock_num != 0) {
                    valid = false;
                }
            } else {
                // Subsequent blocks should increment
                if (block_num != block || superblock_num != 0) {
                    valid = false;
                }
            }
        }

        if (valid) {
            return static_cast<int>(frame_offset);
        }
    }

    return -1;
}

void EtiNaDetector::deinterleave(const uint8_t* frames, uint8_t* deint) {
    // Process 3 superblocks
    const uint8_t* superblock = frames;
    uint8_t* out = deint;

    for (size_t sb = 0; sb < SUPERBLOCKS_IN_MULTIFRAME; sb++) {
        size_t in_ptr = 0;

        // Deinterleave 8×240 table (from na2ni.c)
        // Skip every 16th byte (frame sync/management bytes in interleaved format)
        for (size_t col = 0; col < INTERLEAVE_COLS; col++) {
            for (size_t row = 0; row < INTERLEAVE_ROWS; row++) {
                // Skip sync byte every 16 bytes (as per na2ni.c)
                if ((in_ptr % 16) == 0) {
                    in_ptr++;
                }

                size_t out_ptr = col + row * INTERLEAVE_COLS;
                out[out_ptr] = superblock[in_ptr];
                in_ptr++;
            }
        }

        superblock += FRAMES_IN_BLOCK * BLOCKS_IN_SUPERBLOCK * E1_FRAME_SIZE;
        out += INTERLEAVE_ROWS * INTERLEAVE_COLS;
    }
}

void EtiNaDetector::outputEtiNi(const uint8_t* deint) {
    if (!callback_) return;

    // ETI-NI sync words
    static constexpr uint32_t FSYNC0 = 0xb63a07ff;
    static constexpr uint32_t FSYNC1 = 0x49c5f8ff;

    std::vector<uint8_t> eti_ni(ETI_NI_FRAME_SIZE);

    // Write sync word (little-endian)
    uint32_t sync = even_frame_ ? FSYNC0 : FSYNC1;
    eti_ni[0] = sync & 0xff;
    eti_ni[1] = (sync >> 8) & 0xff;
    eti_ni[2] = (sync >> 16) & 0xff;
    eti_ni[3] = (sync >> 24) & 0xff;

    uint8_t* out_ptr = eti_ni.data() + 4;

    // Check type bit from management byte (determines payload size)
    uint8_t mgmt = deint[30];  // M01 byte position
    uint8_t type_bit = (mgmt >> 1) & 0x01;
    size_t max_read = type_bit ? 226 : 235;

    // Copy data from deinterleaved buffer to ETI-NI format
    // First 2 rows of each superblock have special handling (skip management bytes)
    for (size_t row = 0; row < INTERLEAVE_ROWS * SUPERBLOCKS_IN_MULTIFRAME; row++) {
        const uint8_t* row_data = deint + row * INTERLEAVE_COLS;

        if (row % INTERLEAVE_ROWS < 2) {
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
            // Other rows: copy directly
            memcpy(out_ptr, row_data, max_read);
            out_ptr += max_read;
        }
    }

    // Pad remainder with 0x55
    while (out_ptr < eti_ni.data() + ETI_NI_FRAME_SIZE) {
        *out_ptr++ = 0x55;
    }

    even_frame_ = !even_frame_;

    // Call the callback with the complete ETI-NI frame
    callback_(eti_ni.data(), ETI_NI_FRAME_SIZE);
}

} // namespace dvbdab
