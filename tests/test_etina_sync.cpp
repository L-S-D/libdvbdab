// Tests for the E1 sync search of the ETI-NA pipeline: a stream of E1 frames
// behind a random prefix, shifted by 0-7 bits and optionally inverted, is found
// and the frames come out unchanged, also when it arrives in small pieces (the
// search then runs over many calls). Random data finds no sync, and the bytes
// fed without sync are counted while the buffer stays bounded.

#include "../src/etina_pipeline.hpp"
#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

using namespace dvbdab;

static int failures = 0;

static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

// E1 frames: every second one starts with the sync word (x0011011), the
// others with bit 6 set, so they never look like one.
static std::vector<uint8_t> make_frames(std::mt19937& rng, size_t count) {
    std::vector<uint8_t> f(count * E1_FRAME_SIZE);
    for (auto& b : f) b = static_cast<uint8_t>(rng());
    for (size_t i = 0; i < count; i++) {
        uint8_t& ts0 = f[i * E1_FRAME_SIZE];
        if (i % 2 == 0)
            ts0 = static_cast<uint8_t>((ts0 & 0x80) | E1_SYNC_VAL);
        else
            ts0 = static_cast<uint8_t>(ts0 | 0x40);
    }
    return f;
}

// prefix random bytes, then `shift` random bits, then the frames; inverted on request
static std::vector<uint8_t> make_stream(std::mt19937& rng, const std::vector<uint8_t>& frames,
                                        size_t prefix, int shift, bool inverted) {
    std::vector<uint8_t> bits;
    for (size_t i = 0; i < prefix * 8 + shift; i++) bits.push_back(rng() & 1);
    for (uint8_t b : frames)
        for (int i = 7; i >= 0; i--) bits.push_back((b >> i) & 1);
    while (bits.size() % 8) bits.push_back(0);
    std::vector<uint8_t> out(bits.size() / 8);
    for (size_t i = 0; i < bits.size(); i++)
        out[i / 8] = static_cast<uint8_t>(out[i / 8] | (bits[i] << (7 - i % 8)));
    if (inverted)
        for (auto& b : out) b ^= 0xFF;
    return out;
}

// feed in pieces of 1..max_chunk bytes, collect the aligned frames
static std::vector<uint8_t> feed(EtinaE1State& st, std::mt19937& rng,
                                 const std::vector<uint8_t>& data, size_t max_chunk) {
    std::vector<uint8_t> out;
    size_t pos = 0;
    while (pos < data.size()) {
        size_t n = std::min<size_t>(1 + rng() % max_chunk, data.size() - pos);
        const uint8_t* f = etina_extract_e1_frame(st, data.data() + pos, n);
        while (f) {
            out.insert(out.end(), f, f + E1_FRAME_SIZE);
            f = etina_extract_e1_frame(st, nullptr, 0);
        }
        pos += n;
    }
    return out;
}

int main() {
    std::mt19937 rng(20261116);
    const size_t nframes = 64;

    int found = 0, total = 0;
    for (size_t max_chunk : {1u, 37u, 184u}) {
        for (int shift = 0; shift < 8; shift++) {
            for (int inv = 0; inv < 2; inv++) {
                const size_t prefix = 5 + (shift * 13 + inv * 7) % 100;
                auto frames = make_frames(rng, nframes);
                auto stream = make_stream(rng, frames, prefix, shift, inv);
                EtinaE1State st;
                auto out = feed(st, rng, stream, max_chunk);
                bool ok = st.sync_found && st.bit_offset == shift && st.inverted == (inv == 1) &&
                          st.sync_start == prefix && out.size() >= (nframes - 2) * E1_FRAME_SIZE &&
                          std::equal(out.begin(), out.end(), frames.begin());
                total++;
                if (ok) found++;
                else std::printf("  chunk %zu shift %d inv %d: sync %d bit_offset %d inverted %d start %zu frames %zu\n",
                                 max_chunk, shift, inv, st.sync_found, st.bit_offset, st.inverted,
                                 st.sync_start, out.size() / E1_FRAME_SIZE);
            }
        }
    }
    char what[96];
    std::snprintf(what, sizeof(what), "E1 sync and frames for every bit shift and inversion (%d of %d)", found, total);
    check(found == total, what);

    // random data: no sync, all bytes counted, buffer bounded
    std::vector<uint8_t> noise(65536);
    for (auto& b : noise) b = static_cast<uint8_t>(rng());
    EtinaE1State st;
    auto out = feed(st, rng, noise, 184);
    check(!st.sync_found && out.empty(), "no sync in random data");
    check(st.unsynced_bytes == noise.size(), "bytes without sync are counted");
    check(st.buffer.size() <= 12288 + 184, "buffer stays bounded without sync");

    return failures ? 1 : 0;
}
