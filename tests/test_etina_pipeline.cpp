#include "etina_pipeline.hpp"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>

using namespace dvbdab;

int main(int argc, char* argv[]) {
    const char* file_path = "test_streams/9E-12092H.ts";
    uint16_t target_pid = 1062;

    if (argc > 1) file_path = argv[1];
    if (argc > 2) target_pid = static_cast<uint16_t>(atoi(argv[2]));

    FILE* f = fopen(file_path, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", file_path);
        return 1;
    }

    printf("Testing ETI-NA pipeline with PID %u from %s\n", target_pid, file_path);

    EtinaPipelineState state;
    uint8_t ts_packet[188];

    size_t packets_read = 0;
    size_t pid_packets = 0;
    size_t eti_frames = 0;

    while (fread(ts_packet, 1, 188, f) == 188) {
        packets_read++;

        // Check sync byte
        if (ts_packet[0] != 0x47) {
            fprintf(stderr, "Lost sync at packet %zu\n", packets_read);
            continue;
        }

        // Extract PID
        uint16_t pid = ((ts_packet[1] & 0x1F) << 8) | ts_packet[2];
        if (pid != target_pid) continue;

        pid_packets++;

        // ETI-NA uses continuous mode (no PUSI), 184-byte payload
        const uint8_t* payload = ts_packet + 4;
        size_t payload_len = 184;

        // Check for adaptation field
        uint8_t adaptation = (ts_packet[3] >> 4) & 0x03;
        if (adaptation == 0x02) continue;  // no payload
        if (adaptation == 0x03) {
            // adaptation + payload
            uint8_t af_len = ts_packet[4];
            payload = ts_packet + 5 + af_len;
            payload_len = 183 - af_len;
        }

        // Feed to pipeline
        etina_feed_payload(state, payload, payload_len,
            [&](const uint8_t* eti, size_t len) {
                eti_frames++;

                // Verify sync word
                uint32_t sync = eti[0] | (eti[1] << 8) | (eti[2] << 16) | (eti[3] << 24);
                bool valid_sync = (sync == 0xb63a07ff || sync == 0x49c5f8ff);

                // Parse ETI header to find FIC
                uint8_t nst = eti[5] & 0x7F;
                uint8_t ficf = (eti[5] >> 7) & 0x01;
                uint16_t fp_mid_fl = (eti[6] << 8) | eti[7];
                uint8_t mid = (fp_mid_fl >> 11) & 0x03;

                size_t header_size = 4 + 4 + nst * 4 + 4;  // SYNC + FC + STC + EOH
                size_t fic_size = 0;
                if (ficf) {
                    switch (mid) {
                        case 1: fic_size = 96; break;
                        case 2: fic_size = 32; break;
                        case 3: fic_size = 128; break;
                        case 4: fic_size = 96; break;
                        default: fic_size = 96; break;
                    }
                }

                // Check first FIB CRC (if we have FIC)
                int fib_crc_ok = -1;  // -1 = no FIC
                if (fic_size >= 32 && header_size + 32 <= len) {
                    const uint8_t* fib = eti + header_size;
                    // CRC-16 CCITT
                    uint16_t crc = 0xFFFF;
                    for (int i = 0; i < 30; i++) {
                        crc ^= (uint16_t)fib[i] << 8;
                        for (int j = 0; j < 8; j++) {
                            if (crc & 0x8000) crc = (crc << 1) ^ 0x1021;
                            else crc <<= 1;
                        }
                    }
                    crc ^= 0xFFFF;
                    uint16_t stored_crc = (fib[30] << 8) | fib[31];
                    fib_crc_ok = (crc == stored_crc) ? 1 : 0;
                }

                printf("ETI frame %zu: sync=%s FIB_CRC=%s nst=%u mid=%u\n",
                       eti_frames,
                       valid_sync ? "OK" : "BAD",
                       fib_crc_ok == 1 ? "OK" : (fib_crc_ok == 0 ? "FAIL" : "N/A"),
                       nst, mid);

                if (eti_frames <= 3) {
                    printf("  First 16 bytes: ");
                    for (size_t i = 0; i < 16 && i < len; i++) {
                        printf("%02x ", eti[i]);
                    }
                    printf("\n");
                }
            });

        // Stop after getting some ETI frames
        if (eti_frames >= 10) break;
    }

    fclose(f);

    printf("\nResults:\n");
    printf("  Total packets read: %zu\n", packets_read);
    printf("  PID %u packets: %zu\n", target_pid, pid_packets);
    printf("  ETI frames produced: %zu\n", eti_frames);
    printf("  Offset detection: %d bytes\n", state.offset.detected_offset);
    printf("  E1 sync found: %s (bit_offset=%d, inverted=%d)\n",
           state.e1.sync_found ? "yes" : "no",
           state.e1.bit_offset,
           state.e1.inverted ? 1 : 0);
    printf("  Multiframe synced: %s\n",
           state.multiframe.multiframe_synced ? "yes" : "no");

    return eti_frames > 0 ? 0 : 1;
}
