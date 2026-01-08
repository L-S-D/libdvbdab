// Test ETI-NA streaming via C API
#include <dvbdab/dvbdab_c.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>

int main(int argc, char* argv[]) {
    const char* file_path = "test_streams/9E-12092H.ts";
    uint16_t target_pid = 1062;

    if (argc > 1) file_path = argv[1];
    if (argc > 2) target_pid = static_cast<uint16_t>(atoi(argv[2]));

    printf("ETI-NA streamer: PID %u from %s\n", target_pid, file_path);

    FILE* f = fopen(file_path, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", file_path);
        return 1;
    }

    // Create streamer config
    dvbdab_streamer_config_t config = {};
    config.format = DVBDAB_FORMAT_ETI_NA;
    config.pid = target_pid;

    dvbdab_streamer_t* streamer = dvbdab_streamer_create(&config);
    if (!streamer) {
        fprintf(stderr, "Failed to create streamer\n");
        fclose(f);
        return 1;
    }

    // Set output callback - write to file
    static size_t output_bytes = 0;
    static FILE* out_file = nullptr;
    out_file = fopen("/tmp/etina_output.ts", "wb");
    if (!out_file) {
        fprintf(stderr, "Cannot create output file\n");
        fclose(f);
        dvbdab_streamer_destroy(streamer);
        return 1;
    }
    dvbdab_streamer_set_output(streamer, [](void*, const uint8_t* data, size_t len) {
        output_bytes += len;
        fwrite(data, 1, len, out_file);
    }, nullptr);

    uint8_t buffer[188 * 256];  // 256 TS packets per read
    size_t total_bytes = 0;
    size_t packets_fed = 0;
    bool printed_basic = false;
    bool printed_complete = false;
    bool printed_no_etina = false;

    // Run until EOF (for files) or forever (for streams)
    while (!feof(f)) {
        size_t bytes_read = fread(buffer, 1, sizeof(buffer), f);
        if (bytes_read == 0) break;

        total_bytes += bytes_read;
        packets_fed += bytes_read / 188;

        dvbdab_streamer_feed(streamer, buffer, bytes_read);

        // Check for no ETI-NA after reasonable amount of data
        if (!printed_no_etina && !printed_basic && packets_fed > 50000) {
            printed_no_etina = true;
            printf("=== NO ETI-NA detected after %zu packets ===\n", packets_fed);
        }

        // Check for basic ready
        if (!printed_basic && dvbdab_streamer_is_basic_ready(streamer)) {
            printed_basic = true;
            printf("=== BASIC READY after %zu packets ===\n", packets_fed);

            dvbdab_ensemble_t* ens = dvbdab_streamer_get_ensemble(streamer);
            if (ens) {
                printf("Ensemble: EID=0x%04x '%s'\n", ens->eid, ens->label);
                printf("Services: %d\n", ens->service_count);
                for (int i = 0; i < ens->service_count; i++) {
                    printf("  [%d] SID=0x%04x '%s' SubCh=%u %s %dkbps\n",
                           i, ens->services[i].sid, ens->services[i].label,
                           ens->services[i].subchannel_id,
                           ens->services[i].dabplus ? "DAB+" : "DAB",
                           ens->services[i].bitrate);
                }
                dvbdab_streamer_free_ensemble(ens);
            }

            // Start all services for streaming
            int started = dvbdab_streamer_start_all(streamer);
            printf("Started %d services\n\n", started);
        }

        // Check for complete (all labels)
        if (!printed_complete && dvbdab_streamer_is_ready(streamer)) {
            printed_complete = true;
            printf("=== COMPLETE (all labels) after %zu packets ===\n", packets_fed);

            dvbdab_ensemble_t* ens = dvbdab_streamer_get_ensemble(streamer);
            if (ens) {
                printf("Ensemble: EID=0x%04x '%s'\n", ens->eid, ens->label);
                printf("Services: %d\n", ens->service_count);
                for (int i = 0; i < ens->service_count; i++) {
                    printf("  [%d] SID=0x%04x '%s' SubCh=%u %s %dkbps\n",
                           i, ens->services[i].sid, ens->services[i].label,
                           ens->services[i].subchannel_id,
                           ens->services[i].dabplus ? "DAB+" : "DAB",
                           ens->services[i].bitrate);
                }
                dvbdab_streamer_free_ensemble(ens);
            }
            printf("\n");
        }
    }

    fclose(f);
    fclose(out_file);
    dvbdab_streamer_destroy(streamer);

    printf("EOF: %zu packets, %zu bytes TS output -> /tmp/etina_output.ts\n", packets_fed, output_bytes);

    return printed_basic ? 0 : 1;
}
