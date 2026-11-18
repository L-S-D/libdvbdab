/*
 * A TS (ETI-NA or TS NI V.11 on one PID) in, the services of its DAB
 * ensemble out as an MPEG-TS on stdout.
 *
 *   streamer tsni <pid> < capture.ts > radio.ts
 *   streamer etina <pid> [padding bit_offset inverted] < capture.ts > radio.ts
 *
 * The three numbers of ETI-NA are what the scanner found (examples/scanner).
 *
 * DAB over IP works the same way with DVBDAB_FORMAT_IPV4: the caller takes
 * the IPv4 packets out of MPE or GSE and feeds them one per call.
 */
#include <dvbdab/dvbdab_c.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void ts_out(void *opaque, const uint8_t *data, size_t len)
{
    fwrite(data, 1, len, (FILE *)opaque);
}

static void log_line(int level, const char *tag, const char *message)
{
    if (level <= DVBDAB_LOG_WARN) {
        fprintf(stderr, "[%s] %s\n", tag, message);
    }
}

int main(int argc, char **argv)
{
    if (argc != 3 && argc != 6) {
        fprintf(stderr, "usage: %s etina|tsni <pid> [padding bit_offset inverted]  (TS on stdin, TS on stdout)\n",
                argv[0]);
        return 2;
    }

    /* header and library must be of one version: the structures have no size field */
    if (dvbdab_version() >> 8 != (DVBDAB_VERSION_MAJOR << 8 | DVBDAB_VERSION_MINOR)) {
        fprintf(stderr, "built with libdvbdab %d.%d, linked is %s\n", DVBDAB_VERSION_MAJOR,
                DVBDAB_VERSION_MINOR, dvbdab_version_string());
        return 1;
    }

    dvbdab_set_log_callback(log_line);
    dvbdab_set_log_level(DVBDAB_LOG_WARN);

    dvbdab_streamer_config_t config;
    memset(&config, 0, sizeof(config));
    config.format = strcmp(argv[1], "tsni") == 0 ? DVBDAB_FORMAT_TSNI : DVBDAB_FORMAT_ETI_NA;
    config.pid = (uint16_t)strtoul(argv[2], NULL, 0);
    config.eti_padding = argc == 6 ? (uint8_t)atoi(argv[3]) : 12;
    config.eti_bit_offset = argc == 6 ? (uint8_t)atoi(argv[4]) : 0;
    config.eti_inverted = argc == 6 ? (uint8_t)atoi(argv[5]) : 0;
    /* DAB+ as AAC-LC any player plays right, when the library can do it */
    config.aac_output = dvbdab_aac_transcode() ? DVBDAB_AAC_TRANSCODE : DVBDAB_AAC_ADTS;

    dvbdab_streamer_t *streamer = dvbdab_streamer_create(&config);
    if (!streamer) {
        return 1;
    }
    dvbdab_streamer_set_output(streamer, ts_out, stdout);

    uint8_t buf[188 * 64];
    size_t n;
    int started = 0;
    while ((n = fread(buf, 1, sizeof(buf), stdin)) >= 188) {
        dvbdab_streamer_feed(streamer, buf, n - n % 188);

        /* The services and their subchannels are known (labels may follow,
         * the SDT is updated then): all services go out from here on */
        if (!started && dvbdab_streamer_is_basic_ready(streamer)) {
            dvbdab_streamer_start_all(streamer);
            started = 1;

            dvbdab_ensemble_t *e = dvbdab_streamer_get_ensemble(streamer);
            if (e) {
                fprintf(stderr, "ensemble 0x%04x \"%s\", %d services\n", e->eid, e->label, e->service_count);
                for (int i = 0; i < e->service_count; i++) {
                    fprintf(stderr, "  0x%04x \"%s\" %d kbit/s %s\n", (unsigned)e->services[i].sid,
                            e->services[i].label, e->services[i].bitrate,
                            e->services[i].dabplus ? "DAB+" : "DAB");
                }
                dvbdab_streamer_free_ensemble(e);
            }
        }
    }

    dvbdab_streamer_destroy(streamer);
    return started ? 0 : 1;
}
