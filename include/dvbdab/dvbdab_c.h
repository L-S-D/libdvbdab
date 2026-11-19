/*
 * libdvbdab C API
 * C wrapper for using libdvbdab from C code (e.g., tvheadend)
 *
 * MEMORY MANAGEMENT
 * =================
 * This API uses explicit ownership with create/destroy and get/free pairs:
 *
 * Opaque handles (scanner_t, streamer_t):
 *   - Created with dvbdab_*_create(), destroyed with dvbdab_*_destroy()
 *   - Caller owns the handle and MUST call destroy when done
 *   - All internal state is freed on destroy
 *
 * Result structures (dvbdab_results_t, dvbdab_ensemble_t):
 *   - Returned by get_* functions, freed with corresponding free_* functions
 *   - Contains nested allocations (e.g., services array in ensemble)
 *   - Use the provided free function - do NOT manually free nested pointers
 *
 * Ownership rules:
 *   - dvbdab_scanner_get_results()    -> dvbdab_results_free()
 *   - dvbdab_streamer_get_ensemble()  -> dvbdab_streamer_free_ensemble()
 *   - dvbdab_streamer_get_all_ensembles() -> dvbdab_streamer_free_all_ensembles()
 *
 * Thread safety:
 *   - Handles are NOT thread-safe; serialize access or use one handle per thread
 *   - Result structures can be safely used from any thread after retrieval
 *
 * Example usage:
 *   dvbdab_scanner_t *scanner = dvbdab_scanner_create();
 *   // ... feed data ...
 *   dvbdab_results_t *results = dvbdab_scanner_get_results(scanner);
 *   // ... use results ...
 *   dvbdab_results_free(results);    // Free results when done
 *   dvbdab_scanner_destroy(scanner); // Destroy scanner when done
 */
#ifndef DVBDAB_C_H
#define DVBDAB_C_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque scanner handle - created with dvbdab_scanner_create() */
typedef struct dvbdab_scanner dvbdab_scanner_t;

/* A label as UTF-8 with its terminator: 16 characters of the DAB character
 * sets, which are up to 3 bytes each (2.5.0 on; 17 bytes before, which cut
 * labels with letters outside ASCII short) */
#define DVBDAB_LABEL_SIZE 65

/* DAB service info (C struct) */
typedef struct {
    uint32_t sid;           /* Service ID */
    char label[DVBDAB_LABEL_SIZE]; /* Service label, UTF-8 */
    int bitrate;            /* Bitrate in kbps */
    int subchannel_id;      /* Sub-channel ID */
    int dabplus;            /* 1 for DAB+, 0 for DAB */
    /* DVBDAB_HAVE_SERVICE_INFO (2.5.0 on) */
    char language[4];       /* Language of its audio (FIG 0/5), ISO 639-2; "" = not said */
    uint8_t pty;            /* Programme type (FIG 0/17, international code); 0 = none */
} dvbdab_service_t;

/* DAB ensemble info (C struct) */
typedef struct {
    uint16_t eid;           /* Ensemble ID */
    char label[DVBDAB_LABEL_SIZE]; /* Ensemble label, UTF-8 */
    uint32_t source_ip;     /* Source multicast IP (0 for ETI-NA) */
    uint16_t source_port;   /* Source UDP port (0 for ETI-NA) */
    uint16_t source_pid;    /* PID where ensemble was found */
    int service_count;      /* Number of services */
    dvbdab_service_t *services; /* Array of services (freed by free_* functions) */
    /* Source type flags */
    int is_etina;           /* 1 if ETI-NA encapsulation */
    int is_gse;             /* 0 from the library; for the caller: 1 if its IPv4
                               packets came from GSE (BBFrames), 0 if MPE */
    int is_tsni;            /* 1 if TS NI V.11 encapsulation */
    /* ETI-NA specific fields (valid when is_etina is true) */
    int etina_padding;      /* ETI-NA: leading 0xFF bytes */
    int etina_bit_offset;   /* ETI-NA: bit position of E1 sync */
    int etina_inverted;     /* ETI-NA: signal is inverted */
    /* Country, LTO and international table of the ensemble (FIG 0/9),
     * DVBDAB_HAVE_SERVICE_INFO (2.5.0 on); from a streamer, 0 from a scanner */
    uint8_t has_country;    /* 1 when FIG 0/9 was received */
    uint8_t ecc;            /* Extended country code */
    int8_t lto_half_hours;  /* Local time offset from UTC, in half hours */
    uint8_t international_table; /* 1: the programme types of RDS, 2: of RBDS */
} dvbdab_ensemble_t;

/* ETI-NA detection info */
typedef struct {
    uint16_t pid;           /* PID where ETI-NA detected */
    int padding_bytes;      /* Leading 0xFF bytes (typically 12) */
    int sync_bit_offset;    /* Bit position of E1 sync (0-7) */
    int inverted;           /* Signal is inverted */
} dvbdab_etina_info_t;

/* Scanner results - freed with dvbdab_results_free() */
typedef struct {
    int ensemble_count;                 /* Number of ensembles found */
    dvbdab_ensemble_t *ensembles;       /* Array of ensembles (freed by dvbdab_results_free) */
    int etina_count;                    /* Number of ETI-NA streams */
    dvbdab_etina_info_t *etina_streams; /* Array of ETI-NA info (freed by dvbdab_results_free) */
} dvbdab_results_t;

/**
 * Create a new TS scanner.
 * @return Scanner handle, or NULL on error
 */
dvbdab_scanner_t *dvbdab_scanner_create(void);

/**
 * Destroy a scanner.
 * @param scanner Scanner handle
 */
void dvbdab_scanner_destroy(dvbdab_scanner_t *scanner);

/**
 * Set scanner timeout.
 * @param scanner    Scanner handle
 * @param timeout_ms Timeout in milliseconds (default: 500)
 */
void dvbdab_scanner_set_timeout(dvbdab_scanner_t *scanner, unsigned int timeout_ms);

/**
 * Feed TS data to scanner.
 * @param scanner Scanner handle
 * @param data    Raw TS data (must start at sync byte 0x47)
 * @param len     Length in bytes
 * @return        0 = continue feeding, 1 = done
 */
int dvbdab_scanner_feed(dvbdab_scanner_t *scanner, const uint8_t *data, size_t len);

/**
 * Check if scanner is done.
 * @param scanner Scanner handle
 * @return        1 if done, 0 otherwise
 */
int dvbdab_scanner_is_done(dvbdab_scanner_t *scanner);

/**
 * Check if scanner received any traffic.
 * @param scanner Scanner handle
 * @return        1 if traffic received, 0 otherwise
 */
int dvbdab_scanner_had_traffic(dvbdab_scanner_t *scanner);

/**
 * Get scanner results.
 * Caller must free the results using dvbdab_results_free().
 * @param scanner Scanner handle
 * @return        Results structure (caller owns memory)
 */
dvbdab_results_t *dvbdab_scanner_get_results(dvbdab_scanner_t *scanner);

/**
 * Free results structure.
 * @param results Results to free
 */
void dvbdab_results_free(dvbdab_results_t *results);

/* ============================================================================
 * Unified DAB Streaming API
 * Supports ETI-NA, TS NI V.11 and IPv4 (DAB over IP: EDI in UDP)
 * Uses FFmpeg for proper TS output with PSI tables (PAT, PMT, SDT)
 * ============================================================================ */

/* Callback for TS output packets */
typedef void (*dvbdab_ts_output_cb)(void *opaque, const uint8_t *data, size_t len);

/* DAB stream format */
typedef enum {
    DVBDAB_FORMAT_ETI_NA = 0,  /* ETI-NA encapsulation */
    /* 1-3 were MPE, GSE and BBFrames in a pseudo TS (up to 1.x): the caller
     * takes the IPv4 packets out of them now (DVBDAB_FORMAT_IPV4) */
    DVBDAB_FORMAT_TSNI   = 4,  /* TS NI V.11 encapsulation */
    DVBDAB_FORMAT_IPV4   = 5   /* IPv4 packets the caller took out of their
                                  encapsulation (GSE, MPE): one per feed */
} dvbdab_format_t;

/* the library has DVBDAB_FORMAT_IPV4 (1.1.0 on) */
#define DVBDAB_HAVE_FORMAT_IPV4 1
/* the streamer config has aac_output (2.2.0 on): what becomes of DAB+ audio */
#define DVBDAB_HAVE_AAC_OUTPUT 1
/* the AUs as they came, in ADTS (stream type 0x0F). ADTS cannot tell their
 * 960-sample frames: decoders take 1024 samples per AU, the audio plays 6.7 %
 * slow and about a semitone low (and so do the PTS) */
#define DVBDAB_AAC_ADTS       0
/* the AUs as they came, in LATM/LOAS (stream type 0x11) with the
 * AudioSpecificConfig of the subchannel: 960 samples per AU, PTS in real
 * time; few decoders do SBR with 960 (FFmpeg does not: no SBR, 24 kHz) */
#define DVBDAB_AAC_LATM       1
/* decoded (faad2, 960 with SBR/PS) and encoded again as AAC-LC with 1024
 * samples per frame in ADTS (libavcodec): plays right with any decoder; lost
 * AUs become silence of their length. Only if dvbdab_aac_transcode() says
 * so, else ADTS */
#define DVBDAB_AAC_TRANSCODE  2
/* the streamer has dvbdab_streamer_set_wanted_pids() (2.2.0 on) */
#define DVBDAB_HAVE_WANTED_PIDS 1
/* the TS has the dynamic label of each service as RDS RadioText (stream type
 * 0x89, UECP; PID 0x1100 + subchannel ID) (2.3.0 on); a label of more than
 * 64 characters in RadioTexts that take turns, and the whole label in a
 * manufacturer's specific command, MEC 0x2D "dl" (2.7.0 on); the slides of
 * the slideshow of a service in pieces in such commands (2.8.0 on) */
#define DVBDAB_HAVE_RDS 1
/* the library has no MPE, GSE and BBFrame input (2.0.0 on) */
/* language and programme type of the services, country and LTO of the
 * ensemble, dvbdab_streamer_get_time(); the TS has the language in the PMT,
 * language and content in the EIT, and a TDT (2.5.0 on) */
#define DVBDAB_HAVE_SERVICE_INFO 1
/* dvbdab_streamer_get_stats(), dvbdab_streamer_get_service_stats() (2.5.0 on) */
#define DVBDAB_HAVE_STATS 1
/* dvbdab_streamer_set_logo_callback(): the logos of the services from the
 * programme guide of the ensemble (2.6.0 on) */
#define DVBDAB_HAVE_LOGOS 1
#define DVBDAB_VERSION_MAJOR 2
/* lost frames: DAB+ AUs of incomplete superframes, PTS with the gaps,
 * subchannels of EDI packets with lost fragments (2.1.0 on); the DAB+ output
 * modes (aac_output) and the wanted PIDs (2.2.0 on); dynamic labels checked
 * by their CRC, also of DAB, put out as RDS RadioText (2.3.0 on); the TS
 * with a PCR per service ahead of the PTS, PES by time, an SDT in sections
 * (2.4.0 on) */
#define DVBDAB_VERSION_MINOR 8
#define DVBDAB_VERSION_PATCH 0

/* The version of the library that is linked, to compare with the macros
 * above (the version of the header the caller was built with): the
 * structures here have no size field, header and library must be of one
 * version. As (major << 16 | minor << 8 | patch), and as "2.4.0". */
unsigned int dvbdab_version(void);
const char *dvbdab_version_string(void);

/* Opaque unified streamer handle - created with dvbdab_streamer_create() */
typedef struct dvbdab_streamer dvbdab_streamer_t;

/* Unified streamer configuration */
typedef struct {
    dvbdab_format_t format;     /* Stream format (ETI_NA, TSNI, IPV4) */
    uint16_t pid;               /* PID containing DAB data */

    /* ETI-NA specific (only used when format == DVBDAB_FORMAT_ETI_NA) */
    uint8_t eti_padding;        /* Leading 0xFF bytes (typically 12) */
    uint8_t eti_bit_offset;     /* Bit position of E1 sync (0-7) */
    uint8_t eti_inverted;       /* Signal is inverted */

    /* IPv4 specific (only used when format == IPV4) */
    uint32_t filter_ip;         /* Multicast IP to filter (host byte order) */
    uint16_t filter_port;       /* UDP port to filter */

    /* Optional: known ensemble ID (0 = discover from stream) */
    uint16_t eid;               /* Ensemble ID for TS output TSID */

    /* DAB+ output (DVBDAB_HAVE_AAC_OUTPUT): DVBDAB_AAC_ADTS (0),
     * DVBDAB_AAC_LATM or DVBDAB_AAC_TRANSCODE */
    uint8_t aac_output;
} dvbdab_streamer_config_t;

/* Whether the library can transcode DAB+ audio (DVBDAB_AAC_TRANSCODE): it
 * was built with faad2 and libavcodec, and the libavcodec that is linked
 * is of the major version it was built with and has an AAC encoder; 1 yes,
 * 0 no. A streamer asked for it all the same puts out ADTS and logs a
 * warning. */
int dvbdab_aac_transcode(void);

/**
 * Create a new unified DAB streamer.
 * Supports ETI-NA, TS NI V.11 and IPv4 (DAB over IP, EDI in UDP).
 * @param config Streamer configuration
 * @return Streamer handle, or NULL on error
 */
dvbdab_streamer_t *dvbdab_streamer_create(const dvbdab_streamer_config_t *config);

/**
 * Destroy a streamer.
 * @param streamer Streamer handle
 */
void dvbdab_streamer_destroy(dvbdab_streamer_t *streamer);

/**
 * Set TS output callback.
 * The callback receives complete TS packets (188 bytes each) with their
 * tables (PAT, PMT, SDT, EIT).
 * @param streamer Streamer handle
 * @param callback Function to call with output data
 * @param opaque   User data passed to callback
 */
void dvbdab_streamer_set_output(dvbdab_streamer_t *streamer,
                                 dvbdab_ts_output_cb callback, void *opaque);

/**
 * Feed raw TS data to streamer.
 * The streamer will filter for the configured PID internally.
 * DVBDAB_FORMAT_IPV4: one IPv4 packet (its UDP datagrams of the configured
 * address and port, or of all of them for discovery, count).
 * @param streamer Streamer handle
 * @param data     Raw TS data (must start at sync byte 0x47), or an IPv4 packet
 * @param len      Length in bytes (should be multiple of 188 for TS)
 * @return         0 on success, -1 on error
 */
int dvbdab_streamer_feed(dvbdab_streamer_t *streamer,
                          const uint8_t *data, size_t len);

/**
 * Check if ensemble discovery is complete.
 * @param streamer Streamer handle
 * @return         1 if ready, 0 if still discovering
 */
int dvbdab_streamer_is_ready(dvbdab_streamer_t *streamer);

/**
 * Check if basic service info is ready (before labels).
 * This allows starting audio earlier than full discovery.
 * @param streamer Streamer handle
 * @return         1 if basic ready, 0 if not
 */
int dvbdab_streamer_is_basic_ready(dvbdab_streamer_t *streamer);

/**
 * Get discovered ensemble info.
 * Caller must free with dvbdab_streamer_free_ensemble().
 * @param streamer Streamer handle
 * @return         Ensemble info, or NULL if not ready
 */
dvbdab_ensemble_t *dvbdab_streamer_get_ensemble(dvbdab_streamer_t *streamer);

/**
 * Free ensemble info returned by get_ensemble.
 * @param ensemble Ensemble to free
 */
void dvbdab_streamer_free_ensemble(dvbdab_ensemble_t *ensemble);

/**
 * Get all discovered ensembles (for discovery mode with filter_ip=0).
 * Returns all ensembles found by the EnsembleManager with their actual IPs:
 * the UDP streams whose FIC gave an ensemble id (eid != 0), not other data.
 * Caller must free with dvbdab_streamer_free_all_ensembles().
 * @param streamer Streamer handle
 * @param count    Output: number of ensembles returned
 * @return         Array of ensemble info, or NULL if none discovered
 */
dvbdab_ensemble_t *dvbdab_streamer_get_all_ensembles(dvbdab_streamer_t *streamer,
                                                       int *count);

/**
 * Free ensemble array returned by get_all_ensembles.
 * @param ensembles Array to free
 * @param count     Number of ensembles in array
 */
void dvbdab_streamer_free_all_ensembles(dvbdab_ensemble_t *ensembles, int count);

/*
 * Statistics (DVBDAB_HAVE_STATS, 2.5.0 on). All counters count from the
 * creation of the streamer (those of a service: from its start) and never
 * go back. Both calls take the size of the caller's structure and fill at
 * most that much: a caller built with an older header gets the fields it
 * knows.
 */
typedef struct {
    uint64_t eti_frames;         /* ETI frames that went to the services */
    uint64_t eti_frames_lost;    /* frames missing by the frame counter */
    uint64_t eti_bad_frames;     /* ETI-NA, TS NI: frames dropped for the CRC of their header */
    uint64_t eti_bad_data;       /* ETI-NA, TS NI: frames whose data CRC failed (FIC not
                                    read, their subchannels count as lost) */
    uint64_t etina_resyncs;      /* ETI-NA: times the frame sync was searched anew */
    uint64_t edi_partial_frames; /* EDI: frames from AF packets with lost PF fragments */
    uint64_t ts_packets;         /* TS packets put out */
    uint32_t services;           /* services of the output */
    uint32_t services_started;   /* of them started */
} dvbdab_stats_t;

/* output of a service */
#define DVBDAB_OUT_MP2      0    /* DAB: MPEG Layer II as it came */
#define DVBDAB_OUT_ADTS     1    /* DAB+: the AUs in ADTS */
#define DVBDAB_OUT_LATM     2    /* DAB+: the AUs in LATM/LOAS */
#define DVBDAB_OUT_AAC_LC   3    /* DAB+: transcoded to AAC-LC (ADTS) */

typedef struct {
    uint64_t frames;             /* frames of its subchannel that came */
    uint64_t audio_units;        /* DAB+ AUs or MP2 frames taken out of them */
    uint64_t audio_units_lost;   /* DAB+: AUs of lost frames and of superframes without their header */
    uint64_t crc_errors;         /* DAB+: AUs dropped by their CRC */
    uint64_t sync_losses;        /* DAB+: superframe sync lost; DAB: frames without an MP2 header */
    uint64_t transcode_errors;   /* AUs the decoder of the transcoder refused */
    uint64_t silent_units;       /* AUs the transcoder put out as silence */
    uint64_t labels;             /* dynamic labels that came whole */
    uint64_t pad_crc_errors;     /* PAD data groups dropped by their CRC */
    int dabplus;                 /* 1 for DAB+, 0 for DAB */
    int output;                  /* DVBDAB_OUT_* */
    int started;                 /* 1 if the service is started */
    int transcoding;             /* 1 while its transcoder runs (DVBDAB_AAC_TRANSCODE
                                    and its PIDs are wanted) */
} dvbdab_service_stats_t;

/**
 * Statistics of a streamer.
 * @param streamer Streamer handle
 * @param stats    Output
 * @param size     sizeof(*stats) of the caller
 * @return         0 on success, -1 on error
 */
int dvbdab_streamer_get_stats(dvbdab_streamer_t *streamer, dvbdab_stats_t *stats, size_t size);

/*
 * Logos (DVBDAB_HAVE_LOGOS, 2.6.0 on). An ensemble with a programme guide
 * (SPI, ETSI TS 102 818) can send logos of its services with it: image
 * files in the carousel of the guide, which its service information gives
 * to the services. A service usually has several, of different sizes
 * (32x32, 112x32, 128x128, 320x240, 600x600). A carousel takes minutes to
 * come round.
 */
typedef struct {
    uint32_t sid;           /* the service */
    const char *mime_type;  /* "image/png" or "image/jpeg" */
    int width, height;      /* pixels; 0 = not known */
    const uint8_t *data;    /* the image file as it was sent; valid during the call */
    size_t len;
} dvbdab_logo_t;

typedef void (*dvbdab_logo_cb)(void *opaque, const dvbdab_logo_t *logo);

/**
 * Set the callback for the logos of the services. Each logo of each service
 * is told once, and again when its image changed. Called from
 * dvbdab_streamer_feed(). Without a callback the images are not kept: set
 * it before feeding.
 * @param streamer Streamer handle
 * @param callback Function to call with a logo, or NULL for none
 * @param opaque   User data passed to callback
 */
void dvbdab_streamer_set_logo_callback(dvbdab_streamer_t *streamer, dvbdab_logo_cb callback, void *opaque);

/**
 * Statistics of one service of a streamer.
 * @param streamer      Streamer handle
 * @param subchannel_id Its subchannel ID
 * @param stats         Output
 * @param size          sizeof(*stats) of the caller
 * @return              0 on success, -1 if there is no such service (yet)
 */
int dvbdab_streamer_get_service_stats(dvbdab_streamer_t *streamer, int subchannel_id,
                                       dvbdab_service_stats_t *stats, size_t size);

/**
 * The date and time the ensemble sends (FIG 0/10), as of the last frame
 * that was fed (DVBDAB_HAVE_SERVICE_INFO).
 * @param streamer Streamer handle
 * @param utc_ms   Output: UTC in milliseconds since 1970-01-01
 * @return         1 if the ensemble sent a time, 0 if not (yet)
 */
int dvbdab_streamer_get_time(dvbdab_streamer_t *streamer, int64_t *utc_ms);

/**
 * Start streaming a specific service (by subchannel ID).
 * Multiple services can be started.
 * @param streamer     Streamer handle
 * @param subchannel_id Subchannel ID to stream
 * @return              0 on success, -1 on error
 */
int dvbdab_streamer_start_service(dvbdab_streamer_t *streamer,
                                   uint8_t subchannel_id);

/**
 * Stop streaming a specific service.
 * @param streamer     Streamer handle
 * @param subchannel_id Subchannel ID to stop
 * @return              0 on success, -1 on error
 */
int dvbdab_streamer_stop_service(dvbdab_streamer_t *streamer,
                                  uint8_t subchannel_id);

/**
 * The PIDs of the output the caller takes (count < 0: all, the default).
 * With DVBDAB_AAC_TRANSCODE, the DAB+ audio of a service is decoded and
 * encoded again only while its PMT or audio PID is among them; the other
 * services have no audio in the output (they stay in PAT, PMT and SDT).
 * Any time, from the thread that feeds the streamer.
 * @param streamer Streamer handle
 * @param pids     The PIDs (count of them; NULL with count <= 0)
 * @param count    Their number, < 0 for all
 * @return         0 on success, -1 on error
 */
int dvbdab_streamer_set_wanted_pids(dvbdab_streamer_t *streamer,
                                    const uint16_t *pids, int count);

/**
 * Start streaming all services in the ensemble.
 * @param streamer Streamer handle
 * @return         Number of services started, or -1 on error
 */
int dvbdab_streamer_start_all(dvbdab_streamer_t *streamer);

/* ============================================================================
 * Logging API
 * ============================================================================ */

/** Log levels (matching logging.h enum) */
#define DVBDAB_LOG_ERROR  0
#define DVBDAB_LOG_WARN   1
#define DVBDAB_LOG_INFO   2
#define DVBDAB_LOG_DEBUG  3
#define DVBDAB_LOG_TRACE  4

/**
 * Log callback signature.
 * @param level   Log level (DVBDAB_LOG_*)
 * @param tag     Component tag (e.g., "DABPLUS", "PAD", "MP2")
 * @param message Log message
 */
typedef void(*dvbdab_log_callback_t)(int level, const char* tag, const char* message);

/**
 * Set log callback for integrating with external logging systems.
 * @param callback Callback function, or NULL to use default stderr output
 */
void dvbdab_set_log_callback(dvbdab_log_callback_t callback);

/**
 * Set minimum log level (messages below this level are filtered).
 * @param level Minimum log level (DVBDAB_LOG_*)
 */
void dvbdab_set_log_level(int level);

#ifdef __cplusplus
}
#endif

#endif /* DVBDAB_C_H */
