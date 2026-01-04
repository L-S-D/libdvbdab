/*
 * libdvbdab C API
 * C wrapper for using libdvbdab from C code (e.g., tvheadend)
 */
#ifndef DVBDAB_C_H
#define DVBDAB_C_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque scanner handle */
typedef struct dvbdab_scanner dvbdab_scanner_t;

/* DAB service info (C struct) */
typedef struct {
    uint32_t sid;           /* Service ID */
    char label[17];         /* Service label (16 chars + null) */
    int bitrate;            /* Bitrate in kbps */
    int subchannel_id;      /* Sub-channel ID */
    int dabplus;            /* 1 for DAB+, 0 for DAB */
} dvbdab_service_t;

/* DAB ensemble info (C struct) */
typedef struct {
    uint16_t eid;           /* Ensemble ID */
    char label[17];         /* Ensemble label */
    uint32_t source_ip;     /* Source multicast IP (0 for ETI-NA) */
    uint16_t source_port;   /* Source UDP port (0 for ETI-NA) */
    uint16_t source_pid;    /* PID where ensemble was found */
    int service_count;      /* Number of services */
    dvbdab_service_t *services; /* Array of services (caller must free) */
    /* Source type flags */
    int is_etina;           /* 1 if ETI-NA encapsulation */
    int is_gse;             /* 1 if GSE encapsulation (BBFrame), 0 if MPE */
    int is_tsni;            /* 1 if TS NI V.11 encapsulation */
    /* ETI-NA specific fields (valid when is_etina is true) */
    int etina_padding;      /* ETI-NA: leading 0xFF bytes */
    int etina_bit_offset;   /* ETI-NA: bit position of E1 sync */
    int etina_inverted;     /* ETI-NA: signal is inverted */
} dvbdab_ensemble_t;

/* ETI-NA detection info */
typedef struct {
    uint16_t pid;           /* PID where ETI-NA detected */
    int padding_bytes;      /* Leading 0xFF bytes (typically 12) */
    int sync_bit_offset;    /* Bit position of E1 sync (0-7) */
    int inverted;           /* Signal is inverted */
} dvbdab_etina_info_t;

/* Scanner results */
typedef struct {
    int ensemble_count;                 /* Number of ensembles found */
    dvbdab_ensemble_t *ensembles;       /* Array of ensembles */
    int etina_count;                    /* Number of ETI-NA streams */
    dvbdab_etina_info_t *etina_streams; /* Array of ETI-NA info */
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
 * Supports ETI-NA, MPE, and GSE encapsulation formats
 * Uses FFmpeg for proper TS output with PSI tables (PAT, PMT, SDT)
 * ============================================================================ */

/* Callback for TS output packets */
typedef void (*dvbdab_ts_output_cb)(void *opaque, const uint8_t *data, size_t len);

/* DAB stream format */
typedef enum {
    DVBDAB_FORMAT_ETI_NA = 0,  /* ETI-NA encapsulation */
    DVBDAB_FORMAT_MPE    = 1,  /* MPE/IP encapsulation */
    DVBDAB_FORMAT_GSE    = 2,  /* GSE encapsulation (in normal TS) */
    DVBDAB_FORMAT_BBF_TS = 3,  /* BBFrame-in-PseudoTS (from DMX_SET_FE_STREAM) */
    DVBDAB_FORMAT_TSNI   = 4   /* TS NI V.11 encapsulation */
} dvbdab_format_t;

/* Opaque unified streamer handle */
typedef struct dvbdab_streamer dvbdab_streamer_t;

/* Unified streamer configuration */
typedef struct {
    dvbdab_format_t format;     /* Stream format (ETI_NA, MPE, or GSE) */
    uint16_t pid;               /* PID containing DAB data */

    /* ETI-NA specific (only used when format == DVBDAB_FORMAT_ETI_NA) */
    uint8_t eti_padding;        /* Leading 0xFF bytes (typically 12) */
    uint8_t eti_bit_offset;     /* Bit position of E1 sync (0-7) */
    uint8_t eti_inverted;       /* Signal is inverted */

    /* MPE/GSE specific (only used when format == MPE or GSE) */
    uint32_t filter_ip;         /* Multicast IP to filter (host byte order) */
    uint16_t filter_port;       /* UDP port to filter */

    /* Optional: known ensemble ID (0 = discover from stream) */
    uint16_t eid;               /* Ensemble ID for TS output TSID */
} dvbdab_streamer_config_t;

/**
 * Create a new unified DAB streamer.
 * Supports ETI-NA, MPE, and GSE formats.
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
 * The callback receives complete TS packets (188 bytes each) with proper
 * PSI tables (PAT, PMT, SDT) generated by FFmpeg.
 * @param streamer Streamer handle
 * @param callback Function to call with output data
 * @param opaque   User data passed to callback
 */
void dvbdab_streamer_set_output(dvbdab_streamer_t *streamer,
                                 dvbdab_ts_output_cb callback, void *opaque);

/**
 * Feed raw TS data to streamer.
 * The streamer will filter for the configured PID internally.
 * @param streamer Streamer handle
 * @param data     Raw TS data (must start at sync byte 0x47)
 * @param len      Length in bytes (should be multiple of 188)
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
 * Returns all ensembles found by the EnsembleManager with their actual IPs.
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
 * Start streaming all services in the ensemble.
 * @param streamer Streamer handle
 * @return         Number of services started, or -1 on error
 */
int dvbdab_streamer_start_all(dvbdab_streamer_t *streamer);

#ifdef __cplusplus
}
#endif

#endif /* DVBDAB_C_H */
