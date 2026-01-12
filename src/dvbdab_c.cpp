/*
 * libdvbdab C API implementation
 */
#include <dvbdab/dvbdab_c.h>
#include <dvbdab/ts_scanner.hpp>
#include "etina_pipeline.hpp"
#include "dab_parser.h"
#include "output/dab_stream_processor.hpp"
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <map>
#include <memory>

using namespace dvbdab;

struct dvbdab_scanner {
    TsScanner scanner;
};

extern "C" {

dvbdab_scanner_t *dvbdab_scanner_create(void)
{
    try {
        return new dvbdab_scanner();
    } catch (...) {
        return nullptr;
    }
}

void dvbdab_scanner_destroy(dvbdab_scanner_t *scanner)
{
    delete scanner;
}

void dvbdab_scanner_set_timeout(dvbdab_scanner_t *scanner, unsigned int timeout_ms)
{
    if (scanner) {
        scanner->scanner.setTimeout(timeout_ms);
    }
}

int dvbdab_scanner_feed(dvbdab_scanner_t *scanner, const uint8_t *data, size_t len)
{
    if (!scanner || !data || len == 0) {
        return 1;
    }
    return scanner->scanner.feed(data, len);
}

int dvbdab_scanner_is_done(dvbdab_scanner_t *scanner)
{
    if (!scanner) return 1;
    return scanner->scanner.isDone() ? 1 : 0;
}

int dvbdab_scanner_had_traffic(dvbdab_scanner_t *scanner)
{
    if (!scanner) return 0;
    return scanner->scanner.hadTraffic() ? 1 : 0;
}

dvbdab_results_t *dvbdab_scanner_get_results(dvbdab_scanner_t *scanner)
{
    if (!scanner) return nullptr;

    auto results = static_cast<dvbdab_results_t*>(calloc(1, sizeof(dvbdab_results_t)));
    if (!results) return nullptr;

    // Get ensembles
    auto ensembles = scanner->scanner.getResults();
    results->ensemble_count = static_cast<int>(ensembles.size());

    if (results->ensemble_count > 0) {
        results->ensembles = static_cast<dvbdab_ensemble_t*>(
            calloc(results->ensemble_count, sizeof(dvbdab_ensemble_t)));

        for (int i = 0; i < results->ensemble_count; i++) {
            const auto& ens = ensembles[i];
            auto& out = results->ensembles[i];

            out.eid = ens.eid;
            strncpy(out.label, ens.label.c_str(), 16);
            out.label[16] = '\0';
            out.source_ip = ens.ip;
            out.source_port = ens.port;
            out.source_pid = ens.pid;
            out.service_count = static_cast<int>(ens.services.size());

            // Source type flags
            out.is_etina = ens.is_etina ? 1 : 0;
            out.is_tsni = ens.is_tsni ? 1 : 0;
            if (ens.is_etina) {
                out.etina_padding = ens.etina_info.padding_bytes;
                out.etina_bit_offset = ens.etina_info.sync_bit_offset;
                out.etina_inverted = ens.etina_info.inverted ? 1 : 0;
            }

            if (out.service_count > 0) {
                out.services = static_cast<dvbdab_service_t*>(
                    calloc(out.service_count, sizeof(dvbdab_service_t)));

                for (int j = 0; j < out.service_count; j++) {
                    const auto& svc = ens.services[j];
                    auto& svc_out = out.services[j];

                    svc_out.sid = svc.sid;
                    strncpy(svc_out.label, svc.label.c_str(), 16);
                    svc_out.label[16] = '\0';
                    svc_out.bitrate = svc.bitrate;
                    svc_out.subchannel_id = svc.subchannel_id;
                    svc_out.dabplus = svc.dabplus ? 1 : 0;
                }
            }
        }
    }

    // Get ETI-NA results
    auto etina = scanner->scanner.getEtiNaResults();
    results->etina_count = static_cast<int>(etina.size());

    if (results->etina_count > 0) {
        results->etina_streams = static_cast<dvbdab_etina_info_t*>(
            calloc(results->etina_count, sizeof(dvbdab_etina_info_t)));

        for (int i = 0; i < results->etina_count; i++) {
            const auto& e = etina[i];
            auto& out = results->etina_streams[i];

            out.pid = e.pid;
            out.padding_bytes = e.padding_bytes;
            out.sync_bit_offset = e.sync_bit_offset;
            out.inverted = e.inverted ? 1 : 0;
        }
    }

    return results;
}

void dvbdab_results_free(dvbdab_results_t *results)
{
    if (!results) return;

    if (results->ensembles) {
        for (int i = 0; i < results->ensemble_count; i++) {
            free(results->ensembles[i].services);
        }
        free(results->ensembles);
    }

    free(results->etina_streams);
    free(results);
}

} // extern "C" - pause for C++ helpers

/* ============================================================================
 * ETI-NA Streaming Implementation
 * ============================================================================ */

#include "utils/byte_utils.hpp"

// Use TS constants and helpers from dvbdab namespace
using dvbdab::TS_PACKET_SIZE;
using dvbdab::TS_HEADER_SIZE;
using dvbdab::ts_get_pid;
using dvbdab::ts_has_payload;
using dvbdab::ts_has_adaptation;
using dvbdab::ts_payload_start;

// Local helpers not in byte_utils.hpp
static inline bool ts_is_sync(const uint8_t* ts) { return ts[0] == 0x47; }

// TS payload extraction with length output (unique to this file)
static inline const uint8_t* ts_get_payload_with_len(const uint8_t* ts, size_t* payload_len) {
    if (!ts_has_payload(ts)) {
        *payload_len = 0;
        return nullptr;
    }
    size_t offset = TS_HEADER_SIZE;
    if (ts_has_adaptation(ts)) {
        offset += 1 + ts[4];  // AF length byte + AF data
    }
    if (offset >= TS_PACKET_SIZE) {
        *payload_len = 0;
        return nullptr;
    }
    *payload_len = TS_PACKET_SIZE - offset;
    return &ts[offset];
}

// Generic TS packet processor - extracts payloads from matching PID
// Callback signature: void(const uint8_t* payload, size_t payload_len, bool pusi)
// Returns number of bytes consumed from buffer
template<typename Callback>
static size_t process_ts_payloads(std::vector<uint8_t>& ts_buffer, uint16_t target_pid, Callback&& callback) {
    size_t offset = 0;
    while (offset + TS_PACKET_SIZE <= ts_buffer.size()) {
        const uint8_t* ts = ts_buffer.data() + offset;

        // Find sync byte (handle lost sync)
        if (!ts_is_sync(ts)) {
            offset++;
            continue;
        }

        if (ts_get_pid(ts) != target_pid) {
            offset += TS_PACKET_SIZE;
            continue;
        }

        size_t payload_len;
        const uint8_t* payload = ts_get_payload_with_len(ts, &payload_len);
        if (!payload || payload_len == 0) {
            offset += TS_PACKET_SIZE;
            continue;
        }

        callback(payload, payload_len, ts_payload_start(ts));
        offset += TS_PACKET_SIZE;
    }
    return offset;
}

// Helper to clean up processed data from buffer
static void ts_buffer_consume(std::vector<uint8_t>& ts_buffer, size_t consumed) {
    if (consumed > 0) {
        ts_buffer.erase(ts_buffer.begin(), ts_buffer.begin() + consumed);
    }
}

/* ============================================================================
 * Unified DAB Streaming Implementation
 * ============================================================================ */

#include "sources/mpe_ts_source.hpp"
#include "sources/gse_ts_source.hpp"
#include "sources/bbf_ts_source.hpp"
#include "ensemble_manager.hpp"
#include "parsers/udp_extractor.hpp"

struct dvbdab_streamer {
    // Configuration
    dvbdab_streamer_config_t config;

    // Output callback
    dvbdab_ts_output_cb output_cb;
    void* output_opaque;

    // Format-specific sources (input stage)
    std::unique_ptr<MpeTsSource> mpe_source;
    std::unique_ptr<GseTsSource> gse_source;
    std::unique_ptr<BbfTsSource> bbf_source;  // For BBF-in-PseudoTS (DMX_SET_FE_STREAM)

    // ETI-NA modular pipeline state
    EtinaPipelineState etina_pipeline;
    bool etina_detected{false};  // True once pipeline is producing ETI frames

    // Partial TS packet buffer for ETI-NA/TSNI (handles unaligned input chunks)
    std::vector<uint8_t> ts_buffer;

    // TSNI (TS NI V.11) state
    std::vector<uint8_t> tsni_frame_buffer;  // Frame accumulation buffer
    bool tsni_detected{false};  // True once TSNI is producing ETI frames
    static constexpr size_t TSNI_FRAME_SIZE = 6140;  // ETI-NI frame size

    // UDP extraction (for MPE/GSE)
    std::unique_ptr<UdpExtractor> udp_extractor;

    // DAB parsing - EnsembleManager for all formats (MPE/GSE/ETI-NA)
    std::unique_ptr<EnsembleManager> manager;

    // Unified stream processor (audio + EPG + TS muxing)
    std::unique_ptr<DabStreamProcessor> processor;

    // State
    bool processor_initialized;
    bool basic_ready;
    bool complete;
    bool auto_start_all;  // Auto-start all services when ensemble ready

    // Debug counters (per-streamer)
    int ts_output_count{0};
    size_t ts_output_bytes{0};

    // Cached ensemble for get_ensemble
    DABEnsemble cached_ensemble;
};

// Helper to configure processor from ensemble
static void setup_processor_from_ensemble(dvbdab_streamer* s, const DABEnsemble& ensemble) {
    if (s->processor_initialized || !s->processor) return;

    // Use config EID if provided, otherwise use discovered EID
    uint16_t eid = (s->config.eid != 0) ? s->config.eid : ensemble.eid;
    s->processor->setEnsemble(eid, ensemble.label, ensemble.label);

    // Use subchannel_id for deterministic PID allocation
    for (const auto& svc : ensemble.services) {
        TsService cs;
        cs.sid = static_cast<uint16_t>(svc.sid);
        cs.pmt_pid = 0x0100 + svc.subchannel_id;
        cs.audio_pid = 0x1000 + svc.subchannel_id;
        cs.name = svc.label;
        cs.provider = ensemble.label;
        cs.dabplus = svc.dabplus;
        cs.subchannel_id = svc.subchannel_id;
        cs.bitrate = svc.bitrate;
        // Estimate sample rate based on codec and bitrate
        // DAB (MP2) at low bitrates typically uses 24kHz (MPEG-2 Layer II)
        // DAB+ (AAC) typically uses 48kHz or 32kHz
        // Note: actual PTS calculation parses sample rate from frame headers
        if (svc.dabplus) {
            cs.sample_rate = 48000;  // DAB+ typically 48kHz
        } else {
            cs.sample_rate = (svc.bitrate <= 80) ? 24000 : 48000;  // DAB MP2
        }

        s->processor->addService(cs);
    }

    s->processor_initialized = true;
}

// Forward declaration
static int internal_start_all_services(dvbdab_streamer* s);

// Called when processor is ready and auto_start_all is set
static void auto_start_services_if_ready(dvbdab_streamer* s) {
    if (!s->processor_initialized || !s->auto_start_all) return;
    // Start all services if not yet started
    internal_start_all_services(s);
}

// Shared ETI frame processing - used by all input formats (ETI-NA, MPE, GSE, TSNI)
// All formats produce ETI frames that are processed identically here
// Called via eti_callback from EnsembleManager
static void process_eti_frame(dvbdab_streamer* s, const uint8_t* eti_ni, size_t len) {
    if (!s->processor_initialized || !s->processor) return;
    // Feed to unified processor - handles audio + EPG + TS muxing
    s->processor->feedEtiFrame(eti_ni, len);
}

extern "C" { // Resume C API

dvbdab_streamer_t *dvbdab_streamer_create(const dvbdab_streamer_config_t *config)
{
    if (!config) return nullptr;

    try {
        auto s = new dvbdab_streamer();
        s->config = *config;
        s->output_cb = nullptr;
        s->output_opaque = nullptr;
        s->processor_initialized = false;
        s->basic_ready = false;
        s->complete = false;
        s->auto_start_all = false;

        switch (config->format) {
        case DVBDAB_FORMAT_ETI_NA:
            // ETI-NA: TS -> etina_pipeline -> ETI-NI -> EnsembleManager -> audio
            // Uses same EnsembleManager path as MPE/GSE for FIC parsing and callbacks
            s->manager = std::make_unique<EnsembleManager>();

            // Set ensemble callbacks - for ETI-NA the key is (pid, 0)
            s->manager->setBasicReadyCallback([s](const StreamKey& key, const DABEnsemble& ens) {
                // ETI-NA key: ip=pid, port=0
                if (key.ip == static_cast<uint32_t>(s->config.pid) && key.port == 0) {
                    s->cached_ensemble = ens;
                    s->basic_ready = true;
                    if (s->processor) {
                        setup_processor_from_ensemble(s, ens);
                        auto_start_services_if_ready(s);
                    }
                }
            });

            s->manager->setCompleteCallback([s](const StreamKey& key, const DABEnsemble& ens) {
                if (key.ip == static_cast<uint32_t>(s->config.pid) && key.port == 0) {
                    s->cached_ensemble = ens;
                    s->complete = true;
                    if (s->processor) {
                        // Update ensemble name/provider now that label is available
                        uint16_t eid = (s->config.eid != 0) ? s->config.eid : ens.eid;
                        s->processor->setEnsemble(eid, ens.label, ens.label);
                        for (const auto& svc : ens.services) {
                            s->processor->updateServiceLabel(static_cast<uint16_t>(svc.sid), svc.label);
                        }
                    }
                }
            });

            // ETI callback from EnsembleManager -> shared ETI processing for audio
            s->manager->setEtiCallback([s](const StreamKey& key, const uint8_t* data, size_t len, uint16_t) {
                if (key.ip != static_cast<uint32_t>(s->config.pid) || key.port != 0) return;
                process_eti_frame(s, data, len);
            });
            break;

        case DVBDAB_FORMAT_MPE:
            // MPE: TS -> MpeTsSource -> IP -> UdpExtractor -> UDP -> EnsembleManager -> ETI
            s->mpe_source = std::make_unique<MpeTsSource>(config->pid);
            s->mpe_source->setIpFilter(config->filter_ip, config->filter_port);
            s->manager = std::make_unique<EnsembleManager>();

            // Create UDP extractor: IP packets -> UDP payloads -> EnsembleManager
            s->udp_extractor = std::make_unique<UdpExtractor>(
                [s](uint32_t ip, uint16_t port, const uint8_t* payload, size_t len) {
                    s->manager->processUdp(ip, port, payload, len);
                });

            // Connect MpeTsSource -> UdpExtractor
            s->mpe_source->setIpCallback([s](const uint8_t* ip_data, size_t len) {
                s->udp_extractor->process(ip_data, len);
            });

            // Set ensemble callbacks
            s->manager->setBasicReadyCallback([s](const StreamKey& key, const DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->basic_ready = true;
                    if (s->processor) {
                        setup_processor_from_ensemble(s, ens);
                        auto_start_services_if_ready(s);
                    }
                }
            });

            s->manager->setCompleteCallback([s](const StreamKey& key, const DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->complete = true;
                    if (s->processor) {
                        // Update ensemble name/provider now that label is available
                        uint16_t eid = (s->config.eid != 0) ? s->config.eid : ens.eid;
                        s->processor->setEnsemble(eid, ens.label, ens.label);
                        for (const auto& svc : ens.services) {
                            s->processor->updateServiceLabel(static_cast<uint16_t>(svc.sid), svc.label);
                        }
                    }
                }
            });

            // ETI callback from EnsembleManager -> shared ETI processing
            s->manager->setEtiCallback([s](const StreamKey& key, const uint8_t* data, size_t len, uint16_t) {
                if (key.ip != s->config.filter_ip || key.port != s->config.filter_port) return;
                process_eti_frame(s, data, len);
            });
            break;

        case DVBDAB_FORMAT_GSE:
            // GSE: TS -> GseTsSource -> IP -> UdpExtractor -> UDP -> EnsembleManager -> ETI
            // Note: GseTsSource extracts from all GSE data, filtering by IP is done at EnsembleManager level
            s->gse_source = std::make_unique<GseTsSource>();
            s->manager = std::make_unique<EnsembleManager>();

            // Create UDP extractor
            s->udp_extractor = std::make_unique<UdpExtractor>(
                [s](uint32_t ip, uint16_t port, const uint8_t* payload, size_t len) {
                    s->manager->processUdp(ip, port, payload, len);
                });

            // Connect GseTsSource -> UdpExtractor
            s->gse_source->setIpCallback([s](const uint8_t* ip_data, size_t len) {
                s->udp_extractor->process(ip_data, len);
            });

            // Set ensemble callbacks
            s->manager->setBasicReadyCallback([s](const StreamKey& key, const DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->basic_ready = true;
                    if (s->processor) {
                        setup_processor_from_ensemble(s, ens);
                        auto_start_services_if_ready(s);
                    }
                }
            });

            s->manager->setCompleteCallback([s](const StreamKey& key, const DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->complete = true;
                    if (s->processor) {
                        // Update ensemble name/provider now that label is available
                        uint16_t eid = (s->config.eid != 0) ? s->config.eid : ens.eid;
                        s->processor->setEnsemble(eid, ens.label, ens.label);
                        for (const auto& svc : ens.services) {
                            s->processor->updateServiceLabel(static_cast<uint16_t>(svc.sid), svc.label);
                        }
                    }
                }
            });

            // ETI callback from EnsembleManager -> shared ETI processing
            s->manager->setEtiCallback([s](const StreamKey& key, const uint8_t* data, size_t len, uint16_t) {
                if (key.ip != s->config.filter_ip || key.port != s->config.filter_port) return;
                process_eti_frame(s, data, len);
            });
            break;

        case DVBDAB_FORMAT_BBF_TS:
            // BBF-in-PseudoTS: Raw BBFrames from DMX_SET_FE_STREAM -> IP -> EnsembleManager
            // This is for GSE data delivered via the special demux mode
            s->bbf_source = std::make_unique<BbfTsSource>();
            s->manager = std::make_unique<EnsembleManager>();

            // Create UDP extractor
            s->udp_extractor = std::make_unique<UdpExtractor>(
                [s](uint32_t ip, uint16_t port, const uint8_t* payload, size_t len) {
                    s->manager->processUdp(ip, port, payload, len);
                });

            // Connect BbfTsSource -> UdpExtractor
            s->bbf_source->setIpCallback([s](const uint8_t* ip_data, size_t len) {
                s->udp_extractor->process(ip_data, len);
            });

            // Set ensemble callbacks
            s->manager->setBasicReadyCallback([s](const StreamKey& key, const DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->basic_ready = true;
                    if (s->processor) {
                        setup_processor_from_ensemble(s, ens);
                        auto_start_services_if_ready(s);
                    }
                }
            });

            s->manager->setCompleteCallback([s](const StreamKey& key, const DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->complete = true;
                    if (s->processor) {
                        // Update ensemble name/provider now that label is available
                        uint16_t eid = (s->config.eid != 0) ? s->config.eid : ens.eid;
                        s->processor->setEnsemble(eid, ens.label, ens.label);
                        for (const auto& svc : ens.services) {
                            s->processor->updateServiceLabel(static_cast<uint16_t>(svc.sid), svc.label);
                        }
                    }
                }
            });

            // ETI callback from EnsembleManager -> shared ETI processing
            s->manager->setEtiCallback([s](const StreamKey& key, const uint8_t* data, size_t len, uint16_t) {
                if (key.ip != s->config.filter_ip || key.port != s->config.filter_port) return;
                process_eti_frame(s, data, len);
            });
            break;

        case DVBDAB_FORMAT_TSNI:
            // TSNI: TS -> parse sections with incrementing table_id -> ETI-NI -> EnsembleManager -> audio
            // Similar to ETI-NA but with different encapsulation (PUSI + pointer + sequence byte)
            s->manager = std::make_unique<EnsembleManager>();
            s->tsni_frame_buffer.reserve(s->TSNI_FRAME_SIZE + 188);

            // Set ensemble callbacks - for TSNI the key is (pid, 0) like ETI-NA
            s->manager->setBasicReadyCallback([s](const StreamKey& key, const DABEnsemble& ens) {
                if (key.ip == static_cast<uint32_t>(s->config.pid) && key.port == 0) {
                    s->cached_ensemble = ens;
                    s->basic_ready = true;
                    if (s->processor) {
                        setup_processor_from_ensemble(s, ens);
                        auto_start_services_if_ready(s);
                    }
                }
            });

            s->manager->setCompleteCallback([s](const StreamKey& key, const DABEnsemble& ens) {
                if (key.ip == static_cast<uint32_t>(s->config.pid) && key.port == 0) {
                    s->cached_ensemble = ens;
                    s->complete = true;
                    if (s->processor) {
                        // Update ensemble name/provider now that label is available
                        uint16_t eid = (s->config.eid != 0) ? s->config.eid : ens.eid;
                        s->processor->setEnsemble(eid, ens.label, ens.label);
                        for (const auto& svc : ens.services) {
                            s->processor->updateServiceLabel(static_cast<uint16_t>(svc.sid), svc.label);
                        }
                    }
                }
            });

            // ETI callback from EnsembleManager -> shared ETI processing for audio
            s->manager->setEtiCallback([s](const StreamKey& key, const uint8_t* data, size_t len, uint16_t) {
                if (key.ip != static_cast<uint32_t>(s->config.pid) || key.port != 0) return;
                process_eti_frame(s, data, len);
            });
            break;

        default:
            delete s;
            return nullptr;
        }

        return s;
    } catch (...) {
        return nullptr;
    }
}

void dvbdab_streamer_destroy(dvbdab_streamer_t *streamer)
{
    delete streamer;
}

void dvbdab_streamer_set_output(dvbdab_streamer_t *streamer,
                                 dvbdab_ts_output_cb callback, void *opaque)
{
    if (!streamer) return;

    streamer->output_cb = callback;
    streamer->output_opaque = opaque;

    if (!streamer->processor) {
        streamer->processor = std::make_unique<DabStreamProcessor>();
        streamer->processor->setOutput([streamer](const uint8_t* data, size_t len) {
            streamer->ts_output_count++;
            streamer->ts_output_bytes += len;
            if (streamer->output_cb) {
                streamer->output_cb(streamer->output_opaque, data, len);
            }
        });
    }
}

int dvbdab_streamer_feed(dvbdab_streamer_t *streamer, const uint8_t *data, size_t len)
{
    if (!streamer || !data || len == 0) return -1;

    switch (streamer->config.format) {
    case DVBDAB_FORMAT_ETI_NA: {
        streamer->ts_buffer.insert(streamer->ts_buffer.end(), data, data + len);

        size_t consumed = process_ts_payloads(streamer->ts_buffer, streamer->config.pid,
            [streamer](const uint8_t* payload, size_t payload_len, bool /*pusi*/) {
                // Feed to modular pipeline, get ETI frames via callback
                etina_feed_payload(streamer->etina_pipeline, payload, payload_len,
                    [streamer](const uint8_t* eti_ni, size_t len) {
                        if (!streamer->manager) return;
                        streamer->etina_detected = true;
                        streamer->manager->processEtiFrame(streamer->config.pid, eti_ni, len);
                    });
            });

        ts_buffer_consume(streamer->ts_buffer, consumed);
        break;
    }

    case DVBDAB_FORMAT_MPE:
        if (!streamer->mpe_source) return -1;
        streamer->mpe_source->feed(data, len);
        break;

    case DVBDAB_FORMAT_GSE:
        if (!streamer->gse_source) return -1;
        streamer->gse_source->feed(data, len);
        break;

    case DVBDAB_FORMAT_BBF_TS:
        if (!streamer->bbf_source) return -1;
        streamer->bbf_source->feed(data, len);
        break;

    case DVBDAB_FORMAT_TSNI: {
        // TSNI: TS NI V.11 format - ETI-NI frames with incrementing sequence byte (0x69-0x9A)
        if (!streamer->manager) return -1;

        streamer->ts_buffer.insert(streamer->ts_buffer.end(), data, data + len);

        size_t consumed = process_ts_payloads(streamer->ts_buffer, streamer->config.pid,
            [streamer](const uint8_t* payload, size_t payload_len, bool pusi) {
                if (pusi && payload_len > 1) {
                    // Frame boundary - output previous frame if we have data
                    if (streamer->tsni_frame_buffer.size() >= 4) {
                        uint8_t seq_byte = streamer->tsni_frame_buffer[0];
                        std::vector<uint8_t> frame;
                        frame.reserve(streamer->TSNI_FRAME_SIZE);

                        // ETI-NI sync: ff 07 3a b6 (even) or ff f8 c5 49 (odd)
                        if (seq_byte % 2 == 0) {
                            frame.insert(frame.end(), {0xff, 0x07, 0x3a, 0xb6});
                        } else {
                            frame.insert(frame.end(), {0xff, 0xf8, 0xc5, 0x49});
                        }
                        frame.insert(frame.end(), streamer->tsni_frame_buffer.begin(),
                                     streamer->tsni_frame_buffer.end());

                        if (frame.size() < streamer->TSNI_FRAME_SIZE) {
                            frame.resize(streamer->TSNI_FRAME_SIZE, 0x55);
                        }

                        streamer->tsni_detected = true;
                        streamer->manager->processEtiFrame(streamer->config.pid, frame.data(), frame.size());
                    }

                    // Start new frame - skip pointer_field (byte 0)
                    streamer->tsni_frame_buffer.clear();
                    streamer->tsni_frame_buffer.insert(streamer->tsni_frame_buffer.end(),
                                                       payload + 1, payload + payload_len);
                } else if (!streamer->tsni_frame_buffer.empty()) {
                    // Continuation - append payload to frame buffer
                    streamer->tsni_frame_buffer.insert(streamer->tsni_frame_buffer.end(),
                                                       payload, payload + payload_len);
                }
            });

        ts_buffer_consume(streamer->ts_buffer, consumed);
        break;
    }
    }

    return 0;
}

int dvbdab_streamer_is_ready(dvbdab_streamer_t *streamer)
{
    if (!streamer) return 0;
    return streamer->complete ? 1 : 0;
}

int dvbdab_streamer_is_basic_ready(dvbdab_streamer_t *streamer)
{
    if (!streamer) return 0;
    return streamer->basic_ready ? 1 : 0;
}

dvbdab_ensemble_t *dvbdab_streamer_get_ensemble(dvbdab_streamer_t *streamer)
{
    if (!streamer || streamer->cached_ensemble.services.empty()) return nullptr;

    auto result = static_cast<dvbdab_ensemble_t*>(calloc(1, sizeof(dvbdab_ensemble_t)));
    if (!result) return nullptr;

    const auto& ens = streamer->cached_ensemble;
    result->eid = ens.eid;
    strncpy(result->label, ens.label.c_str(), 16);
    result->label[16] = '\0';
    result->source_ip = streamer->config.filter_ip;
    result->source_port = streamer->config.filter_port;
    result->source_pid = streamer->config.pid;
    result->service_count = static_cast<int>(ens.services.size());
    result->is_etina = (streamer->config.format == DVBDAB_FORMAT_ETI_NA) ? 1 : 0;
    result->is_gse = (streamer->config.format == DVBDAB_FORMAT_GSE ||
                      streamer->config.format == DVBDAB_FORMAT_BBF_TS) ? 1 : 0;

    if (result->service_count > 0) {
        result->services = static_cast<dvbdab_service_t*>(
            calloc(result->service_count, sizeof(dvbdab_service_t)));

        for (int i = 0; i < result->service_count; i++) {
            const auto& svc = ens.services[i];
            auto& out = result->services[i];

            out.sid = svc.sid;
            strncpy(out.label, svc.label.c_str(), 16);
            out.label[16] = '\0';
            out.bitrate = svc.bitrate;
            out.subchannel_id = svc.subchannel_id;
            out.dabplus = svc.dabplus ? 1 : 0;
        }
    }

    return result;
}

void dvbdab_streamer_free_ensemble(dvbdab_ensemble_t *ensemble)
{
    if (!ensemble) return;
    free(ensemble->services);
    free(ensemble);
}

dvbdab_ensemble_t *dvbdab_streamer_get_all_ensembles(dvbdab_streamer_t *streamer,
                                                       int *count)
{
    if (!streamer || !count || !streamer->manager) {
        if (count) *count = 0;
        return nullptr;
    }

    auto all_ensembles = streamer->manager->getAllEnsembles();
    *count = static_cast<int>(all_ensembles.size());

    if (*count == 0) return nullptr;

    auto result = static_cast<dvbdab_ensemble_t*>(
        calloc(*count, sizeof(dvbdab_ensemble_t)));
    if (!result) {
        *count = 0;
        return nullptr;
    }

    int idx = 0;
    for (const auto& [key, ens] : all_ensembles) {
        auto& out = result[idx++];

        out.eid = ens.eid;
        strncpy(out.label, ens.label.c_str(), 16);
        out.label[16] = '\0';
        out.source_ip = key.ip;       /* Actual discovered IP from key */
        out.source_port = key.port;   /* Actual discovered port from key */
        out.source_pid = 0;           /* Not tracked per-ensemble for GSE */
        out.service_count = static_cast<int>(ens.services.size());
        out.is_gse = (streamer->config.format == DVBDAB_FORMAT_GSE ||
                      streamer->config.format == DVBDAB_FORMAT_BBF_TS) ? 1 : 0;
        out.is_etina = 0;

        if (out.service_count > 0) {
            out.services = static_cast<dvbdab_service_t*>(
                calloc(out.service_count, sizeof(dvbdab_service_t)));

            for (int j = 0; j < out.service_count; j++) {
                const auto& svc = ens.services[j];
                auto& svc_out = out.services[j];

                svc_out.sid = svc.sid;
                strncpy(svc_out.label, svc.label.c_str(), 16);
                svc_out.label[16] = '\0';
                svc_out.bitrate = svc.bitrate;
                svc_out.subchannel_id = svc.subchannel_id;
                svc_out.dabplus = svc.dabplus ? 1 : 0;
            }
        }
    }

    return result;
}

void dvbdab_streamer_free_all_ensembles(dvbdab_ensemble_t *ensembles, int count)
{
    if (!ensembles) return;
    for (int i = 0; i < count; i++) {
        free(ensembles[i].services);
    }
    free(ensembles);
}

int dvbdab_streamer_start_service(dvbdab_streamer_t *streamer, uint8_t subchannel_id)
{
    if (!streamer || !streamer->processor) return -1;
    streamer->processor->startService(subchannel_id);
    return 0;
}

int dvbdab_streamer_stop_service(dvbdab_streamer_t *streamer, uint8_t subchannel_id)
{
    if (!streamer || !streamer->processor) return -1;
    streamer->processor->stopService(subchannel_id);
    return 0;
}

} // extern "C" - pause for C++ helper

// Internal function to start all services (called when ensemble is ready)
static int internal_start_all_services(dvbdab_streamer* s) {
    if (!s) return -1;

    int count = 0;
    for (const auto& svc : s->cached_ensemble.services) {
        if (dvbdab_streamer_start_service(s, svc.subchannel_id) == 0) {
            count++;
        }
    }

    return count;
}

extern "C" {

int dvbdab_streamer_start_all(dvbdab_streamer_t *streamer)
{
    if (!streamer) return -1;

    // Set flag to auto-start when ensemble becomes ready
    streamer->auto_start_all = true;

    // If ensemble already ready, start now
    if (!streamer->cached_ensemble.services.empty()) {
        return internal_start_all_services(streamer);
    }

    return 0;  // Will start later when ensemble is ready
}

} // extern "C"
