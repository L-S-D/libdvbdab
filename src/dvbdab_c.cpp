/*
 * libdvbdab C API implementation
 */
#include <dvbdab/dvbdab_c.h>
#include <dvbdab/ts_scanner.hpp>
#include "parsers/eti_na_detector.hpp"
#include "etina_pipeline.hpp"
#include "dab_parser.h"
#include "output/dabplus_decoder.hpp"
#include "output/dab_mp2_decoder.hpp"
#include "output/ffmpeg_ts_muxer.hpp"
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

            // ETI-NA specific fields
            out.is_etina = ens.is_etina ? 1 : 0;
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

/* ============================================================================
 * ETI-NA Streaming Implementation
 * ============================================================================ */

// Use TS constants from dvbdab namespace
using dvbdab::TS_PACKET_SIZE;
using dvbdab::TS_HEADER_SIZE;

// TS packet helpers
static inline bool etina_ts_is_sync(const uint8_t* ts) { return ts[0] == 0x47; }
static inline bool etina_ts_has_payload(const uint8_t* ts) { return (ts[3] & 0x10) != 0; }
static inline bool etina_ts_has_af(const uint8_t* ts) { return (ts[3] & 0x20) != 0; }
static inline uint16_t etina_ts_get_pid(const uint8_t* ts) { return ((ts[1] & 0x1F) << 8) | ts[2]; }

static inline const uint8_t* etina_ts_get_payload(const uint8_t* ts, size_t* payload_len) {
    if (!etina_ts_has_payload(ts)) {
        *payload_len = 0;
        return nullptr;
    }
    size_t offset = TS_HEADER_SIZE;
    if (etina_ts_has_af(ts)) {
        offset += 1 + ts[4];  // AF length byte + AF data
    }
    if (offset >= TS_PACKET_SIZE) {
        *payload_len = 0;
        return nullptr;
    }
    *payload_len = TS_PACKET_SIZE - offset;
    return &ts[offset];
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

    // Partial TS packet buffer for ETI-NA (handles unaligned input chunks)
    std::vector<uint8_t> ts_buffer;

    // UDP extraction (for MPE/GSE)
    std::unique_ptr<UdpExtractor> udp_extractor;

    // DAB parsing - EnsembleManager for all formats (MPE/GSE/ETI-NA)
    std::unique_ptr<EnsembleManager> manager;

    // Audio decoders (by subchannel ID) - shared by all formats
    std::map<uint8_t, std::unique_ptr<DabPlusDecoder>> dabplus_decoders;
    std::map<uint8_t, std::unique_ptr<DabMp2Decoder>> mp2_decoders;

    // TS muxer (FFmpeg-based) - shared output stage
    std::unique_ptr<FfmpegTsMuxer> muxer;

    // Service info
    std::map<uint8_t, uint16_t> subch_to_sid;
    std::map<uint16_t, int64_t> pts_counter;

    // State
    bool muxer_initialized;
    bool basic_ready;
    bool complete;
    bool auto_start_all;  // Auto-start all services when ensemble ready

    // Debug counters (per-streamer)
    int ts_output_count{0};
    size_t ts_output_bytes{0};
    int audio_frame_count{0};
    int eti_frame_count{0};

    // Cached ensemble for get_ensemble
    lsdvb::DABEnsemble cached_ensemble;
};

// Helper to configure muxer from ensemble
static void setup_muxer_from_ensemble(dvbdab_streamer* s, const lsdvb::DABEnsemble& ensemble) {
    if (s->muxer_initialized) return;

    s->muxer->setEnsemble(ensemble.eid, ensemble.label);

    // Sort services by SID for consistent PAT/PMT ordering
    auto sorted_services = ensemble.services;
    std::sort(sorted_services.begin(), sorted_services.end(),
        [](const auto& a, const auto& b) { return a.sid < b.sid; });

    for (const auto& svc : sorted_services) {
        FfmpegService fs;
        fs.sid = static_cast<uint16_t>(svc.sid);
        fs.name = svc.label;
        fs.dabplus = svc.dabplus;
        fs.subchannel_id = svc.subchannel_id;
        fs.bitrate = svc.bitrate;
        fs.sample_rate = 48000;

        s->muxer->addService(fs);
        s->subch_to_sid[svc.subchannel_id] = fs.sid;
        s->pts_counter[fs.sid] = 90000;
    }

    if (s->muxer->initialize()) {
        s->muxer_initialized = true;
    }
}

// Forward declaration
static int internal_start_all_services(dvbdab_streamer* s);

// Called when muxer is ready and auto_start_all is set
static void auto_start_services_if_ready(dvbdab_streamer* s) {
    if (!s->muxer_initialized || !s->auto_start_all) return;
    if (s->dabplus_decoders.empty() && s->mp2_decoders.empty()) {
        internal_start_all_services(s);
    }
}

// Shared ETI frame processing - used by all input formats (ETI-NA, MPE, GSE)
// All formats produce ETI frames that are processed identically here
// Called via eti_callback from EnsembleManager for audio decoding
static void process_eti_frame(dvbdab_streamer* s, const uint8_t* eti_ni, size_t len) {
    if (!s->muxer_initialized) {
        s->eti_frame_count++;
        return;
    }
    if (len < 12) return;

    s->eti_frame_count++;

    // Parse ETI frame header
    uint8_t nst = eti_ni[5] & 0x7F;
    uint8_t ficf = (eti_ni[5] >> 7) & 0x01;
    uint16_t fp_mid_fl = (eti_ni[6] << 8) | eti_ni[7];
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

    size_t stream_offset = header_size + fic_size;

    // Process each subchannel stream
    for (uint8_t i = 0; i < nst && i < 64; i++) {
        size_t stc_pos = 8 + i * 4;
        if (stc_pos + 4 > len) break;

        uint8_t scid = (eti_ni[stc_pos] >> 2) & 0x3F;
        uint16_t stl = ((eti_ni[stc_pos + 2] & 0x03) << 8) | eti_ni[stc_pos + 3];
        size_t stream_size = stl * 8;

        if (stream_offset + stream_size > len) break;

        // Feed to DAB+ decoder if active
        auto dabplus_it = s->dabplus_decoders.find(scid);
        if (dabplus_it != s->dabplus_decoders.end()) {
            dabplus_it->second->feedFrame(eti_ni + stream_offset, stream_size);
        }

        // Feed to MP2 decoder if active
        auto mp2_it = s->mp2_decoders.find(scid);
        if (mp2_it != s->mp2_decoders.end()) {
            mp2_it->second->feedFrame(eti_ni + stream_offset, stream_size);
        }

        stream_offset += stream_size;
    }
}

dvbdab_streamer_t *dvbdab_streamer_create(const dvbdab_streamer_config_t *config)
{
    if (!config) return nullptr;

    try {
        auto s = new dvbdab_streamer();
        s->config = *config;
        s->output_cb = nullptr;
        s->output_opaque = nullptr;
        s->muxer_initialized = false;
        s->basic_ready = false;
        s->complete = false;
        s->auto_start_all = false;

        switch (config->format) {
        case DVBDAB_FORMAT_ETI_NA:
            // ETI-NA: TS -> etina_pipeline -> ETI-NI -> EnsembleManager -> audio
            // Uses same EnsembleManager path as MPE/GSE for FIC parsing and callbacks
            s->manager = std::make_unique<EnsembleManager>();

            // Set ensemble callbacks - for ETI-NA the key is (pid, 0)
            s->manager->setBasicReadyCallback([s](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
                // ETI-NA key: ip=pid, port=0
                if (key.ip == static_cast<uint32_t>(s->config.pid) && key.port == 0) {
                    s->cached_ensemble = ens;
                    s->basic_ready = true;
                    if (s->muxer) {
                        setup_muxer_from_ensemble(s, ens);
                        auto_start_services_if_ready(s);
                    }
                }
            });

            s->manager->setCompleteCallback([s](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
                if (key.ip == static_cast<uint32_t>(s->config.pid) && key.port == 0) {
                    s->cached_ensemble = ens;
                    s->complete = true;
                    if (s->muxer) {
                        for (const auto& svc : ens.services) {
                            s->muxer->updateServiceLabel(static_cast<uint16_t>(svc.sid), svc.label);
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
            s->manager->setBasicReadyCallback([s](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->basic_ready = true;
                    if (s->muxer) {
                        setup_muxer_from_ensemble(s, ens);
                        auto_start_services_if_ready(s);
                    }
                }
            });

            s->manager->setCompleteCallback([s](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->complete = true;
                    // Update service labels in muxer now that we have all names
                    if (s->muxer) {
                        for (const auto& svc : ens.services) {
                            s->muxer->updateServiceLabel(static_cast<uint16_t>(svc.sid), svc.label);
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
            s->manager->setBasicReadyCallback([s](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->basic_ready = true;
                    if (s->muxer) {
                        setup_muxer_from_ensemble(s, ens);
                        auto_start_services_if_ready(s);
                    }
                }
            });

            s->manager->setCompleteCallback([s](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->complete = true;
                    // Update service labels in muxer now that we have all names
                    if (s->muxer) {
                        for (const auto& svc : ens.services) {
                            s->muxer->updateServiceLabel(static_cast<uint16_t>(svc.sid), svc.label);
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
            s->manager->setBasicReadyCallback([s](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->basic_ready = true;
                    if (s->muxer) {
                        setup_muxer_from_ensemble(s, ens);
                        auto_start_services_if_ready(s);
                    }
                }
            });

            s->manager->setCompleteCallback([s](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
                if (key.ip == s->config.filter_ip && key.port == s->config.filter_port) {
                    s->cached_ensemble = ens;
                    s->complete = true;
                    if (s->muxer) {
                        for (const auto& svc : ens.services) {
                            s->muxer->updateServiceLabel(static_cast<uint16_t>(svc.sid), svc.label);
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
    if (streamer) {
        if (streamer->muxer) {
            streamer->muxer->finalize();
        }
        delete streamer;
    }
}

void dvbdab_streamer_set_output(dvbdab_streamer_t *streamer,
                                 dvbdab_ts_output_cb callback, void *opaque)
{
    if (!streamer) return;

    streamer->output_cb = callback;
    streamer->output_opaque = opaque;

    if (!streamer->muxer) {
        streamer->muxer = std::make_unique<FfmpegTsMuxer>();
        streamer->muxer->setOutput([streamer](const uint8_t* data, size_t len) {
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
        // Buffer incoming data to handle partial TS packets across feed calls
        streamer->ts_buffer.insert(streamer->ts_buffer.end(), data, data + len);

        // Process complete 188-byte packets from buffer
        size_t offset = 0;
        while (offset + TS_PACKET_SIZE <= streamer->ts_buffer.size()) {
            const uint8_t* ts = streamer->ts_buffer.data() + offset;

            // Find sync byte (handle lost sync)
            if (ts[0] != 0x47) {
                offset++;
                continue;
            }

            uint16_t pid = ((ts[1] & 0x1F) << 8) | ts[2];
            if (pid != streamer->config.pid) {
                offset += TS_PACKET_SIZE;
                continue;
            }

            if ((ts[3] & 0x10) == 0) {
                offset += TS_PACKET_SIZE;
                continue;  // No payload
            }

            uint8_t adapt_ctrl = (ts[3] >> 4) & 3;
            size_t payload_offset = TS_HEADER_SIZE;
            if (adapt_ctrl == 3) {
                payload_offset += 1 + ts[4];
                if (payload_offset >= TS_PACKET_SIZE) {
                    offset += TS_PACKET_SIZE;
                    continue;
                }
            }

            size_t payload_len = TS_PACKET_SIZE - payload_offset;
            const uint8_t* payload = ts + payload_offset;

            // Feed to modular pipeline, get ETI frames via callback
            // Use EnsembleManager->processEtiFrame() (same path as MPE/GSE)
            etina_feed_payload(streamer->etina_pipeline, payload, payload_len,
                [streamer](const uint8_t* eti_ni, size_t len) {
                    if (!streamer->manager) return;

                    // Mark as detected once we get first ETI frame
                    streamer->etina_detected = true;

                    // Feed to EnsembleManager - fires eti_callback immediately for audio,
                    // and fires basic_ready/complete callbacks when FIC parsing is done
                    streamer->manager->processEtiFrame(streamer->config.pid, eti_ni, len);
                });

            offset += TS_PACKET_SIZE;
        }

        // Remove processed data from buffer, keep any partial packet
        if (offset > 0) {
            streamer->ts_buffer.erase(streamer->ts_buffer.begin(),
                                      streamer->ts_buffer.begin() + offset);
        }
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
    if (!streamer) return -1;

    // Find service info
    const lsdvb::DABService* svc = nullptr;
    for (const auto& s : streamer->cached_ensemble.services) {
        if (s.subchannel_id == subchannel_id) {
            svc = &s;
            break;
        }
    }
    if (!svc) return -1;

    // Create appropriate decoder
    if (svc->dabplus) {
        if (streamer->dabplus_decoders.find(subchannel_id) == streamer->dabplus_decoders.end()) {
            auto decoder = std::make_unique<DabPlusDecoder>(svc->bitrate);

            decoder->setCallback([streamer, subchannel_id](const uint8_t* data, size_t len) {
                streamer->audio_frame_count++;
                if (!streamer->muxer || len < 7) return;

                auto it = streamer->subch_to_sid.find(subchannel_id);
                if (it == streamer->subch_to_sid.end()) return;

                static const int adts_rates[] = {
                    96000, 88200, 64000, 48000, 44100, 32000,
                    24000, 22050, 16000, 12000, 11025, 8000, 7350
                };
                int sample_rate = 48000;
                if (data[0] == 0xFF && (data[1] & 0xF0) == 0xF0) {
                    int sr_idx = (data[2] >> 2) & 0xF;
                    if (sr_idx < 13) sample_rate = adts_rates[sr_idx];
                }

                int64_t pts = streamer->pts_counter[it->second];
                streamer->pts_counter[it->second] += (int64_t)1024 * 90000 / sample_rate;

                streamer->muxer->feedAudioFrame(subchannel_id, data, len, pts);
            });

            streamer->dabplus_decoders[subchannel_id] = std::move(decoder);
        }
    } else {
        if (streamer->mp2_decoders.find(subchannel_id) == streamer->mp2_decoders.end()) {
            auto decoder = std::make_unique<DabMp2Decoder>(svc->bitrate);

            decoder->setCallback([streamer, subchannel_id](const uint8_t* data, size_t len) {
                if (!streamer->muxer || len < 4) return;

                auto it = streamer->subch_to_sid.find(subchannel_id);
                if (it == streamer->subch_to_sid.end()) return;

                // Parse MP2 header for sample rate
                // Byte 1 bits 4-3: version (11=MPEG1, 10=MPEG2, 00=MPEG2.5)
                // Byte 2 bits 3-2: sample rate index
                static const int mp2_sample_rates[4][4] = {
                    {11025, 12000, 8000, 0},   // MPEG2.5 (version=00)
                    {0, 0, 0, 0},              // Reserved (version=01)
                    {22050, 24000, 16000, 0},  // MPEG2 (version=10)
                    {44100, 48000, 32000, 0}   // MPEG1 (version=11)
                };
                int sample_rate = 48000;  // default
                if (len >= 4 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0) {
                    int version = (data[1] >> 3) & 0x03;
                    int sr_idx = (data[2] >> 2) & 0x03;
                    if (mp2_sample_rates[version][sr_idx] > 0)
                        sample_rate = mp2_sample_rates[version][sr_idx];
                }

                int64_t pts = streamer->pts_counter[it->second];
                // 1152 samples per MP2 frame, PTS in 90kHz units
                streamer->pts_counter[it->second] += (int64_t)1152 * 90000 / sample_rate;

                streamer->muxer->feedAudioFrame(subchannel_id, data, len, pts);
            });

            streamer->mp2_decoders[subchannel_id] = std::move(decoder);
        }
    }

    return 0;
}

int dvbdab_streamer_stop_service(dvbdab_streamer_t *streamer, uint8_t subchannel_id)
{
    if (!streamer) return -1;

    streamer->dabplus_decoders.erase(subchannel_id);
    streamer->mp2_decoders.erase(subchannel_id);

    return 0;
}

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
