// Test SPI/MOT data extraction using PacketDecoder
// DR Deutschland SubCh 30 uses MOT (EN 301 234) with EHB files
// Usage: test_spi_mot <input.ts> <ip:port> <pid> [subchannel]
// If subchannel not specified, auto-detects from FIG 0/13 + FIG 0/2/3

#include "ensemble_manager.hpp"
#include "sources/mpe_ts_source.hpp"
#include "parsers/packet_decoder.hpp"
#include "parsers/ehb_parser.hpp"
#include <iostream>
#include <fstream>
#include <set>
#include <arpa/inet.h>

using namespace dvbdab;

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <input.ts> <ip:port> <pid> [subchannel]\n";
        std::cerr << "Example: " << argv[0] << " Astra3-1.BuMux.ts 239.128.43.43:50043 4121\n";
        std::cerr << "If subchannel not specified, auto-detects EPG subchannel from FIG data\n";
        return 1;
    }

    const char* input_file = argv[1];
    std::string filter_str = argv[2];
    int pid = std::stoi(argv[3]);
    int target_subch = (argc >= 5) ? std::stoi(argv[4]) : -1;  // -1 = auto-detect

    size_t colon = filter_str.find(':');
    struct in_addr addr;
    inet_aton(filter_str.substr(0, colon).c_str(), &addr);
    uint32_t filter_ip = ntohl(addr.s_addr);
    uint16_t filter_port = std::stoi(filter_str.substr(colon + 1));

    std::ifstream infile(input_file, std::ios::binary);
    if (!infile) {
        std::cerr << "Cannot open " << input_file << "\n";
        return 1;
    }

    printf("=== SPI/MOT Test (using PacketDecoder) ===\n");
    printf("Input: %s\n", input_file);
    printf("Filter: %s\n", filter_str.c_str());
    printf("PID: %d\n", pid);
    if (target_subch >= 0) {
        printf("Target SubCh: %d (manual)\n\n", target_subch);
    } else {
        printf("Target SubCh: auto-detect from FIG 0/13\n\n");
    }

    EnsembleManager manager;
    PacketDecoder decoder;
    EhbParser ehb_parser;
    size_t frames_fed = 0;
    size_t mot_objects = 0;
    size_t ehb_files = 0;
    size_t ehb_events = 0;

    // Set EHB callback for parsed schedules
    ehb_parser.setScheduleCallback([&](const ServiceSchedule& sched) {
        printf("\n=== EHB Schedule: service=0x%04x, %zu events ===\n",
               sched.service_id, sched.events.size());
        for (const auto& ev : sched.events) {
            char time_str[32] = "N/A";
            if (ev.start_time > 0) {
                struct tm* tm = gmtime(&ev.start_time);
                snprintf(time_str, sizeof(time_str), "%02d:%02d",
                         tm->tm_hour, tm->tm_min);
            }
            printf("  [%s] %s\n", time_str, ev.title.c_str());
            ehb_events++;
        }
    });

    // Set MOT callback to receive complete objects
    decoder.setMotCallback([&](uint16_t transport_id, const MOTHeaderInfo& header,
                               const uint8_t* body_data, size_t body_len) {
        mot_objects++;

        const char* ct_name = "unknown";
        switch (header.content_type) {
            case 0: ct_name = "GeneralData"; break;
            case 1: ct_name = "Text"; break;
            case 2: ct_name = "Image"; break;
            case 5: ct_name = "MOT-Transport"; break;
            case 6: ct_name = "EPG"; break;
            case 7: ct_name = "Java"; break;
        }

        // Check if it's an EHB file
        bool is_ehb = header.content_name.size() >= 4 &&
                      header.content_name.substr(header.content_name.size() - 4) == ".EHB";

        if (is_ehb) {
            ehb_files++;
            printf("\n=== EHB File: %s (%zu bytes) ===\n",
                   header.content_name.c_str(), body_len);

            // Save first EHB file to /tmp for analysis
            if (ehb_files == 1) {
                std::string fname = "/tmp/mot_" + header.content_name;
                std::ofstream f(fname, std::ios::binary);
                if (f) {
                    f.write(reinterpret_cast<const char*>(body_data), body_len);
                    printf("[SAVED] %s (%zu bytes)\n", fname.c_str(), body_len);
                }
            }

            ehb_parser.parse(header.content_name, body_data, body_len);
        } else {
            // Just print summary for non-EHB objects
            printf("[MOT] %s (%s, %u bytes)\n",
                   header.content_name.c_str(), ct_name, header.body_size);
        }
    });

    // Track which subchannels are being used (for auto-detection logging)
    std::set<int> active_epg_subchannels;
    bool epg_detected_logged = false;

    manager.setEtiCallback([&](const StreamKey& key, const uint8_t* data, size_t len, uint16_t) {
        if (key.ip != filter_ip || key.port != filter_port) return;
        if (len < 6144 || data[0] != 0xFF) return;

        uint8_t nst = data[5] & 0x7F;
        uint8_t ficf = (data[5] >> 7) & 0x01;
        uint16_t fp_mid_fl = (data[6] << 8) | data[7];
        uint8_t mid = (fp_mid_fl >> 11) & 0x03;
        size_t header_size = 4 + 4 + nst * 4 + 4;
        size_t fic_size = ficf ? (mid == 3 ? 128 : 96) : 0;
        size_t stream_offset = header_size + fic_size;

        // Get auto-detected EPG subchannels from parser (if auto-detect mode)
        std::vector<int> epg_subchannels;
        if (target_subch < 0) {
            epg_subchannels = manager.getEpgSubchannels(key);
            if (!epg_subchannels.empty() && !epg_detected_logged) {
                printf("[AUTO-DETECT] EPG subchannels found: ");
                for (int sc : epg_subchannels) printf("%d ", sc);
                printf("\n");
                epg_detected_logged = true;
            }
        }

        for (uint8_t i = 0; i < nst && i < 64; i++) {
            size_t stc_pos = 8 + i * 4;
            uint8_t scid = (data[stc_pos] >> 2) & 0x3F;
            uint16_t stl = ((data[stc_pos + 2] & 0x03) << 8) | data[stc_pos + 3];
            size_t stream_size = stl * 8;

            // Check if this subchannel should be processed
            bool should_process = false;
            if (target_subch >= 0) {
                // Manual mode: use specified subchannel
                should_process = (scid == target_subch);
            } else {
                // Auto-detect mode: check if scid is in EPG subchannels
                for (int epg_sc : epg_subchannels) {
                    if (scid == epg_sc) {
                        should_process = true;
                        active_epg_subchannels.insert(scid);
                        break;
                    }
                }
            }

            if (should_process && stream_offset + stream_size <= len) {
                const uint8_t* subch_data = data + stream_offset;
                decoder.feedSubchannelData(subch_data, stream_size);
                frames_fed++;
            }
            stream_offset += stream_size;
        }
    });

    MpeTsSource source(pid);
    source.setIpCallback([&](const uint8_t* ip, size_t len) {
        manager.processIpPacket(ip, len);
    });

    std::vector<uint8_t> buffer(188 * 1000);
    size_t total_bytes = 0;
    while (infile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || infile.gcount()) {
        source.feed(buffer.data(), infile.gcount());
        total_bytes += infile.gcount();

        if (total_bytes % (10 * 1024 * 1024) == 0) {
            printf("[Progress] %zuMB, %zu frames, %zu MOT objects\n",
                   total_bytes / (1024 * 1024), frames_fed, mot_objects);
        }
    }

    printf("\n=== Summary ===\n");
    printf("Input bytes: %zu\n", total_bytes);
    printf("Frames fed: %zu\n", frames_fed);
    if (target_subch < 0 && !active_epg_subchannels.empty()) {
        printf("EPG subchannels used (auto-detected): ");
        for (int sc : active_epg_subchannels) printf("%d ", sc);
        printf("\n");
    } else if (target_subch >= 0) {
        printf("EPG subchannel used (manual): %d\n", target_subch);
    } else {
        printf("EPG subchannels: none detected\n");
    }
    printf("Packets decoded: %zu\n", decoder.getPacketCount());
    printf("Data groups: %zu\n", decoder.getDataGroupCount());
    printf("CRC errors: %zu\n", decoder.getCrcErrors());
    printf("MOT objects: %zu\n", mot_objects);
    printf("EHB files: %zu\n", ehb_files);
    printf("EHB events: %zu\n", ehb_events);

    return 0;
}
