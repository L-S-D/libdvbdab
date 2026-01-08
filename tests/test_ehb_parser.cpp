// Test EHB (WDR EPG format) parser
// Usage: test_ehb_parser <input.ts> <ip:port> <subchannel>

#include "ensemble_manager.hpp"
#include "sources/mpe_ts_source.hpp"
#include "parsers/packet_decoder.hpp"
#include "parsers/ehb_parser.hpp"
#include <iostream>
#include <fstream>
#include <set>
#include <map>
#include <arpa/inet.h>

using namespace dvbdab;

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <input.ts> <ip:port> <subchannel>\n";
        return 1;
    }

    const char* input_file = argv[1];
    std::string filter_str = argv[2];
    int target_subch = std::stoi(argv[3]);

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

    EnsembleManager manager;
    PacketDecoder decoder;
    EhbParser ehb_parser;

    std::set<uint16_t> seen_tids;
    std::map<uint16_t, ServiceSchedule> schedules;  // service_id -> schedule

    ehb_parser.setScheduleCallback([&](const ServiceSchedule& schedule) {
        printf("\n=== EPG for service 0x%04x (%s) ===\n",
               schedule.service_id, schedule.service_name.c_str());
        printf("Base date: %s", ctime(&schedule.base_date));
        printf("Events: %zu\n", schedule.events.size());

        for (const auto& event : schedule.events) {
            char time_str[64];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", localtime(&event.start_time));
            printf("  [%03d] %s - %s\n", event.event_id, time_str, event.title.c_str());
            if (!event.description.empty()) {
                printf("        %s\n", event.description.c_str());
            }
        }

        schedules[schedule.service_id] = schedule;
    });

    decoder.setMotCallback([&](uint16_t tid, const MOTHeaderInfo& info, const uint8_t* data, size_t len) {
        if (seen_tids.count(tid)) return;
        seen_tids.insert(tid);

        // Parse EHB files
        if (info.content_name.find(".EHB") != std::string::npos) {
            ehb_parser.parse(info.content_name, data, len);
        }
    });

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

        for (uint8_t i = 0; i < nst && i < 64; i++) {
            size_t stc_pos = 8 + i * 4;
            uint8_t scid = (data[stc_pos] >> 2) & 0x3F;
            uint16_t stl = ((data[stc_pos + 2] & 0x03) << 8) | data[stc_pos + 3];
            size_t stream_size = stl * 8;

            if (scid == target_subch && stream_offset + stream_size <= len) {
                decoder.feedSubchannelData(data + stream_offset, stream_size);
            }
            stream_offset += stream_size;
        }
    });

    MpeTsSource source(3000);
    source.setIpCallback([&](const uint8_t* ip, size_t len) {
        manager.processIpPacket(ip, len);
    });

    std::vector<uint8_t> buffer(188 * 1000);
    while (infile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || infile.gcount()) {
        source.feed(buffer.data(), infile.gcount());
    }

    printf("\n=== Summary ===\n");
    printf("EHB files processed: %zu\n", seen_tids.size());
    printf("Services with EPG: %zu\n", schedules.size());

    size_t total_events = 0;
    for (const auto& [sid, sched] : schedules) {
        total_events += sched.events.size();
    }
    printf("Total events extracted: %zu\n", total_events);

    return 0;
}
