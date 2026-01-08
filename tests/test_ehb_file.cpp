// Quick test: parse EHB files directly
// Usage: test_ehb_file <file.EHB> [file2.EHB ...]

#include "parsers/ehb_parser.hpp"
#include <iostream>
#include <fstream>
#include <vector>

using namespace dvbdab;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <file.EHB> [file2.EHB ...]\n";
        return 1;
    }

    EhbParser parser;
    size_t total_files = 0;
    size_t total_events = 0;

    parser.setScheduleCallback([&](const ServiceSchedule& schedule) {
        printf("\n=== Service 0x%04x: %s ===\n",
               schedule.service_id, schedule.service_name.c_str());
        printf("Events: %zu\n", schedule.events.size());

        for (const auto& event : schedule.events) {
            char time_str[64] = "???";
            if (event.start_time > 0) {
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M",
                         localtime(&event.start_time));
            }
            int dur_mins = event.duration_seconds / 60;
            printf("  %s (%d min): %s\n", time_str, dur_mins, event.title.c_str());

            // Show description with preserved newlines
            if (!event.description.empty()) {
                // Indent multiline descriptions
                std::string desc = event.description;
                size_t pos = 0;
                while ((pos = desc.find('\n', pos)) != std::string::npos) {
                    desc.replace(pos, 1, "\n    ");
                    pos += 5;
                }
                printf("    %s\n", desc.c_str());
            }
        }

        total_events += schedule.events.size();
    });

    for (int i = 1; i < argc; i++) {
        std::ifstream file(argv[i], std::ios::binary);
        if (!file) {
            std::cerr << "Cannot open: " << argv[i] << "\n";
            continue;
        }

        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());

        printf("\n--- Parsing: %s (%zu bytes) ---\n", argv[i], data.size());

        if (parser.parse(argv[i], data.data(), data.size())) {
            total_files++;
        } else {
            printf("Failed to parse: %s\n", argv[i]);
        }
    }

    printf("\n=== Summary ===\n");
    printf("Files parsed: %zu\n", total_files);
    printf("Total events: %zu\n", total_events);

    return total_files > 0 ? 0 : 1;
}
