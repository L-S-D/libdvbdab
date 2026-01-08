// Test the TsScanner - auto-detect DAB ensembles from raw TS files

#include <dvbdab/ts_scanner.hpp>
#include <iostream>
#include <iomanip>
#include <cstdlib>

using namespace dvbdab;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <file.ts> [timeout_s]\n";
        std::cerr << "\nScans a transport stream file for DAB ensembles.\n";
        std::cerr << "No prior knowledge of PIDs or format required.\n";
        std::cerr << "\nOptions:\n";
        std::cerr << "  file.ts    Input transport stream file\n";
        std::cerr << "  timeout_s  Timeout in seconds (default: 30)\n";
        return 1;
    }

    const char* file_path = argv[1];
    unsigned int timeout_s = (argc > 2) ? static_cast<unsigned int>(std::atoi(argv[2])) : 30;
    unsigned int timeout_ms = timeout_s * 1000;

    std::cout << "Scanning " << file_path << " for DAB ensembles...\n";
    std::cout << "Timeout: " << timeout_s << " seconds\n\n";

    TsScanner scanner;
    scanner.setTimeout(timeout_ms);

    // For progress reporting
    FILE* fp = fopen(file_path, "rb");
    if (!fp) {
        std::cerr << "Error: Cannot open file: " << file_path << "\n";
        return 1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    std::vector<uint8_t> buffer(65536);
    size_t total_read = 0;
    int last_percent = -1;

    while (!scanner.isDone()) {
        size_t bytes_read = fread(buffer.data(), 1, buffer.size(), fp);
        if (bytes_read == 0) {
            break;
        }

        total_read += bytes_read;
        int percent = (total_read * 100) / file_size;
        if (percent != last_percent && percent % 10 == 0) {
            std::cout << "  " << percent << "% (" << (total_read / 1024) << " KB)\r" << std::flush;
            last_percent = percent;
        }

        if (scanner.feed(buffer.data(), bytes_read) != 0) {
            break;
        }
    }

    fclose(fp);
    std::cout << "\n\n";

    // Show discovered MPE PIDs
    auto mpe_pids = scanner.getMpePids();
    if (!mpe_pids.empty()) {
        std::cout << "MPE PIDs detected: ";
        for (size_t i = 0; i < mpe_pids.size(); i++) {
            if (i > 0) std::cout << ", ";
            std::cout << mpe_pids[i] << " (0x" << std::hex << mpe_pids[i] << std::dec << ")";
        }
        std::cout << "\n\n";
    } else {
        std::cout << "No MPE PIDs detected.\n\n";
    }

    // Show ETI-NA detection results (UK satellite DAB feeds)
    auto etina_results = scanner.getEtiNaResults();
    if (!etina_results.empty()) {
        std::cout << "ETI-NA streams detected:\n";
        for (const auto& info : etina_results) {
            std::cout << "  PID " << info.pid << " (0x" << std::hex << info.pid << std::dec << "): "
                      << "padding=" << info.padding_bytes << " bytes, "
                      << "bit_offset=" << info.sync_bit_offset
                      << (info.inverted ? " (inverted)" : "") << "\n";
        }
        std::cout << "\n";
    }

    // Show results
    auto results = scanner.getResults();

    if (results.empty() && etina_results.empty()) {
        std::cout << "No DAB ensembles discovered.\n";
        return 1;
    }

    if (results.empty()) {
        // ETI-NA detected but no MPE ensembles - still a success
        std::cout << "No MPE-based DAB ensembles discovered (ETI-NA streams found above).\n";
        return 0;
    }

    std::cout << "Discovered " << results.size() << " DAB ensemble(s):\n\n";
    std::cout << std::left
              << std::setw(22) << "IP:Port"
              << std::setw(10) << "EID"
              << std::setw(8) << "Services"
              << "Label\n";
    std::cout << std::string(60, '-') << "\n";

    for (const auto& ens : results) {
        std::cout << std::left
                  << std::setw(22) << ens.address()
                  << "0x" << std::hex << std::setw(8) << ens.eid << std::dec
                  << std::setw(8) << ens.service_count()
                  << ens.label << "\n";

        // Show services
        for (const auto& svc : ens.services) {
            std::cout << "    SID 0x" << std::hex << std::setw(4) << std::setfill('0') << svc.sid
                      << std::dec << std::setfill(' ')
                      << " SubCh " << std::setw(2) << static_cast<int>(svc.subchannel_id)
                      << " " << std::setw(4) << svc.bitrate << " kbps"
                      << " " << (svc.dabplus ? "DAB+" : "DAB ")
                      << " \"" << svc.label << "\"\n";
        }
        std::cout << "\n";
    }

    return 0;
}
