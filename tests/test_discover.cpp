// Test the discoverEnsembles library function

#include <dvbdab/dvbdab.hpp>
#include <iostream>
#include <iomanip>

using namespace dvbdab;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <format> <file> [pid] [timeout_s]\n";
        std::cerr << "  format: mpe, bbf, or gse\n";
        std::cerr << "  pid: PID for MPE format (default 3000)\n";
        std::cerr << "  timeout_s: timeout in seconds (default 20)\n";
        return 1;
    }

    const char* format_str = argv[1];
    const char* file_path = argv[2];
    uint16_t pid = (argc > 3) ? static_cast<uint16_t>(std::stoi(argv[3])) : 3000;
    unsigned int timeout_s = (argc > 4) ? static_cast<unsigned int>(std::stoi(argv[4])) : 20;

    InputFormat format;
    if (std::string(format_str) == "mpe") {
        format = InputFormat::MPE;
    } else if (std::string(format_str) == "bbf") {
        format = InputFormat::BBF;
    } else if (std::string(format_str) == "gse") {
        format = InputFormat::GSE;
    } else {
        std::cerr << "Unknown format: " << format_str << "\n";
        return 1;
    }

    std::cout << "Discovering ensembles in " << file_path << "...\n";
    std::cout << "Format: " << format_str << ", Timeout: " << timeout_s << "s\n";
    if (format == InputFormat::MPE) {
        std::cout << "PID: " << pid << "\n";
    }
    std::cout << "\n";

    auto results = discoverEnsembles(file_path, format, pid, timeout_s * 1000);

    if (results.empty()) {
        std::cout << "No ensembles discovered.\n";
        return 1;
    }

    std::cout << "Discovered " << results.size() << " ensemble(s):\n\n";
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
    }

    return 0;
}
