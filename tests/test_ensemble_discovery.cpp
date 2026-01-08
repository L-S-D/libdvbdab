// Test full pipeline: Input Source → IPv4 → UDP → EDI → ETI → FIC → Ensemble
// Works with all three input formats

#include "../src/sources/gse_ts_source.hpp"
#include "../src/sources/bbf_ts_source.hpp"
#include "../src/sources/mpe_ts_source.hpp"
#include "../src/parsers/udp_extractor.hpp"
#include "../src/ensemble_manager.hpp"
#include <iostream>
#include <fstream>
#include <cstring>

void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " <format> <file> [pid]\n";
    std::cerr << "  format: gse, bbf, or mpe\n";
    std::cerr << "  file: input file path\n";
    std::cerr << "  pid: PID for MPE format (default 3000)\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    const char* format = argv[1];
    const char* filename = argv[2];
    uint16_t pid = 3000;
    if (argc > 3) {
        pid = static_cast<uint16_t>(std::stoi(argv[3]));
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open: " << filename << std::endl;
        return 1;
    }

    // Create ensemble manager with completion callback
    dvbdab::EnsembleManager manager;
    manager.setCompleteCallback([](const dvbdab::StreamKey& key, const dvbdab::DABEnsemble& ens) {
        std::cout << "\n=== ENSEMBLE COMPLETE ===" << std::endl;
        std::cout << "Stream: " << dvbdab::ipToString(key.ip) << ":" << key.port << std::endl;
        std::cout << "EID: 0x" << std::hex << ens.eid << std::dec << std::endl;
        std::cout << "Label: " << ens.label << std::endl;
        std::cout << "Services: " << ens.services.size() << std::endl;

        for (const auto& svc : ens.services) {
            std::cout << "  - " << svc.label << " (SID=0x" << std::hex << svc.sid << std::dec
                      << ", " << svc.bitrate << " kbps, "
                      << (svc.dabplus ? "DAB+" : "DAB") << ")" << std::endl;
        }
    });

    // Create UDP extractor that feeds to ensemble manager
    dvbdab::UdpExtractor udp_extractor([&](uint32_t ip, uint16_t port,
                                            const uint8_t* payload, size_t len) {
        manager.processUdp(ip, port, payload, len);
    });

    // Create appropriate input source
    std::unique_ptr<dvbdab::InputSource> source;

    if (strcmp(format, "gse") == 0) {
        source = std::make_unique<dvbdab::GseTsSource>();
        std::cout << "Using GSE-in-TS format" << std::endl;
    } else if (strcmp(format, "bbf") == 0) {
        source = std::make_unique<dvbdab::BbfTsSource>();
        std::cout << "Using BBF-in-pseudoTS format" << std::endl;
    } else if (strcmp(format, "mpe") == 0) {
        source = std::make_unique<dvbdab::MpeTsSource>(pid);
        std::cout << "Using MPE-in-TS format (PID " << pid << ")" << std::endl;
    } else {
        std::cerr << "Unknown format: " << format << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    // Connect source to UDP extractor via IP callback
    source->setIpCallback([&](const uint8_t* ip_data, size_t len) {
        udp_extractor.process(ip_data, len);
    });

    // Read and process file
    std::vector<uint8_t> buffer(65536);
    size_t total_bytes = 0;

    std::cout << "Processing " << filename << "..." << std::endl;

    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount()) {
        size_t bytes_read = file.gcount();
        total_bytes += bytes_read;
        source->feed(buffer.data(), bytes_read);

        // Check if all discovered ensembles are complete
        if (manager.allComplete() && manager.getCompleteCount() > 0) {
            std::cout << "\nAll " << manager.getCompleteCount() << " ensembles complete!" << std::endl;
            break;
        }
    }

    // Flush BBF source if applicable
    if (auto* bbf = dynamic_cast<dvbdab::BbfTsSource*>(source.get())) {
        bbf->flush();
    }

    // Print final summary
    std::cout << "\n=== SUMMARY ===" << std::endl;
    std::cout << "File: " << filename << std::endl;
    std::cout << "Total bytes: " << total_bytes << std::endl;
    std::cout << "Discontinuities: " << source->getDiscontinuityCount() << std::endl;
    std::cout << "Streams discovered: " << manager.getStreamCount() << std::endl;
    std::cout << "Ensembles complete: " << manager.getCompleteCount() << std::endl;

    if (manager.getCompleteCount() == 0) {
        std::cout << "\nNo ensembles completed. Partial data:" << std::endl;
        for (const auto& [key, ens] : manager.getEnsembles()) {
            std::cout << "  " << dvbdab::ipToString(key.ip) << ":" << key.port
                      << " - " << ens.services.size() << " services"
                      << " (label: " << (ens.label.empty() ? "<none>" : ens.label) << ")"
                      << std::endl;
        }
    }

    return manager.getCompleteCount() > 0 ? 0 : 1;
}
