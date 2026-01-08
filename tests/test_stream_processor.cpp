// Test DabStreamProcessor - full pipeline test
//
// Usage: test_stream_processor <format> <file.ts> <ip:port> <output.ts> [pid]

#include "../src/output/dab_stream_processor.hpp"
#include "../src/ensemble_manager.hpp"
#include "../src/parsers/udp_extractor.hpp"
#include "../src/sources/mpe_ts_source.hpp"
#include "../src/sources/bbf_ts_source.hpp"
#include "../src/sources/gse_ts_source.hpp"
#include <iostream>
#include <fstream>
#include <arpa/inet.h>
#include <cstring>

using namespace dvbdab;

static bool parseFilter(const std::string& filter, uint32_t& ip, uint16_t& port) {
    size_t colon = filter.find(':');
    if (colon == std::string::npos) return false;
    struct in_addr addr;
    if (inet_aton(filter.substr(0, colon).c_str(), &addr) == 0) return false;
    ip = ntohl(addr.s_addr);
    port = static_cast<uint16_t>(std::stoi(filter.substr(colon + 1)));
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <format> <file.ts> <ip:port> <output.ts> [pid]\n";
        std::cerr << "  format: mpe, bbf, or gse\n";
        std::cerr << "  ip:port: multicast address (e.g. 228.10.1.5:10010)\n";
        std::cerr << "  pid: PID for MPE format (default 3000)\n";
        return 1;
    }

    const char* format = argv[1];
    const char* input_file = argv[2];
    std::string filter_str = argv[3];
    const char* output_file = argv[4];
    int mpe_pid = (argc > 5) ? std::stoi(argv[5]) : 3000;

    uint32_t filter_ip = 0;
    uint16_t filter_port = 0;
    if (!parseFilter(filter_str, filter_ip, filter_port)) {
        std::cerr << "Invalid filter format. Use ip:port\n";
        return 1;
    }

    std::cout << "Using DabStreamProcessor (unified pipeline)\n";
    std::cout << "Filter: " << filter_str << "\n";

    std::ifstream infile(input_file, std::ios::binary);
    if (!infile) {
        std::cerr << "Cannot open: " << input_file << "\n";
        return 1;
    }

    std::ofstream outfile(output_file, std::ios::binary);
    if (!outfile) {
        std::cerr << "Cannot create: " << output_file << "\n";
        return 1;
    }

    EnsembleManager manager;
    DabStreamProcessor processor;
    bool configured = false;

    // Output: TS packets go to file
    processor.setOutput([&](const uint8_t* data, size_t len) {
        outfile.write(reinterpret_cast<const char*>(data), len);
    });

    // When ensemble discovered, configure processor
    manager.setCompleteCallback([&](const StreamKey& key, const DABEnsemble& ensemble) {
        if (key.ip != filter_ip || key.port != filter_port || configured) return;

        std::cout << "\n=== Ensemble: " << ensemble.label << " (EID: 0x"
                  << std::hex << ensemble.eid << std::dec << ") ===\n";

        processor.setEnsemble(ensemble.eid, ensemble.label);

        // Add services - use subchannel_id for deterministic PID allocation
        for (const auto& svc : ensemble.services) {
            TsService ts_svc;
            ts_svc.sid = svc.sid;
            ts_svc.pmt_pid = 0x0100 + svc.subchannel_id;
            ts_svc.audio_pid = 0x1000 + svc.subchannel_id;
            ts_svc.name = svc.label;
            ts_svc.provider = ensemble.label;
            ts_svc.dabplus = svc.dabplus;
            ts_svc.subchannel_id = svc.subchannel_id;
            ts_svc.bitrate = svc.bitrate;

            processor.addService(ts_svc);

            std::cout << "  + " << svc.label << " [SID=0x" << std::hex << svc.sid << std::dec
                      << " SubCh=" << (int)svc.subchannel_id
                      << " " << svc.bitrate << " kbps " << (svc.dabplus ? "DAB+" : "MP2")
                      << " PID=0x" << std::hex << ts_svc.audio_pid << std::dec << "]\n";
        }

        processor.startAllServices();
        configured = true;
        std::cout << "Processor initialized with " << ensemble.services.size() << " services\n";
    });

    // ETI frames go to processor
    manager.setEtiCallback([&](const StreamKey& key, const uint8_t* data, size_t len, uint16_t) {
        if (key.ip != filter_ip || key.port != filter_port) return;
        processor.feedEtiFrame(data, len);
    });

    // Set up input pipeline
    std::unique_ptr<InputSource> source;
    if (strcmp(format, "mpe") == 0) {
        auto mpe_source = std::make_unique<MpeTsSource>(mpe_pid);
        mpe_source->setIpFilter(filter_ip, filter_port);
        source = std::move(mpe_source);
        std::cout << "Using MPE format (PID " << mpe_pid << ")\n";
    } else if (strcmp(format, "bbf") == 0) {
        source = std::make_unique<BbfTsSource>();
        std::cout << "Using BBF (pseudo-TS) format\n";
    } else if (strcmp(format, "gse") == 0) {
        source = std::make_unique<GseTsSource>();
        std::cout << "Using GSE format\n";
    } else {
        std::cerr << "Unknown format: " << format << "\n";
        return 1;
    }

    UdpExtractor udp_extractor([&](uint32_t ip, uint16_t port, const uint8_t* payload, size_t len) {
        manager.processUdp(ip, port, payload, len);
    });
    source->setIpCallback([&](const uint8_t* ip_packet, size_t len) {
        udp_extractor.process(ip_packet, len);
    });

    // Process input
    std::cout << "Processing " << input_file << "...\n";
    std::vector<uint8_t> buffer(188 * 1000);
    while (infile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || infile.gcount()) {
        source->feed(buffer.data(), infile.gcount());
    }

    std::cout << "\n=== Summary ===\n";
    std::cout << "ETI frames processed: " << processor.getEtiFrameCount() << "\n";
    std::cout << "Audio frames decoded: " << processor.getAudioFrameCount() << "\n";
    std::cout << "TS packets output: " << processor.getTsPacketCount() << "\n";
    std::cout << "Data subchannels: " << processor.getDataSubchannelCount() << "\n";
    std::cout << "EPG schedules parsed: " << processor.getEpgScheduleCount() << "\n";
    std::cout << "Output: " << output_file << "\n";

    if (configured) {
        std::cout << "\nVerify with: ffprobe " << output_file << "\n";
        std::cout << "Play with:  vlc " << output_file << "\n";
    }

    return configured ? 0 : 1;
}
