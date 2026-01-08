// Test SPI (Service and Programme Information) parsing from DAB packet mode data
// Extracts EPG schedule data from MOT objects in WDR streams

#include "../src/ensemble_manager.hpp"
#include "../src/sources/mpe_ts_source.hpp"
#include "../src/parsers/packet_decoder.hpp"
#include "../src/parsers/spi_parser.hpp"
#include "../src/output/spi_schedule_bridge.hpp"
#include <iostream>
#include <fstream>
#include <cstring>
#include <map>
#include <set>
#include <arpa/inet.h>
#include <iomanip>

using namespace dvbdab;

// Parse IP:port string into filter values
static bool parseFilter(const std::string& filter, uint32_t& ip, uint16_t& port) {
    size_t colon = filter.find(':');
    if (colon == std::string::npos) return false;

    std::string ip_str = filter.substr(0, colon);
    std::string port_str = filter.substr(colon + 1);

    struct in_addr addr;
    if (inet_aton(ip_str.c_str(), &addr) == 0) return false;

    ip = ntohl(addr.s_addr);
    port = static_cast<uint16_t>(std::stoi(port_str));
    return true;
}

// Format time_t as readable string
static std::string formatTime(time_t t) {
    if (t == 0) return "(none)";
    struct tm* tm = localtime(&t);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
    return buf;
}

// Format duration as HH:MM:SS
static std::string formatDuration(int seconds) {
    int h = seconds / 3600;
    int m = (seconds % 3600) / 60;
    int s = seconds % 60;
    char buf[32];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", h, m, s);
    return buf;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <ip:port> [subch1,subch2,...]\n";
        std::cerr << "  input_file: MPE TS file (e.g., astra1-wdr-longer.ts)\n";
        std::cerr << "  ip:port: multicast address to filter (e.g., 228.10.1.5:10010)\n";
        std::cerr << "  subch: comma-separated subchannel IDs for packet data (default: 10,11)\n";
        std::cerr << "\nExample:\n";
        std::cerr << "  " << argv[0] << " ../astra1-wdr-longer.ts 228.10.1.5:10010 10,11\n";
        return 1;
    }

    const char* input_file = argv[1];
    std::string filter_str = argv[2];

    // Parse target subchannels
    std::set<int> target_subchs;
    if (argc > 3) {
        std::string subchs_str = argv[3];
        size_t pos = 0;
        while (pos < subchs_str.size()) {
            size_t comma = subchs_str.find(',', pos);
            if (comma == std::string::npos) comma = subchs_str.size();
            target_subchs.insert(std::stoi(subchs_str.substr(pos, comma - pos)));
            pos = comma + 1;
        }
    } else {
        // Default: check subchannels 10 and 11 (common for WDR data)
        target_subchs.insert(10);
        target_subchs.insert(11);
    }

    // Parse filter
    uint32_t filter_ip = 0;
    uint16_t filter_port = 0;
    if (!parseFilter(filter_str, filter_ip, filter_port)) {
        std::cerr << "Invalid filter format. Use ip:port (e.g., 228.10.1.5:10010)\n";
        return 1;
    }

    std::cout << "=== SPI/EPG Parser Test ===\n";
    std::cout << "Input: " << input_file << "\n";
    std::cout << "Filter: " << filter_str << "\n";
    std::cout << "Target SubChIds: ";
    for (int sc : target_subchs) std::cout << sc << " ";
    std::cout << "\n\n";

    // Open input file
    std::ifstream infile(input_file, std::ios::binary);
    if (!infile) {
        std::cerr << "Cannot open input file: " << input_file << "\n";
        return 1;
    }

    // Create ensemble manager
    EnsembleManager manager;

    // Packet decoders for each target subchannel
    std::map<int, PacketDecoder> packet_decoders;
    for (int sc : target_subchs) {
        packet_decoders[sc] = PacketDecoder();
    }

    // SPI Parser
    SpiParser spi_parser;

    // Track MOT objects received
    size_t mot_objects_received = 0;
    size_t xml_objects_received = 0;

    // Set up MOT callbacks to feed SPI parser
    for (auto& [subch, decoder] : packet_decoders) {
        decoder.setMotCallback([&](uint16_t transport_id, const MOTHeaderInfo& header,
                                   const uint8_t* data, size_t len) {
            mot_objects_received++;

            // Check if it's XML
            bool is_xml = false;
            if (header.content_name.size() >= 4) {
                std::string ext = header.content_name.substr(header.content_name.size() - 4);
                for (char& c : ext) c = tolower(c);
                if (ext == ".xml") is_xml = true;
            }
            if (!is_xml && len > 5) {
                if (memcmp(data, "<?xml", 5) == 0 || data[0] == '<') {
                    is_xml = true;
                }
            }

            std::cout << "[MOT] transport_id=" << transport_id
                      << " content_type=" << (int)header.content_type
                      << " name=\"" << header.content_name << "\""
                      << " size=" << len
                      << (is_xml ? " [XML]" : "") << "\n";

            if (is_xml) {
                xml_objects_received++;
                // Show first 200 bytes of XML
                std::cout << "[XML] First 200 bytes:\n";
                for (size_t i = 0; i < std::min(len, (size_t)200); i++) {
                    char c = data[i];
                    if (c >= 32 && c < 127) {
                        std::cout << c;
                    } else if (c == '\n' || c == '\r') {
                        std::cout << c;
                    } else {
                        std::cout << '.';
                    }
                }
                std::cout << "\n...\n\n";
            }

            // Feed to SPI parser
            spi_parser.onMotObject(transport_id, header, data, len);
        });
    }

    // Set up SPI parser callback
    spi_parser.setScheduleCallback([](const EpgSchedule& schedule) {
        std::cout << "\n=== EPG Schedule Received ===\n";
        std::cout << "Service ID: 0x" << std::hex << schedule.service_id << std::dec << "\n";
        std::cout << "Service Name: " << schedule.service_name << "\n";
        std::cout << "Programmes: " << schedule.programmes.size() << "\n";
        std::cout << "Last Update: " << formatTime(schedule.last_update) << "\n";

        for (size_t i = 0; i < schedule.programmes.size() && i < 10; i++) {
            const auto& prog = schedule.programmes[i];
            std::cout << "\n  [" << (i+1) << "] " << prog.name << "\n";
            std::cout << "      Start: " << formatTime(prog.start_time) << "\n";
            std::cout << "      Duration: " << formatDuration(prog.duration_seconds) << "\n";
            if (!prog.description.empty()) {
                std::cout << "      Desc: " << prog.description.substr(0, 80);
                if (prog.description.size() > 80) std::cout << "...";
                std::cout << "\n";
            }
            if (!prog.genre.empty()) {
                std::cout << "      Genre: " << prog.genre << "\n";
            }
        }
        if (schedule.programmes.size() > 10) {
            std::cout << "  ... and " << (schedule.programmes.size() - 10) << " more programmes\n";
        }
        std::cout << "\n";
    });

    bool stream_found = false;

    // Set callback for basic ready
    manager.setBasicReadyCallback([&](const StreamKey& key, const DABEnsemble& ensemble) {
        if (key.ip != filter_ip || key.port != filter_port) return;

        std::cout << "\n=== Stream Ready ===\n";
        std::cout << "EID: 0x" << std::hex << ensemble.eid << std::dec << "\n";
        if (!ensemble.label.empty()) {
            std::cout << "Ensemble: " << ensemble.label << "\n";
        }
        std::cout << "Services: " << ensemble.services.size() << "\n\n";

        stream_found = true;
    });

    // Set ETI callback to extract packet mode data
    manager.setEtiCallback([&](const StreamKey& key, const uint8_t* data, size_t len, uint16_t /*dflc*/) {
        if (key.ip != filter_ip || key.port != filter_port) return;
        if (len < 6144) return;

        if (data[0] != 0xFF) return;  // Check ERR byte

        uint8_t ficf = (data[5] >> 7) & 0x01;
        uint8_t nst = data[5] & 0x7F;
        uint16_t fp_mid_fl = (data[6] << 8) | data[7];
        uint8_t mid = (fp_mid_fl >> 11) & 0x03;

        // Calculate header size
        size_t header_size = 4 + 4 + nst * 4 + 4;

        // FIC size
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

        // MST starts after FIC
        size_t stream_offset = header_size + fic_size;

        // Parse stream descriptors and extract target subchannels
        for (uint8_t i = 0; i < nst && i < 64; i++) {
            size_t stc_pos = 8 + i * 4;
            if (stc_pos + 4 > len) break;

            uint8_t scid = (data[stc_pos] >> 2) & 0x3F;
            uint16_t stl = ((data[stc_pos + 2] & 0x03) << 8) | data[stc_pos + 3];
            size_t stream_size = stl * 8;

            if (stream_offset + stream_size > len) break;

            // Check if this is one of our target subchannels
            if (target_subchs.count(scid) > 0) {
                auto it = packet_decoders.find(scid);
                if (it != packet_decoders.end()) {
                    it->second.feedSubchannelData(data + stream_offset, stream_size);
                }
            }

            stream_offset += stream_size;
        }
    });

    // Create MPE source
    MpeTsSource source(3000);  // PID 3000 for MPE

    // Connect source to ensemble manager
    source.setIpCallback([&](const uint8_t* ip_packet, size_t len) {
        manager.processIpPacket(ip_packet, len);
    });

    // Read and process input
    std::vector<uint8_t> buffer(188 * 1000);
    size_t total_bytes = 0;

    std::cout << "Processing...\n\n";

    while (infile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || infile.gcount()) {
        size_t bytes_read = infile.gcount();
        source.feed(buffer.data(), bytes_read);
        total_bytes += bytes_read;

        // Show progress every 10MB
        static size_t last_report = 0;
        if (total_bytes - last_report >= 10000000) {
            size_t total_dg = 0, total_packets = 0;
            for (const auto& [sc, dec] : packet_decoders) {
                total_dg += dec.getDataGroupCount();
                total_packets += dec.getPacketCount();
            }
            std::cout << "[Progress] " << (total_bytes / 1000000) << "MB, "
                      << total_packets << " packets, "
                      << total_dg << " data groups, "
                      << mot_objects_received << " MOT objects, "
                      << spi_parser.getXmlCount() << " XML parsed\n";
            last_report = total_bytes;
        }
    }

    // Summary
    std::cout << "\n=== Summary ===\n";
    std::cout << "Input bytes: " << total_bytes << "\n";
    std::cout << "Streams discovered: " << manager.getStreamCount() << "\n";

    for (const auto& [sc, dec] : packet_decoders) {
        std::cout << "\nSubChannel " << sc << ":\n";
        std::cout << "  Packets: " << dec.getPacketCount() << "\n";
        std::cout << "  Data groups: " << dec.getDataGroupCount() << "\n";
        std::cout << "  CRC errors: " << dec.getCrcErrors() << "\n";
    }

    std::cout << "\nSPI Parser:\n";
    std::cout << "  MOT objects received: " << mot_objects_received << "\n";
    std::cout << "  XML objects: " << xml_objects_received << "\n";
    std::cout << "  XML files parsed: " << spi_parser.getXmlCount() << "\n";
    std::cout << "  Schedules parsed: " << spi_parser.getScheduleCount() << "\n";
    std::cout << "  Parse errors: " << spi_parser.getParseErrors() << "\n";

    // Show cached schedules
    const auto& schedules = spi_parser.getAllSchedules();
    if (!schedules.empty()) {
        std::cout << "\nCached schedules:\n";
        for (const auto& [sid, sched] : schedules) {
            std::cout << "  SID 0x" << std::hex << sid << std::dec
                      << ": " << sched.programmes.size() << " programmes\n";
        }
    }

    return 0;
}
