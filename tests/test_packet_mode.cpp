// Test Packet Mode Extraction - extracts EPG and other data services from DAB
// Targets SubChId=1 which carries EPG in WDR streams

#include "../src/ensemble_manager.hpp"
#include "../src/sources/mpe_ts_source.hpp"
#include "../src/parsers/packet_decoder.hpp"
#include <iostream>
#include <fstream>
#include <cstring>
#include <map>
#include <set>
#include <arpa/inet.h>

using namespace dvbdab;

// Parse IP:port string into StreamKey filter
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

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <ip:port> [target_subch]\n";
        std::cerr << "  input_file: MPE TS file (e.g., astra1-wdr-long.ts)\n";
        std::cerr << "  ip:port: multicast address to filter (e.g., 228.10.2.5:10010)\n";
        std::cerr << "  target_subch: subchannel ID for packet data (default: 10)\n";
        std::cerr << "\nNote: Subchannel assignments vary by ensemble. For WDR:\n";
        std::cerr << "  SubChId 1-9: Audio subchannels (DAB+ frames)\n";
        std::cerr << "  SubChId 10: Data subchannel (48-byte packets, Addr=2)\n";
        std::cerr << "  SubChId 11: Data subchannel (24-byte packets, Addr=1)\n";
        return 1;
    }

    const char* input_file = argv[1];
    std::string filter_str = argv[2];
    // Note: SubChId assignments vary by ensemble!
    // For WDR streams on Astra 1:
    //   SubChId=1-9: Audio subchannels (DAB+ audio frames)
    //   SubChId=10: Data subchannel with 48-byte packets (Addr=2)
    //   SubChId=11: Data subchannel with 24-byte packets (Addr=1)
    // Use SubChId=10 or 11 for packet mode data
    int target_subch = argc > 3 ? std::stoi(argv[3]) : 10;  // Default to data subchannel

    // Parse filter
    uint32_t filter_ip = 0;
    uint16_t filter_port = 0;
    if (!parseFilter(filter_str, filter_ip, filter_port)) {
        std::cerr << "Invalid filter format. Use ip:port (e.g., 228.10.2.5:10010)\n";
        return 1;
    }

    std::cout << "=== Packet Mode Data Extraction ===\n";
    std::cout << "Input: " << input_file << "\n";
    std::cout << "Filter: " << filter_str << "\n";
    std::cout << "Target SubChId: " << target_subch << " (EPG/data subchannel)\n\n";

    // Open input file
    std::ifstream infile(input_file, std::ios::binary);
    if (!infile) {
        std::cerr << "Cannot open input file: " << input_file << "\n";
        return 1;
    }

    // Create ensemble manager
    EnsembleManager manager;

    // Packet decoder for the target subchannel
    PacketDecoder packet_decoder;
    bool stream_found = false;
    int target_stream_index = -1;

    // Map from subchannel ID to stream index in ETI
    std::map<int, int> subch_to_stream;

    // Set callback for basic ready
    manager.setBasicReadyCallback([&](const StreamKey& key, const DABEnsemble& ensemble) {
        if (key.ip != filter_ip || key.port != filter_port) return;

        std::cout << "\n=== Stream Ready ===\n";
        std::cout << "IP: " << ((key.ip >> 24) & 0xFF) << "." << ((key.ip >> 16) & 0xFF) << "."
                  << ((key.ip >> 8) & 0xFF) << "." << (key.ip & 0xFF) << ":" << key.port << "\n";
        std::cout << "EID: 0x" << std::hex << ensemble.eid << std::dec << "\n";
        if (!ensemble.label.empty()) {
            std::cout << "Ensemble: " << ensemble.label << "\n";
        }
        std::cout << "Services: " << ensemble.services.size() << "\n";

        stream_found = true;
    });

    // Set ETI callback to extract packet mode data
    manager.setEtiCallback([&](const StreamKey& key, const uint8_t* data, size_t len, uint16_t /*dflc*/) {
        // Debug: show which streams are calling this callback
        static std::set<uint64_t> seen_keys;
        uint64_t key_id = ((uint64_t)key.ip << 16) | key.port;
        if (seen_keys.find(key_id) == seen_keys.end()) {
            seen_keys.insert(key_id);
            std::cout << "[ETI-CB] Stream " << ((key.ip >> 24) & 0xFF) << "."
                      << ((key.ip >> 16) & 0xFF) << "." << ((key.ip >> 8) & 0xFF) << "."
                      << (key.ip & 0xFF) << ":" << key.port
                      << (key.ip == filter_ip && key.port == filter_port ? " (MATCHED)" : " (filtered out)") << "\n";
        }

        if (key.ip != filter_ip || key.port != filter_port) return;
        if (len < 6144) return;

        // Parse ETI frame to find subchannel data
        // ETI-NI frame structure (ETSI EN 300 799):
        // Bytes 0-3: SYNC (ERR + FSYNC)
        // Byte 4: FCT (frame counter)
        // Byte 5: FICF (bit 7) + NST (bits 6-0)
        // Bytes 6-7: FP (bits 15-13) + MID (bits 12-11) + FL (bits 10-0)
        // Bytes 8..8+nst*4: STC (4 bytes per stream)
        // Then: EOH (MNSC 2 + CRC 2 = 4 bytes)
        // Then: FIC (variable)
        // Then: MST (stream data)

        if (data[0] != 0xFF) return;  // Check ERR byte

        uint8_t ficf = (data[5] >> 7) & 0x01;
        uint8_t nst = data[5] & 0x7F;
        uint16_t fp_mid_fl = (data[6] << 8) | data[7];
        uint8_t mid = (fp_mid_fl >> 11) & 0x03;

        // Debug ETI header once
        static int eti_debug = 0;
        if (eti_debug < 1) {
            std::cout << "[ETI] len=" << len << " ERR=0x" << std::hex << (int)data[0]
                      << " FSYNC=" << (int)data[1] << (int)data[2] << (int)data[3]
                      << " FCT=" << std::dec << (int)data[4]
                      << " FICF=" << (int)ficf << " NST=" << (int)nst
                      << " MID=" << (int)mid << "\n";
            std::cout << "[ETI] First 16 bytes: ";
            for (int i = 0; i < 16; i++) printf("%02x ", data[i]);
            std::cout << "\n";

            // Debug: Calculate and show MST start
            size_t dbg_header = 4 + 4 + nst * 4 + 4;
            size_t dbg_fic = 96;  // MID=1
            size_t dbg_mst = dbg_header + dbg_fic;
            std::cout << "[ETI] header_size=" << dbg_header << " fic_size=" << dbg_fic
                      << " mst_offset=" << dbg_mst << "\n";
            std::cout << "[ETI] MST first 48 bytes (offset " << dbg_mst << "): ";
            for (size_t i = 0; i < 48 && dbg_mst + i < len; i++) {
                printf("%02x ", data[dbg_mst + i]);
            }
            std::cout << "\n";

            eti_debug++;
        }

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
        size_t mst_offset = header_size + fic_size;
        size_t stream_offset = mst_offset;

        // Parse stream descriptors and find target subchannel
        // Debug: dump STC entries once
        static int stc_debug = 0;
        if (stc_debug < 1) {
            std::cout << "[STC] Stream descriptors (nst=" << (int)nst << "):\n";
            for (uint8_t j = 0; j < nst && j < 64; j++) {
                size_t p = 8 + j * 4;
                uint8_t sc = (data[p] >> 2) & 0x3F;
                uint16_t sad = ((data[p] & 0x03) << 8) | data[p + 1];
                uint8_t tpl = (data[p + 2] >> 6) & 0x03;
                uint16_t st = ((data[p + 2] & 0x03) << 8) | data[p + 3];
                std::cout << "  [" << (int)j << "] SCID=" << (int)sc
                          << " SAD=" << sad << " TPL=" << (int)tpl
                          << " STL=" << st << " (" << (st*8) << " bytes)\n";
            }
            stc_debug++;
        }

        for (uint8_t i = 0; i < nst && i < 64; i++) {
            size_t stc_pos = 8 + i * 4;
            if (stc_pos + 4 > len) break;

            uint8_t scid = (data[stc_pos] >> 2) & 0x3F;  // Subchannel ID
            uint16_t stl = ((data[stc_pos + 2] & 0x03) << 8) | data[stc_pos + 3];
            size_t stream_size = stl * 8;

            if (stream_offset + stream_size > len) break;

            // Check if this is our target subchannel
            if (scid == target_subch) {
                // Debug: show subchannel info once
                static int subch_debug = 0;
                if (subch_debug < 3) {
                    std::cout << "[SUBCH] SubChId=" << (int)scid << " stream_size=" << stream_size
                              << " STL=" << stl << " offset=" << stream_offset << "\n";
                    std::cout << "[SUBCH] First 32 bytes: ";
                    for (size_t j = 0; j < 32 && j < stream_size; j++) {
                        printf("%02x ", data[stream_offset + j]);
                    }
                    std::cout << "\n";
                    subch_debug++;
                }
                // Feed to packet decoder
                packet_decoder.feedSubchannelData(data + stream_offset, stream_size);
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
    size_t frames = 0;

    std::cout << "Processing...\n\n";

    while (infile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || infile.gcount()) {
        size_t bytes_read = infile.gcount();
        source.feed(buffer.data(), bytes_read);
        total_bytes += bytes_read;
        frames++;

        // Show progress every 1MB
        static size_t last_report = 0;
        if (total_bytes - last_report >= 1000000) {
            std::cout << "[Progress] " << (total_bytes / 1000000) << "MB processed, "
                      << packet_decoder.getDataGroupCount() << " data groups\n";
            last_report = total_bytes;
        }
    }

    // Summary
    std::cout << "\n=== Summary ===\n";
    std::cout << "Input bytes: " << total_bytes << "\n";
    std::cout << "Streams discovered: " << manager.getStreamCount() << "\n";
    std::cout << "Packets parsed: " << packet_decoder.getPacketCount() << "\n";
    std::cout << "Data groups (valid CRC): " << packet_decoder.getDataGroupCount() << "\n";
    std::cout << "CRC errors: " << packet_decoder.getCrcErrors() << "\n";

    std::cout << "\nNote: To complete MOT objects, a longer capture covering a full\n"
              << "carousel cycle is needed. The segment numbers suggest objects with\n"
              << "10,000+ segments each (~10-20MB per object for EPG data).\n";

    return 0;
}
