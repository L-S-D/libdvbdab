// Test full library pipeline: MpeTsSource → UdpExtractor → EdiParser → ETI frames
#include "../src/sources/mpe_ts_source.hpp"
#include "../src/parsers/udp_extractor.hpp"
#include "../src/edi_parser.hpp"
#include <iostream>
#include <fstream>
#include <arpa/inet.h>

// CRC-16 CCITT (same as in edi_parser.cpp)
uint16_t crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint16_t>(data[i]) << 8;
        for (int j = 0; j < 8; ++j) {
            if (crc & 0x8000) crc = (crc << 1) ^ 0x1021;
            else crc <<= 1;
        }
    }
    return crc ^ 0xFFFF;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <file.ts> <mpe_pid> <ip:port>\n";
        return 1;
    }

    uint16_t mpe_pid = static_cast<uint16_t>(std::stoi(argv[2]));
    std::string filter = argv[3];
    size_t colon = filter.find(':');
    struct in_addr addr;
    inet_aton(filter.substr(0, colon).c_str(), &addr);
    uint32_t filter_ip = ntohl(addr.s_addr);
    uint16_t filter_port = static_cast<uint16_t>(std::stoi(filter.substr(colon + 1)));

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) { std::cerr << "Cannot open: " << argv[1] << std::endl; return 1; }

    std::cout << "Processing " << argv[1] << " (full library pipeline)\n";
    std::cout << "MPE PID: " << mpe_pid << ", Filter: " << filter << std::endl;

    size_t udp_packets = 0;
    size_t eti_frames = 0;
    int prev_fct = -1;
    int prev_dflc = -1;
    int fct_gaps = 0;
    int dflc_gaps = 0;
    int size_errors = 0;
    int fsync_errors = 0;
    int eoh_crc_errors = 0;
    int mst_crc_errors = 0;

    // ETI frame callback - verify and count frames
    EdiParser edi_parser([&](const uint8_t* frame, size_t len, uint16_t dflc) {
        // Check size
        if (len != 6144) {
            size_errors++;
            return;
        }

        // Check FSYNC
        uint8_t fct = frame[4];
        uint32_t fsync = (frame[1] << 16) | (frame[2] << 8) | frame[3];
        uint32_t expected_fsync = (fct % 2 == 1) ? 0xF8C549 : 0x073AB6;
        if (fsync != expected_fsync) {
            fsync_errors++;
        }

        // Parse FC to find structure
        uint8_t nst = frame[5] & 0x3F;
        bool ficf = (frame[5] >> 7) & 1;
        uint8_t mid = (frame[6] >> 3) & 0x03;
        uint16_t fl = ((frame[6] & 0x07) << 8) | frame[7];

        // EOH position: after FC (4 bytes) + STC entries (NST*4 bytes)
        size_t eoh_pos = 8 + nst * 4;

        // EOH CRC covers FC to MNSC (bytes 4 to eoh_pos+1 inclusive)
        uint16_t eoh_crc_calc = crc16(frame + 4, eoh_pos - 4 + 2);
        uint16_t eoh_crc_stored = (frame[eoh_pos + 2] << 8) | frame[eoh_pos + 3];
        if (eoh_crc_calc != eoh_crc_stored) {
            eoh_crc_errors++;
        }

        // MST starts after EOH (4 bytes: MNSC + CRC)
        size_t mst_start = eoh_pos + 4;

        // MST length in bytes: (FL - NST - 1) * 4
        // FL includes: NST (STC count) + 1 (EOH) + FIC/MST words
        size_t mst_len = (fl - nst - 1) * 4;

        // MST CRC covers FIC + subchannel data
        uint16_t mst_crc_calc = crc16(frame + mst_start, mst_len);
        uint16_t mst_crc_stored = (frame[mst_start + mst_len] << 8) | frame[mst_start + mst_len + 1];
        if (mst_crc_calc != mst_crc_stored) {
            mst_crc_errors++;
        }

        // Check FCT continuity (0-249)
        if (prev_fct >= 0) {
            int expected = (prev_fct + 1) % 250;
            if (fct != expected) fct_gaps++;
        }
        prev_fct = fct;

        // Check DFLC continuity
        // DFLC = FCTH*250 + FCT, where FCTH can wrap at 20 or 32 depending on transmitter
        // Try both modulos to detect the actual wrap point
        if (prev_dflc >= 0) {
            int expected_5000 = (prev_dflc + 1) % 5000;
            int expected_8000 = (prev_dflc + 1) % 8000;
            if (dflc != expected_5000 && dflc != expected_8000) {
                dflc_gaps++;
                int prev_fcth = prev_dflc / 250;
                int curr_fcth = dflc / 250;
                printf("DFLC gap at frame %zu: prev=%d (FCTH=%d) expected=%d or %d got=%d (FCTH=%d, FCT=%d)\n",
                       eti_frames, prev_dflc, prev_fcth, expected_5000, expected_8000, dflc, curr_fcth, fct);
            }
        }
        prev_dflc = dflc;

        eti_frames++;
    });

    // UDP callback - feed to EdiParser
    dvbdab::UdpExtractor udp_extractor([&](uint32_t ip, uint16_t port, const uint8_t* payload, size_t len) {
        udp_packets++;
        edi_parser.feed(payload, len);
    });

    // MPE source with IP filter
    dvbdab::MpeTsSource source(mpe_pid);
    source.setIpFilter(filter_ip, filter_port);
    source.setIpCallback([&](const uint8_t* ip_data, size_t len) {
        udp_extractor.process(ip_data, len);
    });

    // Process file
    std::vector<uint8_t> buffer(65536);
    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount()) {
        source.feed(buffer.data(), file.gcount());
    }

    std::cout << "\n=== RESULTS (full library pipeline) ===\n";
    std::cout << "UDP packets: " << udp_packets << std::endl;
    std::cout << "ETI frames: " << eti_frames << std::endl;
    std::cout << "Size errors: " << size_errors << std::endl;
    std::cout << "FSYNC errors: " << fsync_errors << std::endl;
    std::cout << "EOH CRC errors: " << eoh_crc_errors << std::endl;
    std::cout << "MST CRC errors: " << mst_crc_errors << std::endl;
    std::cout << "FCT gaps: " << fct_gaps << std::endl;
    std::cout << "DFLC gaps: " << dflc_gaps << std::endl;

    int total_errors = size_errors + fsync_errors + eoh_crc_errors + mst_crc_errors + fct_gaps + dflc_gaps;
    return total_errors > 0 ? 1 : 0;
}
