#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <map>
#include <functional>
#include <optional>

// Callback for complete ETI frames (data, length, DFLC for continuity checking)
using EtiFrameCallback = std::function<void(const std::uint8_t* data, std::size_t len, std::uint16_t dflc)>;

// Subchannel data from EST tags
struct SubchannelData {
    std::uint8_t scid{0};      // Subchannel ID
    std::uint16_t sad{0};      // Start address
    std::uint8_t tpl{0};       // Protection level
    std::vector<std::uint8_t> mst;  // MSC data
};

// Frame Control data from DETI tag
struct FrameControl {
    bool atstf{false};         // ATST flag
    bool ficf{false};          // FIC flag
    std::uint8_t mid{0};       // Mode ID
    std::uint8_t fp{0};        // Frame phase
    std::uint16_t dflc{0};     // Data field length counter
    std::uint32_t tsta{0xFFFFFF}; // Timestamp
    std::uint8_t nst{0};       // Number of streams
};

// ETI builder state
struct EtiBuilder {
    bool is_eti{false};
    bool fc_valid{false};
    std::uint8_t err{0xFF};
    std::uint16_t mnsc{0};
    std::uint16_t rfu{0xFFFF};

    FrameControl fc;
    std::vector<std::uint8_t> fic;
    std::array<SubchannelData, 64> subchannels;
};

// PF packet fragment collector (stores fragments individually like standalone tool)
struct PfCollector {
    std::uint16_t pseq{0};
    std::uint32_t fcount{0};
    std::map<std::uint32_t, std::vector<std::uint8_t>> fragments;
};

// EDI Parser - handles PF fragmentation and AF/tag parsing
class EdiParser {
public:
    explicit EdiParser(EtiFrameCallback callback);

    // Feed a UDP packet (PF or AF format)
    void feed(const std::uint8_t* data, std::size_t len);

private:
    // PF packet handling
    bool handlePfPacket(const std::uint8_t* data, std::size_t len);

    // AF packet handling
    bool handleAfPacket(const std::uint8_t* data, std::size_t len);

    // Tag parsing
    bool decodeTagPacket(const std::uint8_t* data, std::size_t len);
    bool decodeStarPtr(const std::uint8_t* data, std::size_t len);
    bool decodeDeti(const std::uint8_t* data, std::size_t len);
    bool decodeEstN(const std::uint8_t* data, std::size_t len, std::uint8_t n);

    // ETI frame assembly
    void assembleEtiFrame();

    // CRC16 calculation (CCITT)
    static std::uint16_t crc16(const std::uint8_t* data, std::size_t len);
    static bool checkCrc(const std::uint8_t* data, std::size_t len);

    EtiFrameCallback callback_;
    EtiBuilder eti_;

    // PF fragment collectors indexed by Pseq
    std::map<std::uint16_t, PfCollector> pf_collectors_;
    std::uint16_t last_pseq_{0};
};
