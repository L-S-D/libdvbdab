#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <functional>
#include <map>
#include <memory>

// Callback for extracted UDP packets: (dst_ip, dst_port, payload, length)
using UdpCallback = std::function<void(std::uint32_t dst_ip, std::uint16_t dst_port,
                                        const std::uint8_t* data, std::size_t len)>;

// GSE fragment reassembly buffer
struct GseFragment {
    std::vector<std::uint8_t> data;
    std::size_t total_length{0};
    std::size_t current_pos{0};
    bool active{false};
};

class Bbf2Udp {
public:
    explicit Bbf2Udp(UdpCallback callback);

    // Feed raw BBF stream data (output from pts2bbf)
    void feed(const std::uint8_t* data, std::size_t len);

    // Feed raw GSE packets directly (for DMX_SET_STID_STREAM output)
    // This bypasses BBFrame parsing and processes GSE packets directly
    void feedGse(const std::uint8_t* data, std::size_t len);

private:
    // BBF header structure (10 bytes after 0xb8 sync)
    struct BbfHeader {
        std::uint8_t matype1;
        std::uint8_t matype2;  // MIS (Multistream ID)
        std::uint16_t upl;
        std::uint16_t dfl;     // Data field length in bits
        std::uint8_t sync;
        std::uint8_t syncd1;
        std::uint8_t syncd2;
        std::uint8_t crc8;
    };

    enum class State {
        SEEKING_SYNC,    // Looking for 0xb8 BBF sync
        READING_HEADER,  // Reading 10-byte BBF header
        READING_PAYLOAD  // Reading GSE packets
    };

    void processByte(std::uint8_t byte);
    void processGsePackets();
    bool processGsePacket(const std::uint8_t* data, std::size_t max_len, std::size_t& consumed);
    void handleCompleteGsePacket(const std::uint8_t* data, std::size_t len);
    void extractUdpFromIpv4(const std::uint8_t* ip_data, std::size_t len);

    UdpCallback callback_;
    State state_{State::SEEKING_SYNC};

    // BBF accumulation
    std::array<std::uint8_t, 10> header_buf_{};
    std::size_t header_pos_{0};

    std::vector<std::uint8_t> payload_buf_;
    std::size_t payload_expected_{0};
    std::size_t payload_pos_{0};

    // GSE fragment reassembly (indexed by fragment ID 0-255)
    std::array<GseFragment, 256> fragments_{};

    // Raw GSE accumulation buffer (for feedGse path)
    std::vector<std::uint8_t> gse_buf_;
    std::size_t gse_pos_{0};
};
