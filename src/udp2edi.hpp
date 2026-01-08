#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <functional>
#include <vector>
#include <string>

#include "edi_parser.hpp"

// Callback for complete ETI frames: (ip, port, data, len, dflc)
using EtiCallback = std::function<void(std::uint32_t ip, std::uint16_t port,
                                        const std::uint8_t* data, std::size_t len,
                                        std::uint16_t dflc)>;

// Wrapper around EdiParser that tracks IP:port
class StreamEdiParser {
public:
    StreamEdiParser(std::uint32_t ip, std::uint16_t port, EtiCallback callback);

    void feed(const std::uint8_t* data, std::size_t len);

private:
    std::uint32_t ip_;
    std::uint16_t port_;
    EdiParser parser_;
};

// Manages multiple EDI parsers, one per unique IP:port combination
class Udp2Edi {
public:
    explicit Udp2Edi(EtiCallback callback);
    ~Udp2Edi();

    // Feed UDP packet data for a specific destination
    void feed(std::uint32_t dst_ip, std::uint16_t dst_port,
              const std::uint8_t* data, std::size_t len);

    // Get list of active streams
    std::vector<std::pair<std::uint32_t, std::uint16_t>> getActiveStreams() const;

    // Convert IP to string for logging
    static std::string ipToString(std::uint32_t ip);

private:
    struct StreamKey {
        std::uint32_t ip;
        std::uint16_t port;

        bool operator<(const StreamKey& other) const {
            if (ip != other.ip) return ip < other.ip;
            return port < other.port;
        }
    };

    EtiCallback callback_;
    std::map<StreamKey, std::unique_ptr<StreamEdiParser>> parsers_;
};
