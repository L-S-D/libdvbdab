#include "udp2edi.hpp"
#include <sstream>

// StreamEdiParser implementation

StreamEdiParser::StreamEdiParser(std::uint32_t ip, std::uint16_t port, EtiCallback callback)
    : ip_(ip)
    , port_(port)
    , parser_([this, callback](const std::uint8_t* data, std::size_t len, std::uint16_t dflc) {
        callback(ip_, port_, data, len, dflc);
    })
{
}

void StreamEdiParser::feed(const std::uint8_t* data, std::size_t len) {
    parser_.feed(data, len);
}

// Udp2Edi implementation

Udp2Edi::Udp2Edi(EtiCallback callback)
    : callback_(std::move(callback))
{
}

Udp2Edi::~Udp2Edi() = default;

void Udp2Edi::feed(std::uint32_t dst_ip, std::uint16_t dst_port,
                   const std::uint8_t* data, std::size_t len) {
    StreamKey key{dst_ip, dst_port};

    auto it = parsers_.find(key);
    if (it == parsers_.end()) {
        // New stream detected - create parser
        auto parser = std::make_unique<StreamEdiParser>(dst_ip, dst_port, callback_);
        it = parsers_.emplace(key, std::move(parser)).first;
    }

    it->second->feed(data, len);
}

std::vector<std::pair<std::uint32_t, std::uint16_t>> Udp2Edi::getActiveStreams() const {
    std::vector<std::pair<std::uint32_t, std::uint16_t>> result;
    result.reserve(parsers_.size());
    for (const auto& [key, parser] : parsers_) {
        result.emplace_back(key.ip, key.port);
    }
    return result;
}

std::string Udp2Edi::ipToString(std::uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xff) << '.'
        << ((ip >> 16) & 0xff) << '.'
        << ((ip >> 8) & 0xff) << '.'
        << (ip & 0xff);
    return oss.str();
}
