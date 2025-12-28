#include "ts_streamer.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

namespace dvbdab {

constexpr size_t TS_PKT_SIZE = 188;

UdpTsStreamer::UdpTsStreamer() {
    datagram_buffer_.resize(TS_PKT_SIZE * 7);  // Default: 7 packets per datagram
}

UdpTsStreamer::~UdpTsStreamer() {
    stop();
    if (socket_ >= 0) {
        close(socket_);
    }
}

bool UdpTsStreamer::setDestination(const std::string& host, uint16_t port) {
    host_ = host;
    port_ = port;
    return true;
}

void UdpTsStreamer::setInterface(const std::string& interface) {
    interface_ = interface;
}

void UdpTsStreamer::setTtl(int ttl) {
    ttl_ = ttl;
}

void UdpTsStreamer::setPacketsPerDatagram(size_t count) {
    packets_per_datagram_ = count;
    datagram_buffer_.resize(TS_PKT_SIZE * count);
}

bool UdpTsStreamer::start() {
    if (running_.load()) {
        return true;  // Already running
    }

    // Create UDP socket
    socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_ < 0) {
        std::cerr << "Failed to create UDP socket\n";
        return false;
    }

    // Check if destination is multicast
    uint32_t ip = inet_addr(host_.c_str());
    bool is_multicast = (ntohl(ip) & 0xF0000000) == 0xE0000000;

    if (is_multicast) {
        // Set multicast TTL
        if (setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_, sizeof(ttl_)) < 0) {
            std::cerr << "Failed to set multicast TTL\n";
        }

        // Set multicast interface if specified
        if (!interface_.empty()) {
            struct in_addr addr;
            addr.s_addr = inet_addr(interface_.c_str());
            if (setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr)) < 0) {
                std::cerr << "Failed to set multicast interface\n";
            }
        }

        // Disable loopback by default
        int loopback = 0;
        setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback, sizeof(loopback));
    }

    running_ = true;
    sender_thread_ = std::thread(&UdpTsStreamer::senderThread, this);

    return true;
}

void UdpTsStreamer::stop() {
    if (!running_.load()) {
        return;
    }

    running_ = false;
    queue_cv_.notify_all();

    if (sender_thread_.joinable()) {
        sender_thread_.join();
    }

    if (socket_ >= 0) {
        close(socket_);
        socket_ = -1;
    }
}

void UdpTsStreamer::sendPacket(const uint8_t* packet, size_t len) {
    if (len != TS_PKT_SIZE || !running_.load()) {
        return;
    }

    // Copy to datagram buffer
    std::memcpy(datagram_buffer_.data() + datagram_offset_, packet, TS_PKT_SIZE);
    datagram_offset_ += TS_PKT_SIZE;

    // If buffer is full, queue it
    if (datagram_offset_ >= packets_per_datagram_ * TS_PKT_SIZE) {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        packet_queue_.push(std::vector<uint8_t>(datagram_buffer_.begin(),
                                                 datagram_buffer_.begin() + datagram_offset_));
        datagram_offset_ = 0;
        queue_cv_.notify_one();
    }
}

void UdpTsStreamer::sendPackets(const uint8_t* data, size_t len) {
    size_t offset = 0;
    while (offset + TS_PKT_SIZE <= len) {
        sendPacket(data + offset, TS_PKT_SIZE);
        offset += TS_PKT_SIZE;
    }
}

size_t UdpTsStreamer::getQueueSize() const {
    // Note: This is not thread-safe but is only used for monitoring
    return packet_queue_.size();
}

void UdpTsStreamer::senderThread() {
    struct sockaddr_in dest_addr;
    std::memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port_);
    dest_addr.sin_addr.s_addr = inet_addr(host_.c_str());

    while (running_.load()) {
        std::vector<uint8_t> datagram;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait_for(lock, std::chrono::milliseconds(100), [this] {
                return !packet_queue_.empty() || !running_.load();
            });

            if (!running_.load() && packet_queue_.empty()) {
                break;
            }

            if (packet_queue_.empty()) {
                continue;
            }

            datagram = std::move(packet_queue_.front());
            packet_queue_.pop();
        }

        // Send datagram
        ssize_t sent = sendto(socket_, datagram.data(), datagram.size(), 0,
                              reinterpret_cast<struct sockaddr*>(&dest_addr),
                              sizeof(dest_addr));
        if (sent > 0) {
            datagrams_sent_++;
            packets_sent_ += datagram.size() / TS_PKT_SIZE;
        }
    }

    // Flush remaining data in buffer
    if (datagram_offset_ > 0) {
        ssize_t sent = sendto(socket_, datagram_buffer_.data(), datagram_offset_, 0,
                              reinterpret_cast<struct sockaddr*>(&dest_addr),
                              sizeof(dest_addr));
        if (sent > 0) {
            datagrams_sent_++;
            packets_sent_ += datagram_offset_ / TS_PKT_SIZE;
        }
        datagram_offset_ = 0;
    }
}

void UdpTsStreamer::sendDatagram(const uint8_t* data, size_t len) {
    struct sockaddr_in dest_addr;
    std::memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port_);
    dest_addr.sin_addr.s_addr = inet_addr(host_.c_str());

    sendto(socket_, data, len, 0,
           reinterpret_cast<struct sockaddr*>(&dest_addr),
           sizeof(dest_addr));
}

} // namespace dvbdab
