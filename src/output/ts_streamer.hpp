#pragma once

#include "ts_packetizer.hpp"
#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace dvbdab {

// UDP TS Streamer - sends TS packets to a UDP destination
// Typical usage: multicast output for VLC, Kodi, or other media players
class UdpTsStreamer {
public:
    UdpTsStreamer();
    ~UdpTsStreamer();

    // Set destination (e.g., "239.1.1.1:5004" for multicast)
    bool setDestination(const std::string& host, uint16_t port);

    // Set interface for multicast (optional)
    void setInterface(const std::string& interface);

    // Set TTL for multicast (default: 1)
    void setTtl(int ttl);

    // Set packets per UDP datagram (default: 7 = 1316 bytes per datagram)
    void setPacketsPerDatagram(size_t count);

    // Start streaming (launches sender thread)
    bool start();

    // Stop streaming
    void stop();

    // Queue a TS packet for sending
    void sendPacket(const uint8_t* packet, size_t len);

    // Queue multiple TS packets
    void sendPackets(const uint8_t* data, size_t len);

    // Get statistics
    size_t getPacketsSent() const { return packets_sent_.load(); }
    size_t getDatagramsSent() const { return datagrams_sent_.load(); }
    size_t getQueueSize() const;

    // Check if running
    bool isRunning() const { return running_.load(); }

private:
    void senderThread();
    void sendDatagram(const uint8_t* data, size_t len);

    int socket_{-1};
    std::string host_;
    uint16_t port_{5004};
    std::string interface_;
    int ttl_{1};
    size_t packets_per_datagram_{7};  // 7 * 188 = 1316 bytes

    std::atomic<bool> running_{false};
    std::thread sender_thread_;

    // Packet queue
    std::queue<std::vector<uint8_t>> packet_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;

    // Statistics
    std::atomic<size_t> packets_sent_{0};
    std::atomic<size_t> datagrams_sent_{0};

    // Datagram buffer
    std::vector<uint8_t> datagram_buffer_;
    size_t datagram_offset_{0};
};

// HTTP TS Streamer (stub for future implementation)
// Would use a simple HTTP server to serve the TS stream
// class HttpTsStreamer {
// public:
//     bool start(uint16_t port);
//     void stop();
//     void sendPacket(const uint8_t* packet, size_t len);
// };

} // namespace dvbdab
