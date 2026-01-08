#include <iostream>
#include <array>
#include <cstdint>

constexpr std::size_t TS_PACKET_SIZE = 188;
constexpr std::uint16_t TARGET_PID = 0x010e;
constexpr std::uint8_t START_INDICATOR = 0xb8;

int main() {
    std::array<char, TS_PACKET_SIZE> packet;

    while (std::cin.read(packet.data(), TS_PACKET_SIZE)) {
        // Extract 13-bit PID from bytes 1-2
        std::uint16_t pid = (static_cast<std::uint8_t>(packet[1]) & 0x1F) << 8;
        pid |= static_cast<std::uint8_t>(packet[2]);

        if (pid != TARGET_PID) {
            continue;
        }

        std::uint8_t length = static_cast<std::uint8_t>(packet[7]);

        if (static_cast<std::uint8_t>(packet[8]) == START_INDICATOR) {
            // Start of BBF: output from byte 8, length bytes
            std::cout.write(&packet[8], length);
        } else {
            // Continuation: output from byte 9, length-1 bytes
            std::cout.write(&packet[9], length - 1);
        }
    }

    return 0;
}
