#include "mpe_parser.hpp"
#include <cstring>

namespace dvbdab {

MpeParser::MpeParser(IpPacketCallback callback)
    : callback_(std::move(callback))
{
    section_buffer_.reserve(4096);
}

void MpeParser::reset() {
    section_buffer_.clear();
    section_length_ = 0;
    in_section_ = false;
}

// Exact copy of standalone MpeExtractor logic
void MpeParser::feedTsPayload(const uint8_t* payload, size_t len, bool pusi) {
    const uint8_t* p = payload;

    if (pusi) {
        int ptr = p[0]; p++; len--;
        if (ptr > 0 && ptr <= (int)len) {
            if (in_section_) {
                section_buffer_.insert(section_buffer_.end(), p, p + ptr);
                if (section_buffer_.size() >= section_length_ + 3 && section_buffer_[0] == 0x3E)
                    processSection();
            }
            p += ptr; len -= ptr;
        }
        section_buffer_.clear(); in_section_ = false; section_length_ = 0;
        while (len >= 3 && p[0] != 0xFF) {
            section_length_ = ((p[1] & 0x0F) << 8) | p[2];
            int total = 3 + section_length_;
            if ((size_t)total <= len) {
                if (p[0] == 0x3E) {
                    section_buffer_.assign(p, p + total);
                    processSection();
                    section_buffer_.clear();
                }
                p += total; len -= total;
            } else { section_buffer_.assign(p, p + len); in_section_ = true; break; }
        }
        if (!in_section_ && len > 0 && len < 3 && p[0] != 0xFF) {
            section_buffer_.assign(p, p + len); in_section_ = true; section_length_ = 0;
        }
    } else if (in_section_) {
        if (section_length_ == 0 && section_buffer_.size() < 3) {
            size_t need = 3 - section_buffer_.size();
            size_t copy = std::min(need, len);
            section_buffer_.insert(section_buffer_.end(), p, p + copy); p += copy; len -= copy;
            if (section_buffer_.size() >= 3) section_length_ = ((section_buffer_[1] & 0x0F) << 8) | section_buffer_[2];
            else return;
        }
        if (len == 0) return;
        size_t needed = (section_length_ + 3) - section_buffer_.size();
        size_t to_copy = std::min(needed, len);
        section_buffer_.insert(section_buffer_.end(), p, p + to_copy);
        if (section_buffer_.size() >= section_length_ + 3) {
            if (section_buffer_[0] == 0x3E) processSection();
            section_buffer_.clear(); in_section_ = false;
        }
    }
}

void MpeParser::processSection() {
    // MPE section: 12 bytes header + IP datagram + 4 bytes CRC
    if (section_buffer_.size() < 16) return;

    section_count_++;

    const uint8_t* ip = section_buffer_.data() + 12;
    size_t ip_len = section_buffer_.size() - 16;

    // Verify IPv4 and UDP
    if (ip_len < 28 || (ip[0] >> 4) != 4 || ip[9] != 17) return;

    ip_packet_count_++;
    callback_(ip, ip_len);
}

} // namespace dvbdab
