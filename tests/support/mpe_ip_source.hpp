// Test input: the IPv4 packets of the MPE datagram sections (EN 301 192,
// table_id 0x3E) of one PID of a TS capture.
//
// The library takes IPv4 packets (DVBDAB_FORMAT_IPV4, UdpExtractor): taking
// them out of MPE or GSE is the receiver's job (tvheadend does it). This is
// only for feeding the tests and tools with MPE captures.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>

namespace dvbdab::test {

class MpeIpSource {
public:
    using IpCallback = std::function<void(const uint8_t* ip, size_t len)>;

    explicit MpeIpSource(uint16_t pid = 3000) : pid_(pid) {}

    void setIpCallback(IpCallback cb) { cb_ = std::move(cb); }

    // only IPv4 UDP packets to ip:port (host byte order); ip 0: all, port 0: any
    void setIpFilter(uint32_t ip, uint16_t port) { filter_ip_ = ip; filter_port_ = port; }

    // TS data, any amount
    void feed(const uint8_t* data, size_t len) {
        if (!partial_.empty()) {
            size_t take = 188 - partial_.size() < len ? 188 - partial_.size() : len;
            partial_.insert(partial_.end(), data, data + take);
            data += take;
            len -= take;
            if (partial_.size() < 188) return;
            packet(partial_.data());
            partial_.clear();
        }
        for (; len >= 188; data += 188, len -= 188) packet(data);
        if (len) partial_.assign(data, data + len);
    }

    uint64_t getSectionCount() const { return sections_; }
    uint64_t getCrcErrorCount() const { return crc_errors_; }
    uint64_t getDiscontinuityCount() const { return lost_; }

private:
    void packet(const uint8_t* t) {
        if (t[0] != 0x47 || (t[1] & 0x80)) return;
        if ((((t[1] & 0x1f) << 8) | t[2]) != pid_) return;
        int afc = (t[3] >> 4) & 3;
        if (!(afc & 1) || (t[3] & 0xc0)) return;          // no payload, scrambled
        int cc = t[3] & 0x0f;
        if (cc_ >= 0 && cc == cc_) return;                // a duplicate
        if (cc_ >= 0 && cc != ((cc_ + 1) & 0x0f) && have_) {
            lost_++;
            have_ = 0;
        }
        cc_ = cc;
        size_t off = afc == 3 ? 5u + t[4] : 4u;
        if (off >= 188) return;
        const uint8_t* d = t + off;
        size_t n = 188 - off;
        if (!(t[1] & 0x40)) {
            if (have_) add(d, n);
            return;
        }
        // the end of the section before, then those that start here
        size_t ptr = d[0];
        d++;
        n--;
        if (ptr > n) {
            have_ = 0;
            return;
        }
        if (have_) {
            add(d, ptr);
            if (have_) {                                  // shorter than it said
                lost_++;
                have_ = 0;
            }
        }
        d += ptr;
        n -= ptr;
        while (n > 0 && d[0] != 0xff) {
            size_t used = add(d, n);
            d += used;
            n -= used;
            if (have_) break;                             // goes on in the next packet
        }
    }

    // bytes of a section: its start or more of it; the bytes taken
    size_t add(const uint8_t* d, size_t n) {
        size_t used = 0, take;
        if (have_ < 3) {
            take = 3 - have_ < n ? 3 - have_ : n;
            memcpy(sec_.data() + have_, d, take);
            have_ += take;
            used += take;
            if (have_ < 3) return used;
        }
        size_t len = 3 + ((static_cast<size_t>(sec_[1] & 0x0f) << 8) | sec_[2]);
        take = len - have_ < n - used ? len - have_ : n - used;
        memcpy(sec_.data() + have_, d + used, take);
        have_ += take;
        used += take;
        if (have_ == len) {
            section(sec_.data(), len);
            have_ = 0;
        }
        return used;
    }

    static uint32_t crc32(const uint8_t* d, size_t n) {
        static const std::array<uint32_t, 256> table = [] {
            std::array<uint32_t, 256> t{};
            for (uint32_t i = 0; i < 256; i++) {
                uint32_t c = i << 24;
                for (int j = 0; j < 8; j++) c = (c & 0x80000000u) ? (c << 1) ^ 0x04c11db7u : c << 1;
                t[i] = c;
            }
            return t;
        }();
        uint32_t crc = 0xffffffffu;
        while (n--) crc = (crc << 8) ^ table[((crc >> 24) ^ *d++) & 0xff];
        return crc;
    }

    void section(const uint8_t* s, size_t len) {
        if (s[0] != 0x3e || len < 16) return;
        sections_++;
        if ((s[1] & 0x80) && crc32(s, len) != 0) {
            crc_errors_++;
            return;
        }
        if ((s[5] >> 4) & 3) return;                      // payload scrambled
        const uint8_t* ip = s + 12;
        size_t n = len - 16;
        if ((s[5] >> 1) & 1) {                            // LLC/SNAP: IPv4 only
            if (n < 8 || ip[6] != 0x08 || ip[7] != 0x00) return;
            ip += 8;
            n -= 8;
        }
        if (n < 20 || (ip[0] >> 4) != 4) return;
        if (filter_ip_) {
            size_t hl = static_cast<size_t>(ip[0] & 0x0f) * 4;
            if (ip[9] != 17 || hl < 20 || n < hl + 8) return;
            uint32_t dst = (uint32_t(ip[16]) << 24) | (uint32_t(ip[17]) << 16) |
                           (uint32_t(ip[18]) << 8) | ip[19];
            uint16_t port = static_cast<uint16_t>((ip[hl + 2] << 8) | ip[hl + 3]);
            if (dst != filter_ip_ || (filter_port_ && port != filter_port_)) return;
        }
        if (cb_) cb_(ip, n);
    }

    uint16_t pid_;
    IpCallback cb_;
    uint32_t filter_ip_{0};
    uint16_t filter_port_{0};
    std::vector<uint8_t> partial_;
    std::array<uint8_t, 4100> sec_{};
    size_t have_{0};
    int cc_{-1};
    uint64_t sections_{0}, crc_errors_{0}, lost_{0};
};

} // namespace dvbdab::test
