// Ensemble discovery implementation

#include <dvbdab/dvbdab.hpp>
#include "sources/gse_ts_source.hpp"
#include "sources/bbf_ts_source.hpp"
#include "sources/mpe_ts_source.hpp"
#include "parsers/udp_extractor.hpp"
#include "ensemble_manager.hpp"
#include <fstream>
#include <chrono>
#include <unistd.h>
#include <poll.h>

namespace dvbdab {

std::vector<DiscoveredEnsemble> discoverEnsembles(
    const std::string& file_path,
    InputFormat format,
    uint16_t pid,
    unsigned int timeout_ms)
{
    std::vector<DiscoveredEnsemble> results;

    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        return results;  // Empty result on file open failure
    }

    // Create ensemble manager
    EnsembleManager manager;

    // Track discovered ensembles (with full service info)
    manager.setCompleteCallback([&results](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
        DiscoveredEnsemble de;
        de.ip = key.ip;
        de.port = key.port;
        de.eid = ens.eid;
        de.label = ens.label;

        // Copy service info
        for (const auto& svc : ens.services) {
            DiscoveredService ds;
            ds.sid = svc.sid;
            ds.label = svc.label;
            ds.bitrate = svc.bitrate;
            ds.subchannel_id = static_cast<uint8_t>(svc.subchannel_id);
            ds.dabplus = svc.dabplus;
            de.services.push_back(ds);
        }
        results.push_back(de);
    });

    // Create UDP extractor
    UdpExtractor udp_extractor([&](uint32_t ip, uint16_t port,
                                    const uint8_t* payload, size_t len) {
        manager.processUdp(ip, port, payload, len);
    });

    // Create appropriate input source
    std::unique_ptr<InputSource> source;

    switch (format) {
        case InputFormat::GSE:
            source = std::make_unique<GseTsSource>();
            break;
        case InputFormat::BBF:
            source = std::make_unique<BbfTsSource>();
            break;
        case InputFormat::MPE:
            source = std::make_unique<MpeTsSource>(pid);
            break;
    }

    // Connect source to UDP extractor
    source->setIpCallback([&](const uint8_t* ip_data, size_t len) {
        udp_extractor.process(ip_data, len);
    });

    // Process file with timeout
    auto start_time = std::chrono::steady_clock::now();
    std::vector<uint8_t> buffer(65536);

    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount()) {
        size_t bytes_read = file.gcount();
        source->feed(buffer.data(), bytes_read);

        // Check timeout
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        if (static_cast<unsigned int>(elapsed_ms) >= timeout_ms) {
            break;
        }

        // Early exit if all discovered streams are complete
        if (manager.allComplete() && manager.getCompleteCount() > 0) {
            break;
        }
    }

    // Flush BBF source if applicable
    if (format == InputFormat::BBF) {
        if (auto* bbf = dynamic_cast<BbfTsSource*>(source.get())) {
            bbf->flush();
        }
    }

    return results;
}

std::vector<DiscoveredEnsemble> discoverEnsemblesFromFd(
    int fd,
    InputFormat format,
    uint16_t pid,
    unsigned int timeout_ms)
{
    std::vector<DiscoveredEnsemble> results;

    if (fd < 0) {
        return results;
    }

    // Create ensemble manager
    EnsembleManager manager;

    // Track discovered ensembles (with full service info)
    manager.setCompleteCallback([&results](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
        DiscoveredEnsemble de;
        de.ip = key.ip;
        de.port = key.port;
        de.eid = ens.eid;
        de.label = ens.label;

        // Copy service info
        for (const auto& svc : ens.services) {
            DiscoveredService ds;
            ds.sid = svc.sid;
            ds.label = svc.label;
            ds.bitrate = svc.bitrate;
            ds.subchannel_id = static_cast<uint8_t>(svc.subchannel_id);
            ds.dabplus = svc.dabplus;
            de.services.push_back(ds);
        }
        results.push_back(de);
    });

    // Create UDP extractor
    UdpExtractor udp_extractor([&](uint32_t ip, uint16_t port,
                                    const uint8_t* payload, size_t len) {
        manager.processUdp(ip, port, payload, len);
    });

    // Create appropriate input source
    std::unique_ptr<InputSource> source;

    switch (format) {
        case InputFormat::GSE:
            source = std::make_unique<GseTsSource>();
            break;
        case InputFormat::BBF:
            source = std::make_unique<BbfTsSource>();
            break;
        case InputFormat::MPE:
            source = std::make_unique<MpeTsSource>(pid);
            break;
    }

    // Connect source to UDP extractor
    source->setIpCallback([&](const uint8_t* ip_data, size_t len) {
        udp_extractor.process(ip_data, len);
    });

    // Process fd with timeout
    auto start_time = std::chrono::steady_clock::now();
    std::vector<uint8_t> buffer(65536);

    while (true) {
        // Check timeout
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        if (static_cast<unsigned int>(elapsed_ms) >= timeout_ms) {
            break;
        }

        // Poll for data
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int remaining_ms = timeout_ms - static_cast<unsigned int>(elapsed_ms);
        int poll_timeout = (remaining_ms > 100) ? 100 : remaining_ms;

        if (poll(&pfd, 1, poll_timeout) > 0 && (pfd.revents & POLLIN)) {
            ssize_t bytes_read = read(fd, buffer.data(), buffer.size());
            if (bytes_read > 0) {
                source->feed(buffer.data(), static_cast<size_t>(bytes_read));
            } else if (bytes_read == 0) {
                break;  // EOF
            }
        }

        // Early exit if all discovered streams are complete
        if (manager.allComplete() && manager.getCompleteCount() > 0) {
            break;
        }
    }

    // Flush BBF source if applicable
    if (format == InputFormat::BBF) {
        if (auto* bbf = dynamic_cast<BbfTsSource*>(source.get())) {
            bbf->flush();
        }
    }

    return results;
}

// =============================================================================
// EnsembleDiscovery - callback-fed discovery for table filter integration
// =============================================================================

struct EnsembleDiscovery::Impl {
    EnsembleManager manager;
    UdpExtractor udp_extractor;
    std::vector<DiscoveredEnsemble> results;

    unsigned int early_timeout_ms;
    unsigned int total_timeout_ms;
    std::chrono::steady_clock::time_point start_time;

    bool multicast_seen{false};
    bool done{false};
    bool failed{false};

    Impl(unsigned int early_ms, unsigned int total_ms)
        : udp_extractor([this](uint32_t ip, uint16_t port, const uint8_t* payload, size_t len) {
              onUdp(ip, port, payload, len);
          })
        , early_timeout_ms(early_ms)
        , total_timeout_ms(total_ms)
        , start_time(std::chrono::steady_clock::now())
    {
        // Set up ensemble complete callback
        manager.setCompleteCallback([this](const StreamKey& key, const lsdvb::DABEnsemble& ens) {
            DiscoveredEnsemble de;
            de.ip = key.ip;
            de.port = key.port;
            de.eid = ens.eid;
            de.label = ens.label;

            for (const auto& svc : ens.services) {
                DiscoveredService ds;
                ds.sid = svc.sid;
                ds.label = svc.label;
                ds.bitrate = svc.bitrate;
                ds.subchannel_id = static_cast<uint8_t>(svc.subchannel_id);
                ds.dabplus = svc.dabplus;
                de.services.push_back(ds);
            }
            results.push_back(de);
        });
    }

    void onUdp(uint32_t ip, uint16_t port, const uint8_t* payload, size_t len) {
        // Check for multicast IP (224.x.x.x - 239.x.x.x)
        uint8_t first_octet = (ip >> 24) & 0xFF;
        if (first_octet >= 224 && first_octet <= 239) {
            multicast_seen = true;
            manager.processUdp(ip, port, payload, len);
        }
    }

    int checkTimeout() {
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

        // Early timeout: no multicast seen within early_timeout_ms
        if (!multicast_seen && static_cast<unsigned int>(elapsed_ms) >= early_timeout_ms) {
            failed = true;
            done = true;
            return -1;
        }

        // Total timeout
        if (static_cast<unsigned int>(elapsed_ms) >= total_timeout_ms) {
            done = true;
            return results.empty() ? -1 : 1;
        }

        return 0;
    }
};

EnsembleDiscovery::EnsembleDiscovery(unsigned int early_timeout_ms, unsigned int total_timeout_ms)
    : impl_(std::make_unique<Impl>(early_timeout_ms, total_timeout_ms))
{
}

EnsembleDiscovery::~EnsembleDiscovery() = default;

int EnsembleDiscovery::feedIpPacket(const uint8_t* ip_data, size_t len)
{
    if (impl_->done) {
        return impl_->results.empty() ? -1 : 1;
    }

    // Process IP packet
    impl_->udp_extractor.process(ip_data, len);

    // Check if all ensembles complete
    if (impl_->manager.allComplete() && impl_->manager.getCompleteCount() > 0) {
        impl_->done = true;
        return 1;
    }

    // Check timeouts
    return impl_->checkTimeout();
}

std::vector<DiscoveredEnsemble> EnsembleDiscovery::getResults()
{
    return impl_->results;
}

bool EnsembleDiscovery::isDone() const
{
    return impl_->done;
}

bool EnsembleDiscovery::hasEnsembles() const
{
    return !impl_->results.empty();
}

} // namespace dvbdab
