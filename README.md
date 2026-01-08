# libdvbdab

C/C++ library for receiving DAB/DAB+ (Digital Audio Broadcasting) from DVB satellite streams. Supports multiple encapsulation formats and provides a C API for integration with applications like tvheadend.

## Features

- **DAB/DAB+ Audio Decoding**
  - DAB+ (HE-AAC v2) superframe decoding with Reed-Solomon error correction
  - DAB (MPEG-1 Layer II) frame extraction
  - DLS (Dynamic Label Segment) extraction for now-playing info

- **Multiple Input Formats**
  | Format | Description | Source |
  |--------|-------------|--------|
  | MPE | Multi-Protocol Encapsulation | DVB-S/S2 data carousel |
  | GSE | Generic Stream Encapsulation | DVB-S2 baseband |
  | ETI-NA | ETI Network Adapted | Direct ETI in TS |
  | TSNI | TS NI V.11 | ETI-NI with section headers |
  | BBF-TS | BBFrame in pseudo-TS | DVB-S2 DMX_SET_FE_STREAM |

- **MPEG-TS Output**
  - Custom TS muxer (no FFmpeg dependency)
  - Full DVB SI: PAT, PMT, SDT, TDT, EIT (present/following + schedule)
  - Deterministic PID allocation based on subchannel ID

- **EPG Support**
  - EHB (ETSI TS 102 371) schedule parsing
  - SPI (Service and Programme Information) parsing

- **C API** for easy integration with C applications

## Build

### Requirements

- GCC 10+ or Clang 12+ (C++17 required)
- CMake 3.16+
- zlib
- pugixml

### Compile

```bash
cmake -B build
cmake --build build
```

## Usage

### C API Example

```c
#include <dvbdab/dvbdab_c.h>

// TS output callback
void ts_callback(const uint8_t* data, size_t len, void* opaque) {
    write(fd, data, len);
}

int main() {
    // Configure streamer for GSE format
    dvbdab_streamer_config_t config = {
        .format = DVBDAB_FORMAT_GSE,
        .filter_ip = inet_addr("239.199.2.1"),
        .filter_port = 1234
    };

    dvbdab_streamer_t* streamer = dvbdab_streamer_create(&config);
    dvbdab_streamer_set_output(streamer, ts_callback, NULL);

    // Feed TS packets from DVB tuner
    while (read(tuner_fd, buffer, sizeof(buffer)) > 0) {
        dvbdab_streamer_feed(streamer, buffer, sizeof(buffer));

        // Start output when ensemble info is ready
        if (dvbdab_streamer_is_basic_ready(streamer)) {
            dvbdab_streamer_start_all(streamer);
        }
    }

    dvbdab_streamer_destroy(streamer);
    return 0;
}
```

### Scanner Example

```c
#include <dvbdab/ts_scanner.hpp>

dvbdab::TsScanner scanner;
scanner.feed(ts_data, len);

if (scanner.isComplete()) {
    auto results = scanner.getResults();
    for (const auto& ensemble : results.ensembles) {
        printf("Ensemble: %s (EID=0x%04x)\n",
               ensemble.label.c_str(), ensemble.eid);
        for (const auto& service : ensemble.services) {
            printf("  Service: %s (SID=0x%04x, subch=%d)\n",
                   service.label.c_str(), service.sid, service.subchannel_id);
        }
    }
}
```

### Logging Integration

```c
void my_log_handler(int level, const char* component, const char* message, void* opaque) {
    printf("[%s] %s\n", component, message);
}

dvbdab_set_log_callback(my_log_handler, NULL);
dvbdab_set_log_level(DVBDAB_LOG_DEBUG);
```

## Architecture

```
Input Sources                    Processing                      Output
─────────────                    ──────────                      ──────
MPE-TS ──► MpeTsSource ──┐
GSE-TS ──► GseTsSource ──┼──► UdpExtractor ──► EnsembleManager ──┐
BBF-TS ──► BbfTsSource ──┘                           │           │
                                                     ▼           │
ETI-NA ──► etina_pipeline ───────────────────────────┤           │
TSNI   ──► tsni frame assembly ──────────────────────┘           │
                                                                 ▼
                                                     DabStreamProcessor
                                                     (audio decode + TS mux)
                                                                 │
                                                                 ▼
                                                         MPEG-TS Output
                                                    (PAT/PMT/SDT/EIT + Audio)
```

## PID Allocation

Deterministic PID allocation based on subchannel_id:
- PAT PID: `0x0000` (standard)
- PMT PID: `0x0100 + subchannel_id`
- Audio PID: `0x1000 + subchannel_id`
- SDT PID: `0x0011` (standard)
- EIT PID: `0x0012` (standard)
- TDT PID: `0x0014` (standard)

## Log Levels

| Level | Constant | Description |
|-------|----------|-------------|
| 0 | `DVBDAB_LOG_ERROR` | Errors only |
| 1 | `DVBDAB_LOG_WARN` | Warnings |
| 2 | `DVBDAB_LOG_INFO` | Info (default) |
| 3 | `DVBDAB_LOG_DEBUG` | Debug |
| 4 | `DVBDAB_LOG_TRACE` | Verbose trace |

## References

- ETSI EN 300 401 - DAB system specification
- ETSI TS 102 563 - DAB+ audio (HE-AAC)
- ETSI EN 300 799 - ETI format
- ETSI TS 102 980 - DLS (Dynamic Label Segment)
- ETSI TS 102 371 - EHB (Electronic Programme Guide)
- ISO/IEC 13818-1 - MPEG-2 Systems (TS structure)
- ETSI EN 300 468 - DVB SI (Service Information)

## License

MIT License
