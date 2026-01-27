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
  - Full DVB SI: PAT, PMT, SDT, EIT (present/following + schedule)
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

### Install

```bash
sudo cmake --install build
```

This installs:
- Library: `/usr/local/lib/libdvbdab.a`
- Headers: `/usr/local/include/dvbdab/`

### Link Against Library

```cmake
# In your CMakeLists.txt
find_library(DVBDAB_LIB dvbdab)
target_link_libraries(your_app ${DVBDAB_LIB} z pugixml)
```

Or with pkg-config style flags:
```bash
g++ -o myapp myapp.cpp -ldvbdab -lz -lpugixml
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

## Standalone Tools

### edi_info - EDI Stream Analyzer

Analyzes EDI streams in BBF/GSE/MPE encapsulation. Detects audio codec (MP2 or DAB+) by analyzing the subchannel data directly, without requiring FIC.

```bash
./build/edi_info <format> <input.ts> [pid]
```

Example output:
```
=== EDI Stream Analysis ===
File: dump.ts
Format: bbf
AF packets: 10813
DAB mode: 1
FIC present: NO

=== Subchannels ===
Index SCID  Bitrate   Codec       Frames    Header
----------------------------------------------------------------------
1     18    160 kbps  MP2         10813     ff fc 94 00 80 fe 44 33
2     17    160 kbps  MP2         10813     ff fc 94 00 d0 90 34 34
6     51    32 kbps   unknown     10813     8f 8f f1 ef 6f fb cf ed
10    62    8 kbps    data        10813     c0 00 60 00 f0 12 74 34
```

### edi_extract - Audio Extractor

Extracts raw audio from EDI subchannels without requiring FIC data.

```bash
./build/edi_extract <format> <input.ts> <subchannel> <output> [pid]
```

Arguments:
- `format`: bbf, gse, or mpe
- `subchannel`: index (1-64) or "all" for all audio channels
- `output`: output file (or prefix for "all")
- `pid`: PID for MPE format (default 3000)

Examples:
```bash
# Extract single subchannel
./build/edi_extract bbf input.ts 1 channel1.mp2

# Extract all subchannels
./build/edi_extract bbf input.ts all output_
# Creates: output_1.mp2, output_2.mp2, ..., output_6.raw, ...
```

Output format is determined automatically:
- `.mp2` for detected MPEG-1 Layer II audio
- `.raw` for unknown codec (may be DAB+ or data)

## FIC-less Stream Handling

Some EDI streams do not include FIC (Fast Information Channel) data. Without FIC, ensemble and service labels cannot be discovered through normal means. However:

- **edi_info** can still analyze subchannels by parsing est (subchannel) tags directly
- **edi_extract** can extract raw audio data for manual analysis
- Codec detection works by pattern matching:
  - MP2: Look for 0xFFFC sync word (MPEG-1 Layer II)
  - DAB+: Look for FireCode CRC in superframe header
  - Data: Low bitrate (<16 kbps) subchannels

## Stream Analysis: dump.ts (French Ensemble from 36E)

This section documents findings from analyzing a FIC-less EDI stream captured from Eutelsat 36E (Russian satellite).

### Stream Overview

| Property | Value |
|----------|-------|
| File | dump.ts |
| Size | 58 MB |
| Format | BBF/GSE |
| Source | Eutelsat 36E (PID 270) |
| Multicast | 224.17.101.98:10198 |
| AF packets | 10,813 |
| FIC present | NO (ficf=0) |
| Subchannels | 13 |
| Content | French DAB ensemble |

### Subchannel Analysis

| Index | SCID | Bitrate | Codec | Notes |
|-------|------|---------|-------|-------|
| 1-5 | 14-18 | 160 kbps | MP2 | MPEG-1 Layer II, 48kHz stereo, playable |
| 6-9 | 51-54 | 32 kbps | Unknown | See analysis below |
| 10 | 62 | 8 kbps | Data | Time sync packets (t40/t41) |
| 11-13 | 11-13 | 160 kbps | MP2 | MPEG-1 Layer II, 48kHz stereo, playable |

### Unknown Format Analysis (Subchannels 6-9)

The four 32 kbps subchannels (128 kbps total) contain an unidentified audio format:

**Structure:**
- 256-byte frames with `81 81 ff` sync word
- 37-byte initial header before first frame
- Zero padding at end of each frame
- Additional `81 81 04` markers within payload

**Statistics:**
- Entropy: 7.17 bits/byte (highly compressed)
- ~10,600 `81 81` patterns per subchannel

**Ruled out:**
- MP2 (no 0xFFFC sync)
- DAB+ HE-AAC (no FireCode CRC)
- ADTS AAC (no 0xFFF sync)
- LATM AAC (no 0x56E sync)

**Hypotheses:**
1. MPEG Surround spatial audio (4 channels)
2. Proprietary broadcaster format
3. Scrambled/encrypted DAB+ audio

### Data Channel (Subchannel 10)

- 24-byte repeating blocks with CRC
- Contains "t40"/"t41" identifiers
- Likely time synchronization or tuning data

### Commands Used

```bash
# Analyze stream
./build/edi_info bbf dump.ts

# Extract all audio
./build/edi_extract bbf dump.ts all /tmp/output_
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
