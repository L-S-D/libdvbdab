# libdvbdab

C/C++ library for receiving DAB/DAB+ (Digital Audio Broadcasting) from DVB satellite streams. Supports multiple encapsulation formats and provides a C API for integration with applications like tvheadend.

## Features

- **DAB/DAB+ Audio Decoding**
  - DAB+ (HE-AAC v2) superframe decoding: FireCode sync, AU CRC check (no
    Reed-Solomon correction)
  - DAB (MPEG-1 Layer II) frame extraction
  - Dynamic labels (DLS) and their DL Plus tags from the PAD of DAB+ and DAB
    (MPEG Layer II) audio: data groups checked by their CRC, a label only when
    all its segments came; EBU Latin, UCS-2 and UTF-8 labels

- **Lost frames**
  - The frame counter of the ETI frames (FCT) tells lost frames. A DAB+
    superframe keeps its frames at their place: of one with lost frames the AUs
    before the first lost one are still put out (with their CRC; SBR codes its
    envelopes relative to the AU before, the rest waits for the next
    superframe), one without its first frame (the header) is lost.
  - The PTS keep the time line: lost AUs and MP2 frames leave a gap.
  - EDI without PFT FEC: of an AF packet with lost PF fragments the
    subchannels whose bytes came are still taken (the TAG items of the last
    complete AF packet locate them); the others are marked
    (`EtiFrameExCallback`), the C API streamer uses it.

- **DAB+ output** (`aac_output` of the streamer config, 2.2 on)
  - DAB+ AUs are 960-sample frames. ADTS cannot say so: decoders take 1024
    samples per AU, and the audio plays 6.7 % slow and about a semitone low.
  - `DVBDAB_AAC_ADTS` (the default): the AUs in ADTS, the PTS on that 1024
    time line.
  - `DVBDAB_AAC_LATM`: the AUs as they came, in LATM/LOAS (stream type 0x11)
    with the AudioSpecificConfig of the subchannel (frameLengthFlag, SBR and
    PS signalled explicitly), PTS in real time. Few decoders do SBR with 960
    samples; FFmpeg does not (24 kHz core only).
  - `DVBDAB_AAC_TRANSCODE`: decoded with faad2 (960 with SBR and PS) and
    encoded again with libavcodec as AAC-LC in ADTS, 128 kbit/s per channel:
    plays right with any decoder; lost AUs become silence of their length.
    It costs about a tenth of a CPU core per service, so only the services
    whose PMT or audio PID is wanted are transcoded
    (`dvbdab_streamer_set_wanted_pids()`; all until it is called).
    `dvbdab_aac_transcode()` says whether the library was built with it.

- **Multiple Input Formats**
  | Format | Description | Source |
  |--------|-------------|--------|
  | IPv4 | DAB over IP (EDI in UDP) | IPv4 packets the caller took out of MPE or GSE |
  | ETI-NA | ETI Network Adapted | Direct ETI in TS |
  | TSNI | TS NI V.11 | ETI-NI with section headers |

  Since 2.0 the library takes no MPE, GSE or BBFrames: the receiver takes the
  IPv4 packets out of them (tvheadend does) and feeds them one by one
  (`DVBDAB_FORMAT_IPV4`). Up to 1.x the formats `DVBDAB_FORMAT_MPE`, `_GSE`
  and `_BBF_TS` did it in the library; their numbers 1-3 stay unused.

- **MPEG-TS Output**
  - Custom TS muxer (no FFmpeg dependency)
  - DVB SI: PAT, PMT, SDT, EIT schedule (from EHB/SPI)
  - Deterministic PID allocation based on subchannel ID: PMT 0x100, audio
    0x1000, RDS 0x1100 (each + subchannel ID)
  - The dynamic label of each service as RDS RadioText, as DVB radio carries
    it: UECP frames in a stream of type 0x89 with an ancillary_data_descriptor
    ("RDS via UECP"), on a change and then every 3 s. tvheadend passes it on
    as "RDS", Kodi shows it. RadioText has at most 64 characters: a longer
    label is cut at a word. The programme guide (EIT schedule) stays apart.

- **EPG Support**
  - EHB (ETSI TS 102 371) schedule parsing
  - SPI (Service and Programme Information) parsing

- **C API** for easy integration with C applications

## Build

### Requirements

- GCC 10+ or Clang 12+ (C++17 required)
- CMake 3.20+
- zlib
- pugixml
- Optional, for `DVBDAB_AAC_TRANSCODE`: faad2 and libavcodec/libavutil
  (found with pkg-config; `-DDVBDAB_TRANSCODE=OFF` builds without them)

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

The library is static: `dvbdab.pc` lists what it was built against, with
transcoding also faad2 and libavcodec, so
`pkg-config --cflags --libs dvbdab` gives all of it.

## Usage

### C API Example

```c
#include <dvbdab/dvbdab_c.h>

// TS output callback
void ts_callback(const uint8_t* data, size_t len, void* opaque) {
    write(fd, data, len);
}

int main() {
    // A streamer for the IPv4 packets of one EDI stream (host byte order)
    dvbdab_streamer_config_t config = {
        .format = DVBDAB_FORMAT_IPV4,
        .filter_ip = 0xEFC70201,    // 239.199.2.1
        .filter_port = 1234
    };

    dvbdab_streamer_t* streamer = dvbdab_streamer_create(&config);
    dvbdab_streamer_set_output(streamer, ts_callback, NULL);

    // Feed the IPv4 packets, one per call, as the MPE or GSE decoder of
    // the receiver gives them
    while ((len = next_ipv4_packet(packet, sizeof(packet))) > 0) {
        dvbdab_streamer_feed(streamer, packet, len);

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

The scanner finds the ETI-NA and TS NI V.11 ensembles of a TS (DAB over IP
is the caller's: its IPv4 packets go to a `DVBDAB_FORMAT_IPV4` streamer).

```cpp
#include <dvbdab/ts_scanner.hpp>

dvbdab::TsScanner scanner;
scanner.setTimeout(5000);

if (scanner.feed(ts_data, len) != 0) {
    for (const auto& ensemble : scanner.getResults()) {
        printf("Ensemble: %s (EID=0x%04x, PID %u)\n",
               ensemble.label.c_str(), ensemble.eid, ensemble.pid);
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

## Tests

```bash
cmake -S . -B build -DDVBDAB_SANITIZE=ON   # ASan and UBSan; leave it out for a plain build
make -C build
(cd build && ctest)
```

`ctest` runs the tests that check themselves with synthetic input - the EDI
input with damaged and crafted packets, the DAB+ decoder, dynamic labels and
RDS, the TS that goes out (through a small TS checker), the limits of the
packet mode decoder - and each fuzz harness over its seeds. Fuzzing itself:
[fuzz/README.md](fuzz/README.md). The other programs in `tests/` print what
they find in a capture; captures are not in the repository.

## Standalone Tools

The tools and tests read MPE captures (`tests/support/mpe_ip_source.hpp`
takes the IPv4 packets out of one PID); with 2.0 they no longer read GSE or
BBFrame captures.

### edi_info - EDI Stream Analyzer

Analyzes EDI streams in MPE captures. Detects audio codec (MP2 or DAB+) by analyzing the subchannel data directly, without requiring FIC.

```bash
./build/edi_info <format> <input.ts> [pid]
```

Example output:
```
=== EDI Stream Analysis ===
File: dump.ts
Format: mpe
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
- `format`: mpe
- `subchannel`: index (1-64) or "all" for all audio channels
- `output`: output file (or prefix for "all")
- `pid`: PID for MPE format (default 3000)

Examples:
```bash
# Extract single subchannel
./build/edi_extract mpe input.ts 1 channel1.mp2 3000

# Extract all subchannels
./build/edi_extract mpe input.ts all output_ 3000
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

With libdvbdab 1.x (2.0 reads no BBFrame captures):

```bash
# Analyze stream
./build/edi_info bbf dump.ts

# Extract all audio
./build/edi_extract bbf dump.ts all /tmp/output_
```

## Architecture

```
Input                            Processing                      Output
─────                            ──────────                      ──────
IPv4 (the caller's, from
MPE or GSE) ─────────────────► UdpExtractor ──► EnsembleManager ──┐
                                                     │           │
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
