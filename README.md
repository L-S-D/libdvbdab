# libdvbdab

C/C++ library for receiving DAB/DAB+ (Digital Audio Broadcasting) from DVB satellite streams. Supports multiple encapsulation formats and provides a C API for integration with applications like tvheadend.

## Features

- **DAB/DAB+ Audio Decoding**
  - DAB+ (HE-AAC v2) superframe decoding: FireCode sync, AU CRC check (no
    Reed-Solomon correction)
  - DAB (MPEG-1 Layer II) frame extraction
  - Dynamic labels (DLS) from the PAD of DAB+ and DAB (MPEG Layer II) audio:
    data groups checked by their CRC, a label only when all its segments
    came; EBU Latin, UCS-2 and UTF-8 labels. Their DL Plus tags (title,
    artist, ...) go out with the RadioText as RadioText Plus.

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

- **Service information from the FIC**
  - Language of each service (FIG 0/5), programme type (FIG 0/17), country,
    local time offset and international table (FIG 0/9), date and time
    (FIG 0/10): in the structures of the API
    (`dvbdab_streamer_get_time()` for the time) and in the TS

- **MPEG-TS Output**
  - Custom TS muxer (no FFmpeg dependency)
  - DVB SI: PAT, PMT, SDT, EIT schedule (from EHB) and EIT
    present/following (the programme of the schedule that is on by the time
    of the ensemble, and the next one), TDT. The SDT says for each service
    which EIT it has.
  - The PMT has the language of the audio (ISO 639-2) when the ensemble
    says it. EIT events are in the language the programme guide says for
    itself (its default language), else in that of the audio, else "und";
    they carry the programme type of the service as their content (genre;
    the RDS types of the international table 1, put into the DVB content
    codes).
  - The TDT has the time of the ensemble, not the clock of the host: none
    when the ensemble sends no time.
  - Deterministic PID allocation based on subchannel ID: PMT 0x100, audio
    0x1000, RDS 0x1100 (each + subchannel ID)
  - The dynamic label of each service as RDS RadioText, as DVB radio carries
    it: UECP frames in a stream of type 0x89 with an ancillary_data_descriptor
    ("RDS via UECP"), on a change and then every 3 s. tvheadend passes it on
    as "RDS", Kodi shows it. RadioText has at most 64 characters: a longer
    label is cut at a word. The programme guide (EIT schedule) stays apart.
  - The DL Plus tags of a label as RadioText Plus (RT+, application 0x4BD7):
    a second UECP frame after the RadioText, with the ODA configuration
    (MEC 0x40) and two tags per ODA data message (MEC 0x46), as Kodi reads
    them. The markers are put from the characters of the label to those of
    the RadioText; a tag that the cut to 64 characters took, or that does
    not fit the fields of RT+, is left out.

- **EPG Support**
  - The programme information files of the binary SPI/EPG (ETSI TS 102 371,
    `.EHB` in a MOT carousel): schedules with title, description, and the
    language they are in
  - Not used: the service information file (`.EIB`), station logos and
    other MOT objects of the carousel (the log names them at level debug);
    the XML form of SPI (there is a parser for it, nothing feeds it)

- **C API** for easy integration with C applications

## Build

### Requirements

- A C++17 compiler (built and tested with GCC 10 to 15 and clang 14 to 18)
- CMake 3.20+
- zlib
- pugixml
- Optional, for `DVBDAB_AAC_TRANSCODE`: faad2 and libavcodec/libavutil
  (found with pkg-config)

### Compile

```bash
cmake -B build
cmake --build build
```

| Option | Default | |
|--------|---------|---|
| `CMAKE_BUILD_TYPE` | `RelWithDebInfo` | |
| `DVBDAB_TRANSCODE` | `AUTO` | DAB+ transcoding: `AUTO` builds it in when faad2 and libavcodec are found (and warns when not), `ON` requires them, `OFF` leaves it out |
| `DVBDAB_WARNINGS` | `ON` | `-Wall -Wextra`; everything builds without a warning |
| `DVBDAB_SANITIZE` | `OFF` | ASan and UBSan, for the tests |
| `DVBDAB_FUZZ` | `OFF` | a fuzzing build, see [fuzz/README.md](fuzz/README.md) - never to be installed: checksums are not checked in it |

### Install

```bash
sudo cmake --install build
```

This installs (under `/usr/local` by default):
- the library, `lib/libdvbdab.a`
- `lib/pkgconfig/dvbdab.pc`
- the headers of the API, `include/dvbdab/dvbdab_c.h` (C) and
  `dvbdab.hpp`, `ts_scanner.hpp` (C++)
- headers of the classes inside the library, below `include/dvbdab/`. They
  are no stable interface: they change with any version.

### Link Against Library

The library is static, so its user links what it was built against as well:
pugixml, zlib, the C++ runtime and, with transcoding, faad2 and libavcodec.
`dvbdab.pc` lists all of it:

```bash
cc -o myapp myapp.c $(pkg-config --cflags --libs dvbdab)
```

```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(DVBDAB REQUIRED IMPORTED_TARGET dvbdab)
target_link_libraries(your_app PkgConfig::DVBDAB)
```

A program that brings its own FFmpeg must link the libavcodec the library
was built with, or one of the same major version: with another one the
library notices at run time, logs an error and does not transcode
(`dvbdab_aac_transcode()` returns 0).

## Usage

Two small programs in [examples/](examples/) are built with the library, so
they are kept working: [streamer.c](examples/streamer.c) (C: a TS with
ETI-NA or TS NI in, the radio services out as a TS) and
[scanner.cpp](examples/scanner.cpp) (C++: the ensembles of a capture).

### C API

```c
#include <dvbdab/dvbdab_c.h>

static void ts_out(void *opaque, const uint8_t *data, size_t len)
{
    fwrite(data, 1, len, (FILE *)opaque);
}

    /* a streamer for the IPv4 packets of one EDI stream (host byte order) */
    dvbdab_streamer_config_t config;
    memset(&config, 0, sizeof(config));
    config.format = DVBDAB_FORMAT_IPV4;
    config.filter_ip = 0xEFC70201;    /* 239.199.2.1 */
    config.filter_port = 1234;

    dvbdab_streamer_t *streamer = dvbdab_streamer_create(&config);
    dvbdab_streamer_set_output(streamer, ts_out, stdout);

    /* the IPv4 packets, one per call, as the MPE or GSE decoder of the
     * receiver gives them */
    while ((len = next_ipv4_packet(packet, sizeof(packet))) > 0) {
        dvbdab_streamer_feed(streamer, packet, len);

        /* services and subchannels are known: start the output */
        if (!started && dvbdab_streamer_is_basic_ready(streamer)) {
            dvbdab_streamer_start_all(streamer);
            started = 1;
        }
    }

    dvbdab_streamer_destroy(streamer);
```

For ETI-NA and TS NI the streamer is fed TS packets instead, and `pid` (for
ETI-NA also `eti_padding`, `eti_bit_offset`, `eti_inverted`, which the
scanner finds) takes the place of the address.

An ensemble that changes while the stream runs is followed: services that
come are added (and started, after `dvbdab_streamer_start_all()`), services
that go are taken out of PAT and SDT, new labels get into the SDT.

### Scanner

The scanner finds the ETI-NA and TS NI V.11 ensembles of a TS (DAB over IP
is the caller's: its IPv4 packets go to a `DVBDAB_FORMAT_IPV4` streamer;
with `filter_ip` 0 it lists the ensembles of all the streams it sees,
`dvbdab_streamer_get_all_ensembles()`).

```cpp
#include <dvbdab/ts_scanner.hpp>

dvbdab::TsScanner scanner;
scanner.setTimeout(5000);

while (!scanner.isDone() && more_ts(buf, &len)) {
    scanner.feed(buf, len);
}
for (const auto& ensemble : scanner.getResults()) {
    printf("Ensemble: %s (EID=0x%04x, PID %u)\n",
           ensemble.label.c_str(), ensemble.eid, (unsigned)ensemble.pid);
    for (const auto& service : ensemble.services) {
        printf("  Service: %s (SID=0x%04x, subch=%d)\n",
               service.label.c_str(), (unsigned)service.sid, service.subchannel_id);
    }
}
```

### Logging

```c
static void my_log_handler(int level, const char *tag, const char *message)
{
    printf("[%s] %s\n", tag, message);
}

dvbdab_set_log_callback(my_log_handler);
dvbdab_set_log_level(DVBDAB_LOG_DEBUG);
```

Without a callback the library logs to stderr. Callback and level are one
per process, not per handle.

### Threads and order of calls

- A handle (scanner, streamer) is not thread-safe: all calls on one handle
  come from one thread, or the caller serializes them. Two handles are
  independent of each other.
- The output callback and the log callback are called from inside
  `dvbdab_streamer_feed()`, in the thread that feeds. The streamer must not
  be destroyed from inside them.
- `dvbdab_streamer_set_output()` and `dvbdab_streamer_start_all()` may come
  before or after the ensemble is known: called before, the services start
  when it is.
- What `get_*` functions return belongs to the caller and is freed with the
  `free_*` function next to it; it may be used from any thread.

### Statistics

`dvbdab_streamer_get_stats()` counts what came in and went out: ETI frames,
frames missing by their counter, ETI-NA and TS NI frames with a bad CRC, EDI
frames put together from incomplete packets, TS packets.
`dvbdab_streamer_get_service_stats()` has the same for one service: frames,
audio units (DAB+ AUs, MP2 frames), the ones lost or dropped by their CRC,
what the transcoder could not decode, dynamic labels, and what the service
is put out as. Both take the size of the caller's structure, so a program
built with an older header keeps working. [examples/streamer.c](examples/streamer.c)
prints them.

### Versions

`dvbdab_c.h` has the version it describes (`DVBDAB_VERSION_MAJOR`, `_MINOR`,
`_PATCH`), and `dvbdab_version()` / `dvbdab_version_string()` return the one
of the library that is linked. The structures of the API carry no size:
header and library must be of one version. What a version added can be
asked at compile time:

| Macro | Since | |
|-------|-------|---|
| `DVBDAB_HAVE_FORMAT_IPV4` | 1.1.0 | `DVBDAB_FORMAT_IPV4` |
| `DVBDAB_HAVE_AAC_OUTPUT` | 2.2.0 | `aac_output` of the streamer config |
| `DVBDAB_HAVE_WANTED_PIDS` | 2.2.0 | `dvbdab_streamer_set_wanted_pids()` |
| `DVBDAB_HAVE_RDS` | 2.3.0 | dynamic labels as RDS RadioText in the TS |
| `DVBDAB_LABEL_SIZE` | 2.5.0 | labels of 65 bytes (17 before), `dvbdab_version()` |
| `DVBDAB_HAVE_STATS` | 2.5.0 | `dvbdab_streamer_get_stats()`, `dvbdab_streamer_get_service_stats()` |
| `DVBDAB_HAVE_SERVICE_INFO` | 2.5.0 | language and programme type of a service, country and LTO of the ensemble, `dvbdab_streamer_get_time()` |

[CHANGELOG.md](CHANGELOG.md) has what each version changed.

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

`edi_info` and `edi_extract` (sources in `tools/`, with an EDI parser of
their own that needs no FIC) are built with the library and not installed.

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

What this gave for one such stream: [docs/ficless-edi-36e.md](docs/ficless-edi-36e.md).

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
- RDS PID (the dynamic label as RadioText): `0x1100 + subchannel_id`
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

Copyright (C) 2024-2026 L-S-D

libdvbdab is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version ([LICENSE](LICENSE)). It comes without any warranty. A program linked
with the library can only be passed on under the GPL as well.

The DAB+ superframe decoder is ported from `ni2out.c` of eti-tools, which
goes back to OpenDAB, Copyright (C) 2008 David Crawley, GPL version 3 or
later.

Versions up to 2.4.0 were published under the MIT License.

A library built with transcoding contains faad2 (GPL version 2 or later) and
uses libavcodec (LGPL 2.1 or later, or GPL, depending on how it was
configured); both go with the licence of the library.
`-DDVBDAB_TRANSCODE=OFF` builds a library without them.
