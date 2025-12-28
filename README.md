# libdvbdab

C/C++ library for processing DAB (Digital Audio Broadcasting) streams from DVB transport streams.

## Features

- **Multi-format input support**: MPE (IP over DVB), GSE (Generic Stream Encapsulation), ETI-NA (E1 encapsulation), BBFrame pseudo-TS
- **Ensemble discovery**: Auto-detect DAB ensembles and services from transport streams
- **Service extraction**: Decode DAB/DAB+ audio services to PCM or AAC frames
- **MPEG-TS output**: Re-multiplex DAB services as standard MPEG-TS streams
- **C API**: Clean C interface for integration with applications like tvheadend

## Dependencies

- GCC 15+ (C++23)
- CMake 3.20+
- FFmpeg (libavformat, libavcodec, libavutil)
- fdk-aac
- zlib

## Build

```bash
cmake -B build
cmake --build build
```

## Integration

Add as a subdirectory in your CMake project:

```cmake
add_subdirectory(libdvbdab)
target_link_libraries(your_app dvbdab)
```

## API Usage

### C++ API

```cpp
#include <dvbdab/dvbdab.hpp>

// Discover ensembles from TS file
auto ensembles = lsdvb::discoverEnsembles("input.ts");
for (const auto& ens : ensembles) {
    printf("EID: %04x Label: %s\n", ens.eid, ens.label.c_str());
}
```

### C API

```c
#include <dvbdab/dvbdab_c.h>

// Create streamer for DAB ensemble
dvbdab_streamer_config_t config = {
    .format = DVBDAB_FORMAT_MPE,
    .pid = 701,
    .filter_ip = 0xEFC70201,  // 239.199.2.1
    .filter_port = 1234
};
dvbdab_streamer_t *streamer = dvbdab_streamer_create(&config);

// Feed TS packets
dvbdab_streamer_feed(streamer, ts_data, ts_len);

// Get ensemble info
dvbdab_ensemble_t *ens = dvbdab_streamer_get_ensemble(streamer);

dvbdab_streamer_free_ensemble(ens);
dvbdab_streamer_destroy(streamer);
```

## Supported Input Formats

| Format | Description | Typical Source |
|--------|-------------|----------------|
| MPE | IP over MPEG-TS (RFC 4326) | Astra 1L (19.2E) |
| GSE | Generic Stream Encapsulation | DVB-S2 transponders |
| ETI-NA | ETI over E1 in TS | Some cable/satellite feeds |
| BBF-TS | BBFrame pseudo-TS | DVB-S2 with DMX_SET_FE_STREAM |

## License

GPLv3 - See [LICENSE](LICENSE) for details.
