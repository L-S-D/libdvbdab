# Changes

What each version changed for a user of the library. The versions are the
tags of the repository.

## Not yet released

Input
- EDI: a sender that starts anew (its sequence numbers begin again) is
  followed after 8 packets; before, the stream stayed silent until the
  numbers caught up.
- An ensemble that changes while it is received is followed: services and
  subchannels that come or go, labels that change. Stale entries are dropped
  12 s after they were last announced. Announcements of the next
  configuration (C/N = 1) no longer overwrite the current one.
- No service without a label holds back the others: after 6 s the ensemble
  counts as complete with what is there.
- ETI-NA and TS NI: frames are judged by their two CRCs. A frame with a bad
  header is dropped, one with bad data keeps its FIC out and marks its
  subchannels lost. ETI-NA finds its step again after 8 bad frames (lost TS
  packets shifted it for good before).
- MOT: directory and header are read as EN 301 234 has them.
- UEP subchannel sizes for all 64 table indices; EEP-B sizes.

C API
- `dvbdab_version()`, `dvbdab_version_string()`, `DVBDAB_VERSION_PATCH`.
- Labels in `dvbdab_service_t` and `dvbdab_ensemble_t` have
  `DVBDAB_LABEL_SIZE` (65) bytes instead of 17, which cut labels with
  letters outside ASCII. **Both structures change their size: callers are
  built anew.**
- A streamer whose ensemble changes updates PAT, PMT and SDT: new services
  are added (and started after `dvbdab_streamer_start_all()`), gone ones
  taken out.
- Transcoding that was asked for and cannot be done (not built in, or a
  libavcodec of another major version is linked) is logged as a warning; the
  latter was not noticed at all before.

Build
- C++17 instead of C++23. `RelWithDebInfo` when no build type is given
  (nothing was optimized before).
- `DVBDAB_TRANSCODE` is `AUTO`, `ON` or `OFF`; `AUTO` warns when faad2 or
  libavcodec is missing.
- `-Wall -Wextra` by default (`DVBDAB_WARNINGS`), no warnings.
- The version of `dvbdab.pc` comes from the header.
- `examples/` with a C and a C++ program, built with the library.
- Gone from the library and the installed headers, unused: `UdpTsStreamer`
  (`output/ts_streamer.hpp`), `output/metadata_bridge.hpp`,
  `output/ehb_schedule_bridge.hpp`, `utils/log_throttle.hpp`,
  `EnsembleManager::setSubchannelChangeCallback()` (the changed callback
  replaces it). The library no longer makes stderr unbuffered.
- The tools `edi_info` and `edi_extract` moved to `tools/`.

## 2.4.0

- TS output: MP2 time stamps from the frame numbers; a PES closes after
  60 ms or 1400 bytes; a PCR per service 400 ms ahead of the PTS; the EIT is
  sent by stream time; an SDT of many services goes out in sections.
- DAB+: a subchannel that changes its size is followed; an AU of one or two
  bytes is none.
- ETI: the FIC of a mode II frame is 96 bytes.
- RadioText: sharp s; characters RDS does not have by what comes closest.
- Tests that check themselves, run by `ctest`; fuzz harnesses for the five
  ways bytes come in (`DVBDAB_FUZZ`), `DVBDAB_SANITIZE`.

## 2.3.1

Fixes for input that is damaged or made up:
- EDI: the header CRC of PF packets is checked; limits for fragments,
  payload and collectors; lengths in AF packets are checked against what
  came. No packet decides how much memory is taken.
- Packet mode, MOT, EHB: limits for data groups, objects, directories and
  programme data. Compressed MOT bodies are no longer inflated.
- DAB+: only frame sizes a subchannel can have.
- TS output: the programme guide is pruned (6 h past, 1024 programmes per
  service); the EIT goes out every 10 s.

## 2.3.0

- PAD decoder anew: dynamic labels are checked by their CRC and put
  together from all their segments; also from DAB (MPEG Layer II) audio.
- The dynamic label of each service as RDS RadioText in the TS (UECP,
  stream type 0x89, PID 0x1100 + subchannel ID). `DVBDAB_HAVE_RDS`.

## 2.2.0

- DAB+ output modes (`aac_output`): ADTS, LATM with 960-sample frames, or
  transcoded to AAC-LC (faad2 and libavcodec, optional).
  `DVBDAB_HAVE_AAC_OUTPUT`, `dvbdab_aac_transcode()`.
- `dvbdab_streamer_set_wanted_pids()`: only services whose PIDs are taken
  are transcoded. `DVBDAB_HAVE_WANTED_PIDS`.

## 2.1.0

- Lost frames: DAB+ superframes by frame number, the AUs of an incomplete
  superframe up to the first lost frame, time stamps that keep the gaps.
- EDI: frames from AF packets with lost PF fragments; the subchannels whose
  bytes are missing are marked.

## 2.0.0

- The library takes no MPE, GSE or BBFrames any more: the receiver takes
  the IPv4 packets out of them and feeds them (`DVBDAB_FORMAT_IPV4`). The
  formats `DVBDAB_FORMAT_MPE`, `_GSE` and `_BBF_TS` are gone.
- Only UDP datagrams to the configured IPv4 address and port are read.

## 1.1.0

- `DVBDAB_FORMAT_IPV4`. `DVBDAB_HAVE_FORMAT_IPV4`.
