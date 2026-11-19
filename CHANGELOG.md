# Changes

What each version changed for a user of the library. The versions are the
tags of the repository.

## 2.6.0

C API
- `dvbdab_streamer_set_logo_callback()` (`DVBDAB_HAVE_LOGOS`): the logos of
  the services, from the programme guide of the ensemble. Its service
  information file says which image of the carousel is a logo of which
  service; each logo is told once, with its type and size, and again when
  its image changed.

TS output
- The PMT of a DAB+ service has an AAC_descriptor (profile and level, mono
  or stereo) once its first superframe was read. Each PMT has a version of
  its own: a change of one service no longer gives the PMTs of all of them
  a new version.

## 2.5.0

Licence
- The library is under the GNU General Public License, version 3 or later
  (the DAB+ superframe decoder comes from OpenDAB, which is). Versions up to
  2.4.0 were published under the MIT License.

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

TS output
- EIT: a title or description longer than 120 bytes is cut after a whole
  UTF-8 character (it could end in half of one).

Service information
- The FIC is read for the language of each service (FIG 0/5), its
  programme type (FIG 0/17), country, local time offset and international
  table of the ensemble (FIG 0/9) and date and time (FIG 0/10).
- C API (`DVBDAB_HAVE_SERVICE_INFO`): `language` and `pty` in
  `dvbdab_service_t`; `has_country`, `ecc`, `lto_half_hours` and
  `international_table` in `dvbdab_ensemble_t`;
  `dvbdab_streamer_get_time()`.
- TS: the PMT has the language of the audio. EIT events are in the language
  of the service - "und" when the ensemble does not say it, where every
  event said "ger" before - and have the programme type as their content
  descriptor. A TDT (PID 0x14) with the time of the ensemble every 5 s.
- The default language of a programme guide file is read: its events are
  in that language in the EIT (WDR: "de", so "ger" as before, now from the
  stream), before the language of the audio and "und".
- TS: EIT present/following (table 0x4E) every 2 s for the services with a
  schedule, by the time of the ensemble. The SDT flags say which service
  has an EIT schedule and an EIT present/following; before, every service
  claimed a schedule.

RadioText Plus
- The DL Plus tags of a dynamic label (title, artist and the like) go out
  with its RadioText as RT+: UECP ODA configuration (MEC 0x40) and ODA data
  (MEC 0x46, application 0x4BD7) in a second frame of the same PES. They
  were decoded and only logged before; the item toggle and item running
  bits are kept now, and tags are taken out of a label by characters, not
  bytes.

C API
- Statistics (`DVBDAB_HAVE_STATS`): `dvbdab_streamer_get_stats()` and
  `dvbdab_streamer_get_service_stats()` - frames that came, were lost or
  failed a CRC, audio units, transcoder errors, labels, TS packets.
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
- The sections of PAT, PMT, SDT and EIT are built in `output/ts_tables.hpp`
  (`TsService` and the PID constants moved there; `ts_muxer.hpp` includes
  it).
- The SPI parser logs what it skips (level debug); every MOT object of a
  data service is named once in the log (level debug).

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
