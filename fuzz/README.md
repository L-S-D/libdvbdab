# Fuzzing

Everything this library reads is broadcast data nobody has checked: lossy,
sometimes damaged, possibly made up. The harnesses here feed such bytes to
the entry points and let the sanitizers judge.

| Harness | Input | Reaches |
|---|---|---|
| `fuzz_edi_stream` | records `[length, 2 bytes][UDP payload]` | a streamer of the C API (IPv4 input): PF/AF packets, TAG items, ETI frames, FIC, and with a ready ensemble the decoders, PAD, packet mode, MOT, EHB, TS muxer |
| `fuzz_eti_frames` | ETI frames (sync word and counter set by the harness) | FIC parser; stream processor with a DAB+, a DAB and a data subchannel |
| `fuzz_pad` | frames `[room, 1 byte][X-PAD][F-PAD]` | PAD decoder, character sets, RadioText, UECP frame |
| `fuzz_mot_epg` | a data subchannel, or an EHB file (first byte) | packet mode and MOT decoder, EHB parser |
| `fuzz_ts_inputs` | TS packets (first byte: ETI-NA, TS NI, scanner) | the inputs that take a transport stream |

Each harness is an `LLVMFuzzerTestOneInput()`. The seeds in `seeds/` are
synthetic (made by `make_seeds.py`, no broadcast content); the EDI seed is a
whole ensemble with one DAB+ service that gets as far as audio packets.

## With every `ctest`

In a normal build each harness has a `main()` of its own (`standalone.cpp`):
it runs files, and inputs it makes by simple mutations of them. `ctest` runs
every harness over its seeds and 3000 mutations, with the checksums on - a
smoke test, not fuzzing:

    cmake -S . -B build -DDVBDAB_SANITIZE=ON
    make -C build && (cd build && ctest)

## Fuzzing

`-DDVBDAB_FUZZ=ON` makes a fuzzing build: every checksum counts as right
(FIB, AF, PF header, Fire code, AU, packets, data groups, dynamic labels;
`CHECKSUMS_CHECKED` in `src/utils/crc_utils.hpp`), or no fuzzer gets behind
them. Such a library must never be installed.

With clang the harnesses are libFuzzer programs:

    cmake -S . -B fuzz-build -DCMAKE_CXX_COMPILER=clang++ -DDVBDAB_FUZZ=ON -DDVBDAB_SANITIZE=ON
    make -C fuzz-build fuzz_edi_stream
    mkdir corpus && fuzz-build/fuzz_edi_stream -rss_limit_mb=512 -malloc_limit_mb=64 -timeout=5 corpus fuzz/seeds/edi_stream

Without clang the same build gives the standalone programs, which mutate
without coverage feedback:

    fuzz-build/fuzz_edi_stream -runs=1000000 -seed=1 fuzz/seeds/edi_stream

When a harness dies under a sanitizer, the standalone program writes the
input to `./crash-input`; `fuzz_x crash-input` runs it again.

**Always with a memory limit.** A field of a packet that sets how much
memory is taken is exactly what this finds, and it finds it by taking the
memory: one damaged PF header once asked for 21 GB. libFuzzer has
`-rss_limit_mb` and `-malloc_limit_mb`; for the standalone programs use
`systemd-run --user --scope -p MemoryMax=2G -p MemorySwapMax=0 -- fuzz_x ...`
(an address space limit does not work with ASan).

## Seeds from a capture

Real ensembles go deeper than the synthetic one. A corpus of your own is a
directory of files in the format of the harness; for `fuzz_edi_stream` one
byte (0 or 1: ADTS or LATM) and then, for each UDP datagram of the ensemble,
its payload length in two bytes (big endian) and the payload. Keep captures
out of the repository.

## What a finding becomes

A fix, and a case in the tests (`tests/test_edi_input.cpp` has the damaged
packets fixed in 2.3.1): the next change must not bring it back.
