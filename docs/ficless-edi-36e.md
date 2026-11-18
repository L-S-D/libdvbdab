# A FIC-less EDI stream on 36E

This note documents findings from analyzing a FIC-less EDI stream captured from Eutelsat 36E (Russian satellite).

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
