#!/usr/bin/env python3
"""Writes the seed inputs of the fuzz harnesses to fuzz/seeds/<harness>/.

All of them are synthetic (no broadcast content): an ensemble with one DAB+
service as EDI, ETI frames with a DAB+, a DAB and a data subchannel, dynamic
label segments as PAD, packet mode packets, TS packets. Run it again after a
change; the files are in the repository.
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))


def crc16(data, final_xor=0xFFFF):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc ^ final_xor


FIRE_POLY = 0x782F


def firecode(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ FIRE_POLY) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def write(harness, name, data):
    d = os.path.join(HERE, "seeds", harness)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(bytes(data))


# ---- DAB+ superframe of a 24 kbit/s subchannel: 5 frames of 72 bytes, 3 AUs ----

def superframe(fill):
    fs, audio = 72, 72 * 5 - 3 * 10
    sf = bytearray(fs * 5)
    sf[2] = 0x60  # dac_rate, sbr_flag
    start = [6, 114, 222, audio]
    sf[3] = start[1] >> 4
    sf[4] = ((start[1] & 0x0F) << 4) | (start[2] >> 8)
    sf[5] = start[2] & 0xFF
    for i in range(3):
        n = start[i + 1] - start[i]
        for k in range(n - 2):
            sf[start[i] + k] = fill
        c = crc16(sf[start[i]:start[i] + n - 2])
        sf[start[i] + n - 2] = c >> 8
        sf[start[i] + n - 1] = c & 0xFF
    c = firecode(sf[2:11])
    sf[0], sf[1] = c >> 8, c & 0xFF
    return sf


# ---- FIC of an ensemble with one DAB+ service on subchannel 1 ----

def fib(figs):
    body = bytearray(figs)
    assert len(body) <= 30
    if len(body) < 30:
        body.append(0xFF)
    body += bytes(30 - len(body))
    return body + struct.pack(">H", crc16(body))


def label(text):
    return text.encode("ascii").ljust(16)[:16]


def fic():
    fig00 = bytes([0x05, 0x00, 0x12, 0x34, 0x00, 0x00])
    fig01 = bytes([0x05, 0x01, 0x04, 0x00, 0x88, 0x12])      # subchannel 1, EEP 3-A, 18 CU
    fig02 = bytes([0x06, 0x02, 0x10, 0x01, 0x01, 0x3F, 0x06])  # service 0x1001, DAB+, primary
    fig10 = bytes([0x35, 0x00, 0x12, 0x34]) + label("Fuzz Ensemble") + b"\xFF\x00"
    fig11 = bytes([0x35, 0x01, 0x10, 0x01]) + label("Fuzz Service") + b"\xFF\x00"
    return fib(fig00 + fig01 + fig02) + fib(fig10) + fib(fig11)


# ---- EDI ----

def tag(name, value):
    return name + struct.pack(">I", len(value) * 8) + bytes(value)


def af(dflc, stream):
    deti = struct.pack(">HI", 0x4000 | ((dflc // 250) << 8) | (dflc % 250), 1 << 22) + fic()
    est = bytes([1 << 2, 0, 0]) + bytes(stream)
    tags = tag(b"*ptr", b"DETI\0\0\0\0") + tag(b"deti", deti) + tag(b"est\x01", est)
    pkt = b"AF" + struct.pack(">IHBc", len(tags), dflc & 0xFFFF, 0x90, b"T") + tags
    return pkt + struct.pack(">H", crc16(pkt))


def pf(pseq, findex, fcount, payload):
    hdr = b"PF" + struct.pack(">H", pseq) + findex.to_bytes(3, "big") + fcount.to_bytes(3, "big") + \
        struct.pack(">H", len(payload))
    return hdr + struct.pack(">H", crc16(hdr)) + payload


def records(packets):
    out = bytearray()
    for p in packets:
        out += struct.pack(">H", len(p)) + p
    return out


def edi_seeds():
    frames = []
    for s in range(6):
        sf = superframe(0x40 + s)
        frames += [sf[f * 72:(f + 1) * 72] for f in range(5)]
    afs = [af(i, fr) for i, fr in enumerate(frames)]
    write("edi_stream", "af-adts.seed", bytes([0]) + records(afs))
    write("edi_stream", "af-latm.seed", bytes([1]) + records(afs))
    pfs = []
    for i, a in enumerate(afs):
        h = len(a) // 2
        pfs += [pf(100 + i, 0, 2, a[:h]), pf(100 + i, 1, 2, a[h:])]
    write("edi_stream", "pf.seed", bytes([0]) + records(pfs))
    # with every seventh fragment lost
    write("edi_stream", "pf-loss.seed", bytes([1]) + records([p for i, p in enumerate(pfs) if i % 7 != 3]))


# ---- ETI frames: DAB+ on subchannel 0, DAB on 1, packet mode data on 2 ----

def packet(addr, ci, first, last, data):
    p = bytearray(24)
    p[0] = (ci << 4) | (8 if first else 0) | (4 if last else 0) | (addr >> 8)
    p[1] = addr & 0xFF
    p[2] = len(data)
    p[3:3 + len(data)] = data
    c = crc16(p[:22])
    p[22], p[23] = c >> 8, c & 0xFF
    return p


def data_group(dg_type, seg, last, tid, payload):
    # with CRC, segment field and user access field with a transport id
    dg = bytes([0x70 | dg_type, 0x00]) + struct.pack(">H", (0x8000 if last else 0) | seg) + \
        bytes([0x12]) + struct.pack(">H", tid) + struct.pack(">H", len(payload)) + bytes(payload)
    return dg + struct.pack(">H", crc16(dg))


def packets_of(addr, dg):
    out, ci = bytearray(), 0
    chunks = [dg[i:i + 19] for i in range(0, len(dg), 19)]
    for i, ch in enumerate(chunks):
        out += packet(addr, ci & 3, i == 0, i == len(chunks) - 1, ch)
        ci += 1
    return out


def eti_seeds():
    mp2 = bytearray([0x11]) * 384
    mp2[0:4] = bytes([0xFF, 0xF5, 0x84, 0x00])
    mp2[382:384] = b"\0\0"
    data = packets_of(5, data_group(4, 0, True, 0x0101, b"\x02\x08" + b"EHB data"))
    data = (data + bytes(48))[:48]
    frames = bytearray()
    for s in range(4):
        sf = superframe(0x50 + s)
        for f in range(5):
            n = s * 5 + f
            subs = [sf[f * 72:(f + 1) * 72], mp2[(n % 2) * 192:(n % 2) * 192 + 192], data]
            fr = bytearray(352)
            fr[5] = len(subs)
            for i, sub in enumerate(subs):
                stl = len(sub) // 8
                fr[8 + i * 4] = i << 2
                fr[8 + i * 4 + 2] = (stl >> 8) & 3
                fr[8 + i * 4 + 3] = stl & 0xFF
            off = 8 + len(subs) * 4 + 4
            for sub in subs:
                fr[off:off + len(sub)] = sub
                off += len(sub)
            frames += fr
    write("eti_frames", "three-subchannels-adts.seed", bytes([0, 12]) + frames)
    write("eti_frames", "three-subchannels-latm.seed", bytes([1, 12]) + frames)


# ---- PAD: dynamic label segments in a variable size X-PAD ----

def segment(toggle, num, last, text):
    first = num == 0
    dg = bytes([(toggle << 7) | (0x40 if first else 0) | (0x20 if last else 0) | (len(text) - 1),
                0 if first else num << 4]) + text
    return dg + struct.pack(">H", crc16(dg))


def pad_frame(dg):
    x = bytes([(5 << 5) | 2, 0]) + dg
    x = x.ljust(26, b"\0")
    return bytes([26]) + x[::-1] + bytes([0x20, 0x02])


def pad_seeds():
    text = b"Artist - Title of a song that is on now"
    segs = [text[i:i + 16] for i in range(0, len(text), 16)]
    out = bytearray()
    for toggle in (0, 1):
        for rep in range(2):
            for i, s in enumerate(segs):
                out += pad_frame(segment(toggle, i, i == len(segs) - 1, s))
        dlplus = bytes([0x12, (toggle << 7) | 3, 0x00, 1, 9, 4])
        out += pad_frame(dlplus + struct.pack(">H", crc16(dlplus)))
    out += bytes([255])  # lost frames
    write("pad", "labels.seed", out)


# ---- packet mode / MOT, and an EHB file ----

def mot_seeds():
    stream = bytearray()
    for seg in range(3):
        stream += packets_of(7, data_group(4, seg, seg == 2, 0x0202, bytes([0, 30]) + bytes([0x41 + seg]) * 30))
    stream += packets_of(7, data_group(3, 0, True, 0x0202, bytes([0, 12]) + bytes(7) + b"\xCC\x09\x00test.EHB"))
    write("mot_epg", "packets.seed", bytes([0]) + stream)
    # TLV as TS 102 371: an EPG element with a token table and a string
    ehb = bytes([0x02, 0x10, 0x04, 0x06, 0x01, 0x04]) + b"News" + bytes([0x1C, 0x06, 0x01]) + b" at 9"
    write("mot_epg", "ehb.seed", bytes([1]) + ehb)


# ---- TS for the ETI-NA and TS NI inputs and the scanner ----

def ts_seeds():
    for mode in (0, 1, 2):
        ts = bytearray()
        for i in range(24):
            pkt = bytearray([0x47, 0x40 if i % 8 == 0 else 0x00, 0x00, 0x10 | (i & 15)]) + bytes([(i * 7 + k) & 0xFF for k in range(184)])
            ts += pkt
        write("ts_inputs", "ts-mode%d.seed" % mode, bytes([mode, 0]) + ts)


if __name__ == "__main__":
    edi_seeds()
    eti_seeds()
    pad_seeds()
    mot_seeds()
    ts_seeds()
