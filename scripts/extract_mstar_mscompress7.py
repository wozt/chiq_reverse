#!/usr/bin/env python3
"""Offline extractor for the LZMA chunks used by MStar mscompress7 updates."""

from __future__ import annotations

import argparse
import lzma
import re
import struct
from pathlib import Path


HEADER_SIZE = 0x10000
SECTOR_SIZE = 512


def hx(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value, 16)


def lzma_chunk(data: bytes, output_size: int) -> bytes:
    if len(data) < 13:
        raise ValueError("short mscompress7 chunk")
    prop = data[0]
    lc = prop % 9
    rest = prop // 9
    lp = rest % 5
    pb = rest // 5
    dictionary = struct.unpack_from("<I", data, 1)[0]
    expected = struct.unpack_from("<Q", data, 5)[0]
    if expected != output_size:
        raise ValueError(f"header length 0x{expected:x} != script length 0x{output_size:x}")
    filters = [{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb,
                "dict_size": dictionary}]
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    out = decoder.decompress(data[13:], max_length=output_size)
    if len(out) != output_size:
        raise ValueError(f"decoded 0x{len(out):x}, expected 0x{output_size:x}")
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--partition", action="append", default=[],
                        help="extract only these partitions (repeatable)")
    args = parser.parse_args()
    raw = args.firmware.read_bytes()
    header = raw[:HEADER_SIZE]
    end = header.find(b"\0")
    if end < 0:
        raise SystemExit("header terminator not found")
    lines = header[:end].decode("ascii").splitlines()

    sizes: dict[str, int] = {}
    for line in lines:
        m = re.match(r"mmc create (\S+) (0x[0-9a-fA-F]+)", line)
        if m:
            sizes[m.group(1)] = int(m.group(2), 16)

    wanted = set(args.partition)
    args.output.mkdir(parents=True, exist_ok=True)
    streams: dict[str, object] = {}
    counts: dict[str, int] = {}
    current: dict[str, object] | None = None
    decoded: bytes | None = None
    zero_len: int | None = None

    def selected(name: str) -> bool:
        return not wanted or name in wanted

    def stream_for(name: str):
        if name not in streams:
            path = args.output / f"{name}.img"
            f = path.open("w+b")
            if name in sizes:
                f.truncate(sizes[name])
            streams[name] = f
        return streams[name]

    def write_at(name: str, offset: int, data: bytes) -> None:
        if not selected(name):
            return
        f = stream_for(name)
        f.seek(offset)
        f.write(data)
        counts[name] = counts.get(name, 0) + 1

    for line in lines:
        if line.startswith("filepartload "):
            fields = line.split()
            comment = line.rsplit("#", 1)[-1].strip() if "#" in line else "unknown"
            current = {"source": int(fields[3], 16), "size": int(fields[4], 16),
                       "comment": comment}
            decoded = None
            zero_len = None
            continue

        if line.startswith("mscompress7 "):
            if current is None:
                raise SystemExit("mscompress7 without filepartload")
            continue

        if line.startswith("crc32 ") and current is not None:
            fields = line.split()
            output_size = int(fields[2], 16)
            source = current["source"]
            size = current["size"]
            decoded = lzma_chunk(raw[source:source + size], output_size)
            continue

        if line.startswith("mw "):
            fields = line.split()
            # mw <address> <value> <length>; only zero fills are needed here.
            zero_len = int(fields[3], 16) if len(fields) > 3 else None
            continue

        if line.startswith("mmc write"):
            fields = line.split()
            action = fields[1]
            if action == "write.p":
                name, offset = fields[3], 0
            elif action in ("write.p.continue", "write.p.cont"):
                name, offset = fields[3], hx(fields[4]) * SECTOR_SIZE
            elif action in ("write", "write.boot"):
                # Boot-loader writes are outside the named eMMC partitions.
                current = None
                decoded = None
                zero_len = None
                continue
            else:
                continue
            if decoded is not None:
                write_at(name, offset, decoded)
            elif zero_len is not None:
                write_at(name, offset, b"\0" * zero_len)
            current = None
            decoded = None
            zero_len = None

    for f in streams.values():
        f.close()
    for name, count in sorted(counts.items()):
        print(f"{name}: {count} written chunks -> {args.output / (name + '.img')}")


if __name__ == "__main__":
    main()
