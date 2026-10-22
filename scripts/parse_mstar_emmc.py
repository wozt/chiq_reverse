#!/usr/bin/env python3
"""List the proprietary MStar partition records at the start of an eMMC image."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


SECTOR_SIZE = 512
RECORD_SIZE = 512
FIRST_RECORD = 512
RECORD_MAGIC = 0x5840


def human_size(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB")
    result = float(value)
    for unit in units:
        if result < 1024 or unit == units[-1]:
            return f"{result:.2f} {unit}"
        result /= 1024
    raise AssertionError("unreachable")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument(
        "--extract",
        action="append",
        default=[],
        metavar="NAME",
        help="extract a named partition; may be repeated",
    )
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    if args.extract and args.output_dir is None:
        parser.error("--output-dir is required with --extract")

    image_size = args.image.stat().st_size
    print("name\tstart_lba\tsectors\tstart_bytes\tsize")
    partitions: dict[str, tuple[int, int]] = {}

    with args.image.open("rb") as image:
        record_offset = FIRST_RECORD
        while record_offset + RECORD_SIZE <= image_size:
            image.seek(record_offset)
            record = image.read(RECORD_SIZE)
            magic, _reserved, start_lba, sectors = struct.unpack_from("<IIII", record)
            if magic != RECORD_MAGIC:
                break

            name = record[16:48].split(b"\0", 1)[0].decode("ascii", errors="replace")
            start_bytes = start_lba * SECTOR_SIZE
            size_bytes = sectors * SECTOR_SIZE
            in_bounds = start_bytes + size_bytes <= image_size
            suffix = "" if in_bounds else " [OUT OF BOUNDS]"
            partitions[name] = (start_bytes, size_bytes)
            print(
                f"{name}\t0x{start_lba:x}\t0x{sectors:x}\t"
                f"0x{start_bytes:x}\t{human_size(size_bytes)}{suffix}"
            )
            record_offset += RECORD_SIZE

        if args.extract:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            for name in args.extract:
                if name not in partitions:
                    parser.error(f"unknown partition: {name}")
                start_bytes, size_bytes = partitions[name]
                target = args.output_dir / f"{name}.img"
                print(f"extracting {name} -> {target}")
                image.seek(start_bytes)
                remaining = size_bytes
                with target.open("xb") as output:
                    while remaining:
                        chunk = image.read(min(16 * 1024 * 1024, remaining))
                        if not chunk:
                            raise EOFError(f"unexpected EOF while extracting {name}")
                        output.write(chunk)
                        remaining -= len(chunk)


if __name__ == "__main__":
    main()
