#!/usr/bin/env python3
"""Read-only marker audit for the extracted SRAF/Chromium ARM binary.

This script never executes the target binary and never sends network traffic.
It reports only metadata and printable-string markers; presence is not proof
of reachability or vulnerability.
"""

import hashlib
import re
import struct
import sys
from pathlib import Path


MARKERS = [
    ("user-agent Chrome marker", rb"Chrome/"),
    ("PDF MIME marker", rb"application/pdf"),
    ("PDF Pepper interface marker", rb"PPB_PDF"),
    ("WebAssembly marker", rb"WebAssembly"),
    ("V8 marker", rb"v8::"),
    ("Blink marker", rb"blink::"),
    ("sandbox marker", rb"sandbox"),
    ("SRAF extension IPC marker", rb"FrameMsg_SrafExtensionExecuteRequest"),
    ("SRAF plugin marker", rb"SrafPlugin"),
]


def main():
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(
        "analysis/appfs/sraf/bin/sraf_browser_bin"
    )
    data = path.read_bytes()
    print("file:", path)
    print("size:", len(data), "bytes")
    print("sha256:", hashlib.sha256(data).hexdigest())

    if data[:4] != b"\x7fELF":
        print("ELF: no")
    else:
        elf_class = {1: "ELF32", 2: "ELF64"}.get(data[4], "unknown")
        endian = "<" if data[5] == 1 else ">" if data[5] == 2 else None
        machine = struct.unpack_from(endian + "H", data, 18)[0] if endian else -1
        machine_name = {40: "ARM", 183: "AArch64", 3: "x86", 62: "x86-64"}.get(
            machine, "unknown"
        )
        print("ELF:", elf_class, machine_name)

    strings = re.findall(rb"[ -~]{4,}", data)
    for label, marker in MARKERS:
        hits = [s.decode("ascii", "replace") for s in strings if marker in s]
        print("\n[{}] {} hit(s)".format(label, len(hits)))
        for item in hits[:8]:
            print("  ", item[:180])
        if len(hits) > 8:
            print("   ... {} more".format(len(hits) - 8))

    print("\nNOTE: marker presence does not prove code reachability, patch status, or exploitability.")


if __name__ == "__main__":
    main()
