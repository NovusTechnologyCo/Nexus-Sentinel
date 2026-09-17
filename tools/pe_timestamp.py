#!/usr/bin/env python3
r"""Print a PE image's TimeDateStamp -- the value `PlatformCtl status` reports as `dxe ident`.

WHY THIS EXISTS
---------------
PayloadIdent answers "which NexusCore.sys is embedded", because it is that file's SHA-256. It does
NOT answer "which PlatformRuntimeDxe.efi is running": a DXE-only change leaves the embedded driver
byte-identical, so the ident reads the same before and after the deploy. That happened on 2026-07-28
with the DSE removal, which changed only DXE code and therefore had no observable deploy proof at
all -- the class of change where nothing else is visible either.

An image cannot contain its own hash, so the DXE reports its PE TimeDateStamp instead, read from its
own headers at runtime. This script reads the same field from the file on disk so the two can be
compared directly.

Under /Brepro the linker writes a content hash here rather than a clock value. That is strictly
better for this purpose, and it is why the output deliberately does NOT try to render the value as a
date -- a reproducible-build stamp is not a timestamp, and printing "2089-03-14" next to it would be
a confident lie.

USAGE
    python tools/pe_timestamp.py Nexus/UEFI/build/x64/Release/PlatformRuntimeDxe.efi
    python tools/pe_timestamp.py X:\EFI\OEM\PlatformRuntimeDxe.efi      # what is actually deployed

Comparing the BUILD OUTPUT against the DEPLOYED FILE is the direct way to answer "did my copy
land", without a reboot.
"""

import struct
import sys


def pe_timestamp(path):
    """Return (TimeDateStamp, Machine) from a PE file, or raise ValueError."""
    with open(path, "rb") as f:
        data = f.read(0x400)

    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise ValueError("not a PE image: missing MZ signature")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data):
        raise ValueError(f"e_lfanew 0x{e_lfanew:X} outside the header we read")

    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError(f"no PE signature at e_lfanew 0x{e_lfanew:X}")

    # IMAGE_FILE_HEADER follows the 4-byte signature: Machine(2) NumberOfSections(2) TimeDateStamp(4)
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    stamp = struct.unpack_from("<I", data, e_lfanew + 8)[0]
    return stamp, machine


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2

    path = argv[1]
    try:
        stamp, machine = pe_timestamp(path)
    except (OSError, ValueError) as exc:
        print(f"  {path}: {exc}")
        return 1

    print(f"  file      : {path}")
    print(f"  machine   : 0x{machine:04X}")
    print(f"  dxe ident : 0x{stamp:08X}   <-- compare with `PlatformCtl status`")
    # Deliberately not decoded as a date: with /Brepro this field is a content hash, and rendering a
    # hash as a calendar date would be a confidently wrong answer rather than a missing one.
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
