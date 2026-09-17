r"""
embed_driver.py -- bake a kernel driver's bytes into a C header the DXE compiles in.

WHY EMBED RATHER THAN READ FROM THE ESP (decision 2026-07-27, user's call): a .sys sitting on the
ESP is a file on disk that anything can find, and it would undo part of what scope 4c and the path
rename bought. Embedded, there is no extra file at any point -- the cost is a DXE rebuild per
driver change, which is accepted.

WHAT THIS EMITS
  - the raw PE bytes as a C array in a named section
  - the SHA-256 of those bytes, as a compile-time constant
  - the PE facts the mapper needs up front (SizeOfImage, entry RVA, whether relocs exist), so the
    DXE can sanity-check the payload BEFORE it starts mapping rather than discovering a truncated
    embed halfway through

The digest is the point. The DXE verifies it with the Sha256.c already present from the Tier 3
work, so a corrupted or truncated embed fails closed with a clear reason instead of presenting as
an unexplained early-boot hang -- and an early-boot hang is the single most expensive failure mode
we have, because diagnosing it costs a reboot cycle each time.

Usage:
    python tools/embed_driver.py <driver.sys> <out.h> [--symbol NAME] [--section .name]

Output is ASCII only (Windows console is cp1252).
"""

import argparse
import hashlib
import os
import struct
import sys


def pe_facts(data):
    """Pull the few PE fields the mapper needs, and validate enough to reject junk early.

    Deliberately minimal and hand-rolled: this runs on the BUILD machine against a file we just
    produced, so the job is catching a truncated/wrong file, not parsing hostile input.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise SystemExit("not a PE: missing MZ")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x108 > len(data):
        raise SystemExit("not a PE: e_lfanew out of range (file truncated?)")
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("not a PE: missing PE signature")

    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    if machine != 0x8664:
        raise SystemExit("expected x64 (0x8664), got 0x%04X" % machine)

    opt = e_lfanew + 0x18
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        raise SystemExit("expected PE32+ (0x20B), got 0x%03X" % magic)

    entry_rva = struct.unpack_from("<I", data, opt + 0x10)[0]
    image_base = struct.unpack_from("<Q", data, opt + 0x18)[0]
    size_of_image = struct.unpack_from("<I", data, opt + 0x38)[0]
    size_of_headers = struct.unpack_from("<I", data, opt + 0x3C)[0]

    # Data directory 5 = base relocations. A manually-mapped image that lands anywhere other than
    # its link base NEEDS these; their absence is a build misconfiguration worth failing on now
    # rather than at boot.
    dd = opt + 0x70
    reloc_rva, reloc_size = struct.unpack_from("<II", data, dd + 5 * 8)
    # Directory 10 = load config, which carries the GS SecurityCookie pointer.
    lcfg_rva, lcfg_size = struct.unpack_from("<II", data, dd + 10 * 8)

    if entry_rva == 0 or entry_rva >= size_of_image:
        raise SystemExit("entry RVA 0x%X outside image (size 0x%X)" % (entry_rva, size_of_image))
    if reloc_size == 0:
        raise SystemExit("image has NO base relocations -- it cannot be mapped anywhere but its "
                         "link base. Link with /DYNAMICBASE and do not strip .reloc.")

    return {
        "entry_rva": entry_rva,
        "image_base": image_base,
        "size_of_image": size_of_image,
        "size_of_headers": size_of_headers,
        "reloc_rva": reloc_rva,
        "reloc_size": reloc_size,
        "lcfg_rva": lcfg_rva,
        "lcfg_size": lcfg_size,
    }


def emit(path_in, path_out, symbol, section):
    data = open(path_in, "rb").read()
    facts = pe_facts(data)
    digest = hashlib.sha256(data).digest()

    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        rows.append("\t" + " ".join("0x%02X," % b for b in chunk))

    with open(path_out, "w", encoding="ascii", newline="\r\n") as fh:
        w = fh.write
        w("/**\n")
        w(" * @file %s\n" % os.path.basename(path_out))
        w(" * @brief GENERATED -- do not edit. Embedded kernel driver payload.\n")
        w(" *\n")
        w(" * Produced by tools/embed_driver.py from %s\n" % os.path.basename(path_in))
        w(" * Regenerate with:  python tools/embed_driver.py <driver.sys> <this file>\n")
        w(" *\n")
        w(" * The DXE verifies PayloadSha256 over PayloadBytes before mapping anything. That check is\n")
        w(" * not ceremony: a truncated or stale embed would otherwise surface as an early-boot hang,\n")
        w(" * which is the most expensive failure mode available to us -- each diagnosis costs a reboot.\n")
        w(" * Failing closed with a reason costs nothing.\n")
        w(" */\n\n")
        w("#pragma once\n\n")
        w("#include <Uefi.h>\n\n")

        w("/* PE facts, extracted at build time so the DXE can validate before it starts mapping. */\n")
        w("#define NXC_PAYLOAD_SIZE          0x%08Xu  /* raw file bytes                */\n" % len(data))
        w("#define NXC_PAYLOAD_ENTRY_RVA     0x%08Xu  /* DriverEntry                   */\n" % facts["entry_rva"])
        w("#define NXC_PAYLOAD_IMAGE_BASE    0x%016XULL /* link base            */\n" % facts["image_base"])
        w("#define NXC_PAYLOAD_SIZE_OF_IMAGE 0x%08Xu  /* bytes to reserve              */\n" % facts["size_of_image"])
        w("#define NXC_PAYLOAD_SIZE_OF_HDRS  0x%08Xu\n" % facts["size_of_headers"])
        w("#define NXC_PAYLOAD_RELOC_RVA     0x%08Xu\n" % facts["reloc_rva"])
        w("#define NXC_PAYLOAD_RELOC_SIZE    0x%08Xu\n" % facts["reloc_size"])
        w("#define NXC_PAYLOAD_LCFG_RVA      0x%08Xu  /* load config: GS cookie lives here */\n" % facts["lcfg_rva"])
        w("#define NXC_PAYLOAD_LCFG_SIZE     0x%08Xu\n\n" % facts["lcfg_size"])

        w("/* SHA-256 of the %d payload bytes below. */\n" % len(data))
        w("STATIC CONST UINT8 NxcPayloadSha256[32] = {\n")
        for i in range(0, 32, 16):
            w("\t" + " ".join("0x%02X," % b for b in digest[i:i + 16]) + "\n")
        w("};\n\n")

        w("/*\n")
        w(" * The payload itself. Placed in its own section so the DXE's other sections keep their\n")
        w(" * expected characteristics, and so this blob is trivially locatable for future work that\n")
        w(" * may want to encrypt it at rest rather than ship it as a plain PE inside our image.\n")
        w(" */\n")
        if section:
            w('#pragma section("%s", read)\n' % section)
            w('__declspec(allocate("%s"))\n' % section)
        w("STATIC CONST UINT8 %s[NXC_PAYLOAD_SIZE] = {\n" % symbol)
        w("\n".join(rows))
        w("\n};\n")

    return len(data), digest, facts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("driver")
    ap.add_argument("output")
    ap.add_argument("--symbol", default="NxcPayloadBytes")
    ap.add_argument("--section", default=".nxcpl")
    a = ap.parse_args()

    if not os.path.isfile(a.driver):
        raise SystemExit("no such file: %s" % a.driver)

    n, digest, facts = emit(a.driver, a.output, a.symbol, a.section)
    print("=" * 78)
    print(" EMBED DRIVER : %s" % os.path.basename(a.driver))
    print("=" * 78)
    print("  payload       : %d bytes" % n)
    print("  sha256        : %s" % digest.hex())
    print("  entry RVA     : 0x%X" % facts["entry_rva"])
    print("  link base     : 0x%016X" % facts["image_base"])
    print("  SizeOfImage   : 0x%X (%d KB to reserve)" % (facts["size_of_image"],
                                                         facts["size_of_image"] // 1024))
    print("  relocations   : RVA 0x%X, %d bytes" % (facts["reloc_rva"], facts["reloc_size"]))
    print("  load config   : RVA 0x%X, %d bytes%s" % (
        facts["lcfg_rva"], facts["lcfg_size"],
        "" if facts["lcfg_size"] else "  (no GS cookie to seed)"))
    print("  wrote         : %s" % a.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
