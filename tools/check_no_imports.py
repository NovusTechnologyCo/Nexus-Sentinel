#!/usr/bin/env python3
r"""Fail the build if NexusCore.sys has an import table.

WHY THIS IS A BUILD STEP AND NOT A CHECKLIST ITEM
-------------------------------------------------
The payload deliberately carries NO import table: an IAT is the FF-25 signature scan that the whole
no-imports design removes, and every nt call goes through the NexusNtApi table instead.

Keeping it that way depends on TWO lists staying in sync -- NXC_NT_API_LIST in NexusNtApi.h, and the
`#define` redirects in NexusNtApiRedirect.h. The preprocessor cannot generate the second from the
first, so they drift by hand. NexusNtApiRedirect.h's own header warns about this and prescribes
`dumpbin /IMPORTS` as the verification.

That warning was read, understood, and then the drift shipped anyway (2026-07-28): MmCopyMemory was
added to the table for NXCMD_OP_READ and not to the redirects, so NexusCore.sys went out with a live
`ntoskrnl.exe!MmCopyMemory` import, a new `fothk` thunk section, and a failing scrub verification. It
took a boot and a status read to notice.

A documented manual check that gets skipped is not a check. This runs on every build.

USAGE
    python tools/check_no_imports.py <path-to-NexusCore.sys>

Exit 0 = no imports (correct). Exit 1 = imports present, with the offending names listed.
"""

import os
import struct
import sys


def read_imports(path):
    """Return (list_of_(dll, [funcs]), section_names). Raises ValueError on a malformed PE."""
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise ValueError("not a PE image")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("no PE signature")

    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    size_opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24

    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        raise ValueError(f"expected PE32+ (0x20B), got 0x{magic:X}")

    # Data directory 1 is IMPORT. Offset 112 into the PE32+ optional header.
    import_rva, import_size = struct.unpack_from("<II", data, opt + 112 + 8)

    sec_table = opt + size_opt
    sections = []
    for i in range(num_sections):
        o = sec_table + 40 * i
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, o + 8)
        sections.append((name, vaddr, vsize, raddr, rsize))

    def rva_to_off(rva):
        for _, vaddr, vsize, raddr, rsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return raddr + (rva - vaddr)
        return None

    imports = []
    if import_rva:
        o = rva_to_off(import_rva)
        while o is not None:
            desc = data[o:o + 20]
            if len(desc) < 20 or desc == b"\0" * 20:
                break
            oft, _tds, _fc, name_rva, fta = struct.unpack("<IIIII", desc)
            no = rva_to_off(name_rva)
            dll = data[no:data.index(b"\0", no)].decode("latin1") if no else "<unreadable>"

            funcs = []
            t = rva_to_off(oft or fta)
            while t is not None:
                v = struct.unpack_from("<Q", data, t)[0]
                if v == 0:
                    break
                if not (v >> 63):                     # not an ordinal import
                    fo = rva_to_off(v & 0x7FFFFFFF)
                    if fo is not None:
                        funcs.append(data[fo + 2:data.index(b"\0", fo + 2)].decode("latin1"))
                t += 8
            imports.append((dll, funcs))
            o += 20

    return imports, [s[0] for s in sections]


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2

    path = argv[1]
    try:
        imports, sections = read_imports(path)
    except (OSError, ValueError) as exc:
        print(f"  IMPORT CHECK: cannot parse {path}: {exc}")
        return 1

    if not imports:
        print(f"  import check : OK -- no import table ({len(sections)} sections)")
        return 0

    # (!) NAME THE FILE WE WERE GIVEN, not the one we expected. This line was hardcoded to
    # "NexusCore.sys", so running the gate against any other PE reported a failure about a file it
    # had not looked at. Found 2026-08-08 while proving the gate against a known-bad -- pointing it
    # at PlatformCtl.exe correctly listed PlatformCtl's 100 imports under NexusCore.sys's name.
    # A diagnostic that names the wrong subject sends the reader to the wrong file.
    print("=" * 78)
    print(f"  IMPORT CHECK FAILED -- {os.path.basename(path)} has an import table.")
    print("=" * 78)
    for dll, funcs in imports:
        for fn in funcs:
            print(f"    {dll}!{fn}")
    print()
    print("  Each name above is missing a #define in Nexus/Include/NexusNtApiRedirect.h.")
    print("  Adding it to NXC_NT_API_LIST alone is NOT enough -- the redirect list is a")
    print("  SECOND list the preprocessor cannot generate, and an entry missing from it is")
    print("  emitted as a real import. That is the FF-25 signature the payload removes.")
    print()
    print(f"  sections: {', '.join(sections)}")
    print("  (a 'fothk' section is the import thunk block, and is itself the symptom)")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
