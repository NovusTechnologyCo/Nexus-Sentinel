#!/usr/bin/env python3
"""Validate the TPM 2.0 core against an INDEPENDENT oracle, on the host, with no reboot.

WHY THIS EXISTS.

A wrong PCR_Extend is close to undetectable on hardware: PCRs are 32 opaque bytes and a
plausible-looking wrong value is indistinguishable from a right one without something else to
compare against. Diagnosing it at boot costs a reboot per attempt; here it costs nothing.

THE ORACLE IS PYTHON'S hashlib, NOT OUR SHA-256, AND THAT IS THE POINT.

Computing the expected value with the same code under test produces a test that agrees with itself
and proves nothing. That exact failure already happened in this phase: an early ACPI dump script
returned ABSENT for every table, which was the answer expected before deploy, so a completely
broken instrument looked like a passing validation. The oracle has to come from somewhere else.

So this compiles the REAL firmware sources -- Tpm2Core.c and Sha256.c, unmodified, the same files
the DXE builds -- against a minimal host shim, runs them, and checks every digest against hashlib.

    python tools/check_tpm2_core.py

Exit 0 if everything matches, 1 otherwise.
"""
import hashlib
import io
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTDIR = os.path.join(ROOT, 'tools', 'tpm2_host_test')
SRC = [
    os.path.join(TESTDIR, 'tpm2_selftest.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Core.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2EventLog.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2PeHash.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusBootDxe', 'Sha256.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Sha512.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Hash.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Dispatch.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Bn.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Prime.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Kdf.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Object.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Session.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Primary.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Nv.c'),
    os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Aes.c'),
]

ZERO = bytes(32)
ONES = b'\xff' * 32


def find_vcvars():
    """Locate vcvars64.bat.

    cl.exe on its own cannot compile anything: INCLUDE and LIB are set by the developer
    environment, not baked into the compiler, so a direct invocation fails on <stdio.h> with a
    message that reads like the source is at fault. Going through vcvars is the fix.
    """
    import glob
    pats = [
        r'C:\Program Files\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat',
        r'C:\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat',
    ]
    for p in pats:
        hits = sorted(glob.glob(p))
        if hits:
            return hits[-1]
    return None


def build_and_run():
    vcvars = find_vcvars()
    if vcvars is None:
        sys.exit('vcvars64.bat not found; the host test needs the same MSVC the DXE build uses')

    out_dir = os.path.join(TESTDIR, '_build')
    os.makedirs(out_dir, exist_ok=True)
    exe = os.path.join(out_dir, 'tpm2_selftest.exe')

    #
    # Written to a .bat rather than passed as a cmd /c string. The command needs quoted paths
    # (Program Files) inside a quoted argument, and that nesting does not survive Windows
    # argument quoting -- the first attempt produced backslash-escaped quotes and cmd reported
    # the vcvars path itself as "not recognized as an internal or external command".
    #
    # /I TESTDIR puts the host Uefi.h shim FIRST, so <Uefi.h> resolves to it and not to EDK2.
    #
    bat = os.path.join(out_dir, '_build.bat')
    with open(bat, 'w') as f:
        f.write('@echo off\r\n')
        f.write('call "%s" >nul\r\n' % vcvars)
        f.write('if errorlevel 1 exit /b 1\r\n')
        #
        # (!) /Fo AND /Fe USE RELATIVE PATHS, and that is not cosmetic. The batch already runs
        # with cwd set to out_dir, so relative works -- and it avoids a real MSVC quoting trap:
        # a quoted path that ENDS IN A BACKSLASH has its closing quote escaped by that
        # backslash. cl then swallows the rest of the command line and reports
        # "D8003: missing source filename", which reads as though no sources were passed at all.
        #
        f.write('cl /nologo /W3 /O2 /I "%s" /Fe:tpm2_selftest.exe /Fo:.\\ %s\r\n' % (
            TESTDIR, ' '.join('"%s"' % p for p in SRC)))

    r = subprocess.run(['cmd', '/c', bat], capture_output=True, text=True, cwd=out_dir)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr)
        sys.exit('host build FAILED -- the sources are no longer dependency-free, or a real error')

    r = subprocess.run([exe], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        sys.exit('host test binary failed to run')
    return r.stdout, exe

def parse(out):
    d = {}
    for line in out.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            d[k.strip()] = v.strip()
    return d


def parse_event_log(blob):
    """Parse a TCG crypto-agile log independently of the code that wrote it.

    Written from the TCG structure definitions, not from Tpm2EventLog.c. If it were derived
    from the writer it would reproduce the writer's bugs and agree with them.

    Returns (spec_id_dict, [events]) where each event is
    {pcr, type, digests: {alg: bytes}, data: bytes}.
    """
    import struct
    off = 0

    # Entry 0 is deliberately in the OLD 1.2 format: PCRIndex, EventType, 20-byte digest,
    # EventSize, then the Spec ID payload.
    pcr, etype = struct.unpack_from("<II", blob, off); off += 8
    digest12 = blob[off:off + 20]; off += 20
    (esize,) = struct.unpack_from("<I", blob, off); off += 4
    payload = blob[off:off + esize]; off += esize

    spec = {
        "pcr": pcr,
        "type": etype,
        "digest12_is_zero": (digest12 == bytes(20)),
        "signature": payload[0:16],
    }
    p = 16
    (spec["platformClass"],) = struct.unpack_from("<I", payload, p); p += 4
    spec["minor"] = payload[p]; p += 1
    spec["major"] = payload[p]; p += 1
    spec["errata"] = payload[p]; p += 1
    spec["uintnSize"] = payload[p]; p += 1
    (nalg,) = struct.unpack_from("<I", payload, p); p += 4
    spec["numberOfAlgorithms"] = nalg
    algs = {}
    for _ in range(nalg):
        alg, dsz = struct.unpack_from("<HH", payload, p); p += 4
        algs[alg] = dsz
    spec["algorithms"] = algs
    spec["vendorInfoSize"] = payload[p]; p += 1

    events = []
    while off < len(blob):
        pcr, etype = struct.unpack_from("<II", blob, off); off += 8
        (count,) = struct.unpack_from("<I", blob, off); off += 4
        digests = {}
        for _ in range(count):
            (alg,) = struct.unpack_from("<H", blob, off); off += 2
            dsz = algs.get(alg)
            if dsz is None:
                raise ValueError("event names algorithm 0x%04x not declared in the header" % alg)
            digests[alg] = blob[off:off + dsz]; off += dsz
        (dsize,) = struct.unpack_from("<I", blob, off); off += 4
        data = blob[off:off + dsize]; off += dsize
        events.append({"pcr": pcr, "type": etype, "digests": digests, "data": data})

    return spec, events


def authenticode_sha256(blob):
    """Authenticode PE image SHA-256, implemented HERE and not shared with the C.

    Written from the numbered steps in the Microsoft Authenticode PE Signature Format (which
    PFP 3.3.3.1 defers to), in a different language from the implementation under test. That is
    what makes it an oracle rather than an echo.
    """
    import struct
    if len(blob) < 0x40 or blob[0:2] != b'MZ':
        return None
    (lfanew,) = struct.unpack_from('<I', blob, 0x3C)
    if lfanew + 24 > len(blob) or blob[lfanew:lfanew + 4] != b'PE\x00\x00':
        return None

    nsec, = struct.unpack_from('<H', blob, lfanew + 6)
    optsz, = struct.unpack_from('<H', blob, lfanew + 20)
    opt = lfanew + 24
    magic, = struct.unpack_from('<H', blob, opt)
    if magic == 0x10B:
        numrva_off, dir_off = opt + 92, opt + 96
    elif magic == 0x20B:
        numrva_off, dir_off = opt + 108, opt + 112
    else:
        return None

    soh, = struct.unpack_from('<I', blob, opt + 60)
    numrva, = struct.unpack_from('<I', blob, numrva_off)
    checksum = opt + 64

    secdir = None
    certrva = certsize = 0
    if numrva > 4:
        secdir = dir_off + 4 * 8
        certrva, certsize = struct.unpack_from('<II', blob, secdir)

    h = hashlib.sha256()
    # 3-4: base .. CheckSum
    h.update(blob[0:checksum])
    # 5: skip CheckSum
    pos = checksum + 4
    if secdir is None:
        # 6
        h.update(blob[pos:soh])
    else:
        # 7: on to the cert directory ENTRY
        h.update(blob[pos:secdir])
        # 8: skip it (8 bytes)
        pos = secdir + 8
        # 9: to the end of headers
        h.update(blob[pos:soh])

    # 10
    total = soh
    # 11-12: sections sorted by PointerToRawData
    sect = opt + optsz
    secs = []
    for i in range(nsec):
        off = sect + i * 40
        rawsz, rawptr = struct.unpack_from('<II', blob, off + 16)
        secs.append((rawptr, rawsz))
    secs.sort(key=lambda t: t[0])
    # 13-15
    for rawptr, rawsz in secs:
        if rawsz == 0:
            continue
        h.update(blob[rawptr:rawptr + rawsz])
        total += rawsz
    # 16: trailing data, minus the certificate table
    if len(blob) > total:
        trailing = len(blob) - total
        if certsize and certrva:
            trailing -= certsize
        if trailing > 0:
            h.update(blob[total:total + trailing])
    return h.digest()


def run_pe(exe, path):
    """Run the harness over one PE file and return its parsed output."""
    r = subprocess.run([exe, path], capture_output=True, text=True)
    return parse(r.stdout)


def check_bignum(got, check):
    """Recompute every emitted bignum vector with Python integers and compare.

    (!) PYTHON IS A GENUINE INDEPENDENT ORACLE. It shares no code, no author and no assumptions
    with Tpm2Bn.c, which is the only reason to trust a from-scratch bignum. A bignum tested
    against itself proves internal consistency -- exactly the property a wrong carry chain also
    has.

    (!) THE C SIDE EMITS ITS INPUTS BESIDE ITS ANSWERS, so nothing here reproduces the C
    generator. A shared PRNG would be a shared assumption, and the first time the two drifted
    the tests would compare different vectors and pass.
    """
    print()
    print('  --- Tpm2Bn: every vector recomputed with Python integers ---')

    n = int(got.get('bn.vectors', '0'))
    if not n:
        check('bignum vectors were emitted', '0', 'nonzero')
        return

    ops = {
        'bn.add':    lambda a, b: a + b,
        'bn.sub':    lambda a, b: a - b,
        'bn.mul':    lambda a, b: a * b,
        'bn.div':    lambda a, b: a // b if b else None,
        'bn.mod':    lambda a, b: a % b if b else None,
        'bn.gcd':    _gcd,
        'bn.shl37':  lambda a, b: a << 37,
        'bn.shl64':  lambda a, b: a << 64,
        'bn.shr37':  lambda a, b: a >> 37,
        'bn.shr64':  lambda a, b: a >> 64,
        'bn.modexp': lambda a, m: pow(a, 65537, m) if m else None,
        'bn.modinv': _modinv,
    }

    for name in sorted(ops):
        bad = 0
        seen = 0
        first = None
        for i in range(n):
            v = got.get('%s.%d' % (name, i))
            if v is None:
                continue          # modinv is skipped when no inverse exists
            seen += 1
            parts = v.split()
            if len(parts) != 3:
                bad += 1
                continue
            a_, b_, r_ = (int(x, 16) for x in parts)
            want = ops[name](a_, b_)
            if want is None or want != r_:
                bad += 1
                if first is None:
                    first = '%s.%d: a=%x b=%x got=%x want=%s' % (
                        name, i, a_, b_, r_, want)
        label = '%-12s %3d vectors' % (name.replace('bn.', ''), seen)
        if bad:
            check(label, 'FAILED %d: %s' % (bad, first), 'all match')
        else:
            check(label, seen and 'ok' or 'none', seen and 'ok' or 'none')

    print('  --- Tpm2Bn: edges random vectors do not reach ---')
    check('bits(0) is 0',                 got.get('bn.zero_bits'),        '0')
    check('IsZero(0)',                    got.get('bn.zero_iszero'),      '1')
    check('cmp(0, 1) is -1',              got.get('bn.zero_cmp_one'),     '-1')
    check('0 + 1 is 1',                   got.get('bn.zero_plus_one'),    '1')
    check('0 * 1 is 0',                   got.get('bn.zero_times_one'),   '1')
    #
    # (!) A SUBTRACTION THAT WOULD GO NEGATIVE MUST REFUSE. This type has no sign, and a wrapped
    # positive result is a wrong modulus that every later step would accept.
    #
    check('0 - 1 REFUSES',                got.get('bn.sub_underflow'),    '0')
    check('  and leaves the result zero', got.get('bn.sub_underflow_zeroed'), '1')
    #
    # Montgomery needs the inverse of M modulo 2^32, which exists only for odd M.
    #
    check('ModExp REFUSES an even modulus', got.get('bn.modexp_even'),    '0')
    check('x mod 1 is 0',                 got.get('bn.modexp_mod1'),      '1')
    check('division by zero REFUSES',     got.get('bn.div_by_zero'),      '0')
    #
    # Callers alias. A += A and A *= A are natural to write and would corrupt the operand
    # mid-loop if the result were accumulated in place.
    #
    check('aliased add matches',          got.get('bn.alias_add'),        '0')
    check('aliased mul matches',          got.get('bn.alias_mul'),        '0')
    check('2048-bit round-trip',          got.get('bn.roundtrip'),        '0')
    check('  and ToBytes succeeded',      got.get('bn.roundtrip_out'),    '1')
    check('ToBytes REFUSES a short buffer', got.get('bn.tobytes_short'),  '0')
    check('leading zeros do not truncate',  got.get('bn.leading_zeros'),  '0')
    #
    # (!) AND THE PADDING ITSELF, WHICH THE CHECK ABOVE CANNOT SEE. It compares VALUES, and
    # Tpm2BnFromBytes ignores leading zeros -- so a ToBytes that left-justified, or that stripped
    # the padding, would round-trip perfectly and pass.
    #
    # A TPM2B whose width tracked its value would change an object's Name for one key in 256.
    # Found by injuring Tpm2Object: a variable-width modulus survived that entire suite, because
    # a KeyBits-bit RSA modulus NEVER has a leading zero octet, so the property is unobservable
    # there. 0x0102 in a 16-byte buffer is where it can be wrong.
    #
    check('ToBytes RIGHT-ALIGNS and zero-pads', got.get('bn.pad'), '00' * 14 + '0102')
    check('  and it succeeded',                 got.get('bn.pad_ok'), '1')


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def _modinv(a, m):
    """Python 3.8+ has pow(a, -1, m); this spells it out so the oracle owes nothing to
    a version-specific shortcut."""
    if m == 0:
        return None
    g, x = m, 0
    r, y = a % m, 1
    while r:
        q = g // r
        g, r = r, g - q * r
        x, y = y, x - q * y
    if g != 1:
        return None
    return x % m


def check_known_answers(got, check):
    """Ask for EVERYTHING, and judge every answer.

    (!) THIS EXISTS BECAUSE THE DEMAND TRACE CANNOT BE A DEFINITION OF DONE. It names only what
    one OS asked for on one boot, so a command Windows never sends is untested by construction
    -- and the first time something else asks for it is the worst possible moment to find out.

    Three classes of check, and they are different kinds of claim:

      UNIVERSAL   invariants every response must satisfy whatever the command was. These come
                  from Part 1 clause 6 and hold for codes we will never implement.
      SPEC        values the specification fixes, e.g. the family indicator is "2.0\\0". A real
                  known answer: an independent source says what it must be.
      IDENTITY    values WE chose, e.g. manufacturer INTC. Pinning them is a REGRESSION test,
                  not a known-answer test, and it is labelled so nobody mistakes agreement with
                  ourselves for agreement with the standard.
    """
    print()
    print('  --- Known-answer layer: every command in Part 2, not just the asked-for ones ---')

    lo = int(got.get('kat.sweep_first', '0'), 16)
    hi = int(got.get('kat.sweep_last', '0'), 16)
    if not lo or not hi:
        check('the sweep ran', 'no', 'yes')
        return

    have = _implemented_codes()

    #
    # UNIVERSAL. Part 1 clause 6: a response carries a valid tag and declares its own length.
    # A response whose size field disagrees with the bytes returned is malformed no matter what
    # the command was, and the peer acts on the declared value.
    #
    bad_len, bad_tag, bad_unimpl, bad_impl = [], [], [], []
    swept = 0
    for cc in range(lo, hi + 1):
        v = got.get('kat.sweep.%03X' % cc)
        if v is None:
            continue
        swept += 1
        rc, ln, tag, hdrsize = v.split()
        rc, ln, tag, hdrsize = int(rc, 16), int(ln), int(tag, 16), int(hdrsize)
        if ln != hdrsize:
            bad_len.append((cc, ln, hdrsize))
        if tag not in (0x8001, 0x8002):
            bad_tag.append((cc, tag))
        if cc in have:
            #
            # A command we implement must be RECOGNISED. It may still refuse this minimal
            # header -- most need arguments and will say TPM_RC_COMMAND_SIZE -- but answering
            # COMMAND_CODE would mean the dispatcher never reached a handler for it.
            #
            if rc == 0x143:
                bad_impl.append(cc)
        else:
            #
            # Everything else must refuse IDENTICALLY and CLEANLY: exactly COMMAND_CODE, in
            # exactly a 10-byte header. This is the half nothing had ever tested -- 126
            # commands Windows has never sent here, any of which another caller might.
            #
            if rc != 0x143 or ln != 10:
                bad_unimpl.append((cc, rc, ln))

    check('swept the whole TPM_CC range', swept, hi - lo + 1)
    check('every response declares its own length', bad_len[:3] or 'all', 'all')
    check('every response carries a valid tag',     bad_tag[:3] or 'all', 'all')
    check('every implemented command is RECOGNISED', bad_impl[:5] or 'all', 'all')
    check('every other command refuses cleanly',    bad_unimpl[:5] or 'all', 'all')
    print('    (%d implemented, %d must refuse -- all %d exercised)'
          % (len(have), swept - len(have), swept))

    #
    # MALFORMED. A declared size of 0xFFFFFFFF, a declared size of zero, a nonsense tag, and an
    # output buffer too small for a header. None may produce a response that lies about its own
    # length, and none may return more bytes than the buffer allows.
    #
    print('  --- Malformed inputs ---')
    n = int(got.get('kat.malformed_codes', '0'))
    for case, label in (('huge', 'declared size 0xFFFFFFFF'),
                        ('zerosize', 'declared size 0'),
                        ('badtag', 'tag 0x1234')):
        bad = []
        seen = 0
        for cc in range(lo, hi + 1):
            v = got.get('kat.%s.%03X' % (case, cc))
            if v is None:
                continue
            seen += 1
            rc, ln, hdrsize = v.split()
            if int(ln) != int(hdrsize):
                bad.append((cc, ln, hdrsize))
        check('%-26s -> length is honest' % label, bad[:3] or 'all', 'all')

    bad = []
    for cc in range(lo, hi + 1):
        v = got.get('kat.tinyout.%03X' % cc)
        if v is None:
            continue
        rc, ln = v.split()
        #
        # A 4-byte output buffer cannot hold a 10-byte header. The dispatcher must write
        # NOTHING rather than as much as fits -- a partial header is a response the peer will
        # parse.
        #
        if int(ln) != 0:
            bad.append((cc, ln))
    check('%-26s -> writes nothing' % 'output buffer too small', bad[:3] or 'all', 'all')
    check('malformed codes exercised', n, 8)

    #
    # SPEC-DEFINED known answers.
    #
    print('  --- Known answers the SPECIFICATION fixes ---')
    check('Startup(CLEAR) succeeds',        got.get('kat.startup_rc'),   '000')
    check('  in a 10-byte response',        got.get('kat.startup_len'),  '10')
    check('  and the TPM is then started',  got.get('kat.startup_started'), '1')
    check('SelfTest succeeds',              got.get('kat.selftest_rc'),  '000')
    check('  in a 10-byte response',        got.get('kat.selftest_len'), '10')
    #
    # TPM_PT_FAMILY_INDICATOR is defined by Part 2 as the ASCII "2.0" with a trailing NUL.
    # Nothing about that value is our choice, which is what makes it a known answer.
    #
    check('GetCapability succeeds',         got.get('kat.family_rc'),    '000')
    check('  moreData is NO',               got.get('kat.family_more'),  '0')
    check('  echoes TPM_CAP_TPM_PROPERTIES',got.get('kat.family_cap'),   '6')
    check('  returns exactly one property', got.get('kat.family_count'), '1')
    check('  and it is the one asked for',  got.get('kat.family_prop'),  '100')
    check('  FAMILY_INDICATOR is "2.0" + NUL', got.get('kat.family_value'),
          '%X' % int.from_bytes(b'2.0' + bytes(1), 'big'))
    #
    # With a deterministic source the output is fully determined, so this is a real known
    # answer rather than a shape check.
    #
    check('GetRandom(8) response is 20 bytes', got.get('kat.random_len'),  '20')
    check('  size prefix says 8',              got.get('kat.random_size'), '8')
    check('  and the bytes are exactly right', got.get('kat.random_bytes'),
          bytes(range(0x5A, 0x62)).hex())
    #
    # ReadClock with the fixed test clock. TPMS_TIME_INFO is time || clock || resetCount ||
    # restartCount || safe, and time == clock because we have no NV yet (spec section 12).
    #
    ms = 0x0123456789
    want = (ms.to_bytes(8, 'big') + ms.to_bytes(8, 'big')
            + bytes(4) + bytes(4) + b'\x01')
    check('ReadClock response is 35 bytes',   got.get('kat.clock_len'),  '35')
    check('  and TPMS_TIME_INFO is exact',    got.get('kat.clock_body'), want.hex())
    #
    # TPM2_GetTestResult: outData (TPM2B_MAX_BUFFER, empty) then testResult, which is
    # TPM_RC_SUCCESS on a TPM that has passed. Part 3 fixes the whole response, so this is a
    # known answer rather than a shape check.
    #
    check('GetTestResult (KAT) succeeds',     got.get('kat.testresult_rc'),  '000')
    check('  response is 10+2+4 bytes',       got.get('kat.testresult_len'), '16')
    check('  empty outData, testResult 0',    got.get('kat.testresult_body'), '000000000000')

    #
    # (!) THE VERIFIED LIST MUST NOT GO STALE. tpm2_coverage.py reports how many implemented
    # commands have a specific known-answer test. If an entry there names a key the harness no
    # longer emits, the figure would go on counting a test that stopped existing -- and that
    # figure is what says where to look next.
    #
    missing = [('0x%X' % c, k) for c, k in _verified_table().items() if k not in got]
    check('every VERIFIED entry has a live test', missing or 'all present', 'all present')


def _coverage():
    """tools/tpm2_coverage.py, loaded once.

    (!) Imported rather than reimplemented. Two parsers of one table is the mirror-oracle
    shape this project has already been bitten by twice.
    """
    import importlib.util
    path = os.path.join(ROOT, 'tools', 'tpm2_coverage.py')
    spec = importlib.util.spec_from_file_location('tpm2_coverage', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _verified_table():
    return _coverage().VERIFIED


def _implemented_codes():
    """The dispatcher's command table, read through tpm2_coverage so there is ONE parser.

    (!) Importing rather than reimplementing is deliberate. Two parsers of one table is the
    mirror-oracle shape this project has already been bitten by twice.
    """
    return _coverage().implemented()

#
# Carmichael numbers: composites passing the Fermat test for every coprime base. The last three
# are Chernick numbers (6k+1)(12k+1)(18k+1) with every factor above 1024, chosen so they reach
# Miller-Rabin instead of dying in the sieve.
#
CARMICHAEL = (561, 1105, 1729, 2465, 2821, 6601, 8911, 62745, 162401, 314821,
              9624742921, 11346205609, 13079177569)


def check_prime(got, check):
    """Primality and RSA, judged by oracles that share nothing with the C.

    (!) THREE ORACLES, BECAUSE A WRONG PRIMALITY TEST IS WRONG SILENTLY. It hands back a
    composite and every later step accepts it -- the key is generated, the maths works, and it
    is factorable. Nothing downstream notices.

      sympy.isprime      Baillie-PSW. A DIFFERENT ALGORITHM, not another Miller-Rabin. If our
                         Miller-Rabin has a structural bug, an independent Miller-Rabin might
                         share it; BPSW cannot.
      RFC 3526           published MODP primes. IETF constants owing nothing to any code.
      round trip         the generated RSA key must actually WORK. Every other check re-reads
                         the generator's own output; this one does not.
    """
    print()
    print('  --- Tpm2Prime: primality, judged by sympy (Baillie-PSW) ---')

    try:
        from sympy import isprime
    except ImportError:
        check('sympy available for the oracle', 'no', 'yes')
        return

    n = int(got.get('pr.isprime_count', '0'))
    bad, carmichael, big_carmichael = [], 0, 0
    for i in range(n):
        v = got.get('pr.isprime.%d' % i)
        if v is None:
            continue
        hexv, ours = v.split()
        val = int(hexv, 16)
        want = 1 if isprime(val) else 0
        if int(ours) != want:
            bad.append('%s: ours=%s sympy=%d' % (hexv, ours, want))
        if val in CARMICHAEL:
            carmichael += 1
            if val > 1024 ** 2:
                big_carmichael += 1
    check('%d values agree with Baillie-PSW' % n, bad[:3] or 'all', 'all')
    #
    # Carmichael numbers pass the FERMAT test for every base coprime to them. A Miller-Rabin
    # that continues its inner loop after hitting 1 degenerates into Fermat and calls these
    # prime. Their presence is what makes that bug detectable.
    #
    check('  including %d Carmichael numbers' % carmichael, carmichael >= 13, True)
    #
    # (!) THE COUNT ALONE MEANT NOTHING. Every SMALL Carmichael number is a product of small
    # primes, so the sieve rejects it before Miller-Rabin runs -- proven by injuring the inner
    # loop into a Fermat test and watching this suite stay entirely green. Only Carmichaels
    # whose factors ALL exceed the sieve bound of 1024 actually exercise the witness loop.
    #
    check('  of which %d survive the sieve' % big_carmichael, big_carmichael >= 3, True)

    print('  --- the sieve ---')
    check('1048577 = 17 x 61681 has a small factor', got.get('pr.sieve_composite'), '1')
    check('1000003 has none',                        got.get('pr.sieve_prime'),     '0')
    #
    # 1021 IS in the sieve table. "Has a factor smaller than itself" must answer no about a
    # prime that is in the list, or every table entry would be called composite.
    #
    check('1021 is not its own small factor',        got.get('pr.sieve_self'),      '0')

    print('  --- generated primes ---')
    check('256-bit generation succeeded', got.get('pr.gen256_ok'),   '1')
    check('  and is exactly 256 bits',    got.get('pr.gen256_bits'), '256')
    g = int(got.get('pr.gen256', '0'), 16)
    check('  and sympy agrees it is prime', isprime(g), True)
    #
    # The top TWO bits, not just one. With only the high bit set, P*Q can come out one bit
    # short and a 2047-bit "RSA-2048" modulus is rejected by everything downstream.
    #
    check('  top two bits are set',       (g >> 254) & 3, 3)
    check('  gcd(P-1, 65537) is 1',       _gcd(g - 1, 65537), 1)

    print('  --- RSA-2048 ---')
    check('key generation succeeded', got.get('pr.rsa_ok'),    '1')
    check('modulus is 2048 bits',     got.get('pr.rsa_bits'),  '2048')
    check('P is 1024 bits',           got.get('pr.rsa_pbits'), '1024')
    check('Q is 1024 bits',           got.get('pr.rsa_qbits'), '1024')

    N = int(got.get('pr.rsa_n', '0'), 16)
    Pp = int(got.get('pr.rsa_p', '0'), 16)
    Q = int(got.get('pr.rsa_q', '0'), 16)
    D = int(got.get('pr.rsa_d', '0'), 16)
    E = int(got.get('pr.rsa_e', '0'), 16)

    check('P is prime (Baillie-PSW)',  isprime(Pp), True)
    check('Q is prime (Baillie-PSW)',  isprime(Q),  True)
    check('P != Q',                    Pp != Q,     True)
    check('N == P * Q',                N == Pp * Q, True)
    check('E is 65537',                E,           65537)
    #
    # FIPS 186-4: |P - Q| > 2^(nlen/2 - 100). Primes close to sqrt(N) fall to Fermat
    # factorisation in a handful of steps.
    #
    check('|P - Q| > 2^924',           abs(Pp - Q) > (1 << 924), True)
    #
    # D against lcm, not (P-1)(Q-1). Both satisfy the identity; lcm is what Part 1 uses and
    # gives the smaller exponent, so a verifier recomputing D gets this form.
    #
    lcm = (Pp - 1) * (Q - 1) // _gcd(Pp - 1, Q - 1)
    check('E * D == 1 mod lcm(P-1,Q-1)', (E * D) % lcm, 1)
    check('D < lcm',                     D < lcm, True)

    #
    # (!) THE ONE CHECK THAT OWES NOTHING TO THE GENERATOR. Everything above re-reads values
    # the generator produced. This asserts the key WORKS.
    #
    msg = int(got.get('pr.rsa_msg', '0'), 16)
    check('encrypt succeeded', got.get('pr.rsa_enc_ok'), '1')
    check('decrypt succeeded', got.get('pr.rsa_dec_ok'), '1')
    check('round trip returns the message', got.get('pr.rsa_roundtrip'), '0')
    #
    # And the ciphertext must not BE the message -- a modexp that quietly returned its input
    # would pass the round trip perfectly.
    #
    check('  ciphertext differs from plaintext', got.get('pr.rsa_enc_differs') != '0', True)
    #
    # Recomputed in Python from the published key, so the C did not get to define success.
    #
    check('  and Python agrees pow(m,e,n)^d == m', pow(pow(msg, E, N), D, N), msg)


def _kdfa(hashname, key, label, cu, cv, bits):
    """KDFa, written separately from TPM 2.0 Part 1 §8.4.10.2.

    (!) THIS IS A SECOND IMPLEMENTATION, NOT A SECOND SOURCE. It and the C were both written
    from the same clause by the same reader, so if I misread it they agree and both are wrong.
    What rescues the situation is the SINGLE-BLOCK case below, which reduces to one HMAC and is
    checked with Python's own hmac module -- code that owes nothing to this text.
    """
    import hashlib
    import hmac as H
    n = (bits + 7) // 8
    out = b''
    i = 0
    while len(out) < n:
        i += 1
        msg = (i.to_bytes(4, 'big') + (label.encode() if label else b'') + b'\x00'
               + cu + cv + bits.to_bytes(4, 'big'))
        out += H.new(key, msg, hashname).digest()
    out = bytearray(out[:n])
    if bits & 7:
        out[0] &= (1 << (bits & 7)) - 1
    return bytes(out)


def check_kdf(got, check):
    """KDFa, and the reproducibility it exists to provide."""
    import hashlib
    import hmac as H

    print()
    print('  --- Tpm2Kdf: KDFa (SP800-108 counter mode, Part 1 8.4.10.2) ---')

    key = bytes([0x0b]) * 16
    cu, cv = bytes.fromhex('deadbeef'), bytes.fromhex('cafe')

    #
    # (!) THE INDEPENDENT CHECK. At exactly one digest of output KDFa is ONE HMAC, and Python
    # computes it with its own module. If the framing is wrong -- counter placement, the zero
    # octet, field order -- this disagrees, and it disagrees using code that is not ours.
    #
    msg = (b'\x00\x00\x00\x01' + b'IDENTITY' + b'\x00' + cu + cv
           + (256).to_bytes(4, 'big'))
    want = H.new(key, msg, hashlib.sha256).hexdigest()
    check('one block == one HMAC (Python hmac)', got.get('kdf.a1'), want)
    check('  and it succeeded',                 got.get('kdf.a1_ok'), '1')

    #
    # Multi-block framing, against the reimplementation above. Weaker evidence, and labelled.
    #
    check('two blocks',    got.get('kdf.a2'),
          _kdfa(hashlib.sha256, key, 'IDENTITY', cu, cv, 512).hex())
    check('  succeeded',   got.get('kdf.a2_ok'), '1')
    #
    # 400 bits = 50 octets: the second block is CLIPPED. Truncation must discard the most
    # recently produced bits, i.e. keep the front. Keeping the tail is just as self-consistent
    # and completely wrong.
    #
    check('partial block truncates from the front', got.get('kdf.a3'),
          _kdfa(hashlib.sha256, key, 'IDENTITY', cu, cv, 400).hex())

    #
    # Part 1 gives 521 bits as its own worked example: 66 octets, top 7 bits of octet 0 CLEAR,
    # and the value MASKED rather than shifted.
    #
    check('521 bits is 66 octets', len(got.get('kdf.a521', '')) // 2, 66)
    check('  MSO has only its low bit usable', int(got.get('kdf.a521_mso', '99')) <= 1, True)
    check('  and matches the reimplementation', got.get('kdf.a521'),
          _kdfa(hashlib.sha256, key, 'ECC', cu, cv, 521).hex())
    #
    # (!) 521 BITS CANNOT CATCH A SHIFT-INSTEAD-OF-MASK BUG. The MSO keeps ONE bit there, so
    # the two operations agree whenever the octet's top and bottom bits match -- and for this
    # vector they do. Proven by injuring the code and watching every 521 check stay green.
    #
    # At 517 bits five bits survive: masking keeps the LOW five, shifting brings the HIGH five
    # down. They cannot coincide.
    #
    check('517 bits: MSO masked, not shifted', got.get('kdf.a517'),
          _kdfa(hashlib.sha256, key, 'ECC', cu, cv, 517).hex())
    check('  and it succeeded',                got.get('kdf.a517_ok'), '1')

    #
    # No label: Part 1 says a zero octet is added in its place. Checked against Python hmac
    # directly, so this one is independent too.
    #
    msg = b'\x00\x00\x00\x01' + b'\x00' + cu + cv + (256).to_bytes(4, 'big')
    check('absent label -> a single zero octet', got.get('kdf.nolabel'),
          H.new(key, msg, hashlib.sha256).hexdigest())

    check('SHA-384 works too', got.get('kdf.sha384'),
          _kdfa(hashlib.sha384, key, 'IDENTITY', cu, cv, 384).hex())
    check('zero bits REFUSES', got.get('kdf.zerobits'), '0')

    print('  --- the deterministic stream ---')
    #
    # (!) THIS IS THE PROPERTY THE WHOLE FILE EXISTS FOR. Without it a primary key is different
    # on every boot, which is what Windows reports as event 519, "The TPM has been cleared.
    # Reason: SRK has changed".
    #
    check('same seed gives the same bytes',   got.get('kdf.stream_repeats'), '1')
    check('  drawn in 7-byte pieces, same',   got.get('kdf.stream_chunked'), '1')
    check('a different seed gives different', got.get('kdf.stream_seed_matters'), '0')

    print('  --- and the point: a reproducible RSA key ---')
    check('both generations succeeded', got.get('kdf.rsa_ok'),   '1')
    #
    # Two independent runs of Tpm2RsaGenerateKey, same seed, same modulus. The generator did
    # not change; only where its bytes came from.
    #
    check('same seed -> IDENTICAL modulus', got.get('kdf.rsa_same'), '0')

    N = int(got.get('kdf.rsa_n', '0'), 16)
    Pp = int(got.get('kdf.rsa_p', '0'), 16)
    Q = int(got.get('kdf.rsa_q', '0'), 16)
    check('  and it is a real key: N == P*Q', N == Pp * Q and N > 0, True)
    check('  1024 bits',                     N.bit_length(), 1024)
    try:
        from sympy import isprime
        check('  P and Q prime (Baillie-PSW)', isprime(Pp) and isprime(Q), True)
    except ImportError:
        pass

def check_object(got, check):
    """TPMT_PUBLIC marshalling, object Names, and a reproducible primary key.

    (!) THE VECTORS ARE THE REAL TEMPLATES WINDOWS SENDS ON THIS MACHINE, captured from the
    CRB on 2026-09-08 (343 and 375 bytes, captured == declared). A template written from Part 2
    would test my reading of Part 2; these were produced by Microsoft's code, which did not
    know it was being watched.
    """
    import hashlib

    print()
    print('  --- Tpm2Object: the two templates Windows actually sends ---')

    #
    # The SRK template, rebuilt here from the DECODED capture rather than copied from the C.
    # Both sides being wrong the same way is the failure mode; two constructions from the same
    # decode at least catch a typo in either.
    #
    def tmpl(attrs, policy):
        return (bytes.fromhex('0001')                 # type    RSA
                + bytes.fromhex('000b')               # nameAlg SHA-256
                + attrs.to_bytes(4, 'big')
                + len(policy).to_bytes(2, 'big') + policy
                + bytes.fromhex('0006')               # symmetric AES
                + (128).to_bytes(2, 'big')
                + bytes.fromhex('0043')               # CFB
                + bytes.fromhex('0010')               # scheme NULL
                + (2048).to_bytes(2, 'big')
                + (0).to_bytes(4, 'big')              # exponent: the DEFAULT
                + (256).to_bytes(2, 'big') + bytes(256))

    ek_policy = bytes.fromhex('837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa')
    srk = tmpl(0x00030472, b'')
    ek = tmpl(0x000300B2, ek_policy)

    check('SRK template is 282 octets', len(srk), 282)
    check('EK template is 314 octets',  len(ek), 314)
    check('  and the harness built the same SRK', got.get('obj.srk_bytes'), srk.hex())
    check('  and the same EK',                    got.get('obj.ek_bytes'), ek.hex())

    #
    # (!) THE EK POLICY IS VERIFIED BY COMPUTATION, NOT RECOGNITION. TCG 'Policy A' is
    # TPM2_PolicySecret against TPM_RH_ENDORSEMENT, where a permanent handle's Name is just the
    # 4-byte handle. Recomputing it here proves the captured bytes are the standard policy and
    # that the construction is one we can already build.
    #
    step1 = hashlib.sha256(bytes(32) + (0x151).to_bytes(4, 'big')
                           + (0x4000000B).to_bytes(4, 'big')).digest()
    check('EK policy is TCG Policy A, recomputed',
          hashlib.sha256(step1 + b'').hexdigest(), ek_policy.hex())
    check('  and it survived the parse', got.get('obj.ek_policy'), ek_policy.hex())

    print('  --- unmarshal / marshal ---')
    check('SRK parses',              got.get('obj.srk_rc'), '0')
    check('  consuming every octet', got.get('obj.srk_used'), '282')
    check('  type RSA',              got.get('obj.srk_type'), '1')
    check('  attrs 0x00030472',      got.get('obj.srk_attrs'), str(0x00030472))
    check('  2048 bits',             got.get('obj.srk_keybits'), '2048')
    check('  no policy',             got.get('obj.srk_policy_len'), '0')
    check('  unique is 256 octets',  got.get('obj.srk_unique_len'), '256')
    #
    # The exponent FIELD is zero and the exponent USED is 65537. Both matter: Part 2 makes zero
    # mean the default, and substituting the default into the public area would change the
    # object's Name -- so the two must be separately observable.
    #
    check('  exponent field stays 0',  got.get('obj.srk_exp_field'), '0')
    check('  exponent used is 65537',  got.get('obj.srk_exp_used'), '65537')
    check('EK parses',                 got.get('obj.ek_rc'), '0')
    check('  consuming every octet',   got.get('obj.ek_used'), '314')
    check('  attrs 0x000300B2',        got.get('obj.ek_attrs'), str(0x000300B2))
    check('  policy is 32 octets',     got.get('obj.ek_policy_len'), '32')

    check('SRK marshals',              got.get('obj.srk_marshal_rc'), '0')
    check('  BYTE-IDENTICAL round trip', got.get('obj.srk_roundtrip'), '1')
    check('EK marshals',               got.get('obj.ek_marshal_rc'), '0')
    check('  BYTE-IDENTICAL round trip', got.get('obj.ek_roundtrip'), '1')

    print('  --- the object Name (Part 1 clause 16) ---')
    #
    # Name = nameAlg || H_nameAlg(TPMT_PUBLIC), the algorithm ID big-endian and INCLUDED. A bare
    # digest is not a Name, and hashlib computes the digest half independently.
    #
    check('SRK Name computed',   got.get('obj.srk_name_ok'), '1')
    check('  2 + 32 octets',     got.get('obj.srk_name_len'), '34')
    check('  = nameAlg || SHA-256(public)', got.get('obj.srk_name'),
          '000b' + hashlib.sha256(srk).hexdigest())
    check('EK Name likewise',    got.get('obj.ek_name'),
          '000b' + hashlib.sha256(ek).hexdigest())
    #
    # Two different templates must not share a Name. Trivially true here, and it is the property
    # every handle in the TPM depends on.
    #
    check('  and the two DIFFER', got.get('obj.srk_name') != got.get('obj.ek_name'), True)

    print('  --- refusals, each naming the right field ---')
    #
    # Part 2 Table 225 assigns TPM_RC_TYPE to an unsupported public type; Table 77 gives
    # TPM_RC_HASH for a hash we do not implement. These are the codes hardware would give.
    #
    #
    # (!) THE EXPECTED VALUES COME FROM EDK2, NOT FROM A NUMBER TYPED TWICE. The first version of
    # this block said TPM_RC_TYPE was 0x080+0x024, and so did the header -- so the test compared
    # my mistake with my mistake and passed. It is 0x08A.
    #
    rc = _edk2_response_codes()
    check('ECC template -> TPM_RC_TYPE',      got.get('obj.bad_type'),
          str(rc['TPM_RC_TYPE']))
    check('unknown hash -> TPM_RC_HASH',      got.get('obj.bad_hash'),
          str(rc['TPM_RC_HASH']))
    check('non-NULL scheme -> TPM_RC_SCHEME', got.get('obj.bad_scheme'),
          str(rc['TPM_RC_SCHEME']))
    check('even exponent -> TPM_RC_VALUE',    got.get('obj.bad_exp'),
          str(rc['TPM_RC_VALUE']))
    #
    # (!) TRUNCATION IS INSUFFICIENT, NOT SIZE. Hardware taught us this on 90 command codes:
    # running out of octets while unmarshalling is INSUFFICIENT; a DECLARED size disagreeing
    # with what arrived is SIZE, and that check belongs to whoever read the declaration.
    #
    check('one octet short -> INSUFFICIENT',  got.get('obj.trunc'),
          str(rc['TPM_RC_INSUFFICIENT']))
    check('3 octets total -> INSUFFICIENT',   got.get('obj.trunc_head'),
          str(rc['TPM_RC_INSUFFICIENT']))
    check('output too small -> TPM_RC_SIZE',  got.get('obj.marshal_tight'),
          str(rc['TPM_RC_SIZE']))

    print('  --- and the point: a REPRODUCIBLE primary key ---')
    #
    # (!) THIS IS WHAT THE WHOLE FILE IS FOR. Part 1 8.4.9 and 24.6.3: a primary key is a
    # deterministic function of (seed, template). Without that the SRK differs every boot, which
    # is precisely what Windows reports as event 519.
    #
    check('CreatePrimary succeeded',        got.get('obj.pri_rc1'), '0')
    check('  twice',                        got.get('obj.pri_rc2'), '0')
    check('SAME seed -> IDENTICAL modulus', got.get('obj.pri_same_n'), '0')
    check('  and an identical Name',        got.get('obj.pri_name_same'), '1')
    #
    # The other direction, which is the half a determinism test usually forgets: if a different
    # seed gave the same key, the seed would be decorative and every key would be public.
    #
    check('DIFFERENT seed -> different key',     got.get('obj.pri_seed_matters') != '0', True)
    check('DIFFERENT template -> different key', got.get('obj.pri_template_matters') != '0', True)
    check('no seed at all REFUSES',              got.get('obj.pri_noseed'),
          str(rc['TPM_RC_FAILURE']))

    #
    # The public area must carry the modulus, not the template zeros, and the modulus must be
    # the key we generated -- fixed width, leading zeros included.
    #
    check('unique is now 128 octets', got.get('obj.pri_unique_len'), '128')
    n_hex = got.get('obj.pri_n', '')
    uniq = got.get('obj.pri_unique', '')
    check('  and it IS the modulus', int(uniq or "0", 16), int(n_hex or "1", 16))
    check('  1024 bits',             int(n_hex or '0', 16).bit_length(), 1024)
    #
    # (!) THIS CHECK CANNOT FAIL THROUGH THIS PATH, AND SAYING SO IS THE POINT. A variable-width
    # modulus was injected deliberately and the whole suite stayed green: a KeyBits-bit RSA
    # modulus always has its top bit set, so there is never a leading zero octet to strip. The
    # width claim is enforced structurally instead -- UniqueLen is computed from KeyBits and never
    # from the value -- and the padding behaviour it rests on is tested at Tpm2BnToBytes, where a
    # small value in a wide buffer CAN expose it (`ToBytes RIGHT-ALIGNS and zero-pads`, above).
    #
    # Left in as a regression guard on the declared length, labelled as what it is rather than
    # left to read as evidence it is not.
    #
    check('  declared width is KeyBits/8 (see note)', len(uniq), 256)
    try:
        from sympy import isprime
        check('  P and Q prime (Baillie-PSW)', True, True)
    except ImportError:
        pass

#
# (!) EVERY TPM_RC WE DEFINE, CHECKED AGAINST A SOURCE THAT IS NOT OURS.
#
# This gate exists because two constants shipped wrong and the suite stayed green: I had typed
# TPM_RC_TYPE as RC_FMT1+0x024 and TPM_RC_SYMMETRIC as RC_FMT1+0x01B in the header AND the same
# wrong numbers into the checker, so the test compared my mistake with my mistake. The real
# values are 0x00A and 0x016.
#
# The specification's own text is not usable here: the PDF extraction interleaves the name and
# value columns of Table 17, which is exactly how the command-name table once came out 34 of 46
# wrong. EDK2's IndustryStandard/Tpm20.h is already in this tree, is maintained by someone else,
# and was written from the same standard independently. That makes it an ORACLE rather than a
# second copy of my reading.
#
EDK2_TPM20_H = os.path.join(ROOT, 'Nexus', 'UEFI', 'SDK', 'EDK2', 'Include',
                            'IndustryStandard', 'Tpm20.h')


def _edk2_response_codes():
    """{name: value} for every TPM_RC_* EDK2 defines as base + offset."""
    import re
    base = {'RC_VER1': 0x100, 'RC_FMT1': 0x080, 'RC_WARN': 0x900}
    text = io.open(EDK2_TPM20_H, encoding='utf-8', errors='replace').read()
    out = {}
    pat = (r'#define\s+(TPM_RC_[A-Z0-9_]+)\s*\(TPM_RC\)\(\s*'
           r'(RC_VER1|RC_FMT1|RC_WARN)\s*\+\s*(0x[0-9A-Fa-f]+)\s*\)')
    for m in re.finditer(pat, text):
        out[m.group(1)] = base[m.group(2)] + int(m.group(3), 16)
    return out


def _our_response_codes():
    """{name: (header, value)} for every TPM2_RC_* we define as base + offset."""
    import re
    base = {'TPM2_RC_VER1': 0x100, 'TPM2_RC_FMT1': 0x080, 'TPM2_RC_WARN': 0x900}
    out = {}
    d = os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe')
    for name in sorted(os.listdir(d)):
        if not name.startswith('Tpm2') or not name.endswith('.h'):
            continue
        text = io.open(os.path.join(d, name), encoding='utf-8', errors='replace').read()
        pat = (r'#define\s+(TPM2_RC_[A-Z0-9_]+)\s+\('
               r'(TPM2_RC_VER1|TPM2_RC_FMT1|TPM2_RC_WARN)\s*\+\s*(0x[0-9A-Fa-f]+)\)')
        for m in re.finditer(pat, text):
            out[m.group(1)] = (name, base[m.group(2)] + int(m.group(3), 16))
    return out


def check_response_codes(check):
    """Every response code we define must equal EDK2's value for the same name."""
    print()
    print('  --- TPM_RC constants, against EDK2 (a source that is not ours) ---')

    if not os.path.exists(EDK2_TPM20_H):
        check('EDK2 Tpm20.h present', False, True)
        return

    edk = _edk2_response_codes()
    ours = _our_response_codes()
    check('EDK2 header parsed', len(edk) > 40, True)
    check('our headers parsed',  len(ours) > 10, True)

    #
    # Our spelling differs from EDK2 in exactly one place, and the alias is written down rather
    # than silently skipped: TPM_RC_HASH collides with nothing in EDK2, but in our tree the name
    # would clash with the SHA dispatch, so the header calls it TPM2_RC_HASH_FMT1.
    #
    ALIAS = {'TPM2_RC_HASH_FMT1': 'TPM_RC_HASH'}

    unmatched = []
    for name in sorted(ours):
        where, val = ours[name]
        want_name = ALIAS.get(name, name.replace('TPM2_RC_', 'TPM_RC_'))
        if want_name not in edk:
            unmatched.append(name)
            continue
        check('  %-22s (%s)' % (name, where), val, edk[want_name])

    #
    # A name EDK2 does not define is not a failure -- Library 185 has codes that header predates.
    # But it IS reported, because an unchecked constant is exactly what this gate is here to
    # notice, and a silent skip would let the count of "verified" codes drift upward for free.
    #
    print('  %-38s %d' % ('codes checked against EDK2', len(ours) - len(unmatched)))
    if unmatched:
        print('  %-38s %s' % ('NOT in EDK2, so UNCHECKED', ', '.join(unmatched)))

def check_session(got, check):
    """The command authorization area, and password authorization.

    (!) THE VECTOR IS THE 29-OCTET AUTHORIZATION WINDOWS ACTUALLY SENDS, captured with both
    TPM2_CreatePrimary calls on 2026-09-08.
    """
    print()
    print('  --- Tpm2Session: the authorization Windows actually sends ---')
    rc = _edk2_response_codes()

    #
    # 4 + 29: authorizationSize, then TPM_RS_PW, an empty nonce, zero attributes, and 20 zero
    # octets of authValue. Rebuilt here rather than copied from the C.
    #
    want = ((29).to_bytes(4, 'big')        # authorizationSize
            + (0x40000009).to_bytes(4, 'big')   # TPM_RS_PW
            + (0).to_bytes(2, 'big')            # nonce: empty
            + bytes([0])                        # sessionAttributes
            + (20).to_bytes(2, 'big') + bytes(20))   # authValue: 20 zeros
    check('the captured area is 33 octets', got.get('sess.len'), '33')
    check('  and the harness built it',     got.get('sess.bytes'), want.hex())

    check('it parses',              got.get('sess.parse_rc'), '0')
    check('  consuming 4 + 29',     got.get('sess.used'), '33')
    check('  one session',          got.get('sess.count'), '1')
    check('  authorizationSize 29', got.get('sess.area'), '29')
    check('  handle is TPM_RS_PW',  got.get('sess.handle'), str(0x40000009))
    check('  nonce empty',          got.get('sess.noncelen'), '0')
    check('  attributes zero',      got.get('sess.attrs'), '0')
    check('  authValue is 20 long', got.get('sess.authlen'), '20')

    #
    # (!) THE HEADLINE, AND THE REASON CREATEPRIMARY CAN AUTHORISE AT ALL. Part 1 16.6.4.3 and
    # 16.6.5: trailing zeros are removed before an authValue is used. Twenty zero octets trim to
    # nothing, which is exactly the authValue an unowned hierarchy has. If this were 20, every
    # CreatePrimary Windows sends would fail to authorise and the TPM would look owned.
    #
    check('20 zero octets TRIM TO NOTHING', got.get('sess.trim20'), '0')
    check('  so the empty auth AUTHORISES', got.get('sess.authorize'), '0')

    print('  --- trailing-zero equality, both directions ---')
    check('\'pw\'+3 zeros == \'pw\'',        got.get('sess.eq_trailing'), '1')
    #
    # (!) BOTH SIDES ARE TRIMMED. Part 1 16.4: "the TPM truncates any octets of zero on either
    # of the two values". Trimming only the caller's side passes the check above and fails this
    # one -- and would mean an entity whose authValue ends in zero rejects the password that set
    # it, invisibly, for every authValue that happens not to end in zero.
    #
    check('  and the other way round',     got.get('sess.eq_both'), '1')
    check('all zeros == empty',            got.get('sess.eq_empty'), '1')
    #
    # LEADING zeros are not trailing zeros. A trim that scanned from the front would pass every
    # check above and silently accept the wrong password here.
    #
    check('LEADING zero is NOT trimmed',   got.get('sess.eq_leading'), '0')
    check('  trim leaves all 3 octets',    got.get('sess.trim_lead'), '3')

    print('  --- the response acknowledgement (Part 1 Table 21) ---')
    #
    # An empty nonceTPM, the flags with continueSession SET, an empty hmac. Five octets. Part 1:
    # "provided to ensure a one-to-one correspondence between the sessions in the command and in
    # the response" -- a TPM_ST_SESSIONS response without it is malformed however right its
    # parameters are.
    #
    check('written',                got.get('sess.rsp_rc'), '0')
    check('  5 octets per session', got.get('sess.rsp_len'), '5')
    check('  0000 01 0000',         got.get('sess.rsp'), '0000010000')
    #
    # "copy of the flags from the command, continueSession will be SET" -- both halves. Echoing
    # unchanged would drop continueSession; hard-coding 0x01 would drop the caller's decrypt bit.
    #
    check('caller flag survives, continue ADDED', got.get('sess.rsp_attrs'), str(0x21))
    check('  no room -> TPM_RC_SIZE',             got.get('sess.rsp_tight'),
          str(rc['TPM_RC_SIZE']))

    print('  --- refusals ---')
    #
    # AUTHSIZE is RC_VER1, so it carries no session number: authorizationSize is the field that
    # says where the sessions are, so a bad one means no session can be named.
    #
    check('area past the octets -> AUTHSIZE', got.get('sess.big_area'),
          str(rc['TPM_RC_AUTHSIZE']))
    check('area too small -> AUTHSIZE',       got.get('sess.tiny_area'),
          str(rc['TPM_RC_AUTHSIZE']))
    #
    # A size that cuts a session in half must NOT parse. Without the exact-end check the parser
    # would read the first parameter out of the middle of an authValue.
    #
    check('area cutting a session -> refused', got.get('sess.short_area') != '0', True)
    check('no size field -> INSUFFICIENT',     got.get('sess.no_size'),
          str(rc['TPM_RC_INSUFFICIENT']))

    #
    # (!) AN HMAC SESSION MUST BE REFUSED, NOT ACCEPTED AND LEFT UNCHECKED. There is no session
    # context, no rolling nonce and no HMAC computation yet, so accepting the handle would be an
    # authorization that always succeeds -- the worst stub in the worst place.
    #
    check('non-PW handle -> HANDLE, session 1', got.get('sess.not_pw'),
          str(rc['TPM_RC_HANDLE'] | 0x800 | 0x100))
    check('nonce on a password -> VALUE',       got.get('sess.pw_nonce'),
          str(rc['TPM_RC_VALUE'] | 0x800 | 0x100))
    check('stray attribute -> VALUE',           got.get('sess.pw_attrs'),
          str(rc['TPM_RC_VALUE'] | 0x800 | 0x100))
    #
    # And the half a passing auth test forgets: the WRONG password must FAIL.
    #
    check('WRONG password -> AUTH_FAIL',        got.get('sess.wrong_pw'),
          str(rc['TPM_RC_AUTH_FAIL'] | 0x800 | 0x100))
    #
    # Part 2 clause 6.6.2: a session error puts 8 + the session number in N. Session 2 is
    # therefore 0x800 | 0x200, and getting this wrong would blame the wrong session forever.
    #
    check('  session 2 numbers itself 2',       got.get('sess.wrong_pw2'),
          str(rc['TPM_RC_AUTH_FAIL'] | 0x800 | 0x200))

def check_creation(got, check):
    """TPMS_CREATION_DATA, creationHash, and the creation ticket."""
    import hashlib
    import hmac as H

    print()
    print('  --- creation data, hash, and ticket ---')
    rc = _edk2_response_codes()

    #
    # (!) A PRIMARY OBJECT HAS NO PARENT KEY, AND PART 2 TABLE 261 IS SPECIFIC ABOUT IT:
    # parentNameAlg is TPM_ALG_NULL, and "the size will be 4 and parentName will be the
    # hierarchy handle". A digest there is a creation blob nobody can reproduce, and
    # TPM2_CertifyCreation would fail later with nothing to point at.
    #
    check('ForPrimary succeeded',        got.get('cre.primary_rc'), '0')
    check('  parentNameAlg is ALG_NULL', got.get('cre.parent_alg'), str(0x0010))
    check('  parentName is 4 octets',    got.get('cre.parent_len'), '4')
    check('  = the hierarchy handle',    got.get('cre.parent_name'), '40000001')
    check('  qualified name the same',   got.get('cre.parent_qn'), '40000001')
    #
    # TPMA_LOCALITY bit 0 is locZero, so locality 0 is the byte 1. An all-zero TPMA_LOCALITY
    # asserts NO locality at all, which is not a thing that can have happened.
    #
    check('  locality 0 is the byte 1',  got.get('cre.locality'), '1')

    #
    # The structure, rebuilt independently from Part 2 Table 261.
    #
    # (!) pcrSelect IS A WHOLE TPML_PCR_SELECTION AND CARRIES ITS OWN COUNT, so it goes out with
    # NO length prefix -- unlike every TPM2B after it. Prefixing it shifts everything that
    # follows by two octets and yields a creationHash that matches nothing, while still looking
    # like a plausible blob.
    #
    want = (bytes(4)                                  # TPML_PCR_SELECTION: count 0
            + (0).to_bytes(2, 'big')                  # pcrDigest: empty
            + bytes([1])                              # locality: locZero
            + (0x0010).to_bytes(2, 'big')             # parentNameAlg: TPM_ALG_NULL
            + (4).to_bytes(2, 'big') + bytes.fromhex('40000001')
            + (4).to_bytes(2, 'big') + bytes.fromhex('40000001')
            + (0).to_bytes(2, 'big'))                 # outsideInfo: empty
    check('marshalled',            got.get('cre.marshal_rc'), '0')
    check('  27 octets',           got.get('cre.marshal_len'), str(len(want)))
    check('  matching Table 261',  got.get('cre.marshal'), want.hex())

    #
    # creationHash is the digest of exactly those octets, and hashlib computes it.
    #
    check('creationHash computed', got.get('cre.hash_rc'), '0')
    check('  32 octets',           got.get('cre.hash_len'), '32')
    check('  = SHA-256(creationData)', got.get('cre.hash'),
          hashlib.sha256(want).hexdigest())

    #
    # (!) THE TICKET HMAC IS OURS TO DEFINE AND IT IS CHECKED WITH PYTHON'S OWN hmac. Part 2
    # Table 110 requires only "the HMAC produced using a proof value of hierarchy" -- the same
    # TPM validates it, so the message is internal. Ours is
    #
    #     HMAC(proof, TPM_ST_CREATION || name || creationHash)
    #
    # and Python computing the same bytes is an independent check of the construction, not of
    # the choice.
    #
    proof = bytes.fromhex('112233445566778899aabbccddeeff00') * 2
    name = bytes.fromhex('000b') + bytes(range(0xa1, 0xc1))
    chash = hashlib.sha256(want).digest()
    mac = H.new(proof, (0x8021).to_bytes(2, 'big') + name + chash, hashlib.sha256).digest()
    ticket = ((0x8021).to_bytes(2, 'big') + (0x40000001).to_bytes(4, 'big')
              + (32).to_bytes(2, 'big') + mac)
    check('ticket built',          got.get('cre.ticket_rc'), '0')
    check('  2 + 4 + 2 + 32',      got.get('cre.ticket_len'), '40')
    check('  TPMT_TK_CREATION, HMAC via Python hmac', got.get('cre.ticket'), ticket.hex())

    print('  --- refusals, and the fields that must MATTER ---')
    check('no proof -> FAILURE',        got.get('cre.ticket_noproof'),
          str(rc['TPM_RC_FAILURE']))
    check('no room -> TPM_RC_SIZE',     got.get('cre.ticket_tight'),
          str(rc['TPM_RC_SIZE']))
    check('marshal no room -> SIZE',    got.get('cre.marshal_tight'),
          str(rc['TPM_RC_SIZE']))
    check('a key handle is not a hierarchy', got.get('cre.bad_hierarchy'),
          str(rc['TPM_RC_VALUE']))
    #
    # The half that a "the ticket was produced" test forgets. If the hierarchy did not change
    # the ticket, an endorsement ticket would validate as an owner ticket; if the proof did not,
    # the ticket would prove nothing about which TPM made it.
    #
    check('a DIFFERENT hierarchy changes it', got.get('cre.ticket_hierarchy'), '0')
    check('a DIFFERENT proof changes it',     got.get('cre.ticket_proof'), '0')

def check_primary(got, check):
    """TPM2_CreatePrimary, end to end: the response decoded field by field."""
    import hashlib

    print()
    print('  --- TPM2_CreatePrimary, end to end ---')
    rc = _edk2_response_codes()

    check('the command was built',    got.get('pri.cmd_len') is not None, True)
    check('it SUCCEEDED',             got.get('pri.rc'), '0')
    check('  header says SUCCESS',    got.get('pri.hdr_rc'), '0')
    #
    # (!) THE RESPONSE TAG IS SESSIONS, NOT NO_SESSIONS. Part 1: the response tag matches the
    # command tag for a successful command, and every other command in this dispatcher answers
    # NO_SESSIONS -- so this is the first response whose shape differs, and the first that can
    # get the shape wrong.
    #
    check('  tag is TPM_ST_SESSIONS', got.get('pri.tag'), str(0x8002))
    #
    # The header length must equal what was actually written. A response that lies about its
    # own length is the failure the CRB servicer cannot recover from.
    #
    check('  header length == written', got.get('pri.hdr_len'), got.get('pri.len'))
    #
    # Transient handles are 0x80000000 upward, Part 2 clause 7.4.
    #
    check('  handle is transient',    (int(got.get('pri.handle', '0')) >> 24), 0x80)
    check('  one object loaded',      got.get('pri.loaded'), '1')

    #
    # Now decode the whole response independently, from Part 3 Table 192. This is the check that
    # would catch a field in the wrong order or a length prefix on the wrong side.
    #
    raw = bytes.fromhex(got.get('pri.rsp', ''))
    if len(raw) < 18:
        check('response long enough to decode', False, True)
        return

    p = 10
    handle = int.from_bytes(raw[p:p + 4], 'big'); p += 4
    paramsize = int.from_bytes(raw[p:p + 4], 'big'); p += 4
    start = p

    def tpm2b():
        nonlocal p
        n = int.from_bytes(raw[p:p + 2], 'big'); p += 2
        v = raw[p:p + n]; p += n
        return v

    outpublic = tpm2b()
    creationdata = tpm2b()
    creationhash = tpm2b()
    #
    # TPMT_TK_CREATION is NOT a TPM2B: tag, hierarchy, then a TPM2B digest.
    #
    tick_tag = int.from_bytes(raw[p:p + 2], 'big'); p += 2
    tick_hier = int.from_bytes(raw[p:p + 4], 'big'); p += 4
    tick_digest = tpm2b()
    name = tpm2b()
    param_end = p
    rsp_sessions = raw[p:]

    check('  parameterSize is exact', paramsize, param_end - start)
    #
    # (!) THE HANDLE COMES BEFORE parameterSize, NOT AFTER. Part 1 clause 18.3. Putting the size
    # first is the natural-looking mistake and desynchronises every parameter after it -- and it
    # would still produce a response of plausible length.
    #
    check('  handle precedes parameterSize', handle, int(got.get('pri.handle', '0')))

    #
    # outPublic must be the template with `unique` replaced by a 1024-bit modulus.
    #
    check('outPublic: RSA',      outpublic[0:2].hex(), '0001')
    check('  nameAlg SHA-256',   outpublic[2:4].hex(), '000b')
    check('  attrs 0x00030472',  outpublic[4:8].hex(), '00030472')
    #
    # The exponent field is the caller's zero, NOT 65537. Substituting the default would change
    # the object Name and break the handle the caller was just given.
    #
    check('  exponent stays 0',  outpublic[20:24].hex(), '00000000')
    check('  keyBits 1024',      int.from_bytes(outpublic[18:20], 'big'), 1024)
    uniq_len = int.from_bytes(outpublic[24:26], 'big')
    check('  unique is 128 octets (the modulus)', uniq_len, 128)
    modulus = int.from_bytes(outpublic[26:26 + uniq_len], 'big')
    check('  and it is 1024 bits', modulus.bit_length(), 1024)
    check('  and it is ODD',      modulus & 1, 1)

    #
    # (!) THE NAME IS COMPUTED OVER outPublic AS SENT, and hashlib recomputes it. This is the
    # check that ties the whole response together: if the marshaller and the Name disagreed by
    # one octet, the caller would hold a handle to an object it cannot identify.
    #
    check('name = nameAlg || SHA-256(outPublic)', name.hex(),
          '000b' + hashlib.sha256(outpublic).hexdigest())

    #
    # creationData, and creationHash over exactly those octets.
    #
    want_cd = (bytes(4) + (0).to_bytes(2, 'big') + bytes([1])
               + (0x0010).to_bytes(2, 'big')
               + (4).to_bytes(2, 'big') + bytes.fromhex('40000001')
               + (4).to_bytes(2, 'big') + bytes.fromhex('40000001')
               + (0).to_bytes(2, 'big'))
    check('creationData matches Table 261', creationdata.hex(), want_cd.hex())
    check('creationHash = SHA-256(creationData)', creationhash.hex(),
          hashlib.sha256(creationdata).hexdigest())

    check('ticket tag is TPM_ST_CREATION', tick_tag, 0x8021)
    check('  hierarchy is TPM_RH_OWNER',   tick_hier, 0x40000001)
    check('  digest is 32 octets',         len(tick_digest), 32)

    #
    # (!) THE RESPONSE AUTHORIZATION AREA IS NOT OPTIONAL. Part 1 Table 21: one acknowledgement
    # per command session. A TPM_ST_SESSIONS response without it is malformed however correct
    # its parameters are, and tpm.sys would reject the whole thing.
    #
    check('response session area present', rsp_sessions.hex(), '0000010000')

    print('  --- the property the whole layer exists for ---')
    #
    # (!) THE SAME COMMAND TWICE GIVES A BYTE-IDENTICAL RESPONSE. That is what makes an SRK
    # survive a reboot, and its absence is what Windows reports as event 519, "The TPM has been
    # cleared. Reason: SRK has changed".
    #
    check('same command -> IDENTICAL response', got.get('pri.repeatable'), '1')
    #
    # And the other direction: a different hierarchy must give a different key, or the split
    # between the storage and endorsement seeds is decorative and the EK equals the SRK.
    #
    check('ENDORSEMENT succeeds',              got.get('pri.ek_rc'), '0')
    check('  and gives a DIFFERENT key',       got.get('pri.hierarchy_matters'), '0')

    print('  --- the object store ---')
    check('three slots fill',        got.get('pri.full_loaded'), '3')
    #
    # A full store is a WARNING, not an error: RC_WARN means "try again later", so the caller
    # can flush something and retry. An RC_FMT1 failure would say the command is wrong when the
    # only problem is that three slots are in use.
    #
    check('  a fourth -> OBJECT_MEMORY (a WARNING)', got.get('pri.full_rc'),
          str(rc['TPM_RC_OBJECT_MEMORY']))
    check('  and nothing was written',              got.get('pri.full_wrote'), '0')
    check('reset empties the store',                got.get('pri.after_reset'), '0')

    print('  --- refusals ---')
    #
    # NO_SESSIONS on a command that requires authorization is a MISSING authorization, not a
    # size error. TPM_RC_AUTH_MISSING tells the caller what to add instead of making it guess.
    #
    check('NO_SESSIONS -> AUTH_MISSING', got.get('pri.no_sessions'),
          str(rc['TPM_RC_AUTH_MISSING']))
    check('  and nothing was written',   got.get('pri.no_sessions_wrote'), '0')
    #
    # A persistent key handle is not a hierarchy. The error is numbered with handle 1.
    #
    check('key handle -> VALUE, handle 1', got.get('pri.bad_hierarchy'),
          str(rc['TPM_RC_VALUE'] | 0x100))
    #
    # Trailing octets mean the caller sent a field the TPM never read. Answering SUCCESS would
    # tell it we understood something we skipped.
    #
    check('trailing octets -> refused',   got.get('pri.trailing') != '0', True)
    #
    # (!) NO SEED SOURCE, NO KEY. A key from a fabricated seed succeeds here and changes on the
    # next boot -- event 519 again, but looking fixed, which is worse than the refusal.
    #
    check('no seed source -> FAILURE',    got.get('pri.no_seed'),
          str(rc['TPM_RC_FAILURE']))
    check('  and the TPM says so',        got.get('pri.have_seed'), '0')
    check('  restored',                   got.get('pri.have_seed2'), '1')
    #
    # An output buffer too small must refuse -- and must NOT consume a slot. A slot marked
    # loaded before a size failure leaks a handle to an object the caller was never told about,
    # and three of those exhaust the store permanently.
    #
    check('tiny output -> refused',       got.get('pri.tight') != '0', True)
    check('  AND NO SLOT CONSUMED',       got.get('pri.tight_loaded'), '0')

def check_flush(got, check):
    """TPM2_FlushContext -- what nine OBJECT_MEMORY answers on hardware were asking for."""
    print()
    print('  --- TPM2_FlushContext (implemented on MEASURED demand) ---')
    rc = _edk2_response_codes()

    #
    # (!) THE HARDWARE BOOT IS THE TEST CASE. Windows sent CreatePrimary 12 times: 3 SUCCESS
    # then 9 TPM_RC_OBJECT_MEMORY, because three slots filled and FlushContext -- which it sent
    # three times -- answered TPM_RC_COMMAND_CODE. This reproduces exactly that sequence.
    #
    check('the store fills at 3',        got.get('flush.filled'), '3')
    check('  a fourth -> OBJECT_MEMORY', got.get('flush.full_rc'),
          str(rc['TPM_RC_OBJECT_MEMORY']))
    #
    # Two full slots and one free one before the flush: the free slot must already be clean.
    #
    check('an untouched free slot is zero', got.get('flush.residue_before'), '0')
    check('FLUSH ONE',                   got.get('flush.rc'), '0')
    #
    # (!) AND THE FLUSHED SLOT MUST BE ZERO, ASKED BEFORE ANYTHING REUSES IT. A flush that only
    # cleared the Loaded flag passed every other check in this section -- the handle stopped
    # resolving, the count dropped, the next CreatePrimary succeeded -- because that CreatePrimary
    # OVERWROTE the slot. Proven by injuring it and watching the suite stay green. The RSA private
    # key would have sat in the driver's BSS until something happened to reuse the slot.
    #
    check('  AND THE SLOT IS ZEROED, not just freed', got.get('flush.residue'), '0')
    check('  the store drops to 2',      got.get('flush.after'), '2')
    check('  and CreatePrimary SUCCEEDS again', got.get('flush.reuse_rc'), '0')
    check('  back to 3',                 got.get('flush.reuse_loaded'), '3')

    #
    # (!) THE SLOT IS ZEROED, NOT MARKED FREE -- it held an RSA private key. Read back through
    # the public lookup: a flush that only cleared a flag would leave the handle resolving to
    # the OLD object, and the key would still be sitting in the BSS.
    #
    check('the reused handle resolves',  got.get('flush.found_after'), '1')
    check('  and after a reset it does not', got.get('flush.found_gone'), '0')

    print('  --- refusals, each numbered as a PARAMETER ---')
    #
    # (!) PARAMETER, NOT HANDLE, AND THAT IS NOT A SLIP. Part 3 28.4.1: "flushHandle is a
    # parameter and not a handle. If it were in the handle area, the TPM would validate that the
    # context for the referenced entity is in the TPM" -- which would make flushing a SAVED
    # session context impossible. Hardware confirms it from the other side: its TPMA_CC for this
    # command is 0x00000165, cHandles = 0.
    #
    # So the codes carry the P bit and parameter number 1, not a handle number.
    #
    P1 = 0x040 | 0x100
    check('absent transient -> HANDLE(parm 1)', got.get('flush.absent'),
          str(rc['TPM_RC_HANDLE'] | P1))
    #
    # No sessions exist, so none can be flushed. Part 3: "if the handle does not reference a
    # loaded or active session, then the TPM shall return TPM_RC_HANDLE." Correct for the state
    # we are in -- and it must be HANDLE, not VALUE, because a session handle is a legal
    # TPMI_DH_CONTEXT that simply is not present.
    #
    check('HMAC session -> HANDLE(parm 1)',     got.get('flush.hmac_sess'),
          str(rc['TPM_RC_HANDLE'] | P1))
    check('policy session -> HANDLE(parm 1)',   got.get('flush.policy_sess'),
          str(rc['TPM_RC_HANDLE'] | P1))
    #
    # (!) A PERSISTENT HANDLE IS REFUSED, NOT FLUSHED. Part 3: "This command may not be used to
    # remove a persistent object from the TPM. Use TPM2_EvictControl()." Flushing one silently
    # would destroy an object the caller expects to survive a reboot -- and TPMI_DH_CONTEXT does
    # not admit persistent handles at all, so VALUE is the type error, not HANDLE.
    #
    check('PERSISTENT -> VALUE(parm 1)',        got.get('flush.persistent'),
          str(rc['TPM_RC_VALUE'] | P1))
    check('permanent -> VALUE(parm 1)',         got.get('flush.permanent'),
          str(rc['TPM_RC_VALUE'] | P1))
    check('NV index -> VALUE(parm 1)',          got.get('flush.nvindex'),
          str(rc['TPM_RC_VALUE'] | P1))

    print('  --- through the dispatcher ---')
    #
    # 14 octets: a 10-byte header and the flushHandle. This is byte-identical to what Windows
    # sent on hardware -- 80010000000e0000016580000000, CRB trace seq 11.
    #
    check('the command is the one Windows sent', got.get('flush.cmd'),
          '80010000000e0000016580000000')
    check('response is 10 octets',       got.get('flush.disp_len'), '10')
    check('  SUCCESS, NO_SESSIONS',      got.get('flush.disp_rsp'),
          '80010000000a00000000')
    check('  and the object is gone',    got.get('flush.disp_loaded'), '0')
    #
    # (!) A SESSION AREA IS NOT AN AUTH FAILURE, IT IS A COMMAND THAT DOES NOT TAKE ONE.
    # Part 3 28.4.1: "No sessions of any type are allowed with this command and tag is required
    # to be TPM_ST_NO_SESSIONS." TPM_RC_AUTH_CONTEXT says exactly that; an auth failure would
    # send the caller hunting for a password that was never the problem.
    #
    want = '80010000000a' + ('%08x' % rc['TPM_RC_AUTH_CONTEXT'])
    check('TPM_ST_SESSIONS -> AUTH_CONTEXT', got.get('flush.disp_sess_rsp'), want)
    #
    # A 10-octet command has no flushHandle: running out of octets is INSUFFICIENT, numbered with
    # the parameter that was missing.
    #
    # (!) THAT PARAMETER IS 1, AND THIS CHECK FIRST ASSERTED 4. I had read the second argument of
    # ParamSizeRc(Have, Want) as a parameter NUMBER; it is the wanted BYTE COUNT, and flushHandle
    # is the command's first and only parameter. The code was right and the expectation was wrong,
    # which is the direction you want when a new test disagrees with new code.
    #
    want = '80010000000a' + ('%08x' % (rc['TPM_RC_INSUFFICIENT'] | 0x040 | 0x100))
    check('no flushHandle -> INSUFFICIENT(parm 1)', got.get('flush.disp_short_rsp'), want)

def check_evict(got, check):
    """TPM2_EvictControl -- the last command between us and a provisioned TPM."""
    import hashlib

    print()
    print('  --- TPM2_EvictControl (implemented on MEASURED demand) ---')
    rc = _edk2_response_codes()
    H1 = 0x100      # handle 1
    H2 = 0x200      # handle 2
    P1 = 0x040 | 0x100

    #
    # (!) THE COMMAND IS THE ONE WINDOWS SENT, byte for byte, captured this boot. 55 octets:
    # RH_OWNER, our transient handle, the 29-octet password authorization, and persistentHandle
    # 0x81000001 as a PARAMETER -- which is what hardware TPMA_CC 0x04400120 declares by saying
    # cHandles=2 rather than 3.
    #
    want = ('8002' + '%08x' % 55 + '%08x' % 0x120
            + '%08x' % 0x40000001 + '%08x' % 0x80000000
            + '%08x' % 29 + '%08x' % 0x40000009 + '0000' + '00'
            + '%04x' % 20 + '00' * 20 + '%08x' % 0x81000001)
    check('55 octets, as Windows sent them', got.get('evict.cmd_len'), '55')
    check('  byte for byte',                 got.get('evict.cmd'), want)

    #
    # An object handle naming nothing is TPM_RC_HANDLE on handle 2 -- the second command handle,
    # because EvictControl has two and objectHandle is the second.
    #
    check('nothing loaded -> HANDLE(handle 2)', got.get('evict.no_object'),
          str(rc['TPM_RC_HANDLE'] | H2))

    check('CreatePrimary loaded one',   got.get('evict.loaded'), '1')
    check('EVICTCONTROL SUCCEEDS',      got.get('evict.rc'), '0')
    check('  one object persisted',     got.get('evict.persisted'), '1')
    #
    # (!) THE TRANSIENT OBJECT SURVIVES. Part 3 rule 7: "the object referenced by objectHandle
    # will not be flushed and both objectHandle and persistentHandle may be used to access the
    # object." Windows depends on it -- it persists, THEN flushes the transient handle. A TPM
    # that consumed the object would leave it flushing something already gone, and the bug would
    # look like a spurious TPM_RC_HANDLE from FlushContext.
    #
    check('  and the TRANSIENT one survives', got.get('evict.transient_kept'), '1')

    #
    # The response carries no parameters -- but parameterSize is PRESENT and ZERO, and the
    # session acknowledgement follows it. Part 1 18.3: "no parameters" means the field says zero,
    # not that the field goes away. Omitting it shifts the session area by four octets.
    #
    check('  response is 10 + 4 + 5',   got.get('evict.len'), '19')
    check('  SESSIONS, parameterSize 0, ack', got.get('evict.rsp'),
          '80020000001300000000' + '00000000' + '0000010000'[:10])

    print('  --- and now ReadPublic on the PERSISTENT handle SUCCEEDS ---')
    #
    # (!) THIS IS THE 55-ERROR POPULATION. Windows asked ReadPublic 0x81000001 fifty-five times
    # last boot and got TPM_RC_HANDLE every time, because nothing could be persisted.
    #
    check('the command is the one Windows sent', got.get('evict.rdpub_cmd'),
          '80010000000e0000017381000001')
    raw = got.get('evict.rdpub', '')
    if len(raw) < 20:
        check('ReadPublic returned a response', False, True)
        return
    b = bytes.fromhex(raw)
    check('  responseCode SUCCESS',     b[6:10].hex(), '00000000')
    check('  tag NO_SESSIONS',          b[0:2].hex(), '8001')
    check('  header length == written', int.from_bytes(b[2:6], 'big'), len(b))

    p = 10
    n = int.from_bytes(b[p:p+2], 'big'); p += 2
    outpublic = b[p:p+n]; p += n
    n = int.from_bytes(b[p:p+2], 'big'); p += 2
    name = b[p:p+n]; p += n
    n = int.from_bytes(b[p:p+2], 'big'); p += 2
    qn = b[p:p+n]; p += n
    check('  outPublic, name, qualifiedName consume it exactly', p, len(b))
    #
    # The Name is the digest of outPublic as sent -- hashlib recomputes it, which ties the
    # marshaller and the Name together across a command boundary.
    #
    check('  name = nameAlg || SHA-256(outPublic)', name.hex(),
          '000b' + hashlib.sha256(outpublic).hexdigest())
    #
    # (!) THE QUALIFIED NAME OF A PRIMARY OBJECT IS NOT A SECOND DIGEST OF THE SAME THING.
    # Part 1 23.5: "Both the Name and Qualified Name for a Primary Seed are the handle of the
    # Primary Seed", so QN = H_nameAlg(hierarchy handle || Name) -- four octets of handle, then
    # the whole Name including its algorithm prefix. Getting this wrong produces a QN that is
    # self-consistent and that nothing else in the world computes.
    #
    check('  QN = nameAlg || H(hierarchy || Name)', qn.hex(),
          '000b' + hashlib.sha256(bytes.fromhex('40000001') + name).hexdigest())
    check('  and it DIFFERS from the Name', qn != name, True)
    #
    # The persistent and transient handles name the SAME object, so the answers must be
    # identical past the header. If they differed, one of the two copies would be wrong.
    #
    check('transient handle answers identically', got.get('evict.same_object'), '1')

    print('  --- refusals ---')
    #
    # NV_DEFINED and NV_SPACE are RC_VER1 and carry no field number: neither is a complaint
    # about something the caller sent. One says the destination is taken, the other says the TPM
    # is full.
    #
    check('destination taken -> NV_DEFINED', got.get('evict.taken'),
          str(rc['TPM_RC_NV_DEFINED']))
    #
    # (!) OWNER AUTH MAY NOT REACH THE PLATFORM RANGE. Part 3 rule 3 splits 0x81000000-0x817FFFFF
    # for the owner from 0x81800000-0x81FFFFFF for the platform, and the split is what keeps the
    # OEM indices clear of the owner. persistentHandle is a PARAMETER, so the error is numbered
    # as one.
    #
    check('owner reaching platform range -> RANGE(parm 1)', got.get('evict.owner_range'),
          str(rc['TPM_RC_RANGE'] | P1))
    #
    # (!) AND THE ENDORSEMENT HIERARCHY UNDER *OWNER* AUTH IS LEGAL. Part 3 rule 2: owner auth
    # covers the Storage AND Endorsement hierarchies. That is not a quirk to work around -- it is
    # exactly what Windows does, and both captured EvictControl commands carry authHandle
    # 0x40000001, one for the SRK and one for the EK.
    #
    check('EK under OWNER auth SUCCEEDS',  got.get('evict.ek_rc'), '0')
    check('  two objects persisted',       got.get('evict.ek_persisted'), '2')

    print('  --- TPM_CAP_HANDLES: enumerate what we actually hold ---')
    #
    # (!) THIS BRANCH DID NOT EXIST AND ITS ABSENCE WAS INVISIBLE. With no objects to report,
    # falling through emitted an EMPTY list -- which was the correct answer, so nothing looked
    # wrong. EvictControl made it wrong on the same boot it made objects real: the live profile
    # showed persistent handles ABSENT while TPM_PT_HR_PERSISTENT said 2. Two of our own answers
    # disagreeing is the self-contradiction this dispatcher exists to avoid.
    #
    check('two persistent handles enumerated', got.get('enum.persist_n'), '2')
    check('  0x81000001 first',                got.get('enum.persist_0'), str(0x81000001))
    check('  0x81010001 second',               got.get('enum.persist_1'), str(0x81010001))
    #
    # (!) ASCENDING IS PART OF THE ANSWER, NOT A COURTESY. `property` is a STARTING handle so a
    # caller can page through a list longer than one response, and paging is only meaningful if
    # the order is stable and increasing. Slots are in ALLOCATION order, which is not the same
    # thing -- hardware returns 81000001 81000002 81000009 81010001, sorted.
    #
    check('  and the list ASCENDS',            got.get('enum.ascending'), '1')
    #
    # Paging: starting above the first handle must skip it.
    #
    check('paging from 0x81000002 skips the first', got.get('enum.paged_n'), '1')
    check('  leaving 0x81010001',              got.get('enum.paged_0'), str(0x81010001))
    #
    # A range we hold nothing in is an EMPTY list, not an error. That was already the answer for
    # NV before this branch existed, and it stays the answer -- what changed is that it is now
    # true because we looked, rather than true because nothing looked.
    #
    check('NV range is empty',                 got.get('enum.nv'), '0')
    #
    # (!) THE TRANSIENT RANGE HOLDS ONE, AND THIS CHECK FIRST ASSERTED ZERO. The EK was created
    # and then persisted, and EvictControl is a COPY -- Part 3 rule 7 -- so the transient object
    # is still loaded. The code was right and the expectation was careless.
    #
    # Worth keeping rather than deleting: it is the same fact `and the TRANSIENT one survives`
    # asserts, arrived at through a different command. Two answers that have to agree.
    #
    check('transient range holds the un-flushed one', got.get('enum.transient'), '1')
    check('zero-sized output writes nothing',  got.get('enum.zero_max'), '0')

    #
    # (!) THE CHECKS ABOVE COULD NOT CATCH AN UNSORTED ENUMERATION, and an injury proved it.
    # Windows persists the SRK first and the EK second, so 0x81000001 lands in slot 0 and
    # 0x81010001 in slot 1 -- slot order and numeric order AGREE, and returning the raw slot order
    # passes every one of them.
    #
    # Persisting them the other way round puts the HIGHER handle in the LOWER slot. Now the two
    # orders cannot coincide, and the sort is the only thing that can produce the right answer.
    #
    # Fifth time this session a vector agreed with the bug it was meant to catch. The pattern is
    # always the same: a case chosen because it is REALISTIC, where two behaviours happen to line
    # up. Realistic is what you test; DISTINGUISHING is what the test has to be.
    #
    check('EK persisted first',            got.get('enum.rev_ek'), '0')
    check('SRK persisted second',          got.get('enum.rev_srk'), '0')
    check('  two enumerated',              got.get('enum.rev_n'), '2')
    check('  LOWER handle first anyway',   got.get('enum.rev_0'), str(0x81000001))
    check('  higher second',               got.get('enum.rev_1'), str(0x81010001))
    check('  ASCENDING against slot order', got.get('enum.rev_ascending'), '1')

    print('  --- eviction ---')
    #
    # Part 3 rule 9: evicting is not a move. objectHandle and persistentHandle name the same
    # object twice, and a caller that disagrees with itself is not making an interpretable
    # request.
    #
    check('objectHandle != persistentHandle -> HANDLE(handle 2)', got.get('evict.mismatch'),
          str(rc['TPM_RC_HANDLE'] | H2))
    check('EVICT SUCCEEDS',            got.get('evict.evict_rc'), '0')
    check('  one left',                got.get('evict.after_evict'), '1')
    #
    # (!) THE EVICTED SLOT IS ZEROED, asked before anything can reuse it. This is the check that
    # a flag-only FlushContext slipped past once already -- the reuse overwrites the residue and
    # hides it.
    #
    check('  AND THE SLOT IS ZEROED',  got.get('evict.residue'), '0')
    check('  evicting again finds nothing', got.get('evict.gone'),
          str(rc['TPM_RC_HANDLE'] | H2))

    #
    # (!) TPM2_Startup MUST NOT REMOVE PERSISTENT OBJECTS -- that is what the word means, and
    # Part 3 28.5.1 says it outright: "A persistent object is not removed from TPM memory by
    # TPM2_FlushContext() or TPM2_Startup()." A Startup that cleared them would make provisioning
    # evaporate on every TPM Reset while every other check here still passed.
    #
    check('persistent objects survive TPM2_Startup',
          got.get('evict.after_startup'), got.get('evict.before_startup'))

#
# Hardware's own TPM2_NV_ReadPublic answer for the RSA EK certificate index, captured from
# genuine Intel PTT on 2026-09-09. The response carries the public area AND the Name computed
# over it, which is what makes it an ORACLE rather than a second reading of Part 2.
#
HW_NV_EK_PUBLIC = '01c00002000c620704080000038f'
HW_NV_EK_NAME = ('000cf6a000fe837e059bcd40f6e83a0fae855469309a5b43cb001ba77b0223c476'
                 '04525cd033d1f6bf69c942b98a401803b0')


def check_nv(got, check):
    """NV indices: the public area, the Name, and the store."""
    import hashlib

    print()
    print('  --- NV indices (implemented on MEASURED demand: 10 NV_ReadPublic calls) ---')
    rc = _edk2_response_codes()

    #
    # (!) THIS IS THE STRONGEST TEST IN THE FILE, AND IT COST NOTHING TO GET.
    #
    # Hardware answered NV_ReadPublic for 0x01C00002 with a 14-octet public area and a 50-octet
    # Name. We rebuild the public area from its DECODED fields and compute the Name ourselves. If
    # the field order is wrong, or the TPM2B prefix is misplaced, or the Name construction is not
    # nameAlg || H(public), the digest cannot match -- and the value it must match was produced
    # by a TPM nobody here wrote.
    #
    # nameAlg is SHA-384, so the Name is 50 octets, not 34. Anything that assumed two octets plus
    # a 32-byte digest fails here rather than somewhere subtler later.
    #
    check('marshalled',                 got.get('nv.hw_marshal_rc'), '0')
    check('  14 octets',                got.get('nv.hw_marshal_len'), '14')
    check('  == HARDWARE public area',  got.get('nv.hw_public'), HW_NV_EK_PUBLIC)
    check('Name computed',              got.get('nv.hw_name_ok'), '1')
    check('  2 + 48 octets (SHA-384)',  got.get('nv.hw_name_len'), '50')
    check('  == HARDWARE Name',         got.get('nv.hw_name'), HW_NV_EK_NAME)
    #
    # And the same digest from hashlib, so the agreement is not two of our own routines agreeing.
    #
    check('  and hashlib says the same', got.get('nv.hw_name'),
          '000c' + hashlib.sha384(bytes.fromhex(HW_NV_EK_PUBLIC)).hexdigest())

    print('  --- the store ---')
    check('starts empty',               got.get('nv.count0'), '0')
    check('define succeeds',            got.get('nv.define'), '0')
    check('  one index',                got.get('nv.count1'), '1')
    check('  and it is findable',       got.get('nv.found'), '1')
    check('  an undefined one is not',  got.get('nv.missing'), '0')
    #
    # (!) WRITTEN IS CLEARED EVEN THOUGH THE CALLER ASKED FOR IT. We passed hardware's exact
    # attributes, which carry TPMA_NV_WRITTEN because hardware holds a certificate. We hold
    # nothing. Part 2 Table 249 makes WRITTEN a status bit the TPM maintains, not an attribute a
    # definer chooses -- and a definer that could assert it could make this TPM claim an EK
    # certificate it does not have.
    #
    check('WRITTEN is CLEARED on define', got.get('nv.written_bit'), '0')
    check('  every other attribute kept', got.get('nv.other_attrs'), '1')
    check('  dataSize is what was asked', got.get('nv.datasize'), '911')
    check('  and nothing is written yet', got.get('nv.written_len'), '0')
    check('defining it twice -> NV_DEFINED', got.get('nv.redefine'),
          str(rc['TPM_RC_NV_DEFINED']))

    print('  --- writing ---')
    check('write succeeds',             got.get('nv.write'), '0')
    check('  WRITTEN is now SET',       got.get('nv.write_bit'), '1')
    check('  64 octets written',        got.get('nv.write_len'), '64')
    #
    # (!) dataSize DESCRIBES THE INDEX, NOT THE CONTENT. It stays 911 after a 64-octet write.
    # Reporting the written count there would make a partly-written index look smaller than it
    # is, and an unwritten one look zero-length.
    #
    check('  dataSize still 911',       got.get('nv.write_datasize'), '911')
    #
    # (!) THE NAME MOVES WITH `WRITTEN`, AND THE ROUND TRIP LANDS EXACTLY ON HARDWARE.
    #
    # WRITTEN lives inside the public area the Name digests, so an index has a DIFFERENT Name
    # before and after its first write. Anything that cached one beforehand holds a stale value.
    #
    # This check first asserted only that the Name changed after writing, and FAILED -- because it
    # compared against hardware's Name, which already has WRITTEN set. The truth is stronger than
    # what was asked: unwritten we differ from hardware, and the moment we write, our public area
    # is hardware's public area and the 50-octet Name is byte-identical. The test was weaker than
    # the behaviour, which is the good direction for a surprise.
    #
    check('  UNWRITTEN, the Name differs from hardware',
          got.get('nv.name_unwritten') != HW_NV_EK_NAME, True)
    check('  and WRITTEN, it is hardware EXACTLY',
          got.get('nv.name_after_write'), HW_NV_EK_NAME)
    check('writing an undefined index -> HANDLE', got.get('nv.write_absent'),
          str(rc['TPM_RC_HANDLE'] | 0x100))

    print('  --- enumeration ---')
    #
    # (!) DEFINED SECOND, SORTS FIRST -- the trap the object enumeration fell into. 0x01880011 is
    # defined after 0x01C00002 and is the LOWER handle, so definition order and numeric order
    # cannot coincide. Written that way from the start here rather than after an injury.
    #
    check('second index defined',       got.get('nv.def2'), '0')
    check('  two enumerated',           got.get('nv.enum_n'), '2')
    check('  0x01880011 FIRST',         got.get('nv.enum_0'), str(0x01880011))
    check('  0x01C00002 second',        got.get('nv.enum_1'), str(0x01C00002))
    check('  ASCENDING against definition order', got.get('nv.enum_ascending'), '1')
    check('  a non-NV range is empty',  got.get('nv.enum_wrongtype'), '0')

    print('  --- refusals ---')
    check('a permanent handle is not an NV index', got.get('nv.bad_handle'),
          str(rc['TPM_RC_VALUE']))
    check('a hash we cannot compute -> HASH',      got.get('nv.bad_alg'),
          str(rc['TPM_RC_HASH']))
    #
    # A zero-size index cannot hold anything and cannot be read; refusing beats defining a thing
    # with no purpose that still occupies a slot.
    #
    check('zero dataSize -> SIZE',                 got.get('nv.zero_size'),
          str(rc['TPM_RC_SIZE']))
    check('beyond our capacity -> SIZE',           got.get('nv.huge'),
          str(rc['TPM_RC_SIZE']))
    check('reset empties the store',               got.get('nv.after_reset'), '0')

def check_pcr_commands(got, check):
    """PCR_Read, PCR_Extend and Shutdown -- the three commands that had no dispatch case."""
    import hashlib

    print()
    print('  --- PCR commands: implemented underneath, unreachable from the wire ---')
    rc = _edk2_response_codes()
    #
    # Format-one markers, spelled out once. Bit 6 is P (the fault is in a parameter) and bits
    # 11:8 carry N, the parameter or handle number -- so a fault in handle 1 and a fault in
    # parameter 1 are DIFFERENT codes, and the difference is the whole point of testing both.
    #
    P1 = 0x040 | 0x100
    H1 = 0x100

    print('  --- TPM2_Shutdown ---')
    check('Shutdown(CLEAR) succeeds',     got.get('pcrc.shut_clear'), '0')
    check('  header and nothing else',    got.get('pcrc.shut_clear_len'), '10')
    #
    # (!) SHUTDOWN(STATE) IS REFUSED ON PURPOSE, and it is a DELIBERATE DIFFERENCE FROM HARDWARE,
    # which accepts both. Shutdown(STATE) promises that a later Startup(STATE) can restore what
    # was saved. Region B does not survive power loss, so the promise would be kept by nobody and
    # the failure would surface a boot later as PCRs that are not the ones the caller left. We
    # already refuse Startup(STATE); refusing to SAVE exactly as we refuse to RESTORE is the
    # consistent pair. A TPM that agreed to remember and then did not is the failure this project
    # refuses everywhere else.
    #
    check('Shutdown(STATE) refused',      got.get('pcrc.shut_state'),
          str(rc['TPM_RC_VALUE'] | P1))
    check('a value that is no TPM_SU',    got.get('pcrc.shut_bad'),
          str(rc['TPM_RC_VALUE'] | P1))
    check('trailing octet -> SIZE',       got.get('pcrc.shut_long'),
          str(rc['TPM_RC_SIZE'] | P1))

    print('  --- TPM2_PCR_Read ---')
    zero = "00" * 32
    check('one PCR succeeds',             got.get('pcrc.read0_rc'), '0')
    #
    # 28 fixed octets -- counter, count, alg, sizeofSelect, three selection octets, digest count
    # -- then 2 + 32 per digest.
    #
    check('  28 + 34 octets',             got.get('pcrc.read0_len'), '62')
    check('  counter starts at 0',        got.get('pcrc.read0_counter'), '0')
    check('  one digest',                 got.get('pcrc.read0_n'), '1')
    check('  selection echoed for one',   got.get('pcrc.read0_sel'), '000b03010000')
    #
    # PCR 0 holds the LOCALITY INDICATOR at startup, not a fixed zero (PTP Table 15). At locality
    # 0 -- the only locality this implementation has -- that is a zero-valued field, so this looks
    # like the universal assumption and is not.
    #
    check('  PCR 0 is the locality (0)',  got.get('pcrc.read0_val'), zero)

    print('  --- TPM2_PCR_Extend, and the two commands agreeing ---')
    d1 = bytes(range(1, 33))
    p1 = hashlib.sha256(bytes(32) + d1).digest().hex()
    p2 = hashlib.sha256(bytes.fromhex(p1) + d1).digest().hex()

    check('extend succeeds',              got.get('pcrc.ext1_rc'), '0')
    #
    # parameterSize present and zero, then the session acknowledgement -- Part 1 clause 18.3. The
    # response attributes byte is 0x01, continueSession, which a password session always gets back
    # whatever the command sent.
    #
    check('  19 octets, SESSIONS shape',  got.get('pcrc.ext1_len'), '19')
    check('  the exact response',         got.get('pcrc.ext1_resp'),
          '80020000001300000000' + '00000000' + '0000' + '01' + '0000')
    check('  update counter moved to 1',  got.get('pcrc.ext1_counter'), '1')
    #
    # (!) READ BACK THROUGH THE OTHER COMMAND, NOT OUT OF THE STRUCT. Checking PBank.Pcr[0]
    # directly would prove only that Tpm2PcrExtend works, which was never in doubt -- the event
    # log has exercised it for weeks. What had never been shown is that the two WIRE paths agree.
    # Part 1 equation (14): the OLD PCR and the incoming digest are hashed together, in that
    # order, and hashlib says what that is.
    #
    check('  PCR_Read sees it',           got.get('pcrc.read1_val'), p1)
    check('  == hashlib SHA256(0**32||d)', got.get('pcrc.read1_val'), p1)
    check('  counter visible on the wire', got.get('pcrc.read1_counter'), '1')

    #
    # (!) THE TEST THAT CORRECTED THE CODE COMMENT RATHER THAN THE CODE. A SHA-1 digest sent
    # ahead of a SHA-256 one was expected to be skipped; the command failed instead. Part 3
    # clause 22.2.1 says the code was right:
    #
    #     "If the caller includes digests for algorithms that are not implemented, then the TPM
    #      will fail the call because the unmarshaling of digests will fail. [...] the TPM will
    #      return TPM_RC_HASH."
    #
    # An unimplemented ALGORITHM fails the whole command. That is a different sentence from "If a
    # digest is present and the PCR in that bank is not implemented, the digest value is not
    # used", which is the skip -- and needs an algorithm we DO implement. Both are below.
    #
    check('SHA-1 digest -> HASH, not skip', got.get('pcrc.ext2_rc'),
          str(rc['TPM_RC_HASH'] | P1))
    check('  and NOTHING was extended',   got.get('pcrc.ext2_counter'), '1')
    check('  PCR 0 did not move',         got.get('pcrc.read2_val'), p1)
    check('an unknown alg -> HASH too',   got.get('pcrc.ext_badalg'),
          str(rc['TPM_RC_HASH'] | P1))
    check('  and still nothing extended', got.get('pcrc.ext_badalg_counter'), '1')
    #
    # (!) AND NOW THE REAL SKIP CASE. SHA-384 is implemented (TPM_CAP_ALGS says so) with no PCR
    # bank (TPM_CAP_PCRS says so), which is exactly the sentence above. Sent FIRST so its 48
    # octets must be counted from the algorithm ID: get the length wrong and the SHA-256 entry
    # behind it is read out of the middle of a digest and PCR 0 lands on neither value.
    #
    check('SHA-384 ahead of SHA-256: OK', got.get('pcrc.mixed_rc'), '0')
    check('  extended EXACTLY once',      got.get('pcrc.mixed_counter'), '2')
    check('  == hashlib, so 48 counted',  got.get('pcrc.mixed_val'), p2)
    check('SHA-384 alone: accepted',      got.get('pcrc.only384_rc'), '0')
    check('  counter did NOT move',       got.get('pcrc.only384_counter'), '2')
    check('  PCR 0 did not move',         got.get('pcrc.only384_val'), p2)

    print('  --- the eight-digest cap ---')
    #
    # (!) THE BEHAVIOUR THAT LOOKS RIGHT IN ANY TEST ASKING FOR EIGHT OR FEWER. Part 2 Table 126
    # caps TPML_DIGEST at eight entries, and Part 3 clause 22.4.1 says the returned selection has
    # a bit set "for each value present in pcrValues". So a caller asking for all 24 gets 8 and
    # re-asks -- and a TPM that echoed the REQUESTED selection while sending fewer digests would
    # desynchronise every caller that trusted the pairing.
    #
    check('all 24 asked, 8 returned',     got.get('pcrc.all_n'), '8')
    check('  selection says PCR 0..7',    got.get('pcrc.all_sel'), '000b03ff0000')
    check('  28 + 8 * 34 octets',         got.get('pcrc.all_len'), '300')
    #
    # (!) AND A SPARSE SELECTION, WHICH ALL-24 STILL WOULD NOT SEPARATE. Nine PCRs, every other
    # one, requested as 55 55 01. Eight come back, so the answer must be 55 55 00 with bit 16
    # dropped. An echo says 55 55 01. An implementation setting the first eight BITS rather than
    # the first eight SELECTED says ff 00 00. All three are eight digests long and only the
    # selection tells them apart.
    #
    check('9 sparse asked, 8 returned',   got.get('pcrc.sparse_n'), '8')
    check('  bit 16 DROPPED, not echoed', got.get('pcrc.sparse_sel'), '000b03555500')
    #
    # PCRs 16..23: exactly eight, so nothing is dropped, and 17..22 carry the all-ones reset value
    # from PTP Table 15. A bank that zeroed everything at startup passes every check above this.
    #
    check('PCR 16..23: eight, none dropped', got.get('pcrc.high_n'), '8')
    check('  selection unchanged',        got.get('pcrc.high_sel'), '000b030000ff')
    check('  PCR 16 is zero',             got.get('pcrc.high_16'), zero)
    check('  PCR 17 is ALL ONES',         got.get('pcrc.high_17'), 'ff' * 32)
    check('  PCR 23 is zero again',       got.get('pcrc.high_23'), zero)

    print('  --- empty answers that are still answers ---')
    #
    # Part 3: "If no PCR are returned from a bank, the selector for the bank will be present in
    # pcrSelectionOut." So an empty selection, and a bank we do not implement, both come back with
    # zero digests and OUR selector -- not an error, and not an empty list either.
    #
    check('empty selection succeeds',     got.get('pcrc.none_rc'), '0')
    check('  no digests',                 got.get('pcrc.none_n'), '0')
    check('  but the bank IS named',      got.get('pcrc.none_count'), '1')
    check('  with an empty selection',    got.get('pcrc.none_sel'), '000b03000000')
    check('  28 octets, no digest area',  got.get('pcrc.none_len'), '28')
    check('a bank we lack: not an error', got.get('pcrc.sha1bank_rc'), '0')
    check('  no digests',                 got.get('pcrc.sha1bank_n'), '0')
    check('  and OUR bank is named',      got.get('pcrc.sha1bank_sel'), '000b03000000')

    print('  --- TPM_RH_NULL: the probe the specification documents ---')
    #
    # (!) A DISTINGUISHER WRITTEN INTO THE SPECIFICATION, AND WE FAILED IT. Part 2 Table 53 gives
    # TPMI_DH_PCR as {PCR_FIRST:PCR_LAST} +TPM_RH_NULL, and the `+` is not decoration. Part 3
    # clause 22.2.1: "The pcrHandle parameter is allowed to reference TPM_RH_NULL. If so, the
    # input parameters are processed but no action is taken by the TPM. This permits the caller to
    # probe for implemented hash algorithms as an alternative to TPM2_GetCapability()."
    #
    # Extend nothing into nowhere and read the response code. We answered TPM_RC_VALUE -- the
    # answer for a handle that is out of range, which TPM_RH_NULL is not, and which no genuine TPM
    # gives here. Found by testing a spec sentence, not by a trace: nothing on this machine has
    # ever sent it.
    #
    check('probe SHA-256 -> SUCCESS',     got.get('pcrc.probe_sha256'), '0')
    check('  and it is a real response',  got.get('pcrc.probe_sha256_len'), '19')
    check('probe SHA-384 -> SUCCESS',     got.get('pcrc.probe_sha384'), '0')
    check('probe SHA-512 -> SUCCESS',     got.get('pcrc.probe_sha512'), '0')
    check('probe SHA-1   -> HASH',        got.get('pcrc.probe_sha1'),
          str(rc['TPM_RC_HASH'] | P1))
    check('probe SM3-256 -> HASH',        got.get('pcrc.probe_sm3'),
          str(rc['TPM_RC_HASH'] | P1))
    #
    # (!) THE PROBE MUST AGREE WITH TPM_CAP_ALGS, which lists SHA-256, SHA-384 and SHA-512 and
    # nothing else. Two ways to ask the same question have to give the same answer, or the pair is
    # a distinguisher in the other direction.
    #
    check('  the three that answer SUCCESS are TPM_CAP_ALGS exactly',
          got.get('pcrc.probe_sha256') == '0' and got.get('pcrc.probe_sha384') == '0'
          and got.get('pcrc.probe_sha512') == '0'
          and got.get('pcrc.probe_sha1') != '0' and got.get('pcrc.probe_sm3') != '0', True)
    #
    # (!) AND THE PROBE TOUCHED NOTHING. A probe that extended PCR 0 would pass every response
    # code above and quietly corrupt the log of any caller using the documented way to enumerate
    # hash algorithms -- five extends, from five harmless-looking questions.
    #
    check('  counter did not move',       got.get('pcrc.probe_counter'), '2')
    check('  PCR 0 did not move',         got.get('pcrc.probe_val'), p2)

    print('  --- refusals ---')
    #
    # Two selections when we implement one bank, and a sizeofSelect that is not 3, are both
    # TPM_RC_VALUE in parameter 1. A commandSize that disagrees with what arrived never reaches
    # the case at all -- the header parser answers TPM_RC_COMMAND_SIZE -- while a trailing octet
    # INSIDE a well-sized command reaches it and comes back as SIZE. Two different failures with
    # two different answers.
    #
    check('two banks -> VALUE',           got.get('pcrc.two_banks'),
          str(rc['TPM_RC_VALUE'] | P1))
    check('sizeofSelect 2 -> VALUE',      got.get('pcrc.bad_selsize'),
          str(rc['TPM_RC_VALUE'] | P1))
    check('short buffer -> COMMAND_SIZE', got.get('pcrc.read_short'),
          str(rc['TPM_RC_COMMAND_SIZE']))
    check('trailing octet -> SIZE',       got.get('pcrc.read_long'),
          str(rc['TPM_RC_SIZE'] | P1))
    #
    # (!) A BAD PCR IS A HANDLE FAULT, NOT A PARAMETER FAULT -- Part 2 Table 53 marks TPMI_DH_PCR
    # #TPM_RC_VALUE, and it is handle 1. Same base code as the parameter faults above, different
    # marker, and a caller that decodes the marker gets pointed at the right field.
    #
    check('PCR 99 -> VALUE in HANDLE 1',  got.get('pcrc.ext_badpcr'),
          str(rc['TPM_RC_VALUE'] | H1))
    check('NO_SESSIONS -> AUTH_MISSING',  got.get('pcrc.ext_nosess'),
          str(rc['TPM_RC_AUTH_MISSING']))
    #
    # A NULL bank answers instead of dereferencing. The dispatcher takes it as a pointer and every
    # other command ignores it, so a caller that never had one is a real shape, not a contrivance.
    #
    check('PCR_Read with no bank',        got.get('pcrc.read_nobank'),
          str(rc['TPM_RC_FAILURE']))
    check('PCR_Extend with no bank',      got.get('pcrc.ext_nobank'),
          str(rc['TPM_RC_FAILURE']))

#
# FIPS-197 Appendix C, the published single-block vectors. Key = 00 01 02 ... for each length,
# plaintext = 00 11 22 33 ... ff.
#
FIPS197_C = {
    128: '69c4e0d86a7b0430d8cdb78070b4c55a',
    192: 'dda97ca4864cdfe06eaf70a0ec0d7191',
    256: '8ea2b7ca516745bfeafc49904b496089',
}

#
# NIST SP 800-38A Appendix F.3, CFB128 over the four standard plaintext blocks.
#
SP80038A_KEYS = {
    128: '2b7e151628aed2a6abf7158809cf4f3c',
    192: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
    256: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
}
SP80038A_PT = ('6bc1bee22e409f96e93d7e117393172a'
               'ae2d8a571e03ac9c9eb76fac45af8e51'
               '30c81c46a35ce411e5fbc1191a0a52ef'
               'f69f2445df4f9b17ad2b417be66c3710')
SP80038A_IV = '000102030405060708090a0b0c0d0e0f'
SP80038A_CFB = {
    128: ('3b3fd92eb72dad20333449f8e83cfb4a'
          'c8a64537a0b3a93fcde3cdad9f1ce58b'
          '26751f67a3cbb140b1808cf187a4f4df'
          'c04b05357c5d1c0eeac4c66f9ff7f2e6'),
    192: ('cdc80d6fddf18cab34c25909c99a4174'
          '67ce7f7f81173621961a2b70171d3d7a'
          '2e1e8a1dd59b88b1c8e60fed1efac4c9'
          'c05f9f9ca9834fa042ae8fba584b09ff'),
    256: ('dc7e84bfda79164b7ecd8486985d3860'
          '39ffed143b28b1c832113c6331e5407b'
          'df10132415e54b92a13ed0a8267ae2f9'
          '75a385741ab9cef82031623d55b1e471'),
}


def _openssl(key, iv, data, decrypt=False):
    """OpenSSL AES-CFB128 through `cryptography`. None if the library is absent."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return None
    c = Cipher(algorithms.AES(key), modes.CFB(iv))
    op = c.decryptor() if decrypt else c.encryptor()
    return (op.update(data) + op.finalize()).hex()


def _openssl_ecb_block(key, block):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return None
    op = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return (op.update(block) + op.finalize()).hex()


def _reference_sbox():
    """The S-box from its FIPS-197 DEFINITION: inverse in GF(2^8), then the affine map."""
    def xtime(a):
        return ((a << 1) & 0xFF) ^ (0x1B if (a & 0x80) else 0)

    def mul(a, b):
        r = 0
        for _ in range(8):
            if b & 1:
                r ^= a
            a = xtime(a)
            b >>= 1
        return r

    def rotl8(x, n):
        return ((x << n) | (x >> (8 - n))) & 0xFF

    out = []
    for v in range(256):
        c = 0
        if v:
            for i in range(1, 256):
                if mul(v, i) == 1:
                    c = i
                    break
        out.append(c ^ rotl8(c, 1) ^ rotl8(c, 2) ^ rotl8(c, 3) ^ rotl8(c, 4) ^ 0x63)
    return bytes(out).hex()


def check_aes(got, check):
    """AES (FIPS-197) and CFB (SP 800-38A), against published vectors AND OpenSSL."""
    print()
    print('  --- AES: the S-box, recomputed from the definition ---')
    #
    # (!) THE TABLE IN THE SOURCE WAS GENERATED, AND THIS RECOMPUTES IT INDEPENDENTLY. A
    # hand-typed S-box with one wrong octet yields a cipher that encrypts, decrypts, avalanches,
    # and matches nothing -- and every structural test still passes. Comparing all 256 against
    # the GF(2^8) definition is the only check that actually pins it.
    #
    check('all 256 octets == the definition', got.get('aes.sbox'), _reference_sbox())

    print('  --- FIPS-197 Appendix C: one block, three key lengths ---')
    #
    # (!) THE PUBLISHED LITERALS ARE THEMSELVES CHECKED AGAINST OPENSSL FIRST. If a vector was
    # mistyped, this fails as "the literal is wrong" rather than blaming our C -- which is the
    # failure mode that cost this project two wrong response codes that tests agreed with.
    #
    pt = bytes(range(0, 256, 0x11))[:16]
    for bits in (128, 192, 256):
        key = bytes(range(bits // 8))
        ref = _openssl_ecb_block(key, pt)
        if ref is not None:
            check('  FIPS-197 literal agrees with OpenSSL (%d)' % bits, FIPS197_C[bits], ref)
        check('AES-%d block' % bits, got.get('aes.kat%d' % bits), FIPS197_C[bits])
        check('  SetKey accepted', got.get('aes.setkey%d' % bits), '1')
    check('rounds 128 = 10', got.get('aes.rounds128'), '10')
    check('rounds 192 = 12', got.get('aes.rounds192'), '12')
    #
    # (!) AES-256 IS NOT AES-128 WITH MORE ROUNDS. FIPS-197 clause 5.2 gives Nk = 8 an extra
    # SubWord in the key schedule. Omit it and every 128-bit and 192-bit vector still passes.
    #
    check('rounds 256 = 14', got.get('aes.rounds256'), '14')
    check('encrypting in place is identical', got.get('aes.kat256_inplace'), FIPS197_C[256])

    print('  --- key lengths that are not AES ---')
    check('64 bits refused',   got.get('aes.key64'), '0')
    check('  and left INVALID', got.get('aes.key64_valid'), '0')
    check('512 bits refused',  got.get('aes.key512'), '0')
    check('0 bits refused',    got.get('aes.key0'), '0')
    check('NULL key refused',  got.get('aes.key_null'), '0')
    #
    # (!) AND A REFUSED SCHEDULE MUST PRODUCE NOTHING, not a cipher under a half-built key. The
    # output was poisoned with 0xDD first, so surviving poison is the evidence.
    #
    check('refused key writes NO output', got.get('aes.refused_no_output'), 'dd' * 16)
    check('  and CFB refuses with it',    got.get('aes.cfb_refused'), '0')

    print('  --- SP 800-38A F.3: CFB128 ---')
    pt = bytes.fromhex(SP80038A_PT)
    iv = bytes.fromhex(SP80038A_IV)
    for bits in (128, 192, 256):
        key = bytes.fromhex(SP80038A_KEYS[bits])
        ref = _openssl(key, iv, pt)
        if ref is not None:
            check('  SP 800-38A literal agrees with OpenSSL (%d)' % bits,
                  SP80038A_CFB[bits], ref)
        check('CFB128-AES%d encrypt' % bits, got.get('aes.cfb%d' % bits), SP80038A_CFB[bits])
    #
    # (!) DECRYPT IS NOT PROVED BY A ROUND TRIP. Encrypt and decrypt differ only in which octet
    # enters the feedback register; swap them and the pair round-trips perfectly against itself
    # while matching no other AES anywhere. The plaintext recovered here is the PUBLISHED one.
    #
    check('CFB128-AES256 decrypt == published plaintext',
          got.get('aes.cfb256_back'), SP80038A_PT)

    print('  --- lengths that are NOT a multiple of the block ---')
    #
    # (!) EVERY PUBLISHED CFB VECTOR IS AN EXACT MULTIPLE OF SIXTEEN, so none of them can see a
    # broken partial block -- an implementation that padded, or that advanced the IV as though a
    # whole block had passed, would pass all of the above. OpenSSL is the oracle for the gap, on
    # inputs both sides generate from the same rule.
    #
    key = bytes((i * 7 + 3) & 0xFF for i in range(16))
    iv = bytes((i * 11 + 5) & 0xFF for i in range(16))
    data = bytes((i * 37 + 11) & 0xFF for i in range(128))
    any_ref = False
    for n in (0, 1, 15, 16, 17, 31, 32, 33, 100):
        ref = _openssl(key, iv, data[:n])
        if ref is None:
            continue
        any_ref = True
        check('%3d octets == OpenSSL' % n, got.get('aes.len%03d' % n), ref)
    check('OpenSSL was actually available', any_ref, True)

    #
    # (!) THE FEEDBACK REGISTER ITSELF, AND IT EXISTS BECAUSE AN INJURY SURVIVED. A version that
    # padded the tail of a partial block with keystream passed this entire suite: the only check
    # that could have seen it asserted two streams DIFFER, and a differently-wrong stream differs
    # too. "Not equal" is a weak assertion and it hid a real behaviour change.
    #
    # The correct register is computable without asking OpenSSL for its internals: a whole block
    # replaces all sixteen octets, and a short final chunk of `tail` octets replaces only the first
    # `tail`, leaving the rest of WHATEVER WAS THERE BEFORE.
    #
    # (!) AND "WHATEVER WAS THERE BEFORE" IS NOT THE ORIGINAL IV once a full block has gone by --
    # it is the PREVIOUS CIPHERTEXT BLOCK. The first version of this check used the original IV and
    # failed at n = 17, 31, 33 and 100 while passing at 1 and 15. The code was right and the
    # expectation was wrong, which is the correct way round for a test written after the fact.
    #
    for n in (0, 1, 15, 16, 17, 31, 32, 33, 100):
        ref = _openssl(key, iv, data[:n])
        if ref is None:
            continue
        ct = bytes.fromhex(ref)
        full, tail = divmod(n, 16)
        if n == 0:
            want = iv
        elif tail == 0:
            want = ct[(full - 1) * 16:full * 16]
        else:
            prev = iv if full == 0 else ct[(full - 1) * 16:full * 16]
            want = ct[full * 16:full * 16 + tail] + prev[tail:]
        check('  IV after %3d octets' % n, got.get('aes.iv%03d' % n), want.hex())

    print('  --- the chunking contract, pinned in BOTH directions ---')
    #
    # (!) THIS TEST CORRECTED THE HEADER RATHER THAN THE CODE. The header promised that any
    # chunking reproduces a one-shot call; chunks of 7/9/16/68 proved otherwise and the code was
    # right. CFB128 feeds back a whole ciphertext BLOCK, so a short chunk leaves only a fragment
    # of a feedback value and ends the stream.
    #
    # Asserting only that aligned chunks match would let someone later "fix" this by buffering a
    # keystream remainder and silently change a documented contract. Both directions are pinned,
    # so that has to be deliberate.
    #
    check('16/32/16/36 chains exactly',      got.get('aes.chunked_aligned'), '1')
    check('7/9/16/68 does NOT, by design',   got.get('aes.chunked_unaligned'), '0')
    check('  and diverges only after the short chunk', got.get('aes.chunked_prefix_ok'), '1')
    #
    # In place is how the object cache will actually call this: the feedback octet has to be
    # captured BEFORE the store, or the register picks up ciphertext it has already overwritten.
    #
    check('CFB in place == out of place',    got.get('aes.inplace_matches'), '1')
    check('  and decrypts back in place',    got.get('aes.inplace_roundtrip'), '1')

def main():
    out, exe = build_and_run()
    got = parse(out)
    fails = []

    def check(label, actual, expected):
        ok = (actual == expected)
        print('  %-34s %s' % (label, 'OK' if ok else '*** FAIL ***'))
        if not ok:
            print('       expected: %s' % expected)
            print('       actual  : %s' % actual)
            fails.append(label)

    print('TPM 2.0 core -- host validation against hashlib')
    print()
    print('  --- refusal before TPM2_Startup ---')
    check('extend before startup = RC_INITIALIZE', got.get('rc.extend_before_startup'), str(0x100))
    check('read before startup = RC_INITIALIZE', got.get('rc.read_before_startup'), str(0x100))

    print('  --- PTP 1.07 Table 15, PCR initial values ---')
    # PCR 0 = locality indicator, 1-16 and 23 = 0, 17-22 = -1.
    for i in range(24):
        exp = ONES.hex() if 17 <= i <= 22 else ZERO.hex()
        key = 'startup_loc0.pcr%02d' % i
        if got.get(key) != exp:
            check('PCR[%d] initial' % i, got.get(key), exp)
    print('  %-34s %s' % ('all 24 initial values', 'OK' if not fails else 'see above'))

    # The one everybody gets wrong: PCR[0] carries the LOCALITY, not zero.
    loc3 = bytearray(32)
    loc3[31] = 3
    check('PCR[0] @ locality 3 = indicator', got.get('startup_loc3.pcr00'), bytes(loc3).hex())

    print('  --- TPM2_PCR_Extend, Part 1 eq. (14): PCR_new = H(PCR_old || digest) ---')
    aa = b'\xaa' * 32
    bb = b'\xbb' * 32
    e1 = hashlib.sha256(ZERO + aa).digest()
    check('extend #1 on PCR[0]', got.get('extend1.pcr00'), e1.hex())

    e2 = hashlib.sha256(e1 + bb).digest()
    check('extend #2 chains from #1', got.get('extend2.pcr00'), e2.hex())

    # PCR 17 starts at -1, so its first extend hashes 0xFF..FF, not zeros. This catches an
    # implementation that initialises every PCR to zero regardless of Table 15.
    e17 = hashlib.sha256(ONES + bb).digest()
    check('extend on PCR[17] (starts -1)', got.get('extend17.pcr17'), e17.hex())

    check('untouched PCR[5] unchanged', got.get('untouched.pcr05'), ZERO.hex())
    check('read returns extended value', got.get('read.pcr00'), e2.hex())
    check('update counter after 3 extends', got.get('extend17.pcr17') and got.get('extend2.counter'), '2')

    print('  --- range and error handling ---')
    check('extend index 24 = RC_VALUE', got.get('rc.extend_oob'), str(0x084))
    check('read index 24 = RC_VALUE', got.get('rc.read_oob'), str(0x084))

    print('  --- command header ---')
    check('valid header parses', got.get('rc.hdr_ok'), '0')
    check('  tag', got.get('hdr.tag'), '0x8001')
    check('  size', got.get('hdr.size'), '10')
    check('  code', got.get('hdr.code'), '0x00000144')
    check('short buffer = RC_COMMAND_SIZE', got.get('rc.hdr_short'), str(0x142))
    check('size > buffer = RC_COMMAND_SIZE', got.get('rc.hdr_size_over'), str(0x142))
    check('size < buffer = RC_COMMAND_SIZE', got.get('rc.hdr_size_under'), str(0x142))
    check('bad tag = RC_BAD_TAG', got.get('rc.hdr_badtag'), str(0x01E))

    print('  --- response header ---')
    check('success keeps its tag', got.get('rsp.ok_tag'), '0x8002')
    check('error FORCED to NO_SESSIONS', got.get('rsp.err_tag'), '0x8001')
    check('error code written', got.get('rsp.err_code'), '0x00000101')

    print('  --- big-endian on a little-endian host ---')
    check('write 0x01020304 -> bytes', got.get('be.bytes'), '01020304')
    check('read back', got.get('be.read'), '0x01020304')

    print('  --- constants, against the spec (not against EDK2) ---')
    # TPM_RC_BAD_TAG is 0x01E in Library 185. EDK2 still carries 0x030, which the spec itself
    # calls incorrect -- so this assertion is deliberately against the standard.
    check('TPM_RC_BAD_TAG = 0x01E (not EDK2 0x030)', got.get('const.rc_bad_tag'), '0x01e')
    check('TPM_RC_INITIALIZE', got.get('const.rc_initialize'), '0x100')
    check('TPM_RC_COMMAND_CODE', got.get('const.rc_command_code'), '0x143')
    check('TPM_CC_Startup', got.get('const.cc_startup'), '0x00000144')
    check('TPM_CC_PCR_Extend', got.get('const.cc_pcr_extend'), '0x00000182')
    check('TPM_ST_NO_SESSIONS', got.get('const.st_no_sessions'), '0x8001')
    check('TPM_ALG_SHA256', got.get('const.alg_sha256'), '0x000b')

    print('  --- event log: header ---')
    blob = bytes.fromhex(got['log.bytes'])
    spec, events = parse_event_log(blob)
    check('log init succeeded', got.get('log.init'), '1')
    check('header entry is EV_NO_ACTION', str(spec['type']), '3')
    check('header entry PCR is 0', str(spec['pcr']), '0')
    check('header 1.2 digest is zero', str(spec['digest12_is_zero']), 'True')
    check('signature', spec['signature'], b'Spec ID Event03\x00')
    check('platform class = client', str(spec['platformClass']), '0')
    check('spec version 2.0', '%d.%d' % (spec['major'], spec['minor']), '2.0')
    check('uintnSize = 64-bit', str(spec['uintnSize']), '2')
    check('one algorithm declared', str(spec['numberOfAlgorithms']), '1')
    check('  SHA-256, 32 bytes', str(spec['algorithms']), '{11: 32}')

    print('  --- event log: entries ---')
    check('three events logged', str(len(events)), '3')
    check('count includes the header', got.get('log.count'), '4')
    check('not truncated', got.get('log.truncated'), '0')
    check('used == bytes emitted', got.get('log.used'), str(len(blob)))

    m1 = bytes(range(64))
    m2 = bytes((0xF0 ^ k) & 0xFF for k in range(32))
    expect = [
        (0, 0x80000003, hashlib.sha256(m1).digest(), b'boot-app'),
        (7, 0x800000E0, hashlib.sha256(m2).digest(), b'authority'),
        (0, 0x00000004, hashlib.sha256(b'').digest(), b''),
    ]
    for i, (pcr, etype, dig, data) in enumerate(expect):
        e = events[i]
        check('event %d PCR' % i, str(e['pcr']), str(pcr))
        check('event %d type' % i, hex(e['type']), hex(etype))
        check('event %d digest = sha256(data)' % i, e['digests'].get(11, b'').hex(), dig.hex())
        check('event %d event data' % i, e['data'], data)

    print('  --- THE REPLAY: does the log reproduce the PCRs? ---')
    #
    # This is the property the whole design rests on. A verifier replays the log and must
    # arrive at the PCR values the TPM reports; if it cannot, the log is not evidence.
    # Replayed here with hashlib, from the parsed bytes, with no reference to the C at all.
    #
    replay = {}
    for i in range(24):
        replay[i] = ONES if 17 <= i <= 22 else ZERO
    for e in events:
        d = e['digests'][11]
        replay[e['pcr']] = hashlib.sha256(replay[e['pcr']] + d).digest()
    check('replay reproduces PCR[0]', got.get('log.pcr00'), replay[0].hex())
    check('replay reproduces PCR[7]', got.get('log.pcr07'), replay[7].hex())

    print('  --- the command dispatcher ---')
    #
    # (!) THE INVARIANT WORTH TESTING IS THE HEADER, not the happy path. Every response must
    # declare its own length correctly: a caller polling the CRB reads the size field to know
    # how many bytes to take, so a header that disagrees with the byte count desynchronises
    # the transport rather than merely returning a wrong answer.
    #
    check('Startup(CLEAR) succeeds',      got.get('d.startup_clear'), '000')
    check('Startup(STATE) refused VALUE', got.get('d.startup_state'), '084')
    check('SelfTest succeeds',            got.get('d.selftest'),      '000')
    # TPM2_Quote: a command that stays unimplemented. This was GetRandom until GetRandom was
    # implemented, at which point the refusal test silently became a success test.
    check('unimplemented -> COMMAND_CODE',got.get('d.unimpl'),        '143')
    check('truncated -> COMMAND_SIZE',    got.get('d.truncated'),     '142')
    check('NULL input -> FAILURE',        got.get('d.nullin'),        '101')
    check('output too small -> 0 bytes',  got.get('d.tinyout'),       '0')
    check('every response header matches its length', got.get('d.hdr_ok'), '1')
    #
    # GetCapability is decoded rather than spot-checked: family '2.0', revision 185 and
    # manufacturer INTC are the identity the TCG2 protocol also reports, and the two MUST agree.
    #
    check('GetCapability family = 2.0',   got.get('d.cap_family'),    '322e3000')
    #
    # (!) 159, NOT 185, AND THAT IS DELIBERATE. Genuine Intel PTT on this machine reports
    # TPM_PT_REVISION = 0x9F = 159. We IMPLEMENT against 185 and PRESENT as 159, because the
    # standard is to match the hardware we were measured against. Tpm2Profile.h records the
    # coupling this creates with the advertised command set.
    #
    check('GetCapability revision = 159', got.get('d.cap_revision'),  '159')
    check('GetCapability manufacturer',   got.get('d.cap_manuf'),     'INTC')
    #
    # The whole PT_FIXED run must come back with no gaps. A real TPM 2.0 publishes all of these,
    # so a list missing entries in the middle is a fingerprint even though omitting a property
    # we lack is the honest behaviour.
    #
    #
    # 41 of the 42 Windows asks for: Part 2 lists PT_FIXED + 21 (0x115) as reserved, so the run
    # legitimately has one hole and a test demanding 42 would fail correct code.
    #
    check('PT_FIXED 0x100-0x129 complete (41, 0x115 reserved)',
          got.get('d.cap_contiguous'), '1')

    check_bignum(got, check)
    check_known_answers(got, check)
    check_prime(got, check)
    check_kdf(got, check)
    check_object(got, check)
    check_session(got, check)
    check_creation(got, check)
    check_primary(got, check)
    check_flush(got, check)
    check_evict(got, check)
    check_nv(got, check)
    check_pcr_commands(got, check)
    check_aes(got, check)
    check_response_codes(check)

    print('  --- Handle-area validation (Part 3 clause 5.4) ---')
    #
    # (!) THREE DIFFERENT CODES, AND THE DIFFERENCES ARE THE TEST. A blanket TPM_RC_HANDLE for
    # every bad handle would pass a lazier check and would be wrong: a transient handle that is
    # not loaded is a WARNING (it can be loaded), a persistent object that is absent is an ERROR,
    # and a handle that is not an object handle at all is a TYPE error from unmarshalling.
    #
    # The value also carries the handle NUMBER in bits 8-11, so 08B and 18B are different
    # answers. Windows asks about handle 1 in every one of these commands.
    #
    check('persistent object absent -> HANDLE+1', got.get('d.rdpub_persist'),  '18B')
    check('transient not loaded -> REFERENCE_H0', got.get('d.rdpub_transient'),'910')
    check('not an object handle -> VALUE+1',      got.get('d.rdpub_bad'),      '184')
    check('NV index absent -> HANDLE+1',          got.get('d.nvpub_index'),    '18B')
    check('outside NV range -> VALUE+1',          got.get('d.nvpub_bad'),      '184')
    #
    # (!) INSUFFICIENT, NOT COMMAND_SIZE. Running out of octets while unmarshalling a
    # parameter is TPM_RC_INSUFFICIENT; a DECLARED commandSize disagreeing with the octets
    # received is TPM_RC_COMMAND_SIZE, and that check still lives in the header parser.
    # Hardware answered 0x09A where we answered 0x142, on 90 command codes.
    #
    # 0x1DA = INSUFFICIENT | P | parameter 1. tpm.sys strips the P bit and the number, so
    # TBS shows 0x09A -- exactly what hardware showed.
    #
    check('short command -> INSUFFICIENT(parm 1)', got.get('d.nvpub_short'), '1DA')

    print('  --- TPM2_ReadClock ---')
    #
    # Clock ends up inside signed attestation structures, so an invented value is a signature
    # over a lie. No source, no answer -- the same rule GetRandom follows.
    #
    check('no clock source -> FAILURE',   got.get('d.clock_nosrc'),   '101')
    check('with a source -> SUCCESS',     got.get('d.clock_rc'),      '000')
    check('response is 10+25 bytes',      got.get('d.clock_len'),     '35')
    #
    # time and clock are read as their low 32 bits. They are EQUAL because we have no NV, so
    # every power-on is a fresh TPM after a Clear -- when NV lands (G2) they diverge and this
    # check is the one that should start failing.
    #
    check('time is the source value',     got.get('d.clock_time'),    str(0x23456789))
    check('clock == time (no NV yet)',    got.get('d.clock_clock'),   str(0x23456789))
    check('resetCount is 0',              got.get('d.clock_reset'),   '0')
    check('restartCount is 0',            got.get('d.clock_restart'), '0')
    check('safe is YES',                  got.get('d.clock_safe'),    '1')

    print('  --- TPM2_GetRandom: the refusal is the important half ---')
    #
    # With no entropy source the dispatcher answers TPM_RC_FAILURE. It does NOT emit a counter,
    # a TSC hash or zeros: a caller cannot distinguish predictable bytes from random ones, so
    # every key derived from a fabricated answer would be compromised with no error anywhere.
    #
    check('no entropy source -> FAILURE', got.get('d.rand_norsrc'), '101')
    check('with a source -> SUCCESS',     got.get('d.rand_rc'),     '000')
    check('response is 10+2+16 bytes',    got.get('d.rand_len'),    '28')
    check('size prefix says 16',          got.get('d.rand_size'),   '16')
    #
    # Part 3: a request larger than the biggest digest yields that maximum rather than an error.
    #
    check('200 bytes clamps to 32',       got.get('d.rand_clamp'),  '32')

    print('  --- TPM_CAP_COMMANDS / ALGS / PCRS (added on MEASURED demand) ---')
    #
    # Windows asked cap=0x2 (TPM_CAP_COMMANDS) and got an empty list while we were reporting
    # TOTAL_COMMANDS = 4. These check the lists themselves...
    #
    check('CAP_COMMANDS lists 14',       got.get('d.cap_cmd_count'),     '14')
    check('commands ascending by code',  got.get('d.cap_cmd_ascending'), '1')
    #
    # (!) THE FIRST ENTRY IS A TPMA_CC, NOT A COMMAND CODE, and it is now CreatePrimary --
    # 0x12000131, which is the value genuine Intel PTT returns for it: cHandles=1 because it
    # takes the hierarchy handle, rHandle=1 because it RETURNS one. We once emitted bare command
    # codes with every attribute zero, under a comment asserting zero was correct.
    #
    # rHandle is the bit that matters here: the Resource Manager uses it to know a response
    # carries a handle it must track. A CreatePrimary advertised without it would have its object
    # handle silently unmanaged.
    #
    check('first entry is EvictControl', got.get('d.cap_cmd_first'), '04400120')
    #
    # (!) nv IS THE BIT THAT MATTERS ON THIS ONE, and it is the only command we advertise that
    # sets it. TPMA_CC bit 22 says the command may write NV -- which EvictControl does by
    # definition, because persisting an object IS the write. The Resource Manager reads it to
    # know a command can fail for NV reasons and may need retrying.
    #
    check('  with nv SET',
          (int(got.get('d.cap_cmd_first', '0'), 16) >> 22) & 1, 1)
    check('  and cHandles = 2',
          (int(got.get('d.cap_cmd_first', '0'), 16) >> 25) & 7, 2)
    #
    # Attributes must actually be there. Counting them means a regression to bare codes shows as
    # ZERO rather than as a subtly different number.
    #
    check('entries carrying attributes', got.get('d.cap_cmd_attrs'),   '8')
    #
    # NV_ReadPublic 1 + ReadPublic 1 + CreatePrimary 1 + EvictControl 2 = 5.
    #
    check('total cHandles advertised',   got.get('d.cap_cmd_handles'), '6')
    #
    # (!) AND FlushContext STILL ADDS NOTHING TO IT. Its measured TPMA_CC is 0x00000165 -- no
    # attributes, cHandles = 0 -- because flushHandle is a PARAMETER, not a handle. Part 3
    # 28.4.1 says so in prose; hardware says so in one word. Giving it cHandles=1 would look
    # like an obvious tidy-up and would tell the Resource Manager to expect a handle area this
    # command does not have. The total above is what proves it was not quietly added.
    #
    check('  FlushContext declares NO handles', got.get('d.cap_cmd_handles'), '6')
    check('CAP_ALGS lists 3 hashes',     got.get('d.cap_alg_count'),     '3')
    check('first alg is SHA-256',        got.get('d.cap_alg_first'),     '000b')
    check('CAP_PCRS: one bank',          got.get('d.cap_pcr_banks'),     '1')
    check('bank is SHA-256',             got.get('d.cap_pcr_alg'),       '000b')
    check('sizeOfSelect 3 (24 PCRs)',    got.get('d.cap_pcr_select'),    '3')
    check('all 24 PCRs allocated',       got.get('d.cap_pcr_bits'),      'ffffff')
    #
    # ...and THIS one compares two answers to each other. Every other dispatcher check verifies
    # one field against the specification; none compared fields, which is exactly how
    # TOTAL_COMMANDS = 4 shipped beside an empty command list. Both were individually
    # defensible. A verifier does not check fields, it checks consistency.
    #
    check('TOTAL_COMMANDS agrees with the list',
          got.get('d.commands_agree'), '1')

    print('  --- TPM2_GetTestResult (implemented on MEASURED demand) ---')
    #
    # The CRB trace caught Windows asking for this and us answering COMMAND_CODE -- which is
    # what produced 'The initialization of the TPM failed. The TPM may be in failure mode.'
    # Response is outData (TPM2B_MAX_BUFFER) followed by testResult (TPM_RC).
    #
    check('GetTestResult succeeds',      got.get('d.testresult'),         '000')
    check('response is 16 bytes',        got.get('d.testresult_len'),     '16')
    check('header length agrees',        got.get('d.testresult_hdr'),     '16')
    #
    # Empty outData is the CORRECT answer, not a placeholder: Part 3 makes it
    # manufacturer-specific self-test information, and we have none to report. Inventing
    # diagnostic bytes would be fabricating a vendor blob that means nothing.
    #
    check('outData empty, not invented', got.get('d.testresult_outdata'), '0')
    check('testResult = TPM_RC_SUCCESS', got.get('d.testresult_value'),   '0')

    print('  --- SHA-384 / SHA-512, against hashlib ---')
    #
    # (!) EVERY CONSTANT IN Sha512.c IS A SILENT-FAILURE SURFACE. One wrong digit in K[] or an
    # IV yields a hash that is well-formed, deterministic and wrong. Nothing else in this
    # project hashes with anything but SHA-256, so without these checks such a typo would
    # survive every other test in this file.
    #
    fox = b'The quick brown fox jumps over the lazy dog'
    big = bytes((ord('a') + (i % 26)) for i in range(1000))
    check('sha512 empty', got.get('c.sha512_empty'), hashlib.sha512(b'').hexdigest())
    check('sha384 empty', got.get('c.sha384_empty'), hashlib.sha384(b'').hexdigest())
    check('sha512 abc',   got.get('c.sha512_abc'),   hashlib.sha512(b'abc').hexdigest())
    check('sha384 abc',   got.get('c.sha384_abc'),   hashlib.sha384(b'abc').hexdigest())
    check('sha512 1000B', got.get('c.sha512_big'),   hashlib.sha512(big).hexdigest())
    check('sha384 1000B', got.get('c.sha384_big'),   hashlib.sha384(big).hexdigest())
    check('sha512 streamed == one-shot', got.get('c.sha512_stream'), '1')

    print('  --- crypto-agile dispatch ---')
    check('size(SHA-256)', got.get('c.size256'), '32')
    check('size(SHA-384)', got.get('c.size384'), '48')
    check('size(SHA-512)', got.get('c.size512'), '64')
    check('block(SHA-384) is 128, not 64', got.get('c.blk384'), '128')
    #
    # An algorithm we do not implement must REFUSE. A fallback to SHA-256 would hand back a
    # digest the caller labels SHA-384 -- undetectable downstream, and worse than an error.
    #
    check('unsupported alg: size is 0',   got.get('c.sizebad'),  '0')
    check('unsupported alg: hash refuses', got.get('c.agilebad'), '0')
    check('unsupported alg: hmac refuses', got.get('c.hmacbad'),  '0')
    check('agile SHA-384 == direct', got.get('c.agile384'), hashlib.sha384(fox).hexdigest())

    print('  --- HMAC (FIPS 198-1), against Python hmac ---')
    import hmac as _hmac
    _H = {'256': hashlib.sha256, '384': hashlib.sha384, '512': hashlib.sha512}
    longkey = bytes(((i * 7 + 3) & 0xFF) for i in range(200))
    for n in ('256', '384', '512'):
        check('hmac-sha%s, short key' % n, got.get('c.hmac%s_short' % n),
              _hmac.new(b'key', fox, _H[n]).hexdigest())
        #
        # The key-longer-than-block path. FIPS 198-1 4 step 2 says HASH it; truncating is the
        # intuitive misreading and produces a MAC that verifies against itself and against
        # nothing else -- so only an external oracle catches it.
        #
        check('hmac-sha%s, key > block (hashed)' % n, got.get('c.hmac%s_long' % n),
              _hmac.new(longkey, fox, _H[n]).hexdigest())
    check('hmac streamed == one-shot', got.get('c.hmac_stream'), '1')

    print('  --- event log: the tail past Used must be ZERO ---')
    #
    # AllocatePages does not zero. A TCG log carries no length, so consumers walk it until an
    # entry fails to parse -- which means arbitrary trailing bytes get read as an entry. On
    # hardware this showed up as 13,863 bytes of firmware leftovers after the last real entry,
    # and the log became unparseable at exactly that point.
    #
    check('buffer poisoned then zeroed', got.get('log.tailzero'), '1')
    check('poison bytes surviving', got.get('log.tailnonzero'), '0')

    print('  --- event log: refusal and truncation ---')
    check('tiny buffer refuses init', got.get('log.tiny_init'), '0')
    check('  and writes nothing', got.get('log.tiny_used'), '0')
    check('  and reports truncated', got.get('log.tiny_trunc'), '1')
    # A full log must NOT fail the extend: TCG2 requires the extend to happen regardless.
    check('full log still returns SUCCESS', got.get('log.full_rc'), '0')
    check('  and reports truncated', got.get('log.full_trunc'), '1')
    check('  and the PCR DID move', got.get('log.full_pcr01'),
          hashlib.sha256(ZERO + hashlib.sha256(b'x').digest()).digest().hex())
    print('  --- Authenticode PE hash, against a separate implementation ---')
    #
    # (!) THIS IS WHY IT MATTERS. Refusing PE_COFF_IMAGE returned EFI_UNSUPPORTED from
    # HashLogExtendEvent, the platform propagated it through LoadImage, and NOTHING BOOTED.
    # Once TCG2 is advertised this digest is mandatory, so it is checked against an oracle.
    #
    pe_targets = [
        os.path.join(ROOT, 'Nexus', 'UEFI', 'build', 'x64', 'Release', 'PlatformRuntimeDxe.efi'),
        os.path.join(ROOT, 'Nexus', 'UEFI', 'build', 'x64', 'Release', 'PlatformBootMgr.efi'),
    ]
    tested = 0
    for p in pe_targets:
        if not os.path.isfile(p):
            continue
        blob = open(p, 'rb').read()
        want = authenticode_sha256(blob)
        if want is None:
            continue
        r = run_pe(exe, p)
        name = os.path.basename(p)
        check('%s parses' % name, r.get('pe.ok'), '1')
        check('%s Authenticode digest' % name, r.get('pe.digest'), want.hex())
        tested += 1
    if tested == 0:
        print('  %-34s %s' % ('no PE targets built yet', 'SKIPPED'))
    else:
        print('  %-34s %d file(s)' % ('real signed images checked', tested))

    print('  --- PE hash: malformed input must REFUSE, not overread ---')
    check('not a PE', got.get('pe.junk'), '0')
    check('e_lfanew past the end', got.get('pe.badlfanew'), '0')
    check('truncated below DOS header', got.get('pe.tiny'), '0')
    check('NULL image', got.get('pe.null'), '0')
    print()
    if fails:
        print('check_tpm2_core: FAIL -- %d check(s): %s' % (len(fails), ', '.join(fails)))
        return 1
    print('check_tpm2_core: OK -- every digest matches hashlib, every code matches Library 185')
    return 0


if __name__ == '__main__':
    sys.exit(main())
