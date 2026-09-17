# -*- coding: utf-8 -*-
"""How much of TPM 2.0 do we implement? Measured against Part 2, not estimated.

    python tools/tpm2_coverage.py            summary
    python tools/tpm2_coverage.py --all      every command, implemented or not
    python tools/tpm2_coverage.py --regen    re-extract the command list from the Part 2 PDF

THE POINT. The objective (spec §1) is a COMPLETE TPM 2.0, feature for feature -- not the subset
Windows happens to exercise on this machine. That is a target you can drift away from without
noticing, precisely because this project is driven by a demand trace: the trace only ever names
what one OS asked for on one boot, so "nothing refused" can look like "finished".

So the denominator comes from the SPECIFICATION and the numerator from the SOURCE. Neither is
hand-maintained, and disagreeing with either one is a build failure rather than an opinion.

(!) THE COMMAND LIST IS DATA EXTRACTED FROM THE PDF, NOT TYPED FROM MEMORY. An earlier
hand-written version of this table had 34 of its 46 entries wrong. `--regen` rebuilds
tools/tpm2_commands.txt from the TCG Part 2 PDF, pairing each code with the name that immediately
precedes it in the text stream and refusing to emit unless six known-good anchors survive the
pairing.

`tpm2_commands.txt` is committed, so `--regen` is only needed when moving to a new spec revision.
Point TCG_SPEC_DIR at a directory holding the TCG Library PDFs; the specifications are published
by the Trusted Computing Group and are not redistributed here.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIST = os.path.join(ROOT, 'tools', 'tpm2_commands.txt')
DISPATCH = os.path.join(ROOT, 'Nexus', 'UEFI', 'NexusTpmDxe', 'Tpm2Dispatch.c')

#
# Only --regen needs this, and only when moving to a new spec revision. TCG publishes the Library
# specifications; they are not redistributed with this repository.
#
PDF = os.path.join(os.environ.get('TCG_SPEC_DIR', os.path.join(ROOT, 'spec')),
                   'TPM-2.0-Library-Part2-Structures-v185.pdf')

#
# Anchors: codes Windows demonstrably exercises against this implementation and gets sensible
# answers for. If a re-extraction disagrees with any of them, the pairing is wrong and no table
# is written -- a decoder with confident wrong names is worse than one that prints hex.
#
ANCHORS = {
    'TPM2_SelfTest': 0x143, 'TPM2_Startup': 0x144, 'TPM2_GetCapability': 0x17A,
    'TPM2_GetRandom': 0x17B, 'TPM2_GetTestResult': 0x17C, 'TPM2_CreatePrimary': 0x131,
}

#
# Commands with a SPECIFIC known-answer test, beyond the universal sweep that exercises all 140
# codes for correct refusal and response-header sanity.
#
# (!) IMPLEMENTED IS NOT VERIFIED, and conflating them is how a project convinces itself it is
# further along than it is. This list is what check_tpm2_core.py cross-checks: each value must
# be a key the harness actually emits, and a stale entry fails the suite rather than inflating
# the figure.
#
VERIFIED = {
    0x120: 'evict.rsp',            # TPM2_EvictControl   -- the exact bytes Windows sent
    0x131: 'pri.rsp',              # TPM2_CreatePrimary  -- the whole response decoded
    0x143: 'kat.selftest_rc',      # TPM2_SelfTest
    0x165: 'flush.disp_rsp',        # TPM2_FlushContext   -- the exact bytes Windows sent
    0x144: 'kat.startup_rc',       # TPM2_Startup
    0x169: 'd.nvpub_index',        # TPM2_NV_ReadPublic  -- handle-area validation
    0x173: 'd.rdpub_persist',      # TPM2_ReadPublic     -- handle-area validation
    0x17A: 'kat.family_value',     # TPM2_GetCapability  -- spec-defined family indicator
    0x17B: 'kat.random_bytes',     # TPM2_GetRandom      -- deterministic source
    0x17C: 'kat.testresult_body',  # TPM2_GetTestResult
    0x181: 'kat.clock_body',       # TPM2_ReadClock      -- fixed clock
}
#
# Rough functional grouping, so "48 of 134" becomes a plan rather than a number. A command may
# match several patterns; the FIRST match wins, so order is significance order.
#
GROUPS = [
    ('Startup and self-test',   r'Startup|Shutdown|SelfTest|GetTestResult'),
    ('Capability and misc',     r'GetCapability|GetRandom|StirRandom|ReadClock|ClockSet|'
                                r'ClockRateAdjust|TestParms|SetCapability|ReadOnlyControl'),
    ('PCR',                     r'PCR_'),
    ('Hierarchy and control',   r'Hierarchy|Clear|ChangeEPS|ChangePPS|SetPrimaryPolicy|'
                                r'PP_Commands|SetAlgorithmSet|DictionaryAttack'),
    ('NV storage',              r'NV_'),
    ('Object and key',          r'Create|Load|ReadPublic|ActivateCredential|MakeCredential|'
                                r'ObjectChangeAuth|Duplicate|Rewrap|Import|EvictControl'),
    ('Sessions and context',    r'StartAuthSession|ContextLoad|ContextSave|FlushContext|'
                                r'PolicyRestart'),
    ('Policy',                  r'Policy'),
    ('Signing and attestation', r'Sign|Certify|Quote|GetTime|GetSessionAuditDigest|'
                                r'GetCommandAuditDigest|VerifySignature|Commit|SetCommandCode'),
    ('Symmetric and hashing',   r'EncryptDecrypt|Hash|HMAC|MAC|SequenceUpdate|SequenceComplete|'
                                r'HashSequenceStart|EventSequence'),
    ('Asymmetric primitives',   r'RSA_|ECDH|ECC_|ZGen|EC_Ephemeral|Encapsulate|Decapsulate'),
    ('Field upgrade',           r'FieldUpgrade|FirmwareRead'),
    ('Attached components',     r'^TPM2_AC_|Policy_AC_'),
    ('Unseal',                  r'Unseal'),
]


def load_commands():
    if not os.path.isfile(LIST):
        sys.exit('%s missing -- run with --regen, with TCG_SPEC_DIR pointing at a directory\n'
                 'holding the TCG TPM 2.0 Library PDFs.' % LIST)
    out = {}
    for line in open(LIST, encoding='utf-8'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        code, name = line.split(' ', 1)
        out[int(code, 16)] = name
    return out


def regen():
    """Re-extract from the PDF. See the module docstring for why this is data, not a literal."""
    try:
        from pypdf import PdfReader
    except ImportError:
        sys.exit('pypdf is needed for --regen:  python -m pip install pypdf')
    if not os.path.isfile(PDF):
        sys.exit('Part 2 PDF not found at %s' % PDF)

    TOKEN = re.compile(r'^(TPM_CC_[A-Za-z0-9_]+|Reserved|0x[0-9A-Fa-f]{8})$')
    reader = PdfReader(PDF)
    pairs = {}

    for pageno in range(len(reader.pages)):
        seq = []

        def visit(text, cm, tm, font, size, _q=seq):
            t = (text or '').strip()
            if TOKEN.match(t):
                _q.append(t)

        reader.pages[pageno].extract_text(visitor_text=visit)
        #
        # The table's text stream interleaves name, code, name, code in reading order, so each
        # code belongs to the name immediately before it. That rule needs no counting and
        # survives "Reserved" rows, which carry a code and no command name.
        #
        pending = None
        for tok in seq:
            if tok.startswith('0x'):
                v = int(tok, 16)
                if pending and 0x11F <= v <= 0x1FF:
                    pairs.setdefault(pending, v)
                pending = None
            else:
                pending = tok

    named = {n.replace('TPM_CC_', 'TPM2_'): v for n, v in pairs.items()
             if n not in ('Reserved', 'TPM_CC_FIRST', 'TPM_CC_LAST')}

    bad = [n for n, v in ANCHORS.items() if named.get(n) != v]
    if bad:
        for n in bad:
            print('  ANCHOR FAIL %s: got %s want 0x%03X' % (n, named.get(n), ANCHORS[n]))
        sys.exit('  pairing rejected -- no table written')

    by_code = {}
    for n, v in named.items():
        by_code.setdefault(v, []).append(n)

    with open(LIST, 'w', encoding='utf-8', newline='\n') as f:
        f.write('# TPM_CC, extracted from TPM 2.0 Library Part 2 v185 by tools/tpm2_coverage.py\n')
        f.write('# --regen. Do not hand-edit: regenerate it. Aliases share a code and are joined\n')
        f.write('# with "/" (TPM2_HMAC/TPM2_MAC is a real one -- Part 2 says a TPM implements one\n')
        f.write('# or the other, never both, because there is no way to tell them apart).\n')
        for v in sorted(by_code):
            f.write('0x%08X %s\n' % (v, '/'.join(sorted(by_code[v]))))
    print('  wrote %s: %d commands, all %d anchors OK' % (LIST, len(by_code), len(ANCHORS)))


def implemented():
    """The codes our dispatcher actually answers, read from its command table."""
    src = open(DISPATCH, encoding='utf-8').read()
    tbl = src[src.index('mOurCommands[] = {'):]
    tbl = tbl[:tbl.index('};')]
    codes = [int(c, 16) for c in re.findall(r'/\* (0x[0-9A-Fa-f]+) \*/', tbl)]

    m = re.search(r'#define TPM2_OUR_COMMAND_COUNT\s+(\d+)', src)
    declared = int(m.group(1)) if m else -1
    #
    # (!) THE SAME CROSS-CHECK THE COMPILE-TIME ASSERT MAKES, repeated here because this tool is
    # read by a human deciding what to build next. A count that disagrees with the table has
    # shipped twice in this project.
    #
    if declared != len(codes):
        sys.exit('  TPM2_OUR_COMMAND_COUNT is %d but the table has %d entries'
                 % (declared, len(codes)))
    return set(codes)


def group_of(name):
    for label, pat in GROUPS:
        if re.search(pat, name):
            return label
    return 'Other'


def main():
    if '--regen' in sys.argv:
        regen()
        return 0

    all_cmds = load_commands()
    have = implemented()

    unknown = have - set(all_cmds)
    if unknown:
        sys.exit('  dispatcher answers codes absent from Part 2: %s'
                 % ', '.join('0x%X' % c for c in sorted(unknown)))

    if '--brief' in sys.argv:
        print('tpm2_coverage: %d of %d commands implemented (%.1f%%), %d specifically verified'
              ' -- target is all of them'
              % (len(have), len(all_cmds), 100.0 * len(have) / len(all_cmds),
                 len(have & set(VERIFIED))))
        return 0

    print('=' * 78)
    print(' TPM 2.0 COMMAND COVERAGE -- Library Part 2 v185')
    print('=' * 78)
    print()
    print('  The objective (spec section 1) is the WHOLE specification, feature for')
    print('  feature. The denominator is the SPECIFICATION; the numerator is our source.')
    print()

    buckets = {}
    for code, name in all_cmds.items():
        buckets.setdefault(group_of(name), []).append((code, name))

    order = [g for g, _ in GROUPS] + ['Other']
    print('  %-26s %8s %8s   %s' % ('area', 'done', 'total', 'progress'))
    for label in order:
        rows = buckets.get(label)
        if not rows:
            continue
        done = sum(1 for c, _ in rows if c in have)
        bar = '#' * int(round(20.0 * done / len(rows))) + '.' * (20 - int(round(20.0 * done / len(rows))))
        print('  %-26s %8d %8d   %s' % (label, done, len(rows), bar))

    print()
    print('  %-26s %8d %8d   %.1f%%'
          % ('TOTAL', len(have), len(all_cmds), 100.0 * len(have) / len(all_cmds)))
    print()
    #
    # (!) TWO DIFFERENT NUMBERS. "Implemented" is a claim about the source; "verified" is a claim
    # about behaviour, and only the second one means anything is right.
    #
    unverified = sorted(have - set(VERIFIED))
    print('  verified with a specific known answer : %d of %d implemented'
          % (len(have & set(VERIFIED)), len(have)))
    if unverified:
        print('  IMPLEMENTED BUT NOT SPECIFICALLY VERIFIED:')
        for c in unverified:
            print('    0x%08X  %s' % (c, all_cmds.get(c, '?')))
    print('  every one of the %d codes in range is exercised for correct refusal and'
          % (max(all_cmds) - min(all_cmds) + 1))
    print('  response-header sanity by the sweep in check_tpm2_core.py.')
    print()

    if '--brief' in sys.argv:
        return 0

    if '--all' in sys.argv:
        print('  --- every command ---')
        for label in order:
            rows = sorted(buckets.get(label, []))
            if not rows:
                continue
            print('  %s' % label)
            for code, name in rows:
                print('    [%s] 0x%08X  %s' % ('x' if code in have else ' ', code, name))
        print()

    missing = sorted(c for c in all_cmds if c not in have)
    print('  %d commands remain. Nothing here is out of scope; the order is set by' % len(missing))
    print('  measured demand (the CRB census) and by what each one depends on.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
