/**
 * @file PtSelfTest.c
 * @brief Prove the PT packet decoder against a stream whose answer is KNOWN. No kernel involved.
 *
 * ⚠ THE FIXTURE IS DELIBERATELY AWKWARD, and that is the lesson from I-02: a self-test built on the
 * tidiest possible input tests the one case where a defect is invisible. A page-ALIGNED alias
 * fixture hid a doubled page offset and bugchecked the machine while reporting green. So this
 * stream contains, on purpose:
 *
 *   - GARBAGE BEFORE THE PSB, because a wrapped region always begins mid-packet. A fixture starting
 *     at a clean PSB would never exercise the search at all.
 *   - a FULL 8-byte IP followed by COMPRESSED ones at 2, 4 and 6 bytes, so every width that inherits
 *     high bits actually has something to inherit them from. Compression against a zero previous IP
 *     would pass with the inheritance code deleted.
 *   - a SIGN-EXTENDED 6-byte IP with bit 47 SET, whose correct answer has the top 16 bits ones. Get
 *     that wrong and every kernel address decodes as a usermode one -- plausible, and wrong.
 *   - a SUPPRESSED IP (IPBytes 0): a real packet carrying no address, which must be counted
 *     separately rather than dropped or invented.
 *   - an UNKNOWN OPCODE at the end, to prove the decoder STOPS rather than resynchronising.
 *
 * A wrong mask in the packet table does not produce an error. It produces plausible, well-formed
 * addresses that were never executed -- the worst output this project can generate. This runs first.
 */

#include <stdio.h>
#include <string.h>
#include "PtDecode.h"

int
PtDecodeSelfTest(
    void
    )
{
    printf("==============================================================================\n");
    printf(" PLATFORMCTL : trace decode --selftest  (decoder vs a known stream, no kernel)\n");
    printf("==============================================================================\n");

    unsigned char S[256];
    unsigned n = 0;

    /* Pre-PSB garbage -- what a wrapped region looks like at offset 0. */
    S[n++] = 0xAB; S[n++] = 0xCD; S[n++] = 0xEF; S[n++] = 0x77; S[n++] = 0x99;

    const unsigned PsbAt = n;
    for (int i = 0; i < 8; i++) { S[n++] = 0x02; S[n++] = 0x82; }
    S[n++] = 0x02; S[n++] = 0x23;                        /* PSBEND */

    S[n++] = 0x00;                                       /* PAD */

    /*
     * ⚠ 0x06, NOT 0x02. The first draft of this fixture used 0x02 and commented it "TNT8 -- bit 0
     * clear, not PAD", and the decoder stopped dead on it. It was right to: 0x02 is the EXT opcode,
     * the two-byte-opcode escape. A short TNT is identified by a MASK (bit 0 clear) while PAD and
     * EXT are identified by EXACT VALUE, so both must be tested first -- which is the dispatch order
     * libipt uses and the order the decoder uses.
     *
     * 0x06 is unambiguous: bit 0 clear, not 0x00, not 0x02; (0x06 & 3) == 2 so it is not CYC; and
     * (0x06 & 0x1F) matches no TIP-family opcode.
     *
     * Worth keeping as a note rather than a silent correction, because the failure was in the TEST
     * and the decoder's refusal to guess is exactly what surfaced it.
     */
    S[n++] = 0x06;                                       /* TNT8 */

    /* FUP, IPBytes=6 -> full 8 bytes: 0xFFFFF80011223344 */
    S[n++] = (unsigned char)(0x1D | (6u << 5));
    S[n++] = 0x44; S[n++] = 0x33; S[n++] = 0x22; S[n++] = 0x11;
    S[n++] = 0x00; S[n++] = 0xF8; S[n++] = 0xFF; S[n++] = 0xFF;

    /* TIP, IPBytes=1 -> 2 bytes, upper 48 inherited: 0xFFFFF80011225566 */
    S[n++] = (unsigned char)(0x0D | (1u << 5));
    S[n++] = 0x66; S[n++] = 0x55;

    /* TIP.PGE, IPBytes=2 -> 4 bytes, upper 32 inherited: 0xFFFFF800AABBCCDD */
    S[n++] = (unsigned char)(0x11 | (2u << 5));
    S[n++] = 0xDD; S[n++] = 0xCC; S[n++] = 0xBB; S[n++] = 0xAA;

    /* TIP, IPBytes=3 -> 6 bytes SIGN-EXTENDED from bit 47. 0x8000DEADBEEF has bit 47 set, so the
     * right answer is 0xFFFF8000DEADBEEF and the wrong one is 0x00008000DEADBEEF. */
    S[n++] = (unsigned char)(0x0D | (3u << 5));
    S[n++] = 0xEF; S[n++] = 0xBE; S[n++] = 0xAD; S[n++] = 0xDE; S[n++] = 0x00; S[n++] = 0x80;

    /* TIP.PGD, IPBytes=0 -> a real packet with NO address. */
    S[n++] = (unsigned char)(0x01 | (0u << 5));

    S[n++] = 0x99; S[n++] = 0x00;                        /* MODE */

    /*
     * ==== TIMING AND PTWRITE PAYLOADS (D117) ====
     *
     * These packets were already SIZED correctly and their contents thrown away. The fixtures below
     * are chosen so that discarding a payload, or reading it with the wrong shift, FAILS -- and each
     * one is awkward on purpose:
     */

    /* TSC: 56-bit, little-endian, and deliberately NOT a round number -- every one of the seven
     * bytes is distinct, so a wrong shift or a truncation to 32 bits gives a different answer.
     * Expected: 0x77665544332211. */
    const unsigned TscAt = n;
    S[n++] = 0x19;
    S[n++] = 0x11; S[n++] = 0x22; S[n++] = 0x33; S[n++] = 0x44;
    S[n++] = 0x55; S[n++] = 0x66; S[n++] = 0x77;

    /*
     * ⚠ MTC WITH CTC = 0, AND THAT IS THE ENTIRE POINT OF THIS FIXTURE. 0 is a perfectly valid CTC
     * value, so if "no MTC seen" were represented as 0 this packet would be indistinguishable from
     * absence. A valid value doubling as the unset sentinel cost a hardware run earlier today on
     * `trace alloc 0`. The decoder uses 0x100, and this fixture is the known-bad that proves it:
     * revert MtcFirst's initialiser to 0 and this case still reads 0, so the assertion below
     * checks the COUNT as well as the value.
     */
    S[n++] = 0x59; S[n++] = 0x00;

    /* A second MTC with a non-zero CTC, so First and Last are different and a decoder that
     * overwrote First on every packet would be caught. */
    S[n++] = 0x59; S[n++] = 0xA5;

    /* CYC, SINGLE byte: counter 5 -> (5 << 3) | 0b011 = 0x2B, EXP (bit 2) clear. */
    S[n++] = 0x2B;

    /*
     * CYC, MULTI byte -- the case that was MIS-SIZED until D117. Byte 0 carries counter[4:0] in
     * bits 7:3 with EXP at bit 2; byte 1 carries the next 7 bits in 7:1 with EXP at bit 0.
     *   byte 0 = (1 << 3) | 0x04 | 0x03 = 0x0F   -> low 5 bits = 1, another byte follows
     *   byte 1 = (2 << 1)               = 0x04   -> next 7 bits = 2, bit 0 clear = last byte
     * value = 1 | (2 << 5) = 65.  Total CYC across both packets = 5 + 65 = 70.
     *
     * ⚠ The old size loop checked bit 2 of byte 1 (0x04 -- which IS set here) and would have
     * consumed a third byte. The fixture is built so that mistake changes the packet count.
     */
    S[n++] = 0x0F; S[n++] = 0x04;

    /* CBR: 02 03 <ratio> <reserved>. Ratio 0x2A = 42. */
    S[n++] = 0x02; S[n++] = 0x03; S[n++] = 0x2A; S[n++] = 0x00;

    /* PTWRITE, 4-byte payload: 02 12 <4 bytes>. Expected 0xDEADBEEF. */
    S[n++] = 0x02; S[n++] = 0x12;
    S[n++] = 0xEF; S[n++] = 0xBE; S[n++] = 0xAD; S[n++] = 0xDE;

    /* PTWRITE, 8-byte payload: width bits 6:5 = 1 -> 0x32. Expected 0x0123456789ABCDEF.
     * Both widths, because a decoder that assumed one size would still pass with only the other. */
    S[n++] = 0x02; S[n++] = 0x32;
    S[n++] = 0xEF; S[n++] = 0xCD; S[n++] = 0xAB; S[n++] = 0x89;
    S[n++] = 0x67; S[n++] = 0x45; S[n++] = 0x23; S[n++] = 0x01;

    /*
     * ⚠ 0x05, AND FINDING THAT OUT TOOK TWO TRIES. The first draft used 0x0B as "an unknown opcode"
     * and the decoder cheerfully consumed it -- because 0x0B & 0x03 == 0x03, which is CYC. It was a
     * perfectly valid packet and the test was asserting it should not be.
     *
     * A byte is unknown to this decoder only if it is: not 0x00 (PAD), not 0x02 (EXT), ODD (or the
     * TNT8 mask claims it), not (b & 3) == 3 (CYC), not 0x99/0x19/0x59 (MODE/TSC/MTC), and its low
     * five bits are none of 0x01/0x0D/0x11/0x1D (the TIP family). 0x05 satisfies all of that.
     *
     * ⚠ BOTH FIXTURE BUGS WERE FOUND BY THE DECODER REFUSING TO GUESS. Neither was a decoder fault;
     * each was a wrong assumption in the test, surfaced because the decoder stops on anything it
     * cannot account for instead of skipping a byte and carrying on. A resyncing decoder would have
     * swallowed both and reported success.
     */
    const unsigned BadAt = n;
    S[n++] = 0x05;                                       /* genuinely unknown -- must stop here */
    S[n++] = 0x00; S[n++] = 0x00;

    /* ⚠ STATIC, NOT A STACK LOCAL. PT_DECODE_RESULT carries a 65536-entry IP array -- 512 KB, which
     * is well past a default thread stack. Static puts it in .bss, costs no allocation, and cannot
     * fail; this function runs once and is not reentrant. */
    static PT_DECODE_RESULT R;
    PtDecode(S, n, &R);

    int fail = 0;
    char b[160];

#define CK(name, cond, got)                                                   \
    do {                                                                      \
        if (cond) { printf("  [PASS] %-46s %s\n", name, got); }               \
        else      { printf("  [FAIL] %-46s %s\n", name, got); fail++; }       \
    } while (0)

    sprintf_s(b, sizeof(b), "synced at %u, expected %u", R.StartedAt, PsbAt);
    CK("skips pre-PSB garbage and syncs on the PSB", (R.FoundPsb && R.StartedAt == PsbAt), b);

    sprintf_s(b, sizeof(b), "%llu recovered, %llu suppressed, %u stored",
              R.IpsSeen, R.IpsSuppressed, R.IpCount);
    CK("recovers 4 IPs and counts the suppressed one",
       (R.IpsSeen == 4 && R.IpsSuppressed == 1 && R.IpCount == 4), b);

    sprintf_s(b, sizeof(b), "0x%llX", (R.IpCount > 0) ? R.Ips[0] : 0ull);
    CK("  IPBytes=6 -- full 64-bit IP", (R.IpCount > 0 && R.Ips[0] == 0xFFFFF80011223344ull), b);

    sprintf_s(b, sizeof(b), "0x%llX", (R.IpCount > 1) ? R.Ips[1] : 0ull);
    CK("  IPBytes=1 -- inherits the upper 48 bits",
       (R.IpCount > 1 && R.Ips[1] == 0xFFFFF80011225566ull), b);

    sprintf_s(b, sizeof(b), "0x%llX", (R.IpCount > 2) ? R.Ips[2] : 0ull);
    CK("  IPBytes=2 -- inherits the upper 32 bits",
       (R.IpCount > 2 && R.Ips[2] == 0xFFFFF800AABBCCDDull), b);

    sprintf_s(b, sizeof(b), "0x%llX", (R.IpCount > 3) ? R.Ips[3] : 0ull);
    CK("  IPBytes=3 -- SIGN-EXTENDS from bit 47",
       (R.IpCount > 3 && R.Ips[3] == 0xFFFF8000DEADBEEFull), b);

    sprintf_s(b, sizeof(b), "stopped at %u (bad byte at %u), opcode 0x%02X",
              R.StoppedAt, BadAt, R.StopByte);
    CK("STOPS on an unknown opcode instead of resyncing",
       (!R.Ok && R.StoppedAt == BadAt && R.StopByte == 0x05), b);

    sprintf_s(b, sizeof(b), "PSB %llu PSBEND %llu PAD %llu TNT8 %llu MODE %llu",
              R.Counts[PT_PK_PSB], R.Counts[PT_PK_PSBEND], R.Counts[PT_PK_PAD],
              R.Counts[PT_PK_TNT8], R.Counts[PT_PK_MODE]);
    CK("counts the non-IP packets",
       (R.Counts[PT_PK_PSB] == 1 && R.Counts[PT_PK_PSBEND] == 1 &&
        R.Counts[PT_PK_PAD] == 1 && R.Counts[PT_PK_TNT8] == 1 &&
        R.Counts[PT_PK_MODE] == 1), b);

    /* ==== TIMING AND PTWRITE PAYLOADS (D117) ==== */

    sprintf_s(b, sizeof(b), "first 0x%llX last 0x%llX (%llu packets)",
              R.TscFirst, R.TscLast, R.Counts[PT_PK_TSC]);
    CK("TSC -- 56-bit payload assembled little-endian",
       (R.Counts[PT_PK_TSC] == 1 && R.TscFirst == 0x77665544332211ull &&
        R.TscLast == 0x77665544332211ull), b);

    /* The anchor's OFFSET is the half that does the work, and it is the half a value-only test
     * would never notice was wrong. TscAt is where the 0x19 opcode was written into the fixture. */
    sprintf_s(b, sizeof(b), "%u anchor(s), offset %u expected %u",
              R.TscAnchorCount,
              (R.TscAnchorCount > 0) ? R.TscAnchors[0].Offset : 0u, TscAt);
    CK("  and records the OFFSET it was found at",
       (R.TscAnchorCount == 1 && R.TscAnchors[0].Offset == TscAt &&
        R.TscAnchors[0].Tsc == 0x77665544332211ull), b);

    sprintf_s(b, sizeof(b), "first %u last %u (%llu packets)",
              R.MtcFirst, R.MtcLast, R.Counts[PT_PK_MTC]);
    CK("MTC -- CTC 0 is a VALUE, not 'no packet'",
       (R.Counts[PT_PK_MTC] == 2 && R.MtcFirst == 0x00 && R.MtcLast == 0xA5), b);

    sprintf_s(b, sizeof(b), "%llu CYC packet(s), total %llu cycles",
              R.Counts[PT_PK_CYC], R.CycTotal);
    CK("CYC -- single AND multi-byte, 5 then 65 = 70",
       (R.Counts[PT_PK_CYC] == 2 && R.CycTotal == 70), b);

    sprintf_s(b, sizeof(b), "ratio %u (%llu packets)", R.CbrLast, R.Counts[PT_PK_CBR]);
    CK("CBR -- core bus ratio recovered", (R.Counts[PT_PK_CBR] == 1 && R.CbrLast == 0x2A), b);

    sprintf_s(b, sizeof(b), "%llu seen, %u stored", R.PtwSeen, R.PtwCount);
    CK("PTW -- both payload widths recovered", (R.PtwSeen == 2 && R.PtwCount == 2), b);

    sprintf_s(b, sizeof(b), "0x%llX", (R.PtwCount > 0) ? R.PtwValues[0] : 0ull);
    CK("  PTW 4-byte operand", (R.PtwCount > 0 && R.PtwValues[0] == 0xDEADBEEFull), b);

    sprintf_s(b, sizeof(b), "0x%llX", (R.PtwCount > 1) ? R.PtwValues[1] : 0ull);
    CK("  PTW 8-byte operand",
       (R.PtwCount > 1 && R.PtwValues[1] == 0x0123456789ABCDEFull), b);

#undef CK

    if (fail == 0)
    {
        printf("\n  DECODER PROVEN against a stream whose answer is known, INCLUDING the awkward\n");
        printf("  cases: a wrapped start, three widths of IP compression, a sign-extended kernel\n");
        printf("  address, a suppressed IP, and an unknown opcode it refuses to decode past.\n");
        printf("\n  That is the only order in which it is worth pointing at a real buffer. A wrong\n");
        printf("  mask in the packet table does not produce an error -- it produces plausible\n");
        printf("  addresses that were never executed.\n");
        return 0;
    }

    printf("\n  %d FAILED. Do not read anything this decoder says about a real trace until they\n", fail);
    printf("  pass: every address it reports would be assembled by the same broken table.\n");
    return 1;
}
