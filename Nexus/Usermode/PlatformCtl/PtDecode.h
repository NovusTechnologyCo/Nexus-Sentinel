/**
 * @file PtDecode.h
 * @brief Intel PT packet decoder. USERMODE ONLY -- the kernel hands over bytes and nothing more.
 *
 * ============================================================================================
 * WHY THIS IS NOT IN THE DRIVER (D5, and all three tiers agree)
 * ============================================================================================
 *
 * TIER 1 (`reference material/`): there is NO PT packet decoder anywhere in it. What Cheat Engine's
 *   `ultimap2.c` does is map the ToPA buffer into the waiting usermode process and let that side
 *   consume it. It reached the same split independently, for a codebase with SEH available -- which
 *   this one does not have.
 *
 * TIER 2 (libipt, Intel's own decoder): the packet opcodes and masks below are taken from
 *   `pt_opcodes.h` and checked against it rather than recalled. Getting one mask wrong here does not
 *   produce an error, it produces PLAUSIBLE ADDRESSES, which is the worst failure this project can
 *   have.
 *
 * TIER 3 (v1): never built PT at all. Nothing to carry over, and nothing to be misled by.
 *
 * TIER 4: usermode, because a decoder is a parser over hostile-shaped input and belongs where a
 *   mistake costs a wrong answer rather than the machine.
 *
 * ============================================================================================
 * ⚠ WHAT IT DECODES, AND WHAT IT DELIBERATELY DOES NOT
 * ============================================================================================
 *
 * It recovers PACKET BOUNDARIES and the IPs carried by TIP / FUP / TIP.PGE / TIP.PGD. Those are
 * addresses the target ACTUALLY EXECUTED -- indirect branch targets, and the points where tracing
 * was enabled and disabled -- and they are recoverable from the packet stream ALONE.
 *
 * It does NOT reconstruct full control flow. TNT packets say only "the next conditional branch was
 * taken / not taken", so turning them into a path requires disassembling the traced code and walking
 * it in lockstep. That needs the target's image, which is a different problem with its own failure
 * modes, and pretending otherwise would produce a plausible-looking trace built on guesses.
 *
 * ⚠ AND IT FAILS CLOSED. On an opcode it does not recognise it STOPS and reports the offset, rather
 * than skipping a byte and resynchronising. Resync-on-garbage is how a decoder turns a corrupt
 * region into a confident list of addresses that were never executed.
 */

#ifndef NXC_PT_DECODE_H
#define NXC_PT_DECODE_H

#include <stdint.h>

/* Packet kinds this decoder distinguishes. Ordering is display order, not architectural. */
enum {
    PT_PK_PAD = 0, PT_PK_PSB, PT_PK_PSBEND, PT_PK_TNT8, PT_PK_TNT64,
    PT_PK_TIP,     PT_PK_TIP_PGE, PT_PK_TIP_PGD, PT_PK_FUP,
    PT_PK_MODE,    PT_PK_PIP,  PT_PK_TSC, PT_PK_MTC, PT_PK_CYC, PT_PK_CBR,
    PT_PK_OVF,     PT_PK_STOP, PT_PK_VMCS, PT_PK_TMA, PT_PK_MNT, PT_PK_PTW,
    PT_PK_COUNT
};

/*
 * ============================================================================================
 * THE ORDERED PACKET STREAM -- what control-flow reconstruction needs and counting does not
 * ============================================================================================
 *
 * PT_DECODE_RESULT is a SUMMARY: how many packets of each kind, and the IPs in the order they were
 * recovered. That is everything `trace decode` needs and nothing `trace flow` can use, because
 * reconstruction consumes TNT bits and TIP payloads AGAINST EACH OTHER, in stream order, one
 * instruction at a time. Two separate arrays cannot express "this TNT came before that TIP".
 *
 * ⚠ A SINK RATHER THAN A SECOND PARSER. The obvious alternative -- a second walker in PtFlow.c
 * that knows the packet encodings -- is two copies of every opcode, mask and size in this file,
 * agreeing only by luck. This project has already paid for that shape twice (the record stride
 * that survived as 160 in four places; the CYC continuation bit that was right in byte 0 and wrong
 * in every byte after). ONE parser emits, and everything else consumes.
 */
#define PT_PKF_IP_SUPPRESSED  0x01u   /* an IP packet whose IPBytes said "no IP is provided"     */
#define PT_PKF_IN_PSB         0x02u   /* between PSB and PSBEND -- status, NOT a live event      */

typedef struct _PT_PACKET
{
    uint32_t Offset;      /* byte offset within the region -- what a stop position is reported as */
    uint16_t Size;        /* packet length in bytes                                               */
    uint8_t  Kind;        /* PT_PK_*                                                              */
    uint8_t  Flags;       /* PT_PKF_*                                                             */

    /*
     * TIP / TIP.PGE / TIP.PGD / FUP : the RECONSTRUCTED IP (compression already resolved)
     * TNT8 / TNT64                  : the branch results, B1 (OLDEST) in bit 0 -- see below
     * PTW                           : the operand the target wrote
     * TSC                           : the 56-bit timestamp
     * everything else               : 0
     */
    uint64_t Payload;

    /*
     * ⚠ TNT ONLY, AND IT IS THE FIELD THAT MAKES THE PAYLOAD READABLE. A TNT packet carries 1..6
     * (short) or 1..47 (long) results, and HOW MANY is encoded as a trailing Stop bit rather than
     * given -- SDM vol 3, Table 34-16: "the last valid TNT bit is followed by a trailing 1, or Stop
     * bit... If the TNT packet is not full, the Stop bit moves up, and the trailing bits of the
     * packet are filled with 0s."
     *
     * The decoder resolves that here so no consumer has to: Payload bit 0 is B1, the OLDEST result,
     * and bit (TntBits-1) is the youngest. Consumption order is bit 0 upward, which is the order
     * the SDM says to apply them in -- "these bits should be applied to the next N conditional
     * branches or RETs".
     */
    uint8_t  TntBits;
    uint8_t  Reserved0[7];
} PT_PACKET;

/**
 * Called once per packet, IN STREAM ORDER, if supplied. Return 0 to continue, non-zero to stop the
 * decode early (the stop offset is then reported in PT_DECODE_RESULT.StoppedAt as usual).
 */
typedef int (*PT_PACKET_SINK)(void* Ctx, const PT_PACKET* Packet);

/*
 * ⚠ RAISED FROM 4096 BY MEASUREMENT, NOT BY GUESS. The first real decode on hardware recovered 4602
 * IPs from ONE core's 256 KB region in a 600 ms window -- so the original cap truncated the very
 * first trace it ever saw. It said so (IpsSeen vs IpCount is reported), but a capture tool whose
 * output silently stops at the first interesting result is not much of one.
 *
 * 65536 * 8 = 512 KB, which is why PT_DECODE_RESULT must be HEAP allocated and never a stack local.
 * Both callers do that.
 */
#define PT_MAX_IPS 65536u

/*
 * ⚠ HOW MANY PTWRITE PAYLOADS ARE KEPT. Unlike IPs, these are values the TARGET CHOSE to emit --
 * one per PTWRITE instruction executed -- so the useful count is bounded by how instrumented the
 * code is, not by how much it ran. 4096 is generous for that and costs 32 KB.
 *
 * Like Ips, the count RECOVERED is reported separately from the count STORED (D3). A truncated list
 * read as the whole set is the same defect in a smaller box.
 */
#define PT_MAX_PTW 4096u

/*
 * TSC anchors kept per decode. Measured on this machine: a 256 KB region carries 150-270 TSC
 * packets depending on the encoding, so 4096 is far above any real trace and costs 48 KB.
 */
#define PT_MAX_TSC 4096u

typedef struct _PT_DECODE_RESULT
{
    uint64_t Counts[PT_PK_COUNT];   /* packets seen, by kind                                    */

    /*
     * ==== TIMING PAYLOADS (D117) ====
     *
     * ⚠ THE DECODER USED TO COUNT THESE PACKETS AND THROW THEIR CONTENTS AWAY. Boundaries were
     * right -- TSC, MTC, CYC, TMA and PTW all had correct sizes, so the stream walked cleanly --
     * and every VALUE was discarded. A trace armed with --tsc therefore decoded to "N TSC packets
     * were present", which answers nothing the packet count did not already answer. Emitting timing
     * packets and not reading them is the same gap as documenting a feature and not building it.
     *
     * ⚠ FIRST AND LAST, NOT AN ARRAY. A capture's useful timing summary is its SPAN; storing every
     * timestamp would cost more than the trace and answer no question the span does not.
     */
    uint64_t TscFirst;              /* first TSC payload seen (56-bit), 0 if none               */
    uint64_t TscLast;               /* last TSC payload seen                                    */

    /*
     * ==== TSC ANCHORS: value PLUS the byte offset it was found at ====
     *
     * First/last answer "how long did this capture span". They cannot answer "WHERE IN THIS BUFFER
     * was the machine at time T", which is the question that lets a PEBS record -- exact IP and the
     * full register set, carrying its own TSC at +0x18 -- be placed inside the control-flow trace.
     *
     * That correlation is the ACHIEVABLE form of PEBS-output-to-PT on this processor, which reports
     * IA32_PERF_CAPABILITIES bit 16 CLEAR and will never emit BBP/BIP/BEP blocks. Two streams, one
     * clock, instead of one stream carrying both.
     *
     * ⚠ ANCHORS ARE NOT NECESSARILY IN TIME ORDER. The ToPA region is circular and decoding starts
     * at whichever PSB is found first, so on a wrapped buffer the anchors run ... newest, WRAP,
     * oldest ... Measured on the first real capture: TSC first 0x17C5CA84517, last 0x17C5CA7B1C9 --
     * decreasing. Any consumer that assumes a sorted array is wrong on almost every real trace.
     */
    struct {
        uint64_t Tsc;               /* 56-bit payload as emitted                                */
        uint32_t Offset;            /* byte offset of the packet within the decoded region      */
    } TscAnchors[PT_MAX_TSC];
    uint32_t TscAnchorCount;        /* how many landed in TscAnchors                            */
    uint64_t TscAnchorsSeen;        /* how many were RECOVERED -- may exceed the above (D3)     */
    uint64_t CycTotal;              /* sum of CYC payloads -- cycles accounted for by the trace */
    uint32_t MtcFirst;              /* first MTC CTC byte, 0x100 if none (0 is a valid value)   */
    uint32_t MtcLast;
    uint32_t CbrLast;               /* last core-bus-ratio payload; 0 if no CBR seen            */

    /*
     * PTWRITE payloads -- a VALUE FROM INSIDE THE TARGET, inline with the control flow that
     * produced it. This is the only part of a PT stream that carries data the program chose rather
     * than control flow the hardware observed.
     */
    uint64_t PtwValues[PT_MAX_PTW];
    uint32_t PtwCount;              /* how many landed in PtwValues                             */
    uint64_t PtwSeen;               /* how many were RECOVERED -- may exceed PtwCount (D3)      */

    uint64_t Ips[PT_MAX_IPS];       /* IPs recovered from TIP/FUP/TIP.PGE/TIP.PGD               */
    uint32_t IpCount;               /* how many landed in Ips                                   */
    uint64_t IpsSeen;               /* how many were RECOVERED -- may exceed IpCount (D3)       */
    uint64_t IpsSuppressed;         /* IP packets whose IPBytes said "no IP" -- a real category */

    /*
     * ⚠ BRANCH RESULTS, NOT BRANCH PACKETS. Counts[PT_PK_TNT8] says how many TNT packets arrived;
     * this says how many CONDITIONAL BRANCHES they describe, which is a different number by a
     * factor of up to 47 and is the one that means anything about the target. A trace's TNT packet
     * count says how chatty the encoding was; its TNT BIT count is how many decisions the program
     * made.
     */
    uint64_t TntBitsSeen;
    uint32_t StartedAt;             /* offset of the PSB decoding began at                      */
    uint32_t StoppedAt;             /* offset decoding stopped at                               */
    uint32_t BytesDecoded;
    uint8_t  StopByte;              /* the opcode that stopped it, when Ok == 0                 */
    uint8_t  Ok;                    /* 1 = ran to the end of the input, 0 = hit something unknown */
    uint8_t  FoundPsb;              /* 0 = no PSB anywhere; nothing was decoded                 */
    uint8_t  Reserved0;
} PT_DECODE_RESULT;

/**
 * Decode a raw region.
 *
 * ⚠ IT FINDS A PSB FIRST AND STARTS THERE, ALWAYS. The region is circular, so offset 0 is only the
 * beginning of anything on a trace that has never wrapped -- otherwise it is whatever the writer
 * most recently laid down, mid-packet. PSB is the architecture's own answer to this: a 16-byte
 * pattern that cannot occur inside another packet, placed precisely so a decoder can find its
 * footing. Starting anywhere else and hoping is how a decoder invents addresses.
 *
 * @return 0 on success (including "no PSB found", which is reported in the result, not as an error)
 */
int PtDecode(const uint8_t* Buf, uint32_t Len, PT_DECODE_RESULT* Out);

/**
 * The same decode, with every packet also handed to @p Sink in stream order.
 *
 * `PtDecode` is exactly this with a NULL sink, so the summary path and the reconstruction path
 * are the SAME parser and cannot disagree about where a packet ends.
 */
int PtDecodeEx(const uint8_t* Buf, uint32_t Len, PT_DECODE_RESULT* Out,
               PT_PACKET_SINK Sink, void* SinkCtx);

/** Display name for a packet kind. */
const char* PtPacketName(unsigned Kind);

/** Prove the decoder against a hand-built stream whose answer is known. Returns 0 on success. */
int PtDecodeSelfTest(void);

#endif
