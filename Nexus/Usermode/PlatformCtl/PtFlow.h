/**
 * @file PtFlow.h
 * @brief Intel PT CONTROL-FLOW RECONSTRUCTION -- the executed path, not just the indirect targets.
 *
 * ============================================================================================
 * WHAT THIS ADDS, AND WHY THE PACKET DECODER COULD NEVER ADD IT
 * ============================================================================================
 *
 * `PtDecode.h` states its own limit plainly: it recovers the IPs carried by TIP / FUP / TIP.PGE /
 * TIP.PGD and it "does NOT reconstruct full control flow", because a TNT bit says only
 * *taken / not taken* and names no address. A 1.5 GB capture therefore decoded to a list of
 * indirect branch targets -- true, useful, and a small fraction of what the hardware wrote down.
 *
 * The missing half is the target's OWN CODE. Walking the instructions from a known IP, consuming
 * one TNT bit per conditional branch and one TIP per indirect branch, turns the packet stream back
 * into the sequence of instructions that actually ran. That is the whole capability: PT stops being
 * a sampling of where the program jumped and becomes a record of what it did.
 *
 * ============================================================================================
 * 4-TIER RESEARCH
 * ============================================================================================
 *
 * TIER 1 `reference material/` -- HIT, and it supplies the two rules that cannot be guessed:
 *   - SDM vol 3 Table 34-16: TNT results are ordered B1 = OLDEST, terminated by a trailing Stop
 *     bit, and "Once a decoder consumes a TNT packet with N valid payload bits, these bits should
 *     be applied to (and hence provide the destination for) the next N conditional branches or
 *     RETs." Resolved in PtDecode.c, consumed here.
 *   - SDM vol 3 34.4.2.2, the CALL/RET stack, quoted rather than paraphrased: "Allocate space to
 *     store 64 RET targets... For near CALLs, push the Next IP onto the stack... Note that this
 *     excludes zero-length CALLs, which are direct near CALLs with displacement zero (to the next
 *     IP). These CALLs typically don't have matching RETs." And: "The processor will never compress
 *     a RET across a PSB, a buffer overflow, or scenario where PacketEn=0."
 *   Also in tier 1: a Zydis SDK with an MSVC decoder-only configuration this repo already proves in
 *   `NexusBootDxe` -- so the instruction decoder is a known-good component, not a new risk.
 *
 * TIER 2 the internet -- NOT USED, DELIBERATELY, and this is the result rather than an omission.
 *   The questions here are all "how does this packet encode" and "when does the CPU compress a
 *   RET", which the local Intel manuals answer as PRIMARY sources. The standing rule from
 *   is that for hardware questions the manuals in `reference material/intel/` beat a
 *   web search, and it caught two wrong answers in an hour the day it was written.
 *
 * TIER 3 v1 -- NOTHING. v1 declared Intel PT in seven IOCTLs, implemented none, and shipped BTS.
 *   There is no v1 decoder, no v1 walker, and nothing here to port or to be misled by.
 *
 * TIER 4 how to improve on all of it:
 *   - CODE COMES FROM THE LIVE TARGET, not from a file on disk. Every public PT decoder resolves
 *     instructions out of the images the trace references. This framework exists to inspect code
 *     that NO FILE BACKS -- manually mapped, decrypted in place, JIT-emitted -- and the driver can
 *     already read any VA out of any process. A file-based decoder is blind to precisely the code
 *     worth tracing.
 *   - THE CODE READER IS A CALLBACK, so this engine has no Windows in it and can be driven from a
 *     synthetic image whose answer is known before the test runs.
 *   - FAIL CLOSED AT EVERY SEAM. An unreadable page, an undecodable instruction, a TNT bit that
 *     contradicts the CALL stack, a suppressed IP -- each STOPS the walk and reports where. The
 *     failure this must never have is the one PtDecode.h names: emitting plausible addresses that
 *     nothing executed.
 *
 * ============================================================================================
 * (!)(!) TNT AND TIP ARE TWO QUEUES, NOT ONE STREAM -- THE DEFERRED-TIP RULE
 * ============================================================================================
 *
 * It is tempting to walk the packet array once and consume whatever comes next. That is WRONG, and
 * wrong in a way that produces a confident, plausible, incorrect trace.
 *
 * SDM vol 3 34.4.2.3: "The processor may opt to defer sending out the TNT when TIPs are generated.
 * Thus, rather than sending a partial TNT followed by a TIP, both packets will be deferred while
 * the TNT accumulates more Jcc/RET results. Any number of TIP packets may be accumulated this way,
 * such that only once the TNT is filled... the TNT will be sent, followed by all the deferred TIP
 * packets."
 *
 * So an indirect branch that executed EARLY can have its TIP appear in the buffer AFTER a TNT
 * describing conditional branches that executed LATER. Stream order is not execution order between
 * the two classes -- but it IS preserved within each class. Hence two independent cursors over one
 * packet array: one for TNT bits, one for the IP/event packets.
 *
 * ⚠ AND THAT SAME RULE IS WHAT DISAMBIGUATES A COMPRESSED RET. The SDM continues: "an uncompressed
 * RET will not be deferred, and hence will force out any accumulated TNTs or TIPs. This serves to
 * avoid ambiguity, and make clear to the decoder whether the near RET was compressed, and hence a
 * bit in the in-progress TNT should be consumed, or uncompressed, in which case there will be no
 * in-progress TNT and thus a TIP should be consumed."
 *
 * That is the rule this walker implements literally: at a near RET, unconsumed TNT bits in hand
 * mean COMPRESSED; none in hand means UNCOMPRESSED, take a TIP.
 */

#ifndef NXC_PT_FLOW_H
#define NXC_PT_FLOW_H

#include <stdint.h>
#include "PtDecode.h"

/**
 * Supply @p Len bytes of the traced program's code at @p Va.
 *
 * @return bytes actually provided. A SHORT read is honest and usable -- an instruction may still
 *         decode from it -- but ZERO means the address could not be read at all, and the walk stops
 *         there rather than continuing into memory it has not seen.
 */
typedef uint32_t (*PT_CODE_READ)(void* Ctx, uint64_t Va, uint8_t* Buf, uint32_t Len);

/*
 * What an instruction does to control flow, in the terms Intel PT cares about. These eight are the
 * complete set as far as a trace is concerned -- every x86-64 instruction is one of them, and which
 * one it is decides whether a TNT bit, a TIP, or nothing at all describes what happened next.
 */
enum {
    PT_CLS_NORMAL = 0,     /* no control transfer -- fall through to the next address  */
    PT_CLS_COND,           /* one TNT bit decides                                      */
    PT_CLS_JMP_DIRECT,     /* target is in the instruction; no packet                  */
    PT_CLS_JMP_INDIRECT,   /* one TIP                                                  */
    PT_CLS_CALL_DIRECT,    /* target in the instruction; pushes a return address       */
    PT_CLS_CALL_INDIRECT,  /* one TIP; pushes a return address                         */
    PT_CLS_RET_NEAR,       /* compressed (one TNT bit) or not (one TIP)                */
    PT_CLS_FAR,            /* far branch, IRET, SYSCALL/SYSRET, INT, #UD -- one TIP    */
    PT_CLS_COUNT
};

/**
 * Decode ONE instruction and report which class it is.
 *
 * Exposed so the classifier can be proved against hand-written encodings from outside this file --
 * see PtFlowSelfTest. Bytes in, class out, and no decoder-library type in this header, so nothing
 * else in the program has to know which disassembler is underneath.
 *
 * @return 1 on a successful decode, 0 if the bytes are not an instruction.
 */
int PtFlowClassifyBytes(const uint8_t* Code, uint32_t Len, unsigned* OutClass, uint32_t* OutLen);

/** Display name for a class, for the self-test's failure messages. */
const char* PtFlowClassName(unsigned Class);

/* How a basic block ended. This is the interesting column of a reconstructed trace. */
enum {
    PT_EXIT_NONE = 0,      /* the walk stopped inside the block -- see StopReason           */
    PT_EXIT_COND_TAKEN,    /* Jcc / LOOP / J*CXZ, TNT bit said taken                        */
    PT_EXIT_COND_NOT,      /* ... said not taken; the block continues at the next address   */
    PT_EXIT_JMP_DIRECT,    /* relative JMP -- no packet consumed, the target is in the code */
    PT_EXIT_JMP_INDIRECT,  /* JMP r/m -- one TIP                                            */
    PT_EXIT_CALL_DIRECT,   /* relative CALL -- no packet; return address pushed             */
    PT_EXIT_CALL_INDIRECT, /* CALL r/m -- one TIP; return address pushed                    */
    PT_EXIT_RET_COMPRESSED,/* near RET resolved from the CALL stack by one TNT bit          */
    PT_EXIT_RET_TIP,       /* near RET that was not compressed -- one TIP                   */
    PT_EXIT_FAR,           /* far branch / IRET / SYSCALL / SYSRET / INT -- one TIP         */
    PT_EXIT_DISABLED,      /* TIP.PGD: tracing stopped here (a filter boundary, or a mode
                            * change such as entering the kernel with a ring-3 filter)      */
    PT_EXIT_EVENT,         /* FUP: an asynchronous event (interrupt/exception) interrupted  */
    PT_EXIT_COUNT
};

/* Why the walk stopped. Every one of these is reported with the IP and the packet offset. */
enum {
    PT_STOP_END = 0,          /* packets ran out -- the normal end of a capture             */
    PT_STOP_NO_CODE,          /* the code reader could not supply bytes at StopIp           */
    PT_STOP_BAD_INSN,         /* the bytes at StopIp did not decode as an instruction       */
    PT_STOP_TNT_EMPTY,        /* a conditional branch with no TNT bit left to describe it   */
    PT_STOP_TIP_EMPTY,        /* an indirect branch with no IP packet left                  */
    PT_STOP_RETCOMP,          /* a compressed RET whose TNT bit was NOT taken -- desync     */
    PT_STOP_IP_SUPPRESSED,    /* the IP packet carried no address; the path cannot continue */
    PT_STOP_OVERFLOW,         /* OVF: the hardware dropped trace; there is a real gap here  */
    PT_STOP_BLOCK_RUNAWAY,    /* one block exceeded the instruction ceiling -- see below    */
    PT_STOP_SINK_FULL,        /* the packet array filled; the input was larger than the cap */
    PT_STOP_NOT_STARTED,      /* no TIP.PGE anywhere -- nothing said where execution was    */
    PT_STOP_COUNT
};

typedef struct _PT_FLOW_BLOCK
{
    uint64_t Start;        /* first instruction executed in this block                        */
    uint64_t Last;         /* address of the block's FINAL instruction (the transfer itself)  */
    uint64_t Target;       /* where control actually went; 0 when the exit did not say        */
    uint32_t Insns;        /* instructions executed, inclusive of the transfer                */
    uint16_t Depth;        /* CALL depth on entry -- what makes a long trace readable         */
    uint8_t  Exit;         /* PT_EXIT_*                                                       */
    uint8_t  Reserved0;
} PT_FLOW_BLOCK;

/*
 * ⚠ A CEILING ON ONE BLOCK, BECAUSE A WRONG IP LOOKS EXACTLY LIKE A LONG BLOCK. If the walk is
 * ever handed an address it should not have, it decodes whatever bytes are there and marches until
 * something stops it -- and in a large writable mapping nothing might. 1 << 20 instructions in a
 * single straight-line block is far beyond any real one (the longest unrolled runs in real code are
 * thousands, not a million) and turns an infinite walk into a REPORTED failure.
 */
#define PT_FLOW_MAX_BLOCK_INSNS  (1u << 20)

/* The CALL stack the SDM says to model, at exactly the depth it specifies. */
#define PT_FLOW_RETSTACK_DEPTH   64u

/*
 * ============================================================================================
 * THE BLOCK SITE TABLE -- which code RAN, as opposed to what order it ran in
 * ============================================================================================
 *
 * The block array answers "what happened next". This answers a different and often more useful
 * question: WHICH BASIC BLOCKS EXECUTED AT ALL, and how often. Against an obfuscated target that
 * is the primary result -- a flattened or opaque-predicated CFG has a large majority of edges that
 * never execute, and the set that did is what separates real control flow from the noise built to
 * hide it. It is also how a trace of six million instructions becomes a page of output.
 *
 * ⚠ TALLIED INSIDE THE WALK, NOT OVER THE STORED BLOCKS. A long trace overflows the block array by
 * design (D3: BlocksSeen vs BlockCount), so a summary computed from the array would silently
 * describe the first N blocks and call it coverage. Distinct SITES stay small even when the block
 * count does not -- 6 million blocks over the eight-deep chain is a few dozen sites.
 *
 * Open-addressed, caller-supplied, power-of-two capacity, no allocation in the engine. A full
 * table stops ADMITTING new sites and says so in SitesDropped rather than evicting: an evicting
 * cache would under-count a hot block that lost its slot, which is the one number this exists for.
 */
typedef struct _PT_FLOW_SITE
{
    uint64_t Start;        /* block start VA; 0 marks an empty slot                          */
    uint64_t Executions;   /* times this block was entered                                   */
    uint64_t Instructions; /* instructions attributed to it across all executions            */
    uint64_t LastTarget;   /* where it went most recently -- non-constant means a real branch */
    uint32_t ExitMask;     /* bitmask of PT_EXIT_* kinds seen leaving it                     */
    uint32_t Reserved0;
} PT_FLOW_SITE;

typedef struct _PT_FLOW_RESULT
{
    /*
     * Optional. Set Sites/SiteCap (SiteCap MUST be a power of two) before the call to have the
     * walk tally distinct block sites; leave Sites NULL to skip it entirely.
     */
    PT_FLOW_SITE* Sites;
    uint32_t SiteCap;
    uint32_t SitesUsed;
    uint64_t SitesDropped;  /* blocks whose site could not be recorded -- table was full      */

    /*
     * The reconstructed path. HEAP, supplied by the caller, because a real trace produces millions
     * of blocks and the useful cap is a policy decision rather than a constant in a header.
     *
     * D3: BlocksSeen counts what was RECONSTRUCTED, BlockCount what FIT. A caller that reads only
     * the array would take a truncated path for the whole one.
     */
    PT_FLOW_BLOCK* Blocks;
    uint32_t BlockCap;
    uint32_t BlockCount;
    uint64_t BlocksSeen;

    uint64_t Instructions;      /* instructions the target executed, as reconstructed          */
    uint64_t CondBranches;      /* conditional branches resolved from TNT bits                 */
    uint64_t CondTaken;
    uint64_t DirectJumps;
    uint64_t IndirectJumps;
    uint64_t DirectCalls;
    uint64_t IndirectCalls;
    uint64_t ZeroLengthCalls;   /* CALL +0: executed, but NOT pushed -- the SDM's exclusion     */
    uint64_t RetsCompressed;
    uint64_t RetsUncompressed;
    uint64_t FarTransfers;
    uint64_t Events;            /* FUP-marked asynchronous events encountered                  */

    uint64_t TntBitsAvailable;  /* how many the packets held ...                               */
    uint64_t TntBitsConsumed;   /* ... and how many the walk actually applied                  */
    uint64_t IpPacketsAvailable;
    uint64_t IpPacketsConsumed;

    uint32_t Sections;          /* TIP.PGE .. TIP.PGD spans the walk covered                   */
    uint32_t PacketCount;       /* packets the decode produced                                 */

    /*
     * ⚠ AN OVERFLOW IS A HOLE IN THE TRACE, AND IT IS THE HARDWARE'S HOLE, NOT THE WALKER'S. OVF
     * means the CPU had nowhere to put packets and threw some away, so the path genuinely stops
     * being continuous there. Counted separately from every other section break precisely because
     * a reader must be able to tell "the filter turned tracing off" from "trace was LOST".
     */
    uint32_t Overflows;

    /*
     * PSBs the walk passed, each of which discards the modelled CALL stack because the hardware
     * will not compress a RET across one. Reported because it is the difference between a walk
     * that models the rule and one that ignores it -- and ignoring it is what capped a 189 KB
     * capture at 4.3% coverage before this was a separate cursor.
     */
    uint32_t PsbResyncs;

    /*
     * Sections that began from a PSB+ FUP rather than a TIP.PGE -- i.e. the walk joined a trace
     * that was ALREADY RUNNING. Counted separately because it says something real about the
     * capture: a file full of these was started mid-flight, and its first bytes describe branches
     * whose starting address the stream never stated.
     */
    uint32_t PsbBootstraps;

    uint64_t CodeBytesRead;     /* what the code reader was asked to supply and did            */
    uint32_t CodeReadFails;

    /*
     * ⚠ RETSTACK MISSES ARE EVIDENCE, NOT AN ERROR. A near RET taken with an empty modelled stack
     * is exactly what the SDM describes for a RET whose CALL happened before the trace began, and
     * it is ALSO what a stack-pivoting obfuscator produces. Counted and reported, never smoothed.
     */
    uint32_t RetstackEmpty;
    uint32_t RetstackDepthMax;

    /*
     * ⚠ CURSOR STATE AT THE STOP, AND IT IS NOT DEBUG SPRAY. A desync is always a disagreement
     * between the two cursors about which packet describes a transfer, and the stop reason alone
     * cannot say which way they disagreed. These four make the difference between "the walker read
     * the wrong packet" and "the stream is not what it claims to be" visible from one run, instead
     * of from a rebuild with printfs in it.
     */
    uint32_t StopTntOffset;     /* byte offset of the packet holding the next unconsumed bit   */
    uint32_t StopIpOffset;      /* byte offset of the next unconsumed IP packet                */
    uint32_t StopIpKind;        /* PT_PK_* of that packet                                      */
    uint32_t StopRetDepth;      /* modelled CALL stack depth at the moment it stopped          */

    uint32_t StopReason;        /* PT_STOP_*                                                   */
    uint64_t StopIp;            /* the IP the walk was at when it stopped                      */
    uint32_t StopPacketOffset;  /* byte offset in the region of the packet it stopped on       */
    uint32_t Reserved0;
} PT_FLOW_RESULT;

/**
 * Reconstruct control flow from one raw PT region.
 *
 * @param Buf,Len     the raw PT bytes, exactly as `trace decode` receives them
 * @param Packets     scratch array for the packet stream; sized by the caller
 * @param PacketCap   how many packets it holds -- a full array STOPS the walk and says so
 * @param CodeRead    supplies the traced program's instruction bytes
 * @param CodeCtx     passed through to @p CodeRead untouched
 * @param Out         result; Out->Blocks / Out->BlockCap must be set by the caller
 * @param Summary     optional -- the ordinary packet summary from the same single decode pass
 *
 * @return 0 on a completed call. The walk's own outcome is in Out->StopReason; "stopped early" is
 *         a RESULT reported there, never a return code, because a partially reconstructed path is
 *         still the truth about the part it covered.
 */
int PtFlowRun(const uint8_t* Buf, uint32_t Len,
              PT_PACKET* Packets, uint32_t PacketCap,
              PT_CODE_READ CodeRead, void* CodeCtx,
              PT_FLOW_RESULT* Out, PT_DECODE_RESULT* Summary);

/** Display name for a block exit kind. */
const char* PtFlowExitName(unsigned Exit);

/** Display name for a stop reason, phrased as what it means rather than what it is called. */
const char* PtFlowStopName(unsigned Reason);

/**
 * Prove the walker against a hand-built stream over a synthetic image whose path is known before
 * the test runs. Returns 0 on success. No driver, no hardware, no target.
 */
int PtFlowSelfTest(void);

#endif
