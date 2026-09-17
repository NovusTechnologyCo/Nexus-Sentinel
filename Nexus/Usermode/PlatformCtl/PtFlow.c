/**
 * @file PtFlow.c
 * @brief Walk a target's own instructions in lockstep with its PT packets. Rules in PtFlow.h.
 *
 * ⚠ KNOWN LIMIT, STATED RATHER THAN HIDDEN: this walks 64-BIT CODE. MODE.Exec packets are counted
 * and not decoded, so a 32-bit compatibility-mode section is not misread as 64-bit -- it fails at
 * the first instruction that does not decode and STOPS, reporting the address. That is the intended
 * behaviour and not an oversight: every trace this project arms is 64-bit, and a walker that
 * guessed the mode would produce a plausible path through code that never ran.
 */

#include <string.h>
#include "PtFlow.h"

/*
 * C4201 (nameless struct/union) is how Zydis's own public headers are written and is not ours to
 * fix. Silenced across the include ONLY -- this project's /W4 output is read, and a library's
 * unavoidable noise in it is how a real warning goes unnoticed.
 */
#pragma warning(push)
#pragma warning(disable: 4201)
#include <Zydis/Zydis.h>
#pragma warning(pop)

/* ============================================================================================
 * PASS 1 -- capture the packet stream in order
 * ============================================================================================ */

typedef struct _SINK_CTX
{
    PT_PACKET* Arr;
    uint32_t   Cap;
    uint32_t   Count;
    int        Full;
} SINK_CTX;

static int
PacketSink(
    void* Ctx,
    const PT_PACKET* Pk
    )
{
    SINK_CTX* const S = (SINK_CTX*)Ctx;

    if (S->Count >= S->Cap)
    {
        /* ⚠ STOP, DO NOT DROP. A dropped packet in the middle of a stream is not a smaller trace,
         * it is a WRONG one -- every TNT bit after the gap gets applied to the wrong branch. The
         * decode ends here and the caller is told the array was too small. */
        S->Full = 1;
        return 1;
    }

    S->Arr[S->Count++] = *Pk;
    return 0;
}

/* ============================================================================================
 * INSTRUCTION CLASSIFICATION
 * ============================================================================================ */


/**
 * Is this branch's target written INTO the instruction, or fetched at run time?
 *
 * ⚠⚠ `ZYDIS_ATTRIB_IS_RELATIVE` IS NOT THAT QUESTION, AND USING IT WAS THE WORST BUG THE SELF-TEST
 * COULD HAVE CAUGHT. That attribute means "this instruction has a RIP-relative operand", which is
 * true of `call [rip+0x1234]` -- the encoding of every import-table call in every Windows binary.
 * Classified as direct, the walker would compute a target from the memory operand's DISPLACEMENT
 * (the address of the pointer, not the function), never consume the TIP that names where the call
 * actually went, and desynchronise the entire remaining trace. It would not fail; it would emit a
 * clean, plausible, wholly fictional path, starting at roughly the first library call.
 *
 * The real discriminator is the operand's TYPE. A direct branch takes an IMMEDIATE displacement; a
 * register or memory operand means the CPU had to go and get the target, which is exactly when PT
 * emits a TIP.
 */
static int
IsDirectBranch(
    const ZydisDecodedInstruction* I,
    const ZydisDecodedOperand* Ops
    )
{
    if (I->operand_count_visible < 1)
        return 0;
    if (Ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
        return 0;
    return (I->attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;
}

/**
 * Which of the eight classes an instruction belongs to.
 *
 * ⚠ MNEMONICS ARE CHECKED BEFORE CATEGORIES, ON PURPOSE. `LOOP`, `LOOPE`, `LOOPNE` and `J*CXZ` are
 * conditional branches to Intel PT -- SDM vol 3 Table 34-16 names them explicitly alongside Jcc as
 * the instructions a TNT bit describes -- but they are not `Jcc` and a decoder library is free to
 * file them wherever it likes. Asking the library's category for them would make this walker's
 * correctness depend on a third-party taxonomy decision. The self-test asserts every one of these
 * against a hand-assembled byte sequence, so a disagreement is caught here rather than as a
 * desynced trace on hardware.
 */
static unsigned
ClassifyInsn(
    const ZydisDecodedInstruction* I,
    const ZydisDecodedOperand* Ops
    )
{
    switch (I->mnemonic)
    {
    case ZYDIS_MNEMONIC_LOOP:
    case ZYDIS_MNEMONIC_LOOPE:
    case ZYDIS_MNEMONIC_LOOPNE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JRCXZ:
        return PT_CLS_COND;

    /* An IRET is a far return however the library files it. */
    case ZYDIS_MNEMONIC_IRET:
    case ZYDIS_MNEMONIC_IRETD:
    case ZYDIS_MNEMONIC_IRETQ:
        return PT_CLS_FAR;

    /*
     * ⚠ #UD IS A CONTROL TRANSFER HERE EVEN THOUGH IT IS NOT A BRANCH. The instruction faults, the
     * fault is an asynchronous event, and PT records it as FUP + TIP. Treating UD as an ordinary
     * instruction would step PAST it into whatever bytes follow -- which in obfuscated code is
     * frequently data, and is exactly how a walker starts inventing a path.
     */
    case ZYDIS_MNEMONIC_UD0:
    case ZYDIS_MNEMONIC_UD1:
    case ZYDIS_MNEMONIC_UD2:
        return PT_CLS_FAR;

    default:
        break;
    }

    switch (I->meta.category)
    {
    case ZYDIS_CATEGORY_COND_BR:
        return PT_CLS_COND;

    case ZYDIS_CATEGORY_UNCOND_BR:
        if (I->meta.branch_type == ZYDIS_BRANCH_TYPE_FAR) return PT_CLS_FAR;
        return IsDirectBranch(I, Ops) ? PT_CLS_JMP_DIRECT : PT_CLS_JMP_INDIRECT;

    case ZYDIS_CATEGORY_CALL:
        if (I->meta.branch_type == ZYDIS_BRANCH_TYPE_FAR) return PT_CLS_FAR;
        return IsDirectBranch(I, Ops) ? PT_CLS_CALL_DIRECT : PT_CLS_CALL_INDIRECT;

    case ZYDIS_CATEGORY_RET:
        return (I->meta.branch_type == ZYDIS_BRANCH_TYPE_FAR) ? PT_CLS_FAR : PT_CLS_RET_NEAR;

    case ZYDIS_CATEGORY_INTERRUPT:
    case ZYDIS_CATEGORY_SYSCALL:
    case ZYDIS_CATEGORY_SYSRET:
        return PT_CLS_FAR;

    default:
        return PT_CLS_NORMAL;
    }
}

const char*
PtFlowClassName(
    unsigned Class
    )
{
    static const char* const kNames[PT_CLS_COUNT] = {
        "normal", "cond", "jmp", "jmp-ind", "call", "call-ind", "ret", "far"
    };
    return (Class < PT_CLS_COUNT) ? kNames[Class] : "?";
}

int
PtFlowClassifyBytes(
    const uint8_t* Code,
    uint32_t Len,
    unsigned* OutClass,
    uint32_t* OutLen
    )
{
    ZydisDecoder Dec;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&Dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
        return 0;

    ZydisDecodedInstruction Insn;
    ZydisDecodedOperand     Ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Dec, Code, Len, &Insn, Ops)))
        return 0;

    if (OutClass != NULL) *OutClass = ClassifyInsn(&Insn, Ops);
    if (OutLen   != NULL) *OutLen   = Insn.length;
    return 1;
}

/* ============================================================================================
 * WALK STATE
 * ============================================================================================ */

typedef struct _WALK
{
    const PT_PACKET* Pk;
    uint32_t         N;

    /*
     * TWO CURSORS OVER ONE ARRAY. See the deferred-TIP argument in PtFlow.h -- an indirect branch's
     * TIP can appear in the buffer after a TNT describing branches that ran later, so a single
     * cursor cannot serve both. Order is preserved WITHIN each class, which is what makes two
     * independent cursors correct rather than merely convenient.
     */
    uint32_t TntIdx;        /* packet index of the TNT currently being drained          */
    uint32_t TntBit;        /* next bit to take from it                                 */
    uint32_t IpIdx;         /* next packet the IP/event cursor will consider            */

    /*
     * ⚠⚠ A THIRD CURSOR, AND IT EXISTS BECAUSE OF A BUG THAT ONLY A LONG TRACE COULD SHOW.
     *
     * SDM vol 3 34.4.2.2: "a RET whose corresponding CALL executed while PacketEn=0, or before the
     * last PSB, etc., will not be compressed." Modelling that means DISCARDING the CALL stack when
     * the walk passes a PSB -- entries pushed before it are no longer compressible.
     *
     * That clearing used to live inside IpNext, so it only happened when the IP cursor moved. On a
     * workload that is almost entirely direct calls and compressed returns, the IP cursor barely
     * moves at all: a 189 KB capture of the eight-deep chain held 1,132,940 TNT bits and only
     * THIRTY-FIVE IP packets. Roughly 46 PSBs went past unprocessed, and the first one that landed
     * in the middle of a call nest made the CPU emit a TIP where this walker expected a TNT bit.
     * It desynchronised 5,441 iterations in and stopped -- correctly, but 4.3% of the way through.
     *
     * So PSB handling cannot be a side effect of another cursor. This one advances independently,
     * bounded by whichever packet is needed next, and it is the SOLE owner of the clearing.
     */
    uint32_t StructIdx;     /* PSB / OVF processed up to here                           */

    /* The CALL stack the SDM tells a decoder to model, at the depth it specifies. */
    uint64_t Ret[PT_FLOW_RETSTACK_DEPTH];
    uint32_t RetCount;      /* entries held, <= PT_FLOW_RETSTACK_DEPTH                  */
    uint32_t RetTop;        /* index one past the youngest, modulo the depth            */
} WALK;

static void
RetPush(
    WALK* W,
    uint64_t Ip,
    PT_FLOW_RESULT* Out
    )
{
    W->Ret[W->RetTop] = Ip;
    W->RetTop = (W->RetTop + 1) % PT_FLOW_RETSTACK_DEPTH;
    if (W->RetCount < PT_FLOW_RETSTACK_DEPTH)
        W->RetCount++;
    if (W->RetCount > Out->RetstackDepthMax)
        Out->RetstackDepthMax = W->RetCount;
}

/** @return 1 and the youngest entry, or 0 if the modelled stack is empty. */
static int
RetPop(
    WALK* W,
    uint64_t* Out
    )
{
    if (W->RetCount == 0)
        return 0;
    W->RetTop = (W->RetTop + PT_FLOW_RETSTACK_DEPTH - 1) % PT_FLOW_RETSTACK_DEPTH;
    W->RetCount--;
    *Out = W->Ret[W->RetTop];
    return 1;
}

/*
 * ⚠ CLEARED WHEREVER THE HARDWARE CLEARS ITS OWN. SDM vol 3 34.4.2.2: "The processor will never
 * compress a RET across a PSB, a buffer overflow, or scenario where PacketEn=0." A modelled stack
 * that survived one of those would offer a return address for a RET the CPU chose NOT to compress,
 * and the walk would take the modelled address instead of the TIP that was actually emitted.
 */
static void
RetClear(
    WALK* W
    )
{
    W->RetCount = 0;
    W->RetTop   = 0;
}

/**
 * Put the TNT and structural cursors at a section boundary.
 *
 * ⚠⚠ WITHOUT THIS THE TWO CURSORS DESCRIBE DIFFERENT PARTS OF THE TRACE. The TNT cursor was
 * initialised once, to the first TNT packet in the buffer, and never moved when a section started
 * somewhere else -- so a walk that resynchronised at byte 147,559 was consuming branch results
 * emitted at byte 32, describing code from before tracing was enabled at this point. It produced a
 * confident path that had nothing to do with the section it claimed to be walking.
 *
 * A TIP.PGE (or a PSB+ bootstrap) is a hard boundary: every TNT bit before it belongs to branches
 * the walk is not following. Deferred TIPs reorder TNT against TIP, never across an enable.
 */
static void
SyncCursorsTo(
    WALK* W,
    uint32_t Index
    )
{
    /*
     * ⚠⚠ FORWARD ONLY. Assigning the index unconditionally REWOUND the TNT cursor whenever it was
     * already past the packet a new section started at -- and it frequently is, because TNT bits
     * are consumed as branches occur while the IP cursor only moves on an indirect transfer. Every
     * bit between the two positions was then consumed a SECOND time, applied to branches that had
     * already been resolved.
     *
     * Caught by arithmetic that could not be true: a walk of a real capture reported consuming
     * 1,123 TNT bits while the stream held only 1,118 before the packet it stopped on. Bits can be
     * SKIPPED at a section boundary; they cannot be gained. The only way to spend more than exist
     * is to spend some of them twice.
     *
     * A cursor already ahead of the boundary means the previous section over-ran, which is a
     * separate fault worth seeing rather than papering over -- so this does not rewind to "fix" it,
     * it simply refuses to go backwards, the same rule StructIdx already follows.
     */
    if (Index > W->TntIdx)
    {
        W->TntIdx = Index;
        W->TntBit = 0;
        while (W->TntIdx < W->N &&
               W->Pk[W->TntIdx].Kind != PT_PK_TNT8 && W->Pk[W->TntIdx].Kind != PT_PK_TNT64)
        {
            W->TntIdx++;
        }
    }
    if (W->StructIdx < Index)
        W->StructIdx = Index;
}

/** Packet index holding the next unconsumed TNT bit, or W->N if there is none left. */
static uint32_t
TntNextIndex(
    const WALK* W
    )
{
    if (W->TntIdx < W->N)
    {
        const PT_PACKET* const P = &W->Pk[W->TntIdx];
        if ((P->Kind == PT_PK_TNT8 || P->Kind == PT_PK_TNT64) && W->TntBit < P->TntBits)
            return W->TntIdx;
    }
    for (uint32_t i = (W->TntIdx < W->N) ? W->TntIdx + 1 : W->N; i < W->N; i++)
    {
        if ((W->Pk[i].Kind == PT_PK_TNT8 || W->Pk[i].Kind == PT_PK_TNT64) && W->Pk[i].TntBits > 0)
            return i;
    }
    return W->N;
}

/** Packet index the IP/event cursor would return next, WITHOUT consuming it. */
static uint32_t
IpPeekIndex(
    const WALK* W
    )
{
    for (uint32_t i = W->IpIdx; i < W->N; i++)
    {
        const PT_PACKET* const P = &W->Pk[i];
        if (P->Kind == PT_PK_PSB || (P->Flags & PT_PKF_IN_PSB))
            continue;
        if (P->Kind == PT_PK_TIP     || P->Kind == PT_PK_TIP_PGE ||
            P->Kind == PT_PK_TIP_PGD || P->Kind == PT_PK_FUP     ||
            P->Kind == PT_PK_OVF)
            return i;
    }
    return W->N;
}

/**
 * Is the next unconsumed TNT bit one that was emitted BEFORE the next unconsumed IP packet?
 *
 * ⚠⚠ THIS IS THE WHOLE COMPRESSED-RET TEST, AND "ARE THERE ANY BITS LEFT" IS THE WRONG FORM OF IT.
 * The first version of this function scanned the entire remaining array, so a TNT packet sitting
 * far LATER in the buffer -- describing branches that had not executed yet -- counted as a bit "in
 * hand" and turned every uncompressed RET into a compressed one. It would have consumed a bit
 * belonging to a future branch and popped a return address the hardware never used, and everything
 * after that point would be a confident, well-formed, entirely fictional path.
 *
 * The ordering guarantee from SDM vol 3 34.4.2.3 is what makes the correct test cheap: an
 * uncompressed RET "will force out any accumulated TNTs or TIPs", so at that moment every TNT bit
 * that belongs to an earlier branch has already been emitted -- and consumed -- and the NEXT TNT
 * packet necessarily sits after this RET's TIP in the buffer. Comparing the two cursors' positions
 * therefore answers exactly the question the hardware answered when it chose the encoding.
 *
 * Caught while hand-building the self-test's packet stream, before it ever reached silicon.
 */
static int
TntPendingBeforeIp(
    const WALK* W
    )
{
    return TntNextIndex(W) < IpPeekIndex(W);
}

/**
 * Advance the structural cursor to just before the next packet either consumer needs, applying
 * whatever those packets do to the modelled CALL stack.
 *
 * Bounded by min(next TNT, next IP) because a packet before BOTH of those has certainly already
 * been emitted by the hardware, whichever of the two describes the transfer being decided. The
 * cursor is monotonic, so each PSB is applied exactly once -- clearing the same PSB twice would
 * discard entries pushed after it, which is the mirror of the bug this fixes.
 */
static void
SyncStructural(
    WALK* W,
    PT_FLOW_RESULT* Out
    )
{
    uint32_t Limit = TntNextIndex(W);
    const uint32_t IpLimit = IpPeekIndex(W);
    if (IpLimit < Limit) Limit = IpLimit;

    while (W->StructIdx < Limit)
    {
        const PT_PACKET* const P = &W->Pk[W->StructIdx++];
        if (P->Kind == PT_PK_PSB)
        {
            RetClear(W);
            Out->PsbResyncs++;
        }
        else if (P->Kind == PT_PK_OVF)
        {
            RetClear(W);
        }
    }
}

/** Take the next branch result. @return 1 on success, 0 if the stream held no more. */
static int
TntNext(
    WALK* W,
    int* Taken
    )
{
    for (;;)
    {
        if (W->TntIdx >= W->N)
            return 0;

        const PT_PACKET* const P = &W->Pk[W->TntIdx];
        if ((P->Kind == PT_PK_TNT8 || P->Kind == PT_PK_TNT64) && W->TntBit < P->TntBits)
        {
            *Taken = (int)((P->Payload >> W->TntBit) & 1u);
            W->TntBit++;
            return 1;
        }

        W->TntIdx++;
        W->TntBit = 0;

        /* Skip forward to the next TNT packet. */
        while (W->TntIdx < W->N &&
               W->Pk[W->TntIdx].Kind != PT_PK_TNT8 &&
               W->Pk[W->TntIdx].Kind != PT_PK_TNT64)
        {
            W->TntIdx++;
        }
    }
}

/**
 * The next IP-carrying or flow-changing packet.
 *
 * ⚠ PACKETS INSIDE PSB..PSBEND ARE SKIPPED, AND THAT IS LOAD-BEARING. A PSB+ sequence restates the
 * machine's current state, and the FUP it contains says where the machine IS -- not that anything
 * was interrupted. Treating it as an asynchronous event would manufacture an interrupt at every
 * PSB, and PSBs are emitted forever. The parser flags them; this is where the flag is used.
 *
 * Passing a PSB also invalidates the modelled CALL stack, for the reason RetClear() records.
 */
static const PT_PACKET*
IpNext(
    WALK* W,
    PT_FLOW_RESULT* Out,
    int AllowPsbFup
    )
{
    while (W->IpIdx < W->N)
    {
        const PT_PACKET* const P = &W->Pk[W->IpIdx++];

        if (P->Kind == PT_PK_PSB)
            continue;               /* SyncStructural owns what a PSB does to the CALL stack */
        if (P->Flags & PT_PKF_IN_PSB)
        {
            /*
             * ⚠⚠ THE FUP INSIDE PSB+ IS THE ONLY WAY INTO A TRACE THAT WAS ALREADY RUNNING,
             * AND SKIPPING IT UNCONDITIONALLY COST 96% OF A REAL CAPTURE.
             *
             * A PSB+ block restates the machine's state, and its FUP gives the CURRENT IP -- that
             * is what PSB is FOR, and PtDecode.h already says so about finding packet boundaries.
             * Treating it as an asynchronous event would invent an interrupt at every PSB, which is
             * why it is skipped everywhere else; but at BOOTSTRAP it is the anchor.
             *
             * Measured: a 189 KB capture of a running target contained its first TIP.PGE at byte
             * 147,559, because tracing was already enabled when the capture began. With PSB+ FUPs
             * skipped there was no address to start from until 78% of the way in.
             */
            if (AllowPsbFup && P->Kind == PT_PK_FUP && !(P->Flags & PT_PKF_IP_SUPPRESSED))
                return P;
            continue;
        }

        if (P->Kind == PT_PK_TIP     || P->Kind == PT_PK_TIP_PGE ||
            P->Kind == PT_PK_TIP_PGD || P->Kind == PT_PK_FUP     ||
            P->Kind == PT_PK_OVF)
        {
            Out->IpPacketsConsumed++;
            return P;
        }
    }
    return NULL;
}

/* ============================================================================================
 * THE WALK
 * ============================================================================================ */

const char*
PtFlowExitName(
    unsigned Exit
    )
{
    static const char* const kNames[PT_EXIT_COUNT] = {
        "-", "cond-taken", "cond-not", "jmp", "jmp-ind",
        "call", "call-ind", "ret-comp", "ret-tip", "far",
        "trace-off", "event"
    };
    return (Exit < PT_EXIT_COUNT) ? kNames[Exit] : "?";
}

const char*
PtFlowStopName(
    unsigned Reason
    )
{
    switch (Reason)
    {
    case PT_STOP_END:           return "packets ran out -- the trace was walked to its end";
    case PT_STOP_NO_CODE:       return "the target's code at that address could not be read";
    case PT_STOP_BAD_INSN:      return "the bytes at that address did not decode as an instruction";
    case PT_STOP_TNT_EMPTY:     return "a conditional branch with no TNT bit left to describe it";
    case PT_STOP_TIP_EMPTY:     return "an indirect branch with no IP packet left to name its target";
    case PT_STOP_RETCOMP:       return "a compressed RET whose TNT bit was NOT taken -- desynchronised";
    case PT_STOP_IP_SUPPRESSED: return "the IP packet carried no address, so the path cannot continue";
    case PT_STOP_OVERFLOW:      return "PT overflowed -- the hardware itself dropped trace here";
    case PT_STOP_BLOCK_RUNAWAY: return "one basic block ran past the instruction ceiling";
    case PT_STOP_SINK_FULL:     return "the packet array filled before the region was decoded";
    case PT_STOP_NOT_STARTED:   return "no TIP.PGE anywhere -- nothing ever said where execution was";
    default:                    return "?";
    }
}

/**
 * Record this block against its SITE -- the distinct code address, tallied across every execution.
 *
 * Open addressing with linear probing. The hash is a 64-bit mix rather than a mask of the low bits
 * because block starts are dense and mostly differ in the low byte: masking would pile an entire
 * function's blocks into adjacent slots and turn every lookup into a long probe.
 */
static void
TallySite(
    PT_FLOW_RESULT* Out,
    uint64_t Start,
    uint64_t Target,
    uint32_t Insns,
    unsigned Exit
    )
{
    if (Out->Sites == NULL || Out->SiteCap == 0)
        return;

    uint64_t H = Start;
    H ^= H >> 33; H *= 0xFF51AFD7ED558CCDull;
    H ^= H >> 33; H *= 0xC4CEB9FE1A85EC53ull;
    H ^= H >> 33;

    const uint32_t Mask = Out->SiteCap - 1u;
    uint32_t Slot = (uint32_t)(H & Mask);

    for (uint32_t probe = 0; probe < Out->SiteCap; probe++)
    {
        PT_FLOW_SITE* const S = &Out->Sites[Slot];

        if (S->Start == Start && S->Executions != 0)
        {
            S->Executions++;
            S->Instructions += Insns;
            S->LastTarget    = Target;
            S->ExitMask     |= (1u << (Exit & 31));
            return;
        }
        if (S->Executions == 0)
        {
            S->Start        = Start;
            S->Executions   = 1;
            S->Instructions = Insns;
            S->LastTarget   = Target;
            S->ExitMask     = (1u << (Exit & 31));
            Out->SitesUsed++;
            return;
        }
        Slot = (Slot + 1u) & Mask;
    }

    /* ⚠ ADMIT THE LOSS, DO NOT EVICT. An evicting table would drop a hot block that lost its slot
     * and under-report the exact number this table exists to produce. */
    Out->SitesDropped++;
}

/** Record one completed basic block. D3: SEEN and STORED are separate numbers. */
static void
EmitBlock(
    PT_FLOW_RESULT* Out,
    uint64_t Start,
    uint64_t Last,
    uint64_t Target,
    uint32_t Insns,
    uint32_t Depth,
    unsigned Exit
    )
{
    Out->BlocksSeen++;
    TallySite(Out, Start, Target, Insns, Exit);
    if (Out->Blocks != NULL && Out->BlockCount < Out->BlockCap)
    {
        PT_FLOW_BLOCK* const B = &Out->Blocks[Out->BlockCount++];
        B->Start  = Start;
        B->Last   = Last;
        B->Target = Target;
        B->Insns  = Insns;
        B->Depth  = (uint16_t)((Depth > 0xFFFFu) ? 0xFFFFu : Depth);
        B->Exit   = (uint8_t)Exit;
        B->Reserved0 = 0;
    }
}

int
PtFlowRun(
    const uint8_t* Buf,
    uint32_t Len,
    PT_PACKET* Packets,
    uint32_t PacketCap,
    PT_CODE_READ CodeRead,
    void* CodeCtx,
    PT_FLOW_RESULT* Out,
    PT_DECODE_RESULT* Summary
    )
{
    PT_FLOW_BLOCK* const SaveBlocks = Out->Blocks;
    const uint32_t       SaveCap     = Out->BlockCap;
    PT_FLOW_SITE*  const SaveSites   = Out->Sites;
    const uint32_t       SaveSiteCap = Out->SiteCap;

    memset(Out, 0, sizeof(*Out));
    Out->Blocks   = SaveBlocks;
    Out->BlockCap = SaveCap;
    Out->Sites    = SaveSites;
    Out->SiteCap  = SaveSiteCap;
    if (Out->Sites != NULL && Out->SiteCap != 0)
        memset(Out->Sites, 0, (size_t)Out->SiteCap * sizeof(Out->Sites[0]));

    if (Buf == NULL || Len == 0 || Packets == NULL || PacketCap == 0 || CodeRead == NULL)
    {
        Out->StopReason = PT_STOP_END;
        return 0;
    }

    /* ---- pass 1: the ordered packet stream, from the ONE parser ---- */
    SINK_CTX S;
    S.Arr = Packets; S.Cap = PacketCap; S.Count = 0; S.Full = 0;

    PT_DECODE_RESULT Local;
    PT_DECODE_RESULT* const Sum = (Summary != NULL) ? Summary : &Local;
    PtDecodeEx(Buf, Len, Sum, PacketSink, &S);

    Out->PacketCount = S.Count;

    for (uint32_t i = 0; i < S.Count; i++)
    {
        const PT_PACKET* const P = &Packets[i];
        if (P->Kind == PT_PK_TNT8 || P->Kind == PT_PK_TNT64)
            Out->TntBitsAvailable += P->TntBits;
        else if (!(P->Flags & PT_PKF_IN_PSB) &&
                 (P->Kind == PT_PK_TIP     || P->Kind == PT_PK_TIP_PGE ||
                  P->Kind == PT_PK_TIP_PGD || P->Kind == PT_PK_FUP))
            Out->IpPacketsAvailable++;
    }

    /* ---- pass 2: walk ---- */
    WALK W;
    memset(&W, 0, sizeof(W));
    W.Pk = Packets;
    W.N  = S.Count;

    /*
     * ⚠ THE TNT CURSOR IS NOT POSITIONED HERE ANY MORE. It used to be pointed at the first TNT
     * packet in the buffer exactly once, which silently assumed the walk would start at the front.
     * SyncCursorsTo places it at each section boundary instead -- see the argument there.
     */

    ZydisDecoder Dec;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&Dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
    {
        Out->StopReason = PT_STOP_BAD_INSN;
        return 0;
    }

    int      Enabled       = 0;
    int      AwaitingEvent = 0;   /* a FUP was seen; the TIP that follows is where it resumed */
    int      EverStarted   = 0;
    uint64_t Ip            = 0;
    uint64_t BlockStart    = 0;
    uint32_t BlockInsns    = 0;
    uint32_t Depth         = 0;
    unsigned Stop          = PT_STOP_END;
    uint64_t StopIp        = 0;
    uint32_t StopOffset    = 0;

    for (;;)
    {
        /* ---- resynchronise: find the packet that says where execution is ---- */
        if (!Enabled)
        {
            const PT_PACKET* const P = IpNext(&W, Out, 1);
            if (P == NULL)
                break;

            StopOffset = P->Offset;

            /*
             * Bootstrap: the FUP inside a PSB+ block states where the machine IS. It is the only
             * anchor a trace that was ALREADY RUNNING when the capture began ever offers.
             */
            if ((P->Flags & PT_PKF_IN_PSB) != 0)
            {
                Ip            = P->Payload;
                Enabled       = 1;
                EverStarted   = 1;
                AwaitingEvent = 0;
                BlockStart    = Ip;
                BlockInsns    = 0;
                Out->Sections++;
                Out->PsbBootstraps++;
                RetClear(&W);
                SyncCursorsTo(&W, (uint32_t)(P - W.Pk));
                continue;
            }

            if (P->Kind == PT_PK_OVF)
            {
                Out->Overflows++;
                RetClear(&W);
                AwaitingEvent = 0;
                continue;
            }
            if (P->Kind == PT_PK_TIP_PGD)
            {
                /* Tracing was already off; a PGD here just confirms it. */
                AwaitingEvent = 0;
                continue;
            }
            if (P->Kind == PT_PK_FUP)
            {
                /* An event while disabled: its destination arrives in the next IP packet. */
                AwaitingEvent = 1;
                continue;
            }
            if (P->Flags & PT_PKF_IP_SUPPRESSED)
            {
                /* A PGE or event TIP with no address. Nothing can be walked from it; keep
                 * looking rather than pretending the previous IP was this one's. */
                AwaitingEvent = 0;
                continue;
            }

            /*
             * TIP.PGE always starts a section. A bare TIP starts one only when it is the
             * destination of an event we just saw -- otherwise it is a target for a branch in a
             * section we were never synced to, and walking from it would be a guess.
             */
            if (P->Kind == PT_PK_TIP_PGE || (P->Kind == PT_PK_TIP && AwaitingEvent))
            {
                Ip            = P->Payload;
                Enabled       = 1;
                EverStarted   = 1;
                AwaitingEvent = 0;
                BlockStart    = Ip;
                BlockInsns    = 0;
                Out->Sections++;
                RetClear(&W);
                SyncCursorsTo(&W, (uint32_t)(P - W.Pk));
                continue;
            }

            AwaitingEvent = 0;
            continue;
        }

        /* ---- decode one instruction of the target's own code ---- */
        uint8_t Code[ZYDIS_MAX_INSTRUCTION_LENGTH];
        const uint32_t Got = CodeRead(CodeCtx, Ip, Code, (uint32_t)sizeof(Code));
        if (Got == 0)
        {
            Out->CodeReadFails++;
            Stop = PT_STOP_NO_CODE; StopIp = Ip;
            break;
        }
        Out->CodeBytesRead += Got;

        ZydisDecodedInstruction Insn;
        ZydisDecodedOperand     Ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Dec, Code, Got, &Insn, Ops)))
        {
            Stop = PT_STOP_BAD_INSN; StopIp = Ip;
            break;
        }

        Out->Instructions++;
        BlockInsns++;

        const uint64_t Next  = Ip + Insn.length;
        const unsigned Class = ClassifyInsn(&Insn, Ops);

        /* Before any packet is consumed, apply the PSBs the stream has passed. */
        if (Class != PT_CLS_NORMAL)
            SyncStructural(&W, Out);

        if (Class == PT_CLS_NORMAL)
        {
            if (BlockInsns >= PT_FLOW_MAX_BLOCK_INSNS)
            {
                Stop = PT_STOP_BLOCK_RUNAWAY; StopIp = Ip;
                break;
            }
            Ip = Next;
            continue;
        }

        /* The direct-branch target, resolved from the instruction itself where there is one. */
        uint64_t Direct = 0;
        if (Class == PT_CLS_COND || Class == PT_CLS_JMP_DIRECT || Class == PT_CLS_CALL_DIRECT)
        {
            if (!IsDirectBranch(&Insn, Ops) ||
                !ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Insn, &Ops[0], Ip, &Direct)))
            {
                /* A conditional branch that is not relative does not exist in x86-64. If one
                 * appears to, the decode is wrong and continuing would be a guess. */
                Stop = PT_STOP_BAD_INSN; StopIp = Ip;
                break;
            }
        }

        switch (Class)
        {
        case PT_CLS_COND:
        {
            int Taken = 0;
            /* Report WHERE from the cursor that actually stalled. Reading the last IP packet's
             * offset here put a stop 73% into a file the walk had covered 4% of. */
            if (TntNextIndex(&W) < W.N) StopOffset = W.Pk[TntNextIndex(&W)].Offset;
            if (!TntNext(&W, &Taken))
            {
                Stop = PT_STOP_TNT_EMPTY; StopIp = Ip;
                goto done;
            }
            Out->TntBitsConsumed++;
            Out->CondBranches++;
            if (Taken) Out->CondTaken++;

            const uint64_t Tgt = Taken ? Direct : Next;
            EmitBlock(Out, BlockStart, Ip, Tgt, BlockInsns, Depth,
                      Taken ? PT_EXIT_COND_TAKEN : PT_EXIT_COND_NOT);
            Ip = Tgt; BlockStart = Ip; BlockInsns = 0;
            break;
        }

        case PT_CLS_JMP_DIRECT:
            Out->DirectJumps++;
            EmitBlock(Out, BlockStart, Ip, Direct, BlockInsns, Depth, PT_EXIT_JMP_DIRECT);
            Ip = Direct; BlockStart = Ip; BlockInsns = 0;
            break;

        case PT_CLS_CALL_DIRECT:
            /*
             * ⚠ THE ZERO-LENGTH CALL EXCLUSION IS THE SDM'S, NOT AN OPTIMISATION. 34.4.2.2: "this
             * excludes zero-length CALLs, which are direct near CALLs with displacement zero (to
             * the next IP). These CALLs typically don't have matching RETs." They are the standard
             * position-independent-code idiom for reading RIP, and pushing one would leave a
             * phantom entry that mis-resolves the NEXT compressed RET -- a wrong address produced
             * by a rule that is only five lines long.
             */
            if (Direct == Next)
            {
                Out->ZeroLengthCalls++;
            }
            else
            {
                RetPush(&W, Next, Out);
                Depth++;
            }
            Out->DirectCalls++;
            EmitBlock(Out, BlockStart, Ip, Direct, BlockInsns, Depth, PT_EXIT_CALL_DIRECT);
            Ip = Direct; BlockStart = Ip; BlockInsns = 0;
            break;

        case PT_CLS_RET_NEAR:
        {
            /*
             * The deferred-TIP rule, applied literally (see PtFlow.h): unconsumed TNT bits in hand
             * mean the RET was compressed; none in hand means it was not and a TIP describes it.
             * The modelled stack must also hold something -- the CPU cannot compress a return whose
             * CALL it never saw, so neither can this.
             */
            if (W.RetCount > 0 && TntPendingBeforeIp(&W))
            {
                int Taken = 0;
                (void)TntNext(&W, &Taken);
                Out->TntBitsConsumed++;
                if (!Taken)
                {
                    if (TntNextIndex(&W) < W.N) StopOffset = W.Pk[TntNextIndex(&W)].Offset;
                    /* A compressed RET is a TAKEN indication by definition. A not-taken bit here
                     * means this bit belonged to some other branch and everything after it would
                     * be applied one branch out of step. */
                    Stop = PT_STOP_RETCOMP; StopIp = Ip;
                    goto done;
                }
                uint64_t Tgt = 0;
                (void)RetPop(&W, &Tgt);
                Out->RetsCompressed++;
                if (Depth > 0) Depth--;
                EmitBlock(Out, BlockStart, Ip, Tgt, BlockInsns, Depth, PT_EXIT_RET_COMPRESSED);
                Ip = Tgt; BlockStart = Ip; BlockInsns = 0;
            }
            else
            {
                const PT_PACKET* const P = IpNext(&W, Out, 0);
                if (P == NULL)
                {
                    Stop = PT_STOP_TIP_EMPTY; StopIp = Ip;
                    goto done;
                }
                StopOffset = P->Offset;

                /* The hardware pops on every near RET whether or not it compressed it, so the
                 * model does too -- otherwise the stack drifts one entry deeper forever. */
                uint64_t Discard = 0;
                if (!RetPop(&W, &Discard))
                    Out->RetstackEmpty++;
                if (Depth > 0) Depth--;
                Out->RetsUncompressed++;

                if (P->Kind == PT_PK_TIP && !(P->Flags & PT_PKF_IP_SUPPRESSED))
                {
                    EmitBlock(Out, BlockStart, Ip, P->Payload, BlockInsns, Depth, PT_EXIT_RET_TIP);
                    Ip = P->Payload; BlockStart = Ip; BlockInsns = 0;
                }
                else
                {
                    unsigned Ex = (P->Kind == PT_PK_TIP_PGD) ? PT_EXIT_DISABLED
                                : (P->Kind == PT_PK_FUP)     ? PT_EXIT_EVENT
                                : (P->Kind == PT_PK_OVF)     ? PT_EXIT_NONE
                                                             : PT_EXIT_NONE;
                    if (P->Kind == PT_PK_FUP)   { Out->Events++;    AwaitingEvent = 1; }
                    if (P->Kind == PT_PK_OVF)   { Out->Overflows++; RetClear(&W);      }
                    EmitBlock(Out, BlockStart, Ip, 0, BlockInsns, Depth, Ex);
                    Enabled = 0;
                }
            }
            break;
        }

        case PT_CLS_JMP_INDIRECT:
        case PT_CLS_CALL_INDIRECT:
        case PT_CLS_FAR:
        default:
        {
            const PT_PACKET* const P = IpNext(&W, Out, 0);
            if (P == NULL)
            {
                Stop = PT_STOP_TIP_EMPTY; StopIp = Ip;
                goto done;
            }
            StopOffset = P->Offset;

            if (Class == PT_CLS_CALL_INDIRECT)
            {
                RetPush(&W, Next, Out);
                Depth++;
                Out->IndirectCalls++;
            }
            else if (Class == PT_CLS_JMP_INDIRECT)
            {
                Out->IndirectJumps++;
            }
            else
            {
                Out->FarTransfers++;
            }

            if (P->Kind == PT_PK_TIP && !(P->Flags & PT_PKF_IP_SUPPRESSED))
            {
                const unsigned Ex = (Class == PT_CLS_CALL_INDIRECT) ? PT_EXIT_CALL_INDIRECT
                                  : (Class == PT_CLS_JMP_INDIRECT)  ? PT_EXIT_JMP_INDIRECT
                                                                 : PT_EXIT_FAR;
                EmitBlock(Out, BlockStart, Ip, P->Payload, BlockInsns, Depth, Ex);
                Ip = P->Payload; BlockStart = Ip; BlockInsns = 0;
            }
            else
            {
                /*
                 * A branch whose packet is a PGD, a FUP, or an OVF. All three mean the same thing
                 * for the walk: the path stops being knowable here. Which one it was is recorded
                 * on the block, because "the filter turned tracing off" and "an interrupt arrived"
                 * are entirely different facts about the target.
                 */
                unsigned Ex = PT_EXIT_NONE;
                if (P->Kind == PT_PK_TIP_PGD) { Ex = PT_EXIT_DISABLED; }
                else if (P->Kind == PT_PK_FUP) { Ex = PT_EXIT_EVENT; Out->Events++; AwaitingEvent = 1; }
                else if (P->Kind == PT_PK_OVF) { Out->Overflows++; RetClear(&W); }
                else if (P->Flags & PT_PKF_IP_SUPPRESSED)
                {
                    Stop = PT_STOP_IP_SUPPRESSED; StopIp = Ip;
                    EmitBlock(Out, BlockStart, Ip, 0, BlockInsns, Depth, PT_EXIT_NONE);
                    goto done;
                }
                EmitBlock(Out, BlockStart, Ip, 0, BlockInsns, Depth, Ex);
                Enabled = 0;
            }
            break;
        }
        }
    }

done:
    /* Cursor state at the stop -- captured here so every stop reason carries it, not just the
     * ones somebody thought to instrument. */
    {
        const uint32_t Ti = TntNextIndex(&W);
        const uint32_t Ii = IpPeekIndex(&W);
        Out->StopTntOffset = (Ti < W.N) ? Packets[Ti].Offset : 0xFFFFFFFFu;
        Out->StopIpOffset  = (Ii < W.N) ? Packets[Ii].Offset : 0xFFFFFFFFu;
        Out->StopIpKind    = (Ii < W.N) ? Packets[Ii].Kind   : (uint32_t)PT_PK_COUNT;
        Out->StopRetDepth  = W.RetCount;
    }

    /* A block in progress when the walk ended is still a real run of instructions. */
    if (Enabled && BlockInsns > 0)
        EmitBlock(Out, BlockStart, Ip, 0, BlockInsns, Depth, PT_EXIT_NONE);

    if (S.Full && Stop == PT_STOP_END)
        Stop = PT_STOP_SINK_FULL;
    if (!EverStarted && Stop == PT_STOP_END)
        Stop = PT_STOP_NOT_STARTED;

    Out->StopReason       = Stop;
    Out->StopIp           = StopIp;
    Out->StopPacketOffset = StopOffset;
    return 0;
}
