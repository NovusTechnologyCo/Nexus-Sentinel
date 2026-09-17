/**
 * @file PtFlowSelfTest.c
 * @brief Prove the control-flow walker against an answer computed BEFORE it runs.
 *
 * ============================================================================================
 * WHY A SYNTHETIC PROGRAM AND NOT A REAL TRACE
 * ============================================================================================
 *
 * A reconstructor checked against a real capture looks correct while quietly mis-parsing, because
 * nobody knows what the real answer was. That is the exact failure `PtDecode.h` warns about -- a
 * wrong mask does not produce an error, it produces plausible addresses -- and it applies twice as
 * hard here, since a walker also invents the instructions BETWEEN the addresses.
 *
 * So the input is nine instructions written out by hand and a packet stream assembled byte by byte,
 * and every expected number below was worked out from those two arrays before this file compiled.
 * Nine instructions, eight blocks, one compressed RET, one uncompressed, one zero-length CALL that
 * must NOT be pushed. If the walker disagrees with any of them, it is the walker that is wrong.
 *
 * Three checks, because there are three distinct ways to be wrong:
 *
 *   [1] THE CLASSIFIER, against hand-written encodings of every branch form. This guards a
 *       dependency nothing else can see: whether the disassembler files `LOOP` and `J*CXZ` as
 *       conditional branches is ITS taxonomy decision, while Intel PT's answer is fixed (SDM vol 3
 *       Table 34-16 names them alongside Jcc as the instructions a TNT bit describes). A
 *       disagreement surfaces here as a failed line rather than on hardware as a trace that
 *       desynchronises forty thousand branches in and cannot be told from a target doing something
 *       interesting.
 *
 *   [2] THE WALK -- counts AND the path. The counts alone are not enough: eight blocks with the
 *       right tally of calls and returns is consistent with several different orders, so every
 *       block's start, target and exit kind is asserted individually.
 *
 *   [3] FAIL-CLOSED. Take the code away and the walk must STOP and name the address, not carry on
 *       into memory it has not seen.
 */

#include <stdio.h>
#include <string.h>
#include "PtFlow.h"

/* The synthetic image. The base is arbitrary but must look like a real 64-bit user address. */
#define SELF_BASE  0x0000000140001000ull
#define SELF_SIZE  0x40u

static uint8_t gImage[SELF_SIZE];

/*
 * The program, and the path it takes:
 *
 *   +0x00  call +0x20          ->  push +0x05, enter f1
 *   +0x20  jnz  +0x27          ->  TNT bit 1 = NOT taken, fall through
 *   +0x22  mov eax, 1
 *   +0x27  ret                 ->  TNT bit 2 = taken, COMPRESSED, pop +0x05
 *   +0x05  call +0             ->  zero-length: executed, NOT pushed (SDM 34.4.2.2)
 *   +0x0A  call rax            ->  push +0x0C, TIP -> +0x30
 *   +0x30  ret                 ->  no TNT bits pending, UNCOMPRESSED, TIP -> +0x0C
 *   +0x0C  jmp +0x10           ->  direct, no packet
 *   +0x10  syscall             ->  TIP.PGD: tracing ends here
 */
static void
BuildImage(
    void
    )
{
    /* 0xCC everywhere else. Any step into a gap decodes as INT3, which the walker treats as a
     * transfer needing a packet -- so a wrong path STOPS instead of wandering through padding. */
    memset(gImage, 0xCC, sizeof(gImage));

    /* +0x00  call rel32 -> +0x20   (next = +0x05, so disp = 0x20 - 0x05 = 0x1B) */
    gImage[0x00] = 0xE8; gImage[0x01] = 0x1B;
    gImage[0x02] = 0x00; gImage[0x03] = 0x00; gImage[0x04] = 0x00;

    /* +0x05  call rel32 +0        the position-independent-code idiom for reading RIP */
    gImage[0x05] = 0xE8; gImage[0x06] = 0x00;
    gImage[0x07] = 0x00; gImage[0x08] = 0x00; gImage[0x09] = 0x00;

    /* +0x0A  call rax */
    gImage[0x0A] = 0xFF; gImage[0x0B] = 0xD0;

    /* +0x0C  jmp rel8 -> +0x10     (next = +0x0E, disp = 2) */
    gImage[0x0C] = 0xEB; gImage[0x0D] = 0x02;

    /* +0x0E  nop nop               never executed; here so the jump has something to skip */
    gImage[0x0E] = 0x90; gImage[0x0F] = 0x90;

    /* +0x10  syscall */
    gImage[0x10] = 0x0F; gImage[0x11] = 0x05;

    /* +0x20  jnz rel8 -> +0x27     (next = +0x22, disp = 5) */
    gImage[0x20] = 0x75; gImage[0x21] = 0x05;

    /* +0x22  mov eax, 1 */
    gImage[0x22] = 0xB8; gImage[0x23] = 0x01;
    gImage[0x24] = 0x00; gImage[0x25] = 0x00; gImage[0x26] = 0x00;

    /* +0x27  ret */
    gImage[0x27] = 0xC3;

    /* +0x30  ret                   the indirect call's destination */
    gImage[0x30] = 0xC3;
}

/** The code provider. Outside the image it returns 0, which must stop the walk. */
static uint32_t
ImageRead(
    void* Ctx,
    uint64_t Va,
    uint8_t* Buf,
    uint32_t Len
    )
{
    (void)Ctx;

    if (Va < SELF_BASE || Va >= SELF_BASE + SELF_SIZE)
        return 0;

    const uint32_t Off = (uint32_t)(Va - SELF_BASE);
    uint32_t Take = SELF_SIZE - Off;
    if (Take > Len) Take = Len;

    memcpy(Buf, gImage + Off, Take);
    return Take;
}

/** Append a TIP-family packet carrying a full 8-byte address (IPBytes = 6). */
static uint32_t
PutIp(
    uint8_t* B,
    uint32_t At,
    uint8_t Low5,
    uint64_t Ip
    )
{
    B[At++] = (uint8_t)((6u << 5) | Low5);
    for (int i = 0; i < 8; i++)
        B[At++] = (uint8_t)((Ip >> (8 * i)) & 0xFFu);
    return At;
}

static int gFails;

static void
CheckN(
    const char* What,
    unsigned long long Got,
    unsigned long long Want
    )
{
    if (Got != Want)
    {
        printf("    FAIL  %-32s got %llu, want %llu\n", What, Got, Want);
        gFails++;
    }
    else
    {
        printf("    ok    %-32s %llu\n", What, Got);
    }
}

static void
CheckB(
    const char* What,
    int Cond
    )
{
    if (!Cond) { printf("    FAIL  %s\n", What); gFails++; }
    else       { printf("    ok    %s\n", What); }
}

typedef struct _CLS_CASE
{
    const char* Name;
    unsigned    Want;
    uint32_t    Len;
    uint8_t     Bytes[8];
} CLS_CASE;

int
PtFlowSelfTest(
    void
    )
{
    gFails = 0;

    printf("\n  PT FLOW SELF-TEST -- a known answer, no driver and no target\n");

    /* ==== [1] the classifier ========================================================== */
    printf("\n  [1] instruction classification -- the library's taxonomy against Intel PT's\n");

    static const CLS_CASE kCases[] = {
        { "jz rel8",      PT_CLS_COND,          2, { 0x74, 0x00 } },
        { "jnz rel32",    PT_CLS_COND,          6, { 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00 } },
        { "loop rel8",    PT_CLS_COND,          2, { 0xE2, 0xFE } },
        { "loope rel8",   PT_CLS_COND,          2, { 0xE1, 0xFE } },
        { "loopne rel8",  PT_CLS_COND,          2, { 0xE0, 0xFE } },
        { "jrcxz rel8",   PT_CLS_COND,          2, { 0xE3, 0xFE } },
        { "jmp rel8",     PT_CLS_JMP_DIRECT,    2, { 0xEB, 0x00 } },
        { "jmp rel32",    PT_CLS_JMP_DIRECT,    5, { 0xE9, 0x00, 0x00, 0x00, 0x00 } },
        { "jmp rax",      PT_CLS_JMP_INDIRECT,  2, { 0xFF, 0xE0 } },
        { "jmp [rip+0]",  PT_CLS_JMP_INDIRECT,  6, { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 } },
        { "call rel32",   PT_CLS_CALL_DIRECT,   5, { 0xE8, 0x00, 0x00, 0x00, 0x00 } },
        { "call rax",     PT_CLS_CALL_INDIRECT, 2, { 0xFF, 0xD0 } },
        { "call [rip+0]", PT_CLS_CALL_INDIRECT, 6, { 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00 } },
        { "ret",          PT_CLS_RET_NEAR,      1, { 0xC3 } },
        { "ret imm16",    PT_CLS_RET_NEAR,      3, { 0xC2, 0x08, 0x00 } },
        { "retf",         PT_CLS_FAR,           1, { 0xCB } },
        { "iretq",        PT_CLS_FAR,           2, { 0x48, 0xCF } },
        { "syscall",      PT_CLS_FAR,           2, { 0x0F, 0x05 } },
        { "sysretq",      PT_CLS_FAR,           3, { 0x48, 0x0F, 0x07 } },
        { "int3",         PT_CLS_FAR,           1, { 0xCC } },
        { "int 0x2e",     PT_CLS_FAR,           2, { 0xCD, 0x2E } },
        { "ud2",          PT_CLS_FAR,           2, { 0x0F, 0x0B } },
        { "nop",          PT_CLS_NORMAL,        1, { 0x90 } },
        { "mov rax, rbx", PT_CLS_NORMAL,        3, { 0x48, 0x89, 0xD8 } },
        { "rep movsb",    PT_CLS_NORMAL,        2, { 0xF3, 0xA4 } },
        { "vzeroupper",   PT_CLS_NORMAL,        3, { 0xC5, 0xF8, 0x77 } },
    };

    for (unsigned i = 0; i < sizeof(kCases) / sizeof(kCases[0]); i++)
    {
        unsigned Class = 0;
        uint32_t Len   = 0;

        if (!PtFlowClassifyBytes(kCases[i].Bytes, kCases[i].Len, &Class, &Len))
        {
            printf("    FAIL  %-14s did not decode at all\n", kCases[i].Name);
            gFails++;
            continue;
        }
        if (Class != kCases[i].Want)
        {
            printf("    FAIL  %-14s class %s, want %s\n", kCases[i].Name,
                   PtFlowClassName(Class), PtFlowClassName(kCases[i].Want));
            gFails++;
        }
        else if (Len != kCases[i].Len)
        {
            /* ⚠ THE LENGTH MATTERS AS MUCH AS THE CLASS. A right class with a wrong length steps
             * the walk to the wrong next instruction, and everything after it is fiction. */
            printf("    FAIL  %-14s length %u, want %u\n", kCases[i].Name, Len, kCases[i].Len);
            gFails++;
        }
        else
        {
            printf("    ok    %-14s %-9s len %u\n", kCases[i].Name, PtFlowClassName(Class), Len);
        }
    }

    /* ==== [2] the walk ================================================================= */
    printf("\n  [2] reconstruct nine instructions from a hand-assembled packet stream\n");

    BuildImage();

    uint8_t  Stream[128];
    uint32_t At = 0;

    /* PSB then PSBEND. The decoder syncs on the first PSB and will not start without one. */
    for (int i = 0; i < 8; i++) { Stream[At++] = 0x02; Stream[At++] = 0x82; }
    Stream[At++] = 0x02; Stream[At++] = 0x23;

    /* TIP.PGE -> +0x00. The only thing in the whole stream that says where execution was. */
    At = PutIp(Stream, At, 0x11, SELF_BASE + 0x00);

    /*
     * A short TNT carrying exactly two results: B1 = 0 (the jnz was NOT taken) and B2 = 1 (a
     * compressed RET). The field is Stop<<2 | B1<<1 | B2 = 0b101, and the opcode byte is that
     * shifted up one because bit 0 of a short TNT is the opcode marker: 0b101 << 1 = 0x0A.
     */
    Stream[At++] = 0x0A;

    /* TIP -> +0x30, the destination of `call rax`. */
    At = PutIp(Stream, At, 0x0D, SELF_BASE + 0x30);

    /* TIP -> +0x0C, the destination of the RET at +0x30, UNCOMPRESSED. */
    At = PutIp(Stream, At, 0x0D, SELF_BASE + 0x0C);

    /*
     * ⚠ THIS PACKET IS THE POINT OF THE WHOLE TEST. Three more TNT bits, placed AFTER the RET's
     * TIP. They describe branches that never execute in this program, and they exist to prove the
     * compressed-RET test looks at POSITION rather than at availability.
     *
     * The first version of that test asked "are there any TNT bits left anywhere?", which these
     * three would have answered yes to -- turning the uncompressed RET above into a compressed one,
     * consuming a bit belonging to a branch that had not happened, and popping a return address the
     * hardware never used. The bug was found while hand-building this stream and the packet was
     * kept so it can never come back.
     *
     * Field = Stop<<3 | 1<<2 | 0<<1 | 1 = 0b1101 = 0x0D, in the FIRST payload byte -- a long TNT's
     * payload assembles with its LAST byte most significant (SDM vol 3, Table 34-16).
     */
    Stream[At++] = 0x02; Stream[At++] = 0xA3;
    Stream[At++] = 0x0D;
    for (int i = 0; i < 5; i++) Stream[At++] = 0x00;

    /* TIP.PGD with no IP: the ordinary way a filtered trace stops. */
    Stream[At++] = 0x01;

    static PT_FLOW_BLOCK   Blocks[64];
    static PT_PACKET       Packets[64];
    static PT_FLOW_RESULT  R;
    static PT_DECODE_RESULT Sum;

    memset(&R, 0, sizeof(R));
    R.Blocks   = Blocks;
    R.BlockCap = (uint32_t)(sizeof(Blocks) / sizeof(Blocks[0]));

    PtFlowRun(Stream, At, Packets, (uint32_t)(sizeof(Packets) / sizeof(Packets[0])),
              ImageRead, NULL, &R, &Sum);

    printf("\n    stream  : %u bytes -> %u packets\n", At, R.PacketCount);
    printf("    stopped : %s\n\n", PtFlowStopName(R.StopReason));

    CheckN("instructions executed",      R.Instructions,     9);
    CheckN("basic blocks",               R.BlocksSeen,       8);
    CheckN("sections (PGE..PGD)",        R.Sections,         1);
    CheckN("conditional branches",       R.CondBranches,     1);
    CheckN("  of which taken",           R.CondTaken,        0);
    CheckN("direct calls",               R.DirectCalls,      2);
    CheckN("  zero-length, not pushed",  R.ZeroLengthCalls,  1);
    CheckN("indirect calls",             R.IndirectCalls,    1);
    CheckN("direct jumps",               R.DirectJumps,      1);
    CheckN("compressed RETs",            R.RetsCompressed,   1);
    CheckN("uncompressed RETs",          R.RetsUncompressed, 1);
    CheckN("far transfers (the syscall)", R.FarTransfers,    1);
    CheckN("TNT bits present in stream", R.TntBitsAvailable, 5);
    CheckN("TNT bits actually consumed", R.TntBitsConsumed,  2);
    CheckN("code read failures",         R.CodeReadFails,    0);
    CheckB("walk ran to the end of the stream", R.StopReason == PT_STOP_END);

    static const struct { uint64_t Start, Target; unsigned Exit; } kWant[] = {
        { 0x00, 0x20, PT_EXIT_CALL_DIRECT    },
        { 0x20, 0x22, PT_EXIT_COND_NOT       },
        { 0x22, 0x05, PT_EXIT_RET_COMPRESSED },
        { 0x05, 0x0A, PT_EXIT_CALL_DIRECT    },
        { 0x0A, 0x30, PT_EXIT_CALL_INDIRECT  },
        { 0x30, 0x0C, PT_EXIT_RET_TIP        },
        { 0x0C, 0x10, PT_EXIT_JMP_DIRECT     },
        { 0x10, 0x00, PT_EXIT_DISABLED       },
    };
    const unsigned NWant = (unsigned)(sizeof(kWant) / sizeof(kWant[0]));

    printf("\n    THE RECONSTRUCTED PATH (offsets from the image base)\n");
    printf("      %-3s %-9s %-9s %-6s %-6s %s\n", "#", "START", "TARGET", "INSNS", "DEPTH", "EXIT");
    for (unsigned i = 0; i < R.BlockCount; i++)
    {
        const PT_FLOW_BLOCK* const B = &Blocks[i];
        printf("      %-3u +0x%04llX   +0x%04llX   %-6u %-6u %s\n", i,
               (unsigned long long)(B->Start - SELF_BASE),
               (unsigned long long)(B->Target ? (B->Target - SELF_BASE) : 0),
               B->Insns, B->Depth, PtFlowExitName(B->Exit));
    }
    printf("\n");

    if (R.BlockCount != NWant)
    {
        printf("    FAIL  block count %u, want %u\n", R.BlockCount, NWant);
        gFails++;
    }
    else
    {
        int PathOk = 1;
        for (unsigned i = 0; i < NWant; i++)
        {
            const PT_FLOW_BLOCK* const B = &Blocks[i];
            const uint64_t WantStart  = SELF_BASE + kWant[i].Start;
            const uint64_t WantTarget = kWant[i].Target ? (SELF_BASE + kWant[i].Target) : 0;

            if (B->Start != WantStart || B->Target != WantTarget || B->Exit != kWant[i].Exit)
            {
                printf("    FAIL  block %u: +0x%04llX -> +0x%04llX %s,  want +0x%04llX -> +0x%04llX %s\n",
                       i,
                       (unsigned long long)(B->Start - SELF_BASE),
                       (unsigned long long)(B->Target ? B->Target - SELF_BASE : 0),
                       PtFlowExitName(B->Exit),
                       (unsigned long long)kWant[i].Start,
                       (unsigned long long)kWant[i].Target,
                       PtFlowExitName(kWant[i].Exit));
                gFails++;
                PathOk = 0;
            }
        }
        if (PathOk)
            printf("    ok    all 8 blocks match the path computed before the walker existed\n");
    }

    /* ==== [3] fail-closed ============================================================== */
    printf("\n  [3] fail-closed when the target's code cannot be read\n");
    {
        /*
         * Replace the program with a run of nops. The walk then marches straight past the end of
         * the 0x40-byte image into an address the reader refuses, which is what a wrong IP looks
         * like in the field. It must STOP and say where.
         */
        memset(gImage, 0x90, sizeof(gImage));

        memset(&R, 0, sizeof(R));
        R.Blocks   = Blocks;
        R.BlockCap = (uint32_t)(sizeof(Blocks) / sizeof(Blocks[0]));
        PtFlowRun(Stream, At, Packets, (uint32_t)(sizeof(Packets) / sizeof(Packets[0])),
                  ImageRead, NULL, &R, &Sum);

        CheckB("an unreadable address STOPS the walk", R.StopReason == PT_STOP_NO_CODE);
        CheckB("and the address is reported",          R.StopIp == SELF_BASE + SELF_SIZE);
        CheckN("code read failures",                   R.CodeReadFails, 1);
        printf("    ->    stopped at 0x%llX: %s\n",
               (unsigned long long)R.StopIp, PtFlowStopName(R.StopReason));
    }

    printf("\n  %s -- %d failure(s)\n\n",
           gFails ? "PT FLOW SELF-TEST FAILED" : "PT FLOW SELF-TEST PASSED", gFails);
    return gFails;
}
