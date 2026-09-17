/**
 * @file FlowTarget.c
 * @brief A target whose control flow is KNOWN EXACTLY, for proving `trace flow` on hardware.
 *
 * ============================================================================================
 * WHY THIS EXISTS
 * ============================================================================================
 *
 * `trace flow --selftest` proves the walker against a hand-built packet stream. That covers the
 * decoder and the walk, and it cannot cover the half that only silicon produces: real PSBs, real
 * deferred TIPs, real compressed RETs chosen by the CPU rather than by me, and a real IP filter.
 *
 * A trace of an arbitrary process cannot prove those, because nobody knows what the right answer
 * was. This program is written so that the answer is known before the trace is taken:
 *
 *   ITERATIONS x 8 calls, and ITERATIONS x 8 returns.
 *
 * Eight nested `__declspec(noinline)` functions, one loop, no libraries in the traced range. The
 * count is codegen-independent -- an optimiser can move code around but it cannot change how many
 * times a chain of eight non-inlinable calls is entered -- which is what makes it a known answer
 * and not merely a plausible one.
 *
 * ⚠ AND IT REPORTS THE SAME NUMBER FROM AN INDEPENDENT DIRECTION. `gSink` is incremented once at
 * the bottom of the chain, so the target prints how many times it actually got there. A
 * reconstruction claiming 8 x N calls when the target says it ran M times, M != N, is wrong no
 * matter how well-formed its output looks.
 *
 * Timing is deliberate and printed: it idles first so PT can be armed, runs the chain, then idles
 * again -- ALIVE -- because reconstruction reads the code out of the live process. A target that
 * exits before the walk takes its disassembly with it.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

volatile long long gSink;

/*
 * Eight of them, each calling the next. `noinline` is what makes the count knowable; without it
 * the whole chain collapses to one function and the trace is correct while proving nothing.
 */
__declspec(noinline) static void F8(void) { gSink++; }
__declspec(noinline) static void F7(void) { F8(); }
__declspec(noinline) static void F6(void) { F7(); }
__declspec(noinline) static void F5(void) { F6(); }
__declspec(noinline) static void F4(void) { F5(); }
__declspec(noinline) static void F3(void) { F4(); }
__declspec(noinline) static void F2(void) { F3(); }
__declspec(noinline) static void F1(void) { F2(); }

__declspec(noinline) static void ChainLoop(int N)
{
    for (int i = 0; i < N; i++)
        F1();
}

int
main(
    int argc,
    char** argv
    )
{
    const int Iterations = (argc > 1) ? atoi(argv[1]) : 1000;
    const int ArmDelayMs = (argc > 2) ? atoi(argv[2]) : 12000;
    const int HoldMs     = (argc > 3) ? atoi(argv[3]) : 300000;

    const unsigned long long Base = (unsigned long long)(ULONG_PTR)GetModuleHandleW(NULL);

    /*
     * The IP-range filter needs an address range, and these are the addresses. Printed rather
     * than guessed from a map file: ASLR moves the image every run, so a range recorded from a
     * previous run would filter a trace to somebody else's code.
     *
     * F8 is the lowest and ChainLoop the highest in this file's emission order, but that is the
     * COMPILER's choice, so the bounds are computed rather than assumed.
     */
    unsigned long long Lo = (unsigned long long)(ULONG_PTR)F1;
    unsigned long long Hi = Lo;
    {
        void* const Fns[] = { (void*)F1, (void*)F2, (void*)F3, (void*)F4,
                              (void*)F5, (void*)F6, (void*)F7, (void*)F8, (void*)ChainLoop };
        for (int i = 0; i < (int)(sizeof(Fns) / sizeof(Fns[0])); i++)
        {
            const unsigned long long A = (unsigned long long)(ULONG_PTR)Fns[i];
            if (A < Lo) Lo = A;
            if (A > Hi) Hi = A;
        }
        /* The highest function's own body extends past its entry; 0x200 covers any of these. */
        Hi += 0x200;
    }

    printf("FlowTarget\n");
    printf("  pid        : %lu\n", GetCurrentProcessId());
    printf("  image base : 0x%llX\n", Base);
    printf("  filter     : 0x%llX-0x%llX\n", Lo, Hi);
    printf("  known answer: %d iterations x 8 calls = %d calls, and the same count of returns\n",
           Iterations, Iterations * 8);
    printf("  F1..F8     :");
    printf(" 0x%llX", (unsigned long long)(ULONG_PTR)F1);
    printf(" 0x%llX", (unsigned long long)(ULONG_PTR)F8);
    printf("\n");
    printf("  arming in  : %d ms\n", ArmDelayMs);
    fflush(stdout);

    Sleep((DWORD)ArmDelayMs);

    printf("  RUNNING\n");
    fflush(stdout);

    ChainLoop(Iterations);

    printf("  DONE       : gSink = %lld  (this is the target's own count of chain completions)\n",
           gSink);
    printf("  holding alive %d ms so the walk can read this process's code\n", HoldMs);
    fflush(stdout);

    Sleep((DWORD)HoldMs);
    return 0;
}
