/**
 * @file NexusTestTarget.c
 * @brief A process that deliberately does every thing the capture commands exist to detect.
 *
 * ============================================================================================
 * WHY A USERMODE TARGET RATHER THAN A TEST DRIVER
 * ============================================================================================
 *
 * The obvious way to test the capture surface is a driver to capture against. It is also the
 * expensive way, and mostly unnecessary: the split that matters is not manual-map vs system-loaded,
 * it is WHAT EACH COMMAND TARGETS.
 *
 *   a PROCESS   regions/--hidden, modules, readproc, snapshot, --on-entropy, --atomic,
 *               va2pa, freeze/thaw, procs                       <- everything here
 *   kernel POOL pool list, pool bait                            <- needs no target at all
 *   a MODULE    read <mod>, read --pristine, watch              <- the only three that need a driver
 *
 * So a usermode target covers most of the surface, and covers it BETTER: a driver we wrote and
 * manually mapped could not exercise `regions --hidden` at all, because the detector's whole premise
 * is a region the LOADER does not know about, and in a process we can create exactly that.
 *
 * ============================================================================================
 * ⚠ WHAT MAKES THIS AN HONEST TARGET
 * ============================================================================================
 *
 * Every behaviour here is REAL, not simulated:
 *
 *   1. The hidden region is a genuine manual map of a REAL System32 DLL -- headers, sections,
 *      per-section protections and applied relocations. Not a VirtualAlloc with a fake PE header.
 *      A synthesized image might satisfy whatever the detector happens to key on; a real one is the
 *      actual case.
 *   2. The decrypting region really changes entropy, from encrypted-looking to code-looking and
 *      back. There is no flag saying "pretend I decrypted".
 *   3. The mutating region is written by a real thread, continuously, so a torn read is genuinely
 *      possible and `--atomic` has something to actually prevent.
 *
 * ⚠ IT IS ALSO DELIBERATELY BENIGN. It maps an already-installed Microsoft DLL, executes none of it,
 * downloads nothing, and touches nothing outside its own address space. It is a target, not a
 * payload.
 *
 * ============================================================================================
 * WHAT IT DOES NOT COVER, STATED SO IT IS NOT ASSUMED
 * ============================================================================================
 *
 *   read <mod> / --pristine / watch   need a KERNEL module. `read` is already verified against
 *                                     ntoskrnl.exe, and `watch` can be driven by starting any
 *                                     inbox driver service -- neither needs a custom driver.
 *   pool list / pool bait             kernel pool; no target process involved.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The DLL manually mapped to create the hidden region. Already on every Windows machine, chosen
 * because it is small, has relocations, and is not something the loader would already have mapped
 * into a console program at a fixed base. */
static const char* const kVictimDll = "C:\\Windows\\System32\\winhttp.dll";

#define REGION_BYTES   (64u * 1024u)

static volatile LONG  gRun = 1;
static unsigned char* gMutating;      /* rewritten continuously by a thread   */
static unsigned char* gCycling;       /* encrypted <-> plaintext on a timer   */
static unsigned char* gKnown;         /* fixed, verifiable content            */

/*
 * A deterministic byte stream. Deliberately NOT rand(): the operator has to be able to verify a
 * dump byte-for-byte from a different machine, so the pattern must be reproducible from the seed
 * alone.
 */
static unsigned char
StreamByte(
    unsigned* State
    )
{
    *State = (*State * 1103515245u) + 12345u;
    return (unsigned char)(*State >> 16);
}

/**
 * Fill a region so it looks ENCRYPTED: near-uniform byte distribution, ~8 bits/byte of entropy.
 */
static void
FillEncrypted(
    unsigned char* p,
    size_t n,
    unsigned seed
    )
{
    unsigned s = seed;
    for (size_t i = 0; i < n; i++)
        p[i] = StreamByte(&s);
}

/**
 * Fill a region so it looks like CODE: a small repeating alphabet, ~4 bits/byte.
 *
 * Not literal x86 -- nothing executes this -- but the property the detector uses is the entropy, and
 * this reproduces that property honestly rather than claiming it.
 */
static void
FillPlaintext(
    unsigned char* p,
    size_t n
    )
{
    static const unsigned char kOps[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0xD9
    };
    for (size_t i = 0; i < n; i++)
        p[i] = kOps[i % sizeof(kOps)];
}

/** The thread that makes `--atomic` mean something. */
static DWORD WINAPI
MutatorThread(
    LPVOID Unused
    )
{
    (void)Unused;
    unsigned seq = 0;
    while (InterlockedCompareExchange(&gRun, 1, 1))
    {
        /*
         * Write a monotonically increasing stamp across the whole region, SLOWLY AND CONTINUOUSLY.
         *
         * ⚠ THE PACING IS THE POINT, and the first version got it wrong. It wrote all 64 KB in a
         * few microseconds and then slept ~15 ms (a nominal Sleep(1) rounds up to the system clock
         * tick). A 4 KB read completes in well under a microsecond, so it essentially never landed
         * inside the write window -- BOTH a torn and an atomic read came back consistent, and the
         * test demonstrated nothing about --atomic while looking like a pass.
         *
         * Yielding every page instead spreads one sweep across many scheduling quanta, so the
         * region is almost always PARTLY updated. Tearing becomes the common case rather than a
         * rare race, which is what makes the comparison meaningful.
         *
         * ⚠ AND THE SUCCESS CRITERION IS NOT "ONE STAMP". Freezing mid-sweep leaves the region
         * genuinely half-written, so a correct atomic read of it SHOULD report two stamps -- that
         * is what the memory actually contained at that instant. What distinguishes them is
         * STRUCTURE: a frozen read sees one instant, so a sequential sweep yields at most two
         * adjacent values with exactly ONE boundary. An unfrozen read can catch the writer moving
         * and show extra boundaries or non-adjacent values.
         */
        seq++;
        for (size_t i = 0; i < REGION_BYTES; i += 4)
        {
            *(unsigned*)(gMutating + i) = seq;
            if ((i & 0xFFF) == 0)
                SwitchToThread();   /* yield per page: widens the window without a 15 ms sleep */
        }
    }
    return 0;
}

/** The thread that makes `--on-entropy` mean something. */
static DWORD WINAPI
CyclerThread(
    LPVOID Unused
    )
{
    (void)Unused;
    unsigned seed = 0xC0FFEEu;
    for (;;)
    {
        if (!InterlockedCompareExchange(&gRun, 1, 1))
            break;

        /* ENCRYPTED for a while... */
        FillEncrypted(gCycling, REGION_BYTES, seed++);
        Sleep(3000);

        if (!InterlockedCompareExchange(&gRun, 1, 1))
            break;

        /* ...then briefly PLAINTEXT. This is the window a capture has to catch, and it is short on
         * purpose: a target that stayed decrypted would not test the trigger, it would test a
         * plain read. */
        FillPlaintext(gCycling, REGION_BYTES);
        Sleep(700);
    }
    return 0;
}

/**
 * Manually map a real PE into this process, the way a loader would NOT.
 *
 * ⚠ THIS IS THE POINT OF THE WHOLE PROGRAM. `regions --hidden` subtracts the loader's module list
 * from the region list, so a genuine positive requires memory that is committed, executable, and
 * unknown to the loader. Nothing else in a normal process produces that.
 *
 * Relocations ARE applied, deliberately: it means the mapped bytes differ from the on-disk file, so
 * a dump can be checked for having captured the RELOCATED image rather than something that could
 * have been read off disk instead.
 *
 * Nothing is executed and no imports are resolved. This is a capture target, not a loaded module,
 * and running it would add risk for no test value.
 */
static unsigned char*
ManualMapDll(
    const char* Path,
    size_t* OutSize
    )
{
    *OutSize = 0;

    HANDLE f = CreateFileA(Path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
    {
        printf("  could not open %s (error %lu)\n", Path, GetLastError());
        return NULL;
    }

    const DWORD FileSize = GetFileSize(f, NULL);
    unsigned char* const Raw = (unsigned char*)malloc(FileSize);
    DWORD Got = 0;
    if (Raw == NULL || !ReadFile(f, Raw, FileSize, &Got, NULL) || Got != FileSize)
    {
        printf("  could not read %s\n", Path);
        CloseHandle(f);
        free(Raw);
        return NULL;
    }
    CloseHandle(f);

    const IMAGE_DOS_HEADER* const Dos = (const IMAGE_DOS_HEADER*)Raw;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("  %s is not a PE\n", Path);
        free(Raw);
        return NULL;
    }
    const IMAGE_NT_HEADERS64* const Nt = (const IMAGE_NT_HEADERS64*)(Raw + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE ||
        Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        printf("  %s is not PE32+\n", Path);
        free(Raw);
        return NULL;
    }

    const SIZE_T ImageSize = Nt->OptionalHeader.SizeOfImage;

    /* RW first so headers and sections can be written; per-section protections applied after, which
     * is what gives the region its executable pages and makes it look like a mapped image. */
    unsigned char* const Base =
        (unsigned char*)VirtualAlloc(NULL, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Base == NULL)
    {
        printf("  VirtualAlloc(%llu) failed: %lu\n", (unsigned long long)ImageSize, GetLastError());
        free(Raw);
        return NULL;
    }

    memcpy(Base, Raw, Nt->OptionalHeader.SizeOfHeaders);

    const IMAGE_SECTION_HEADER* const Sec = IMAGE_FIRST_SECTION(Nt);
    for (WORD i = 0; i < Nt->FileHeader.NumberOfSections; i++)
    {
        if (Sec[i].SizeOfRawData == 0)
            continue;
        memcpy(Base + Sec[i].VirtualAddress,
               Raw + Sec[i].PointerToRawData,
               Sec[i].SizeOfRawData);
    }

    /* Relocations. Applied so the mapped bytes are NOT the disk bytes -- see the note above. */
    const ULONGLONG Delta = (ULONGLONG)(ULONG_PTR)Base - Nt->OptionalHeader.ImageBase;
    const IMAGE_DATA_DIRECTORY* const RelocDir =
        &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (Delta != 0 && RelocDir->Size != 0)
    {
        const IMAGE_BASE_RELOCATION* Rel =
            (const IMAGE_BASE_RELOCATION*)(Base + RelocDir->VirtualAddress);
        const unsigned char* const RelEnd = Base + RelocDir->VirtualAddress + RelocDir->Size;

        while ((const unsigned char*)Rel < RelEnd && Rel->SizeOfBlock != 0)
        {
            const DWORD Count = (Rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            const WORD* const Ent = (const WORD*)(Rel + 1);
            for (DWORD k = 0; k < Count; k++)
            {
                if ((Ent[k] >> 12) != IMAGE_REL_BASED_DIR64)
                    continue;
                ULONGLONG* const Patch =
                    (ULONGLONG*)(Base + Rel->VirtualAddress + (Ent[k] & 0x0FFF));
                *Patch += Delta;
            }
            Rel = (const IMAGE_BASE_RELOCATION*)((const unsigned char*)Rel + Rel->SizeOfBlock);
        }
    }

    /* Per-section protections. The executable ones are what `regions --hidden` keys on. */
    for (WORD i = 0; i < Nt->FileHeader.NumberOfSections; i++)
    {
        const DWORD C = Sec[i].Characteristics;
        DWORD Prot = PAGE_READONLY;
        if (C & IMAGE_SCN_MEM_EXECUTE)
            Prot = (C & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (C & IMAGE_SCN_MEM_WRITE)
            Prot = PAGE_READWRITE;

        DWORD Old = 0;
        SIZE_T Size = Sec[i].Misc.VirtualSize ? Sec[i].Misc.VirtualSize : Sec[i].SizeOfRawData;
        if (Size != 0)
            VirtualProtect(Base + Sec[i].VirtualAddress, Size, Prot, &Old);
    }

    free(Raw);
    *OutSize = ImageSize;
    return Base;
}

int
main(
    int argc,
    char** argv
    )
{
    /*
     * `--no-hidden` builds the CONTROL: identical in every way except that no PE is manually
     * mapped.
     *
     * ⚠ THE CONTROL IS WHAT MAKES THE POSITIVE MEAN ANYTHING. "regions --hidden finds nothing on a
     * clean process" was previously checked against whatever process was handy, and that is how the
     * harness ended up pointing at a PowerShell host and reporting 57 hits -- correctly, because a
     * JIT runtime really does allocate executable memory belonging to no module. Two processes from
     * the SAME binary differing by exactly one variable cannot produce that confusion.
     */
    int MapHidden = 1;
    for (int i = 1; i < argc; i++)
        if (_stricmp(argv[i], "--no-hidden") == 0)
            MapHidden = 0;

    /*
     * ⚠ UNBUFFERED, and this is not cosmetic. The whole output of this program is the ADDRESSES the
     * operator needs to drive the capture commands against it -- and the program then runs forever.
     * With stdout redirected to a file or a pipe, the CRT switches to full buffering, so nothing is
     * written until the buffer fills or the process exits. A process that never exits therefore
     * prints NOTHING, and the addresses are unreachable exactly when they are needed.
     *
     * Found by running it: the first version printed everything and the redirect file stayed empty.
     */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("==============================================================================\n");
    printf(" NEXUS TEST TARGET -- a process that does what the capture commands detect\n");
    printf("==============================================================================\n\n");

    /* --- 1. the region with KNOWN content, for byte-for-byte verification ------------------- */
    gKnown = (unsigned char*)VirtualAlloc(NULL, REGION_BYTES, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (gKnown == NULL) { printf("VirtualAlloc failed\n"); return 1; }
    {
        unsigned s = 0x1234u;
        for (size_t i = 0; i < REGION_BYTES; i++)
            gKnown[i] = StreamByte(&s);
    }

    /* --- 2. the region that CHANGES, so --atomic has something to prevent ------------------- */
    gMutating = (unsigned char*)VirtualAlloc(NULL, REGION_BYTES, MEM_COMMIT | MEM_RESERVE,
                                             PAGE_READWRITE);
    if (gMutating == NULL) { printf("VirtualAlloc failed\n"); return 1; }

    /* --- 3. the region that CYCLES entropy, for --on-entropy and the union ------------------ */
    gCycling = (unsigned char*)VirtualAlloc(NULL, REGION_BYTES, MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
    if (gCycling == NULL) { printf("VirtualAlloc failed\n"); return 1; }
    FillEncrypted(gCycling, REGION_BYTES, 1);

    /*
     * --- 3b. a region with a GUARANTEED unmapped boundary, for partial reads -----------------
     *
     * ⚠ THE OTHER REGIONS CANNOT TEST THIS, which is why this one exists. VirtualAlloc hands out
     * 64 KB-granular blocks and consecutive calls land ADJACENT -- measured: `known` at ...F70000
     * and `mutating` at ...F80000, exactly 65536 apart. So a deliberately oversized read off the
     * end of one simply runs into the next and legitimately succeeds, and a partial-read test built
     * on it reports a false failure.
     *
     * Reserving twice the space and committing only the first page gives a boundary that is
     * guaranteed unmapped: a read of 8192 from here MUST come back with 4096.
     */
    unsigned char* const Guarded =
        (unsigned char*)VirtualAlloc(NULL, 2 * 4096, MEM_RESERVE, PAGE_NOACCESS);
    unsigned char* Partial = NULL;
    if (Guarded != NULL)
    {
        Partial = (unsigned char*)VirtualAlloc(Guarded, 4096, MEM_COMMIT, PAGE_READWRITE);
        if (Partial != NULL)
            memset(Partial, 0xAB, 4096);        /* recognisable, and NOT uniform-page degenerate */
    }

    /* --- 4. the HIDDEN region: a real PE the loader knows nothing about --------------------- */
    size_t HiddenSize = 0;
    unsigned char* const Hidden = MapHidden ? ManualMapDll(kVictimDll, &HiddenSize) : NULL;

    printf("  pid              : %lu\n\n", GetCurrentProcessId());
    printf("  known content    : 0x%p  (%u bytes, deterministic from seed 0x1234)\n",
           (void*)gKnown, REGION_BYTES);
    printf("  mutating         : 0x%p  (%u bytes, rewritten every ~1 ms)\n",
           (void*)gMutating, REGION_BYTES);
    printf("  entropy cycling  : 0x%p  (%u bytes, ~3 s encrypted / ~0.7 s plaintext)\n",
           (void*)gCycling, REGION_BYTES);
    if (Partial != NULL)
        printf("  partial boundary : 0x%p  (ONE committed page; the next is RESERVED only, so a\n"
               "                     read of 8192 must come back with exactly 4096)\n",
               (void*)Partial);
    if (Hidden != NULL)
        printf("  HIDDEN (manual)  : 0x%p  (%llu bytes, %s, relocated, NOT executed)\n",
               (void*)Hidden, (unsigned long long)HiddenSize, kVictimDll);
    else if (!MapHidden)
        printf("  HIDDEN (manual)  : SUPPRESSED (--no-hidden) -- this is the CONTROL process;\n"
               "                     `regions --hidden` on it must find NOTHING\n");
    else
        printf("  HIDDEN (manual)  : FAILED -- regions --hidden has no positive to find\n");

    printf("\n------------------------------------------------------------------------------\n");
    printf(" DRIVE THE COMMANDS (elevated shell)\n");
    printf("------------------------------------------------------------------------------\n\n");

    const unsigned long pid = GetCurrentProcessId();
    printf("  THE ONE THAT MATTERS -- a genuine positive for the manual-map detector:\n");
    printf("    PlatformCtl regions %lu --hidden\n", pid);
    if (Hidden != NULL)
        printf("      expect an unclaimed executable region at or inside 0x%p\n\n", (void*)Hidden);

    printf("  byte-for-byte read, verifiable against the seed:\n");
    printf("    PlatformCtl readproc %lu 0x%p 256\n\n", pid, (void*)gKnown);

    printf("  VA -> PA -> physical read, two paths to the same bytes:\n");
    printf("    PlatformCtl va2pa %lu 0x%p\n", pid, (void*)gKnown);
    printf("    PlatformCtl readphys <the PA it prints> 256\n\n");

    printf("  torn vs consistent -- run both, then count STAMP BOUNDARIES in each:\n");
    printf("    PlatformCtl readproc %lu 0x%p 65536 torn.bin\n", pid, (void*)gMutating);
    printf("    PlatformCtl readproc %lu 0x%p 65536 atomic.bin --atomic\n", pid, (void*)gMutating);
    printf("      the region is swept continuously, so BOTH may show two stamps -- that is\n");
    printf("      correct. The difference is STRUCTURE: frozen sees ONE instant, so at most one\n");
    printf("      boundary between two adjacent values. Unfrozen can catch the writer moving.\n\n");

    printf("  catch the decrypt window (it is ~0.7 s in every ~3.7 s):\n");
    printf("    PlatformCtl snapshot %lu 0x%p 4096 --on-entropy --out caught.bin\n",
           pid, (void*)gCycling);
    printf("    PlatformCtl snapshot %lu 0x%p 4096 --count 8 --interval 500 --out series\n\n",
           pid, (void*)gCycling);

    printf("  freeze/thaw against a process that is genuinely busy:\n");
    printf("    PlatformCtl freeze %lu    then    PlatformCtl thaw %lu\n\n", pid, pid);

    printf("------------------------------------------------------------------------------\n");
    printf("  Running. Ctrl+C to stop.\n");
    printf("  (nothing here is executed from the mapped DLL, and nothing leaves this process)\n");
    printf("------------------------------------------------------------------------------\n");

    HANDLE t1 = CreateThread(NULL, 0, MutatorThread, NULL, 0, NULL);
    HANDLE t2 = CreateThread(NULL, 0, CyclerThread, NULL, 0, NULL);

    for (;;)
        Sleep(1000);

    /* Unreachable: the operator stops this with Ctrl+C. Kept so the handles are visibly owned. */
    (void)t1; (void)t2;
}
