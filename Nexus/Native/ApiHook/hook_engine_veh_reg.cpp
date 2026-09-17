/**
 * @file hook_engine_veh_reg.cpp
 * @brief VEH registration bypass strategies — deep-unhook and manual list insertion
 *
 * Unity-included from hook_engine_veh.cpp. Do NOT add to vcxproj.
 *
 * EAC blocks AddVectoredExceptionHandler at multiple levels:
 * - kernel32 wrapper: returns NULL
 * - ntdll entry stub: clean (NOP + JMP), but the JMP target (RtlpAddVectoredHandler)
 *   or functions it calls internally are hooked
 *
 * Strategy: follow the JMP to the real implementation, scan the ntdll .text
 * section for ALL in-memory vs on-disk differences, temporarily restore
 * original bytes across the entire section, call AddVectoredExceptionHandler,
 * then put EAC's hooks back. This deep-unhook covers the entire call chain.
 *
 * Fallback: manually find the VEH linked list in ntdll and insert directly.
 */

// Follow JMP chains to find the real function body
static uint8_t* FollowJmpChain(uint8_t* addr, int maxDepth)
{
    for (int d = 0; d < maxDepth; d++)
    {
        if (addr[0] == 0x90 && addr[1] == 0xE9) // NOP + JMP rel32
        {
            int32_t rel = *(int32_t*)(addr + 2);
            addr = addr + 6 + rel;
            continue;
        }
        if (addr[0] == 0xE9) // JMP rel32
        {
            int32_t rel = *(int32_t*)(addr + 1);
            addr = addr + 5 + rel;
            continue;
        }
        break;
    }
    return addr;
}

// Deep-unhook: restore ALL hooked bytes in ntdll .text section from disk,
// call the target function, then restore EAC's patches.
static PVOID VehRegister_DeepUnhook(ULONG firstHandler, PVECTORED_EXCEPTION_HANDLER handler)
{
    if (!g_pfnRtlAddVEH) return NULL;

    HMODULE hMemNtdll = GetModuleHandleA("ntdll.dll");
    if (!hMemNtdll) return NULL;

    // Load clean ntdll from disk
    HMODULE hDiskNtdll = LoadLibraryExA("ntdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hDiskNtdll)
    {
        DbgLog("[veh-deep] LoadLibraryEx failed, err=%u", GetLastError());
        return NULL;
    }

    // Find .text section boundaries
    IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)hMemNtdll;
    IMAGE_NT_HEADERS* ntHdr = (IMAGE_NT_HEADERS*)((uint8_t*)hMemNtdll + dosHdr->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHdr);

    uint8_t* textMem = NULL;
    uint8_t* textDisk = NULL;
    DWORD textSize = 0;

    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++)
    {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            textMem = (uint8_t*)hMemNtdll + sections[i].VirtualAddress;
            textDisk = (uint8_t*)hDiskNtdll + sections[i].VirtualAddress;
            textSize = sections[i].Misc.VirtualSize;
            DbgLog("[veh-deep] .text section: RVA=0x%X size=0x%X", sections[i].VirtualAddress, textSize);
            break;
        }
    }

    if (!textMem || !textDisk || textSize == 0)
    {
        DbgLog("[veh-deep] Failed to find executable section");
        FreeLibrary(hDiskNtdll);
        return NULL;
    }

    // Follow JMP chain from entry to real implementation
    uint8_t* entryAddr = (uint8_t*)g_pfnRtlAddVEH;
    uint8_t* realFunc = FollowJmpChain(entryAddr, 5);
    DbgLog("[veh-deep] RtlAddVEH entry=%p realFunc=%p (delta=%lld)",
        entryAddr, realFunc, (long long)(realFunc - entryAddr));

    // Dump first 16 bytes of real implementation (mem vs disk)
    uintptr_t realRva = (uintptr_t)realFunc - (uintptr_t)hMemNtdll;
    uint8_t* diskReal = (uint8_t*)hDiskNtdll + realRva;
    DbgLog("[veh-deep] Real @%p RVA=0x%X", realFunc, (unsigned)realRva);
    DbgLog("[veh-deep] MEM: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
        realFunc[0], realFunc[1], realFunc[2], realFunc[3], realFunc[4], realFunc[5],
        realFunc[6], realFunc[7], realFunc[8], realFunc[9], realFunc[10], realFunc[11],
        realFunc[12], realFunc[13], realFunc[14], realFunc[15]);
    DbgLog("[veh-deep] DSK: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
        diskReal[0], diskReal[1], diskReal[2], diskReal[3], diskReal[4], diskReal[5],
        diskReal[6], diskReal[7], diskReal[8], diskReal[9], diskReal[10], diskReal[11],
        diskReal[12], diskReal[13], diskReal[14], diskReal[15]);

    // Count all differences in the entire .text section
    int diffCount = 0;
    for (DWORD off = 0; off < textSize; off++)
    {
        if (textMem[off] != textDisk[off])
            diffCount++;
    }
    DbgLog("[veh-deep] .text section: %d byte differences found (of %u total)", diffCount, textSize);

    // Also scan writable sections (.data, .mrdata, etc.) for differences
    int dataDiffCount = 0;
    int dataSectionsScanned = 0;
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++)
    {
        if ((sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            !(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            uint8_t* secMem = (uint8_t*)hMemNtdll + sections[i].VirtualAddress;
            uint8_t* secDisk = (uint8_t*)hDiskNtdll + sections[i].VirtualAddress;
            DWORD secSize = sections[i].Misc.VirtualSize;
            int secDiffs = 0;

            for (DWORD off = 0; off < secSize; off++)
            {
                if (secMem[off] != secDisk[off])
                    secDiffs++;
            }

            char secName[9] = {0};
            memcpy(secName, sections[i].Name, 8);
            if (secDiffs > 0)
                DbgLog("[veh-deep] Section '%s': %d data diffs (size=0x%X)", secName, secDiffs, secSize);
            dataDiffCount += secDiffs;
            dataSectionsScanned++;
        }
    }
    DbgLog("[veh-deep] Data sections scanned: %d, total data diffs: %d", dataSectionsScanned, dataDiffCount);

    if (diffCount == 0)
    {
        // No hooks in .text at all -- the function fails for a different reason.
        // Try calling anyway (data section diffs are normal runtime state).
        DbgLog("[veh-deep] No .text differences -- trying direct call anyway");
        PVOID result = g_pfnRtlAddVEH(firstHandler, handler);
        DbgLog("[veh-deep] Direct call result=%p", result);
        FreeLibrary(hDiskNtdll);
        return result;
    }

    // Save all hooked bytes, restore original, call, put hooks back
    uint8_t* savedPatch = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, textSize);
    if (!savedPatch)
    {
        DbgLog("[veh-deep] HeapAlloc(%u) failed", textSize);
        FreeLibrary(hDiskNtdll);
        return NULL;
    }
    memcpy(savedPatch, textMem, textSize);

    // Make .text writable
    DWORD oldProtect = 0;
    if (!VirtualProtect(textMem, textSize, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        DbgLog("[veh-deep] VirtualProtect(RWX) failed, err=%u", GetLastError());
        HeapFree(GetProcessHeap(), 0, savedPatch);
        FreeLibrary(hDiskNtdll);
        return NULL;
    }

    // Restore ALL original bytes (nuclear unhook)
    memcpy(textMem, textDisk, textSize);
    FlushInstructionCache(GetCurrentProcess(), textMem, textSize);

    // Call the now-clean function
    PVOID result = g_pfnRtlAddVEH(firstHandler, handler);
    DbgLog("[veh-deep] After deep unhook, call result=%p", result);

    // Restore EAC's hooks
    memcpy(textMem, savedPatch, textSize);
    FlushInstructionCache(GetCurrentProcess(), textMem, textSize);

    // Restore page protection
    DWORD tmp;
    VirtualProtect(textMem, textSize, oldProtect, &tmp);

    HeapFree(GetProcessHeap(), 0, savedPatch);
    FreeLibrary(hDiskNtdll);
    return result;
}

// ---- Manual VEH List Insertion (ultimate fallback) ----
// If deep-unhook fails, manually find the VEH linked list in ntdll
// and insert our handler entry directly, completely bypassing
// AddVectoredExceptionHandler.
//
// ntdll internal structures (Windows 10/11 x64):
//   RTL_VECTORED_HANDLER_LIST { SRWLOCK Lock; LIST_ENTRY List; }
//   Two instances: LdrpVectorHandlerList[0]=VEH, [1]=VCH
//
//   RTL_VECTORED_EXCEPTION_ENTRY {
//     LIST_ENTRY ListEntry;                  // 0x00
//     SRWLOCK*   ListLock;                   // 0x10 (pointer to list's SRWLOCK)
//     ULONG      RefCount;                   // 0x18
//     PVECTORED_EXCEPTION_HANDLER Handler;   // 0x20 (encoded via RtlEncodePointer)
//   }

typedef void (NTAPI *PFN_RtlAcquireSRWLockExclusive)(PVOID SRWLock);
typedef void (NTAPI *PFN_RtlReleaseSRWLockExclusive)(PVOID SRWLock);
typedef PVOID (NTAPI *PFN_RtlEncodePointer)(PVOID Pointer);

static VEH_ENTRY* g_manualVehEntry = NULL;  // for cleanup

// Scan a function body for LEA reg, [RIP+disp32] that references a valid LIST_ENTRY
// Returns the list base address (SRWLOCK + LIST_ENTRY), or NULL if not found.
static void* ScanForVehListHead(uint8_t* func, int scanSize, HMODULE hNtdll, IMAGE_NT_HEADERS* ntHdr)
{
    for (int i = 0; i < scanSize - 7; i++)
    {
        uint8_t* target = NULL;

#ifdef _M_X64
        // x64: REX.W LEA r64, [RIP+disp32]: (48|4C) 8D [modrm with mod=00, rm=101]
        if ((func[i] == 0x48 || func[i] == 0x4C) && func[i + 1] == 0x8D)
        {
            uint8_t modrm = func[i + 2];
            if ((modrm & 0xC7) == 0x05)  // mod=00, rm=101 -> [RIP+disp32]
            {
                int32_t disp = *(int32_t*)(func + i + 3);
                target = func + i + 7 + disp;
            }
        }
#elif defined(_M_IX86)
        // x86: LEA reg, [disp32]: 8D modrm disp32 (mod=00, rm=101 -> [addr32])
        if (func[i] == 0x8D)
        {
            uint8_t modrm = func[i + 1];
            if ((modrm & 0xC7) == 0x05)  // mod=00, rm=101 -> [disp32]
            {
                uint32_t addr = *(uint32_t*)(func + i + 2);
                target = (uint8_t*)(uintptr_t)addr;
            }
        }
        // x86: MOV reg, imm32 used for loading global addresses (B8+reg)
        // PUSH imm32 (68) sometimes used to pass VEH list address
        // Less reliable, so only try LEA pattern
#endif

        if (target)
        {
            uintptr_t rva = (uintptr_t)target - (uintptr_t)hNtdll;
            if (rva < ntHdr->OptionalHeader.SizeOfImage)
            {
                __try
                {
                    LIST_ENTRY* listHead = (LIST_ENTRY*)((uint8_t*)target + VEH_LIST_HEAD_OFFSET);
                    uintptr_t flink = (uintptr_t)listHead->Flink;
                    uintptr_t blink = (uintptr_t)listHead->Blink;
                    uintptr_t self  = (uintptr_t)listHead;

                    bool emptyList = (flink == self && blink == self);
                    bool validPtrs = (flink > 0x10000 && blink > 0x10000);

                    if (emptyList || validPtrs)
                    {
                        DbgLog("[veh-scan] Found candidate @%p (RVA=0x%X) from func=%p+%d",
                            target, (unsigned)rva, func, i);
                        DbgLog("[veh-scan]   Flink=%p Blink=%p Self=%p %s",
                            (void*)flink, (void*)blink, (void*)self,
                            emptyList ? "(EMPTY)" : "(has entries)");
                        return target;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) { }
            }
        }
    }
    return NULL;
}

// ---- Data Section Scan for VEH List ----
// Completely different approach from code-pattern scanning. Instead of tracing
// function calls to find LEA references, scan ntdll's writable data sections
// directly for the RTL_VECTORED_HANDLER_LIST structure pattern.
//
// Structure: { SRWLOCK Lock (8 bytes); LIST_ENTRY List (Flink, Blink); }
// Two adjacent instances: LdrpVectorHandlerList[0]=VEH, [1]=VCH
//
// Detection heuristic:
// - SRWLOCK is 0 or small (unlocked/uncontended)
// - LIST_ENTRY Flink/Blink are valid pointers
// - For empty lists: Flink == Blink == &ListHead (self-referential)
// - For non-empty lists: Flink->Blink == &ListHead (doubly-linked invariant)
// - A second valid list head follows 24 bytes later (VEH + VCH are adjacent)
static void* ScanDataForVehList(HMODULE hNtdll, IMAGE_NT_HEADERS* ntHdr)
{
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHdr);
    int candidateCount = 0;
    void* bestCandidate = NULL;

    for (WORD s = 0; s < ntHdr->FileHeader.NumberOfSections; s++)
    {
        // Only scan writable, non-executable sections (.data, .mrdata, etc.)
        if (!(sections[s].Characteristics & IMAGE_SCN_MEM_WRITE))
            continue;
        if (sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            continue;

        uint8_t* secBase = (uint8_t*)hNtdll + sections[s].VirtualAddress;
        DWORD secSize = sections[s].Misc.VirtualSize;

        char secName[9] = {0};
        memcpy(secName, sections[s].Name, 8);
        DbgLog("[veh-data] Scanning section '%s' @%p size=0x%X", secName, secBase, secSize);

        // RTL_VECTORED_HANDLER_LIST is: { SRWLOCK (8 bytes); LIST_ENTRY (16 bytes) }
        // Total = 24 bytes per list. Two adjacent lists = 48 bytes.
        // Scan aligned addresses (pointer-aligned) within the section.
        if (secSize < 48) continue;

        for (DWORD off = 0; off + 48 <= secSize; off += sizeof(void*))
        {
            uint8_t* candidate = secBase + off;

            __try
            {
                // Check first list head (VEH): SRWLOCK at [0], LIST_ENTRY at [VEH_LIST_HEAD_OFFSET]
                uintptr_t srwValue = *(uintptr_t*)candidate;

                // SRWLOCK when unlocked is 0; when locked/contended, low bits are set
                // Accept 0 or values < 0x100 (reasonable lock states)
                if (srwValue > 0x100) continue;

                LIST_ENTRY* listHead = (LIST_ENTRY*)(candidate + VEH_LIST_HEAD_OFFSET);
                uintptr_t flink = (uintptr_t)listHead->Flink;
                uintptr_t blink = (uintptr_t)listHead->Blink;
                uintptr_t self  = (uintptr_t)listHead;

                // Pointers must be valid (> 64KB, aligned to pointer size)
                if (flink < 0x10000 || blink < 0x10000) continue;
                if (flink & (sizeof(void*) - 1)) continue;
                if (blink & (sizeof(void*) - 1)) continue;

                // Validate doubly-linked list invariant
                bool isEmpty = (flink == self && blink == self);
                bool validChain = false;
                if (!isEmpty)
                {
                    // Check Flink->Blink == listHead
                    LIST_ENTRY* firstEntry = (LIST_ENTRY*)flink;
                    validChain = ((uintptr_t)firstEntry->Blink == self);
                }

                if (!isEmpty && !validChain) continue;

                // Check second list head (VCH): 24 bytes after first
                uint8_t* candidate2 = candidate + 24;  // sizeof(RTL_VECTORED_HANDLER_LIST) = 24 on x64
                uintptr_t srw2 = *(uintptr_t*)candidate2;
                if (srw2 > 0x100) continue;

                LIST_ENTRY* listHead2 = (LIST_ENTRY*)(candidate2 + VEH_LIST_HEAD_OFFSET);
                uintptr_t flink2 = (uintptr_t)listHead2->Flink;
                uintptr_t blink2 = (uintptr_t)listHead2->Blink;
                uintptr_t self2  = (uintptr_t)listHead2;

                if (flink2 < 0x10000 || blink2 < 0x10000) continue;
                if (flink2 & (sizeof(void*) - 1)) continue;
                if (blink2 & (sizeof(void*) - 1)) continue;

                bool isEmpty2 = (flink2 == self2 && blink2 == self2);
                bool validChain2 = false;
                if (!isEmpty2)
                {
                    LIST_ENTRY* firstEntry2 = (LIST_ENTRY*)flink2;
                    validChain2 = ((uintptr_t)firstEntry2->Blink == self2);
                }

                if (!isEmpty2 && !validChain2) continue;

                // Found a pair of valid list heads!
                candidateCount++;
                uintptr_t rva = (uintptr_t)candidate - (uintptr_t)hNtdll;
                DbgLog("[veh-data] Candidate #%d @%p (RVA=0x%X sect='%s'+0x%X)",
                    candidateCount, candidate, (unsigned)rva, secName, off);
                DbgLog("[veh-data]   List0: SRW=%p Flink=%p Blink=%p Self=%p %s%s",
                    (void*)srwValue, (void*)flink, (void*)blink, (void*)self,
                    isEmpty ? "EMPTY" : "HAS-ENTRIES",
                    validChain ? " CHAIN-OK" : "");
                DbgLog("[veh-data]   List1: SRW=%p Flink=%p Blink=%p Self=%p %s%s",
                    (void*)srw2, (void*)flink2, (void*)blink2, (void*)self2,
                    isEmpty2 ? "EMPTY" : "HAS-ENTRIES",
                    validChain2 ? " CHAIN-OK" : "");

                // Additional validation: if list0 has entries, check that entries
                // have a ListLock pointer that matches our SRW lock address
                if (!isEmpty)
                {
                    VEH_ENTRY* entry = (VEH_ENTRY*)flink;
                    if (entry->ListLock == candidate)
                    {
                        DbgLog("[veh-data]   Entry ListLock matches SRW addr -- CONFIRMED!");
                        bestCandidate = candidate;
                        break;  // Very high confidence -- use this one
                    }
                    else
                    {
                        DbgLog("[veh-data]   Entry ListLock=%p (expected %p) -- weak match",
                            entry->ListLock, candidate);
                    }
                }

                // If both lists are empty, this is also a strong candidate
                // (no EAC VEH handler, no VCH handlers)
                if (isEmpty && isEmpty2)
                {
                    DbgLog("[veh-data]   Both lists empty -- possible LdrpVectorHandlerList");
                    if (!bestCandidate) bestCandidate = candidate;
                }
                else if (!bestCandidate)
                {
                    bestCandidate = candidate;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        }
    }

    DbgLog("[veh-data] Data scan done: %d candidates, best=%p", candidateCount, bestCandidate);
    return bestCandidate;
}

static PVOID VehRegister_ManualInsert(PVECTORED_EXCEPTION_HANDLER handler)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;

    // Resolve ntdll functions we need
    PFN_RtlAcquireSRWLockExclusive pfnAcqSrw = (PFN_RtlAcquireSRWLockExclusive)
        GetProcAddress(hNtdll, "RtlAcquireSRWLockExclusive");
    PFN_RtlReleaseSRWLockExclusive pfnRelSrw = (PFN_RtlReleaseSRWLockExclusive)
        GetProcAddress(hNtdll, "RtlReleaseSRWLockExclusive");
    PFN_RtlEncodePointer pfnEncode = (PFN_RtlEncodePointer)
        GetProcAddress(hNtdll, "RtlEncodePointer");

    if (!pfnAcqSrw || !pfnRelSrw || !pfnEncode)
    {
        DbgLog("[veh-manual] Failed to resolve SRW/EncodePointer functions");
        return NULL;
    }

    IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)hNtdll;
    IMAGE_NT_HEADERS* ntHdr = (IMAGE_NT_HEADERS*)((uint8_t*)hNtdll + dosHdr->e_lfanew);
    DbgLog("[veh-manual] ntdll=%p SizeOfImage=0x%X", hNtdll, ntHdr->OptionalHeader.SizeOfImage);

    // Strategy A (FAST): scan ntdll data sections for VEH list structure pattern.
    // Directly finds the RTL_VECTORED_HANDLER_LIST by its memory layout
    // (pair of adjacent {SRWLOCK, LIST_ENTRY} with valid linked-list invariants).
    // Scans ~37KB of .data in <1ms -- much faster than code-pattern tracing.
    void* listBase = ScanDataForVehList(hNtdll, ntHdr);
    DbgLog("[veh-manual] Data section scan: %s", listBase ? "FOUND" : "not found");

    // Strategy B (SLOW): scan code patterns as fallback
    // Only try if data scan fails (shouldn't happen, but defensive)
    if (!listBase && g_pfnRtlAddVEH)
    {
        uint8_t* realFunc = FollowJmpChain((uint8_t*)g_pfnRtlAddVEH, 5);
        DbgLog("[veh-manual] Code scan fallback: func @%p", realFunc);
        listBase = ScanForVehListHead(realFunc, 256, hNtdll, ntHdr);
    }

    if (!listBase)
    {
        DbgLog("[veh-manual] Failed to find VEH list head");
        return NULL;
    }

    // listBase points to LdrpVectorHandlerList[0] (or the base of the array).
    // Structure: { SRWLOCK Lock (sizeof(void*) bytes); LIST_ENTRY List; }
    PVOID srwLock = listBase;
    LIST_ENTRY* vehListHead = (LIST_ENTRY*)((uint8_t*)listBase + VEH_LIST_HEAD_OFFSET);

    DbgLog("[veh-manual] VEH list: lock=%p head=%p", srwLock, vehListHead);

    // Allocate handler entry
    g_manualVehEntry = (VEH_ENTRY*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VEH_ENTRY));
    if (!g_manualVehEntry)
    {
        DbgLog("[veh-manual] HeapAlloc failed");
        return NULL;
    }

    // Encode handler pointer (ntdll uses RtlEncodePointer for the handler field)
    g_manualVehEntry->ListLock = srwLock;
    g_manualVehEntry->RefCount = 1;
    g_manualVehEntry->EncodedHandler = pfnEncode((PVOID)handler);

    DbgLog("[veh-manual] Entry @%p handler=%p encoded=%p",
        g_manualVehEntry, handler, g_manualVehEntry->EncodedHandler);

    // Insert at list HEAD (first handler = highest priority)
    pfnAcqSrw(srwLock);
    {
        // InsertHeadList equivalent
        LIST_ENTRY* entry = &g_manualVehEntry->ListEntry;
        LIST_ENTRY* oldFirst = vehListHead->Flink;
        entry->Flink = oldFirst;
        entry->Blink = vehListHead;
        oldFirst->Blink = entry;
        vehListHead->Flink = entry;
    }
    pfnRelSrw(srwLock);

    DbgLog("[veh-manual] Handler inserted into VEH list successfully");

    // Return non-NULL to indicate success (used as handle for removal)
    return (PVOID)g_manualVehEntry;
}

// Remove manually inserted VEH entry
void VehRemove_ManualEntry(void)
{
    if (!g_manualVehEntry) return;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PFN_RtlAcquireSRWLockExclusive pfnAcqSrw = (PFN_RtlAcquireSRWLockExclusive)
        GetProcAddress(hNtdll, "RtlAcquireSRWLockExclusive");
    PFN_RtlReleaseSRWLockExclusive pfnRelSrw = (PFN_RtlReleaseSRWLockExclusive)
        GetProcAddress(hNtdll, "RtlReleaseSRWLockExclusive");

    if (pfnAcqSrw && pfnRelSrw && g_manualVehEntry->ListLock)
    {
        pfnAcqSrw(g_manualVehEntry->ListLock);
        {
            // RemoveEntryList equivalent
            LIST_ENTRY* entry = &g_manualVehEntry->ListEntry;
            entry->Blink->Flink = entry->Flink;
            entry->Flink->Blink = entry->Blink;
        }
        pfnRelSrw(g_manualVehEntry->ListLock);
    }

    HeapFree(GetProcessHeap(), 0, g_manualVehEntry);
    g_manualVehEntry = NULL;
    DbgLog("[veh-manual] Handler removed from VEH list");
}
