/**
 * @file hook_engine_stubs.cpp
 * @brief Runtime-generated hook stubs (x64 and x86 machine code thunks)
 *
 * Each hook slot gets a small machine-code stub that encodes the slot index
 * and calls GenericDispatch. Both x64 and x86 use runtime-generated stubs
 * allocated from a VirtualAlloc RWX block (g_stubBlock).
 *
 * Extracted from hook_engine.cpp for maintainability.
 */

#include "hook_engine_internal.h"

// ============================================================
// Runtime-Generated Hook Stubs
// ============================================================
// Both x64 and x86 use runtime-generated stubs. Each stub is a small
// machine-code thunk that encodes the slot index and calls GenericDispatch.
// This allows unlimited hook slots (limited only by available memory).

#ifdef _M_X64

// x64 stub: 52 bytes, padded to 64 for alignment.
// At entry (via MinHook JMP from target function):
//   RSP = &returnAddress, RCX=a1, RDX=a2, R8=a3, R9=a4
// Shuffles registers and calls GenericDispatch(slotIndex, a1, a2, a3, a4, &retAddr)

void* CreateStub64(int slotIndex)
{
    if (!g_stubBlock) return NULL;

    uint8_t* stub = g_stubBlock + slotIndex * STUB_SIZE;
    int off = 0;

    // mov r10, rcx           ; save a1 (3 bytes)
    stub[off++] = 0x49; stub[off++] = 0x89; stub[off++] = 0xCA;

    // mov r11, rsp           ; r11 = original RSP = &returnAddress (3 bytes)
    stub[off++] = 0x49; stub[off++] = 0x89; stub[off++] = 0xE3;

    // sub rsp, 0x38          ; frame: 0x20 shadow + 2 stack args + 8 alignment (4 bytes)
    stub[off++] = 0x48; stub[off++] = 0x83; stub[off++] = 0xEC; stub[off++] = 0x38;

    // mov [rsp+0x30], r11    ; 6th arg: returnAddress (5 bytes)
    stub[off++] = 0x4C; stub[off++] = 0x89; stub[off++] = 0x5C; stub[off++] = 0x24; stub[off++] = 0x30;

    // mov [rsp+0x28], r9     ; 5th arg: a4 (5 bytes)
    stub[off++] = 0x4C; stub[off++] = 0x89; stub[off++] = 0x4C; stub[off++] = 0x24; stub[off++] = 0x28;

    // mov r9, r8             ; 4th arg: a3 (3 bytes)
    stub[off++] = 0x4D; stub[off++] = 0x89; stub[off++] = 0xC1;

    // mov r8, rdx            ; 3rd arg: a2 (3 bytes)
    stub[off++] = 0x49; stub[off++] = 0x89; stub[off++] = 0xD0;

    // mov rdx, r10           ; 2nd arg: a1 (saved from RCX) (3 bytes)
    stub[off++] = 0x4C; stub[off++] = 0x89; stub[off++] = 0xD2;

    // mov ecx, <slotIndex>   ; 1st arg: slotIndex (5 bytes)
    stub[off++] = 0xB9;
    *(uint32_t*)(stub + off) = (uint32_t)slotIndex;
    off += 4;

    // movabs rax, <GenericDispatch>  ; absolute 64-bit address (10 bytes)
    stub[off++] = 0x48; stub[off++] = 0xB8;
    *(uint64_t*)(stub + off) = (uint64_t)&GenericDispatch;
    off += 8;

    // call rax               ; (2 bytes)
    stub[off++] = 0xFF; stub[off++] = 0xD0;

    // add rsp, 0x38          ; (4 bytes)
    stub[off++] = 0x48; stub[off++] = 0x83; stub[off++] = 0xC4; stub[off++] = 0x38;

    // ret                    ; (1 byte)
    stub[off++] = 0xC3;

    // Remaining bytes are INT3 fill from initialization
    return stub;
}

#elif defined(_M_IX86)

// x86 stub: ~21 bytes, padded to 32 for alignment.
// On x86, Windows APIs use __stdcall (callee cleans stack with RET N).
// RET N varies per API (N = paramCount * 4), so compile-time templates
// won't work. Instead, we VirtualAlloc an RWX block and generate small
// stubs at runtime, one per hook slot.
//
// Each stub:
//   LEA EAX, [ESP+4]          ; pointer to first arg on caller's stack
//   PUSH EAX                  ; argPtr parameter
//   PUSH <slotIndex>          ; immediate slot index
//   CALL <GenericDispatch32>  ; relative call (__cdecl)
//   ADD ESP, 8                ; clean our 2 pushed args
//   RET <N>                   ; clean caller's args (__stdcall)

void* CreateStub32(int slotIndex, int paramCount)
{
    if (!g_stubBlock) return NULL;

    uint8_t* stub = g_stubBlock + slotIndex * STUB_SIZE;
    int off = 0;

    // LEA EAX, [ESP+4] — pointer to first arg (return addr is at [ESP])
    stub[off++] = 0x8D; stub[off++] = 0x44; stub[off++] = 0x24; stub[off++] = 0x04;

    // PUSH EAX — argPtr
    stub[off++] = 0x50;

    // PUSH <slotIndex> — immediate 32-bit
    stub[off++] = 0x68;
    *(uint32_t*)(stub + off) = (uint32_t)slotIndex;
    off += 4;

    // CALL <GenericDispatch32> — relative call
    stub[off++] = 0xE8;
    uintptr_t callTarget = (uintptr_t)&GenericDispatch32;
    uintptr_t callSite = (uintptr_t)(stub + off + 4); // address after the 4-byte offset
    *(int32_t*)(stub + off) = (int32_t)(callTarget - callSite);
    off += 4;

    // ADD ESP, 8 — clean our 2 pushed args (__cdecl convention)
    stub[off++] = 0x83; stub[off++] = 0xC4; stub[off++] = 0x08;

    // RET <N> — clean caller's args (__stdcall: N = paramCount * 4)
    uint16_t stackClean = (uint16_t)(paramCount * 4);
    stub[off++] = 0xC2;
    *(uint16_t*)(stub + off) = stackClean;
    off += 2;

    return stub;
}
#endif
