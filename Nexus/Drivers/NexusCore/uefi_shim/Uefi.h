/**
 * @file uefi_shim/Uefi.h
 * @brief Let the TPM core compile INSIDE the Windows kernel driver.
 *
 * WHY THIS EXISTS. `Tpm2Core.c`, `Tpm2Dispatch.c`, `Tpm2Hash.c` and `Sha512.c` include nothing but
 * their own headers -- and those headers `#include <Uefi.h>`. That dependency-free discipline was
 * adopted so the code could be validated on the host against `hashlib` with no reboot
 * (`tools/tpm2_host_test/Uefi.h` is the same trick). It turns out to be what lets the SAME SOURCE
 * run after ExitBootServices, where there is no EFI at all.
 *
 * ⚠ WHY IT MATTERS THAT IT IS THE SAME SOURCE. G1 needs a TPM that answers the OS over the CRB.
 * The alternative to this shim is a second implementation of the TPM in kernel C -- and a TPM that
 * answers one thing to the boot loader and another to the OS is a contradiction no real TPM can
 * produce, which is precisely what a verifier looks for. One dispatcher, two environments.
 *
 * ⚠ THIS INCLUDES <ntddk.h> FIRST, DELIBERATELY. The WDK already defines UINT8/16/32/64, BOOLEAN,
 * VOID, CONST, IN, OUT, TRUE, FALSE and C_ASSERT. Redefining a typedef MSVC already has is an
 * error, not a no-op, so this adds ONLY what the WDK lacks. Getting that backwards produces a
 * hundred C2371s that look like a broken port rather than a duplicated definition.
 */

#pragma once

#include <ntddk.h>

//
// EDK2 spellings the WDK does not provide.
//
#ifndef STATIC
#define STATIC static
#endif

typedef ULONG_PTR UINTN;
typedef CHAR      CHAR8;
typedef WCHAR     CHAR16;

//
// EDK2 Base.h signature macros, transcribed rather than reinvented.
//
// (!) THEY MUST MATCH THE DXE EXACTLY. TpmState.h builds NEXUS_TPM_STATE_MAGIC out of these,
// the DXE writes that magic into region B, and this driver refuses to service a region whose
// magic does not match. A shim that computed the value even slightly differently would make
// the servicer reject memory that is in fact ours -- and the symptom would be silence, not an
// error, because refusing is the correct behaviour for a region we do not recognise.
//
#define SIGNATURE_16(A, B)        ((A) | ((B) << 8))
#define SIGNATURE_32(A, B, C, D)  (SIGNATURE_16 (A, B) | (SIGNATURE_16 (C, D) << 16))
#define SIGNATURE_64(A, B, C, D, E, F, G, H) \
    (SIGNATURE_32 (A, B, C, D) | ((UINT64) (SIGNATURE_32 (E, F, G, H)) << 32))

//
// EDK2's OFFSET_OF; the WDK spells the same thing FIELD_OFFSET.
//
#ifndef OFFSET_OF
#define OFFSET_OF(TYPE, Field) ((UINTN)FIELD_OFFSET(TYPE, Field))
#endif

//
// (!) OPTIONAL IS A WDK MACRO TOO, and it means the same nothing. Left alone rather than
// redefined, because the WDK's SAL annotations key off its spelling.
//
