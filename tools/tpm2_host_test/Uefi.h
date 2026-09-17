/**
 * @file Uefi.h  (HOST SHIM -- not EDK2's)
 * @brief The minimum set of UEFI types needed to compile Sha256.c and Tpm2Core.c as a host
 *        program, so their behaviour can be checked against an independent oracle.
 *
 * ⚠ THIS FILE IS ONLY REACHED BY THE HOST TEST. It works by being first on the include path, so
 * `#include <Uefi.h>` inside those sources resolves here instead of to EDK2. Nothing in the
 * firmware build sees it, and it must never be added to the DXE project's include directories.
 *
 * ⚠ IT DELIBERATELY DEFINES ALMOST NOTHING. If a source file starts needing more from this shim,
 * that is the signal that it has stopped being dependency-free -- which is the property the shim
 * exists to protect. Growing this header to keep a test compiling would defeat its purpose: the
 * right response is to remove the dependency from the source, not to satisfy it here.
 *
 * `Sha256.h` has claimed since 2026-07-26 that its implementation "compiles as a host program" so
 * it could be validated against FIPS vectors. That was true in principle and had never been done,
 * because no shim existed. This makes the claim real.
 */

#ifndef NEXUS_HOST_UEFI_SHIM_H
#define NEXUS_HOST_UEFI_SHIM_H

#include <stdint.h>
#include <stddef.h>

typedef uint8_t   UINT8;
typedef uint16_t  UINT16;
typedef uint32_t  UINT32;
typedef uint64_t  UINT64;
typedef int8_t    INT8;
typedef int16_t   INT16;
typedef int32_t   INT32;
typedef int64_t   INT64;
typedef size_t    UINTN;
typedef uint8_t   BOOLEAN;
typedef char      CHAR8;
typedef uint16_t  CHAR16;

#ifndef VOID
#define VOID void
#endif

#ifndef TRUE
#define TRUE  ((BOOLEAN)1)
#endif
#ifndef FALSE
#define FALSE ((BOOLEAN)0)
#endif
#ifndef NULL
#define NULL ((void*)0)
#endif

//
// EDK2's parameter-direction annotations carry no code meaning; they document intent. Empty here.
//
#define IN
#define OUT
#define OPTIONAL

#ifndef CONST
#define CONST const
#endif
#ifndef STATIC
#define STATIC static
#endif

#endif // NEXUS_HOST_UEFI_SHIM_H
