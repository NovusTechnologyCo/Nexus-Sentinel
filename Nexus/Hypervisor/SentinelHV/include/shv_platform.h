/**
 * @file shv_platform.h
 * @brief Platform abstraction layer for NT (Type 2) and UEFI (Type 1) builds.
 *
 * Provides a unified compilation surface for SentinelHV's shared VMX core code
 * across two distinct runtime environments:
 *
 *   - **SHV_PLATFORM_NT**: Windows kernel driver (WDK). Includes ntddk.h,
 *     uses DbgPrintEx for logging, and KeBugCheckEx for fatal errors.
 *
 *   - **SHV_PLATFORM_EFI**: UEFI DXE module. Includes Uefi.h and EDK2 base
 *     libraries. Provides type mappings from WDK types (ULONG64, NTSTATUS, etc.)
 *     to UEFI equivalents. Logging is silent at boot time; fatal errors trigger
 *     CpuDeadLoop.
 *
 * All shared source files include this header (via shv.h) instead of directly
 * including platform-specific headers. If neither SHV_PLATFORM_NT nor
 * SHV_PLATFORM_EFI is defined, NT is assumed as the default.
 */

#pragma once

/* Default to NT platform for the standalone WDK driver build */
#if !defined(SHV_PLATFORM_NT) && !defined(SHV_PLATFORM_EFI)
#define SHV_PLATFORM_NT
#endif

/* ================================================================== */
#ifdef SHV_PLATFORM_NT
/* ================================================================== */

#include <ntddk.h>
#include <intrin.h>

/* ── Logging ─────────────────────────────────────────────────────── */

/* Routed through ShvLogWrite (platform_nt.c) so every line goes BOTH to
 * DbgPrintEx (unchanged behaviour/format) AND into the in-memory ShvLogRing,
 * which `NexusDSEFix --shv-log` dumps to console/file. Motivation: DbgPrintEx
 * alone requires DebugView and drowns our output in unrelated kernel spam.
 *  */
VOID ShvLogWrite(_In_ ULONG Level, _In_ PCSTR Fmt, ...);

#define SHV_LOG(fmt, ...)   ShvLogWrite(DPFLTR_INFO_LEVEL,    "[SentinelHV] " fmt "\n", ##__VA_ARGS__)
#define SHV_WARN(fmt, ...)  ShvLogWrite(DPFLTR_WARNING_LEVEL, "[SentinelHV] WARNING: " fmt "\n", ##__VA_ARGS__)
#define SHV_ERR(fmt, ...)   ShvLogWrite(DPFLTR_ERROR_LEVEL,   "[SentinelHV] ERROR: " fmt "\n", ##__VA_ARGS__)

/* ── Fatal Error ─────────────────────────────────────────────────── */

#define ShvBugCheck(a, b, c, d, e)  KeBugCheckEx(a, b, c, d, e)

/* ================================================================== */
#elif defined(SHV_PLATFORM_EFI)
/* ================================================================== */

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <intrin.h>

/* ── Type Mappings (WDK → UEFI) ──────────────────────────────────── */

typedef UINT64  ULONG64;
typedef UINT32  ULONG32;
typedef UINT32  ULONG;
typedef UINT16  USHORT;
typedef UINT8   UCHAR;
typedef UINTN   SIZE_T;
typedef INT32   LONG;

typedef void*   PVOID;
typedef ULONG64* PULONG64;

/* ── NT Status Codes ─────────────────────────────────────────────── */

/*
 * Guard NTSTATUS with a macro flag so NexusBootDxe's ntdef.h can
 * define _SHV_NTSTATUS_DEFINED_ first to prevent redefinition.
 */
#ifndef _SHV_NTSTATUS_DEFINED_
#define _SHV_NTSTATUS_DEFINED_
typedef INT32 NTSTATUS;
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS          ((NTSTATUS)0)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL     ((NTSTATUS)0xC0000001)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED    ((NTSTATUS)0xC0000022)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000D)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED    ((NTSTATUS)0xC00000BB)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009A)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s)   ((NTSTATUS)(s) == STATUS_SUCCESS)
#endif

/* ── Compile-Time Asserts ────────────────────────────────────────── */

#ifndef C_ASSERT
#define __SHV_JOIN2(a, b)  a ## b
#define __SHV_JOIN(a, b)   __SHV_JOIN2(a, b)
#define C_ASSERT(e) typedef char __SHV_JOIN(__C_ASSERT__, __COUNTER__)[(e)?1:-1]
#endif

/* ── Structure Helpers ───────────────────────────────────────────── */

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field) ((UINTN)&(((type*)0)->field))
#endif

/* ── Misc Macros ─────────────────────────────────────────────────── */

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x)  (void)(x)
#endif

/* Bugcheck code used by unhandled VM-exit */
#define MANUALLY_INITIATED_CRASH    0x000000E2

/* ── SAL Annotations (no-op in UEFI) ────────────────────────────── */

#ifndef _In_
#define _In_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Inout_
#define _Inout_
#endif

/* ── Memory Fill ─────────────────────────────────────────────────── */

#ifndef RtlZeroMemory
#define RtlZeroMemory(d, s)  ZeroMem(d, s)
#endif

/* ── Logging (silent at boot) ────────────────────────────────────── */

#define SHV_LOG(fmt, ...)    /* silent in UEFI DXE */
#define SHV_WARN(fmt, ...)   /* silent */
#define SHV_ERR(fmt, ...)    /* silent */

/* ── Fatal Error ─────────────────────────────────────────────────── */

#define ShvBugCheck(a, b, c, d, e)  CpuDeadLoop()

/* ================================================================== */
#else
#error "Define SHV_PLATFORM_NT or SHV_PLATFORM_EFI"
#endif
