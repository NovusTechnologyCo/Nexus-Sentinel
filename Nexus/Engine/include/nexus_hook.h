/**
 * @file nexus_hook.h
 * @brief Detection of various hooking techniques in target processes.
 *
 * Scans for inline hooks (JMP/hot-patch), IAT hooks, EAT hooks, and
 * other code-modification techniques.  Can compare in-memory code against
 * the on-disk PE image and optionally restore original bytes.
 * Modelled on the TitanEngine hook detection API.
 */

#ifndef NEXUS_HOOK_H
#define NEXUS_HOOK_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Hook Types
 * ============================================================================ */

typedef enum NexusHookType {
    NEXUS_HOOK_UNKNOWN = 0,
    NEXUS_HOOK_INLINE = 1,              /* Inline/detour hook */
    NEXUS_HOOK_IAT = 2,                 /* Import Address Table hook */
    NEXUS_HOOK_EAT = 3,                 /* Export Address Table hook */
    NEXUS_HOOK_VTABLE = 4,              /* Virtual table hook */
    NEXUS_HOOK_HOTPATCH = 5,            /* Hot-patch style hook */
    NEXUS_HOOK_SSDT = 6,                /* System Service Descriptor Table */
    NEXUS_HOOK_IDT = 7,                 /* Interrupt Descriptor Table */
    NEXUS_HOOK_DEBUG_REG = 8,           /* Debug register hook */
    NEXUS_HOOK_PAGE_GUARD = 9,          /* PAGE_GUARD exception hook */
    NEXUS_HOOK_VECTORED = 10            /* Vectored Exception Handler */
} NexusHookType;

typedef enum NexusHookFlags {
    NEXUS_HOOK_FLAG_NONE = 0,
    NEXUS_HOOK_FLAG_SCAN_ALL = 0x0001,      /* Scan all loaded modules */
    NEXUS_HOOK_FLAG_SCAN_SYSTEM = 0x0002,   /* Include system modules */
    NEXUS_HOOK_FLAG_DEEP_SCAN = 0x0004,     /* Deeper analysis */
    NEXUS_HOOK_FLAG_CHECK_DISK = 0x0008     /* Compare with disk image */
} NexusHookFlags;

/* ============================================================================
 * Hook Detection Structures
 * ============================================================================ */

typedef struct NexusHookInfo {
    uint64_t hookAddress;               /* Address where hook is installed */
    uint64_t targetAddress;             /* Where hook redirects to */
    uint64_t originalAddress;           /* Original function address */
    uint32_t hookType;                  /* NexusHookType */
    uint32_t hookSize;                  /* Size of hook code */
    wchar_t moduleName[260];            /* Module containing hook */
    wchar_t targetModule[260];          /* Module containing target */
    char functionName[256];             /* Hooked function name */
    uint8_t originalBytes[32];          /* Original bytes at hook */
    uint8_t hookBytes[32];              /* Current bytes (hook code) */
    uint32_t confidence;                /* Detection confidence 0-100 */
    uint32_t isSuspicious;              /* 1 if hook seems malicious */
} NexusHookInfo;

typedef struct NexusHookScanResult {
    uint32_t totalHooks;                /* Total hooks detected */
    uint32_t inlineHooks;               /* Inline hooks */
    uint32_t iatHooks;                  /* IAT hooks */
    uint32_t eatHooks;                  /* EAT hooks */
    uint32_t vtableHooks;               /* VTable hooks */
    uint32_t otherHooks;                /* Other hook types */
    uint32_t suspiciousCount;           /* Suspicious hooks */
    uint32_t modulesScanned;            /* Modules scanned */
    uint64_t scanTime;                  /* Time taken (ms) */
    uint32_t reserved;
} NexusHookScanResult;

typedef struct NexusIatHookInfo {
    wchar_t importModule[260];          /* Module importing from */
    wchar_t dllName[260];               /* DLL being imported */
    char functionName[256];             /* Function name */
    uint32_t thunkRva;                  /* RVA of IAT entry */
    uint64_t expectedAddress;           /* Expected address */
    uint64_t actualAddress;             /* Actual address in IAT */
    uint64_t hookTarget;                /* Where hook redirects to */
    wchar_t targetModule[260];          /* Module containing target */
    uint32_t isHooked;                  /* 1 if definitely hooked */
    uint32_t reserved;
} NexusIatHookInfo;

typedef struct NexusInlineHookInfo {
    uint64_t functionAddress;           /* Function address */
    wchar_t moduleName[260];            /* Module name */
    char functionName[256];             /* Function name */
    uint64_t jumpTarget;                /* Where jump goes */
    wchar_t targetModule[260];          /* Module containing target */
    uint8_t prologueBytes[16];          /* Current prologue bytes */
    uint8_t originalPrologue[16];       /* Original prologue (if known) */
    uint32_t hookSize;                  /* Hook size in bytes */
    uint32_t isHotpatch;                /* 1 if hotpatch style */
} NexusInlineHookInfo;

/* ============================================================================
 * General Hook Scanning
 * ============================================================================ */

/**
 * Scan process for hooks.
 */
NEXUS_API NexusResult Nexus_HookScan(
    NexusProcessHandle process,
    uint32_t flags,
    NexusHookScanResult* result
);

/**
 * Get detected hooks.
 */
NEXUS_API NexusResult Nexus_HookGetAll(
    NexusProcessHandle process,
    NexusHookInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get hooks in module.
 */
NEXUS_API NexusResult Nexus_HookGetInModule(
    NexusProcessHandle process,
    const wchar_t* moduleName,
    NexusHookInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Check if function is hooked.
 */
NEXUS_API NexusResult Nexus_HookCheck(
    NexusProcessHandle process,
    uint64_t address,
    NexusHookInfo* info
);

/* ============================================================================
 * Inline Hook Detection
 * ============================================================================ */

/**
 * Scan for inline hooks.
 */
NEXUS_API NexusResult Nexus_HookScanInline(
    NexusProcessHandle process,
    uint64_t moduleBase,
    NexusInlineHookInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Check function for inline hook.
 */
NEXUS_API NexusResult Nexus_HookCheckInline(
    NexusProcessHandle process,
    uint64_t functionAddress,
    NexusInlineHookInfo* info
);

/**
 * Compare function with disk image.
 */
NEXUS_API NexusResult Nexus_HookCompareWithDisk(
    NexusProcessHandle process,
    uint64_t functionAddress,
    uint32_t* isModified,
    uint8_t* diskBytes,
    size_t* byteCount
);

/* ============================================================================
 * IAT Hook Detection
 * ============================================================================ */

/**
 * Scan IAT for hooks.
 */
NEXUS_API NexusResult Nexus_HookScanIat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    NexusIatHookInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Check IAT entry.
 */
NEXUS_API NexusResult Nexus_HookCheckIat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    const wchar_t* dllName,
    const char* functionName,
    NexusIatHookInfo* info
);

/**
 * Verify IAT integrity.
 */
NEXUS_API NexusResult Nexus_HookVerifyIat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    uint32_t* hookCount,
    uint32_t* totalEntries
);

/* ============================================================================
 * EAT Hook Detection
 * ============================================================================ */

/**
 * Scan EAT for hooks.
 */
NEXUS_API NexusResult Nexus_HookScanEat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    NexusHookInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Check EAT entry.
 */
NEXUS_API NexusResult Nexus_HookCheckEat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    const char* functionName,
    NexusHookInfo* info
);

/* ============================================================================
 * Hook Restoration
 * ============================================================================ */

/**
 * Restore hooked function from disk.
 */
NEXUS_API NexusResult Nexus_HookRestore(
    NexusProcessHandle process,
    uint64_t functionAddress
);

/**
 * Restore all hooks in module.
 */
NEXUS_API NexusResult Nexus_HookRestoreModule(
    NexusProcessHandle process,
    uint64_t moduleBase
);

/**
 * Restore IAT entry.
 */
NEXUS_API NexusResult Nexus_HookRestoreIat(
    NexusProcessHandle process,
    uint64_t moduleBase,
    const wchar_t* dllName,
    const char* functionName
);

/* ============================================================================
 * System Hook Detection (Kernel)
 * ============================================================================ */

/**
 * Check for SSDT hooks (requires kernel driver).
 */
NEXUS_API NexusResult Nexus_HookScanSsdt(
    NexusKernelHandle kernel,
    NexusHookInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Check for IDT hooks (requires kernel driver).
 */
NEXUS_API NexusResult Nexus_HookScanIdt(
    NexusKernelHandle kernel,
    NexusHookInfo* buffer,
    size_t bufferCount,
    size_t* count
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_HOOK_H */
