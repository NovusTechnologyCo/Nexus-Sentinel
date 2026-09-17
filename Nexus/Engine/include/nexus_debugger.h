/**
 * @file nexus_debugger.h
 * @brief Debugger attachment, breakpoints, debug events, and stack walking.
 *
 * Implements a full user-mode debugger: attach/detach, software (INT3) and
 * hardware (DR0-DR3) breakpoints, memory breakpoints (PAGE_GUARD), debug event
 * loop with single-step support, and module-relative breakpoints that survive
 * ASLR and DLL reload.  Also provides stack walking via StackWalk64/DbgHelp
 * with symbol resolution and multi-thread support.
 */

#ifndef NEXUS_DEBUGGER_H
#define NEXUS_DEBUGGER_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Debugger Types
 * ============================================================================ */

/* Breakpoint types */
typedef enum NexusBreakpointType {
    NEXUS_BP_SOFTWARE = 0,      /* INT3 software breakpoint */
    NEXUS_BP_HARDWARE_EXEC = 1, /* Hardware execution breakpoint (DR0-DR3) */
    NEXUS_BP_HARDWARE_WRITE = 2,/* Hardware write watchpoint */
    NEXUS_BP_HARDWARE_RW = 3,   /* Hardware read/write watchpoint */
    NEXUS_BP_MEMORY = 4         /* Memory breakpoint (page guard) */
} NexusBreakpointType;

/* Breakpoint size (for hardware breakpoints) */
typedef enum NexusBreakpointSize {
    NEXUS_BP_SIZE_1 = 0,        /* 1 byte */
    NEXUS_BP_SIZE_2 = 1,        /* 2 bytes (word) */
    NEXUS_BP_SIZE_4 = 3,        /* 4 bytes (dword) */
    NEXUS_BP_SIZE_8 = 2         /* 8 bytes (qword, x64 only) */
} NexusBreakpointSize;

/* Breakpoint storage mode */
typedef enum NexusBreakpointMode {
    NEXUS_BP_MODE_ABSOLUTE = 0,     /* Absolute address (legacy) */
    NEXUS_BP_MODE_MODULE_RELATIVE = 1 /* Module name + RVA (survives reload) */
} NexusBreakpointMode;

/* Breakpoint information structure */
typedef struct NexusBreakpoint {
    uint64_t id;                /* Unique breakpoint ID */
    uint64_t address;           /* Resolved absolute address (0 if unresolved) */
    uint32_t type;              /* NexusBreakpointType */
    uint32_t size;              /* NexusBreakpointSize (for hardware BP) */
    uint32_t enabled;           /* 1 if enabled, 0 if disabled */
    uint32_t hitCount;          /* Number of times breakpoint was hit */
    uint8_t originalByte;       /* Original byte (for software BP) */
    uint8_t mode;               /* NexusBreakpointMode */
    uint8_t resolved;           /* 1 if module-relative BP is resolved */
    uint8_t reserved[5];        /* Padding for alignment */
    uint64_t rva;               /* RVA within module (if module-relative) */
    wchar_t moduleName[64];     /* Module name (if module-relative) */
} NexusBreakpoint;

/* Debug event types */
typedef enum NexusDebugEventType {
    NEXUS_DBG_NONE = 0,
    NEXUS_DBG_BREAKPOINT = 1,       /* Breakpoint hit */
    NEXUS_DBG_SINGLE_STEP = 2,      /* Single step completed */
    NEXUS_DBG_EXCEPTION = 3,        /* Exception occurred */
    NEXUS_DBG_PROCESS_CREATE = 4,   /* Process created */
    NEXUS_DBG_PROCESS_EXIT = 5,     /* Process exited */
    NEXUS_DBG_THREAD_CREATE = 6,    /* Thread created */
    NEXUS_DBG_THREAD_EXIT = 7,      /* Thread exited */
    NEXUS_DBG_DLL_LOAD = 8,         /* DLL loaded */
    NEXUS_DBG_DLL_UNLOAD = 9,       /* DLL unloaded */
    NEXUS_DBG_OUTPUT_STRING = 10    /* OutputDebugString */
} NexusDebugEventType;

/* Debug event structure */
typedef struct NexusDebugEvent {
    uint32_t type;              /* NexusDebugEventType */
    uint32_t processId;         /* Process ID */
    uint32_t threadId;          /* Thread ID */
    uint32_t reserved;          /* Padding */
    uint64_t address;           /* Address (for BP, exception) */
    uint64_t exceptionCode;     /* Exception code (for exceptions) */
    uint64_t breakpointId;      /* Breakpoint ID (if BP hit) */
    union {
        struct {                /* For DLL_LOAD/UNLOAD */
            uint64_t baseAddress;
            wchar_t moduleName[260];
        } module;
        struct {                /* For OUTPUT_STRING */
            char message[512];
        } outputString;
        struct {                /* For PROCESS_EXIT/THREAD_EXIT */
            uint32_t exitCode;
        } exit;
    } info;
} NexusDebugEvent;

/* ============================================================================
 * Stack Walker Types
 * ============================================================================ */

/* Stack frame information */
typedef struct NexusStackFrame {
    uint64_t frameAddress;          /* Frame pointer (RBP/EBP) */
    uint64_t returnAddress;         /* Return address */
    uint64_t stackPointer;          /* Stack pointer at this frame */
    uint64_t instructionPointer;    /* Instruction pointer (RIP/EIP) */
    uint64_t moduleBase;            /* Module base address (0 if unknown) */
    wchar_t moduleName[64];         /* Module name (empty if unknown) */
    char functionName[128];         /* Function name (empty if unknown) */
    uint32_t functionOffset;        /* Offset within function */
    uint32_t frameIndex;            /* Frame index (0 = top of stack) */
    uint32_t isInline;              /* Non-zero if inline frame */
    uint32_t reserved;
} NexusStackFrame;

/* Stack walk options */
typedef enum NexusStackWalkFlags {
    NEXUS_STACK_DEFAULT = 0x0000,       /* Default stack walk */
    NEXUS_STACK_RESOLVE_SYMBOLS = 0x0001, /* Resolve function names */
    NEXUS_STACK_RESOLVE_MODULES = 0x0002, /* Resolve module names */
    NEXUS_STACK_INCLUDE_INLINE = 0x0004,  /* Include inline frames */
    NEXUS_STACK_FAST = 0x0008             /* Fast walk (may be less accurate) */
} NexusStackWalkFlags;

/* ============================================================================
 * Debugger Operations
 * ============================================================================ */

/**
 * Attach debugger to a process.
 * This enables debugging functionality including breakpoints.
 * Note: The process must not already be debugged.
 *
 * @param process Process handle (must be opened first)
 * @param debugger Output: debugger handle
 * @return NEXUS_OK on success, NEXUS_ERROR_ACCESS_DENIED if already debugged
 */
NEXUS_API NexusResult Nexus_DebuggerAttach(
    NexusProcessHandle process,
    NexusDebuggerHandle* debugger
);

/**
 * Detach debugger from a process.
 * Removes all breakpoints and stops debugging.
 *
 * @param debugger Debugger handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DebuggerDetach(NexusDebuggerHandle debugger);

/**
 * Set a breakpoint at the specified address.
 * For software breakpoints, writes INT3 and saves original byte.
 * For hardware breakpoints, uses debug registers DR0-DR3.
 *
 * @param debugger Debugger handle
 * @param address Address to set breakpoint
 * @param type Breakpoint type (software, hardware exec/write/rw)
 * @param size Breakpoint size (for hardware breakpoints)
 * @param breakpointId Output: breakpoint ID for later reference
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SetBreakpoint(
    NexusDebuggerHandle debugger,
    uint64_t address,
    NexusBreakpointType type,
    NexusBreakpointSize size,
    uint64_t* breakpointId
);

/**
 * Remove a breakpoint.
 * Restores original byte for software breakpoints.
 *
 * @param debugger Debugger handle
 * @param breakpointId Breakpoint ID
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if ID invalid
 */
NEXUS_API NexusResult Nexus_RemoveBreakpoint(
    NexusDebuggerHandle debugger,
    uint64_t breakpointId
);

/**
 * Enable or disable a breakpoint without removing it.
 * @param debugger Debugger handle
 * @param breakpointId Breakpoint ID
 * @param enabled 1 to enable, 0 to disable
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EnableBreakpoint(
    NexusDebuggerHandle debugger,
    uint64_t breakpointId,
    int enabled
);

/**
 * Get information about a breakpoint.
 * @param debugger Debugger handle
 * @param breakpointId Breakpoint ID
 * @param breakpoint Output: breakpoint information
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if ID invalid
 */
NEXUS_API NexusResult Nexus_GetBreakpoint(
    NexusDebuggerHandle debugger,
    uint64_t breakpointId,
    NexusBreakpoint* breakpoint
);

/**
 * Get all breakpoints.
 * @param debugger Debugger handle
 * @param buffer Array to receive breakpoints
 * @param bufferCount Size of buffer array
 * @param count Output: number of breakpoints
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_GetBreakpoints(
    NexusDebuggerHandle debugger,
    NexusBreakpoint* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Wait for a debug event.
 * Blocks until a debug event occurs or timeout expires.
 *
 * @param debugger Debugger handle
 * @param event Output: debug event information
 * @param timeoutMs Timeout in milliseconds (INFINITE for no timeout)
 * @return NEXUS_OK on event, NEXUS_ERROR_NOT_FOUND on timeout
 */
NEXUS_API NexusResult Nexus_WaitForDebugEvent(
    NexusDebuggerHandle debugger,
    NexusDebugEvent* event,
    uint32_t timeoutMs
);

/**
 * Continue execution after a debug event.
 * Must be called after handling a debug event.
 *
 * @param debugger Debugger handle
 * @param threadId Thread ID from the debug event
 * @param continueStatus DBG_CONTINUE or DBG_EXCEPTION_NOT_HANDLED
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ContinueDebugEvent(
    NexusDebuggerHandle debugger,
    uint32_t threadId,
    uint32_t continueStatus
);

/**
 * Single-step a thread.
 * Sets trap flag and continues; next event will be single-step.
 *
 * @param debugger Debugger handle
 * @param threadId Thread ID to single-step
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SingleStep(
    NexusDebuggerHandle debugger,
    uint32_t threadId
);

/**
 * Remove all breakpoints.
 * @param debugger Debugger handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_RemoveAllBreakpoints(NexusDebuggerHandle debugger);

/* ============================================================================
 * Module-Relative Breakpoints (x64dbg pattern)
 *
 * Module-relative breakpoints store breakpoints as module name + RVA instead
 * of absolute addresses. This allows breakpoints to survive:
 * - Module reloading (unload + load)
 * - ASLR (Address Space Layout Randomization)
 * - Session persistence (save/load)
 *
 * When a module-relative breakpoint is set:
 * 1. If the module is loaded, the RVA is resolved to an absolute address
 * 2. If the module is not loaded, the breakpoint is stored as "unresolved"
 * 3. On DLL_LOAD events, unresolved breakpoints are automatically resolved
 * 4. On DLL_UNLOAD events, resolved breakpoints become unresolved again
 * ============================================================================ */

/**
 * Set a module-relative breakpoint.
 * The breakpoint is stored as module + RVA and will survive module reloading.
 *
 * @param debugger Debugger handle
 * @param moduleName Module name (e.g., "ntdll.dll", "kernel32.dll")
 * @param rva Relative Virtual Address within the module
 * @param type Breakpoint type (software, hardware exec/write/rw)
 * @param size Breakpoint size (for hardware breakpoints)
 * @param breakpointId Output: breakpoint ID for later reference
 * @return NEXUS_OK on success (even if module not yet loaded)
 */
NEXUS_API NexusResult Nexus_SetBreakpointModule(
    NexusDebuggerHandle debugger,
    const wchar_t* moduleName,
    uint64_t rva,
    NexusBreakpointType type,
    NexusBreakpointSize size,
    uint64_t* breakpointId
);

/**
 * Set a breakpoint by symbol name (module!function pattern).
 * Resolves the symbol to module + RVA for module-relative storage.
 *
 * @param debugger Debugger handle
 * @param symbol Symbol name (e.g., "ntdll!NtCreateFile", "kernel32!CreateFileW")
 * @param type Breakpoint type
 * @param size Breakpoint size (for hardware breakpoints)
 * @param breakpointId Output: breakpoint ID
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if symbol not found
 */
NEXUS_API NexusResult Nexus_SetBreakpointSymbol(
    NexusDebuggerHandle debugger,
    const char* symbol,
    NexusBreakpointType type,
    NexusBreakpointSize size,
    uint64_t* breakpointId
);

/**
 * Convert an absolute breakpoint to module-relative.
 * If the address is within a module, converts storage to module + RVA.
 *
 * @param debugger Debugger handle
 * @param breakpointId Breakpoint ID to convert
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if not in a module
 */
NEXUS_API NexusResult Nexus_ConvertBreakpointToModuleRelative(
    NexusDebuggerHandle debugger,
    uint64_t breakpointId
);

/**
 * Resolve all unresolved module-relative breakpoints.
 * Typically called after module enumeration or on DLL_LOAD.
 *
 * @param debugger Debugger handle
 * @param resolvedCount Output: number of breakpoints resolved (can be NULL)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_ResolveModuleBreakpoints(
    NexusDebuggerHandle debugger,
    size_t* resolvedCount
);

/**
 * Get list of unresolved module-relative breakpoints.
 * Useful for UI to show which breakpoints are waiting for modules.
 *
 * @param debugger Debugger handle
 * @param buffer Array to receive breakpoints
 * @param bufferCount Size of buffer array
 * @param count Output: number of unresolved breakpoints
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_GetUnresolvedBreakpoints(
    NexusDebuggerHandle debugger,
    NexusBreakpoint* buffer,
    size_t bufferCount,
    size_t* count
);

/* ============================================================================
 * Stack Walker Operations
 * ============================================================================ */

/**
 * Create a stack walker instance.
 * @param process Process handle
 * @param walker Output: stack walker handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StackWalkerCreate(
    NexusProcessHandle process,
    NexusStackWalkerHandle* walker
);

/**
 * Destroy a stack walker instance.
 * @param walker Stack walker handle
 */
NEXUS_API void Nexus_StackWalkerDestroy(NexusStackWalkerHandle walker);

/**
 * Walk the call stack of a thread.
 * The thread should be suspended for accurate results.
 *
 * @param walker Stack walker handle
 * @param threadId Thread ID to walk
 * @param flags Walk flags (NexusStackWalkFlags)
 * @param frames Output buffer for stack frames
 * @param maxFrames Maximum frames to return
 * @param frameCount Output: actual frames returned
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StackWalk(
    NexusStackWalkerHandle walker,
    uint32_t threadId,
    uint32_t flags,
    NexusStackFrame* frames,
    size_t maxFrames,
    size_t* frameCount
);

/**
 * Walk the call stack using a provided thread context.
 * Useful when you already have the context (e.g., from a debug event).
 *
 * @param walker Stack walker handle
 * @param context Thread context (CONTEXT structure)
 * @param contextSize Size of context structure
 * @param is32Bit Non-zero if context is for 32-bit thread (WOW64)
 * @param flags Walk flags (NexusStackWalkFlags)
 * @param frames Output buffer for stack frames
 * @param maxFrames Maximum frames to return
 * @param frameCount Output: actual frames returned
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StackWalkFromContext(
    NexusStackWalkerHandle walker,
    const void* context,
    size_t contextSize,
    int is32Bit,
    uint32_t flags,
    NexusStackFrame* frames,
    size_t maxFrames,
    size_t* frameCount
);

/**
 * Get stack frame at a specific address.
 * Useful for resolving a single return address.
 *
 * @param walker Stack walker handle
 * @param address Address to resolve
 * @param flags Walk flags (NexusStackWalkFlags)
 * @param frame Output: frame information
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StackResolveAddress(
    NexusStackWalkerHandle walker,
    uint64_t address,
    uint32_t flags,
    NexusStackFrame* frame
);

/**
 * Get the current call stack of all threads in the process.
 * Returns one stack trace per thread.
 *
 * @param walker Stack walker handle
 * @param flags Walk flags (NexusStackWalkFlags)
 * @param maxFramesPerThread Maximum frames per thread
 * @param frames Output buffer (sized for threadCount * maxFramesPerThread)
 * @param threadIds Output: thread IDs (array of threadCount)
 * @param frameCounts Output: frame count per thread (array of threadCount)
 * @param maxThreads Maximum threads to process
 * @param threadCount Output: actual threads processed
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StackWalkAllThreads(
    NexusStackWalkerHandle walker,
    uint32_t flags,
    size_t maxFramesPerThread,
    NexusStackFrame* frames,
    uint32_t* threadIds,
    size_t* frameCounts,
    size_t maxThreads,
    size_t* threadCount
);

/**
 * Refresh symbol information.
 * Call this if modules have been loaded/unloaded.
 *
 * @param walker Stack walker handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StackWalkerRefreshSymbols(NexusStackWalkerHandle walker);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_DEBUGGER_H */
