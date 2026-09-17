/**
 * @file nexus_api.h
 * @brief Master include for the Nexus Engine public C API.
 *
 * Including this single header pulls in the complete, stable C ABI
 * surface of the Nexus Engine (engine.dll).  All functions use C
 * linkage for maximum interop compatibility with C#, Delphi, Python
 * ctypes, and similar FFI consumers.
 *
 * You may also include individual headers for narrower dependency:
 *   - nexus_common.h      -- Base types, result codes, opaque handles
 *   - nexus_process.h     -- Process, module, thread, handle operations
 *   - nexus_memory.h      -- Memory read/write, regions, snapshots, PE parsing
 *   - nexus_scanner.h     -- Basic and advanced memory scanning
 *   - nexus_debugger.h    -- Debugger attachment, breakpoints, stack walking
 *   - nexus_pointer.h     -- Pointer path scanning
 *   - nexus_project.h     -- Project / address list management
 *   - nexus_structure.h   -- Structure dissection
 *   - nexus_assembler.h   -- Disassembler, symbol handler, flow control
 *   - nexus_etw.h         -- ETW tracing for process monitoring
 *   - nexus_dumper.h      -- Process dumping and OEP finding
 *   - nexus_pemanip.h     -- PE file manipulation
 *   - nexus_relocation.h  -- Relocation table management
 *   - nexus_resource.h    -- PE resource handling
 *   - nexus_tls.h         -- TLS manipulation
 *   - nexus_import.h      -- Import/export reconstruction
 *   - nexus_hook.h        -- Hook detection
 *   - nexus_static.h      -- Static analysis (hash, entropy, strings)
 *   - nexus_avx512.h      -- AVX-512 register context
 *   - nexus_network.h     -- Network connection enumeration
 *   - nexus_windowheap.h  -- Window and heap enumeration
 *   - nexus_sourcemap.h   -- Source file / line mapping
 *   - nexus_pageprotect.h -- Page protection manipulation
 *   - nexus_cfg.h         -- Control flow graph analysis
 */

#ifndef NEXUS_API_H
#define NEXUS_API_H

/* Include all modular headers */
#include "nexus_common.h"
#include "nexus_process.h"
#include "nexus_memory.h"
#include "nexus_scanner.h"
#include "nexus_debugger.h"
#include "nexus_pointer.h"
#include "nexus_project.h"
#include "nexus_structure.h"
#include "nexus_assembler.h"
#include "nexus_etw.h"
#include "nexus_dumper.h"
#include "nexus_pemanip.h"
#include "nexus_relocation.h"
#include "nexus_resource.h"
#include "nexus_tls.h"
#include "nexus_import.h"
#include "nexus_hook.h"
#include "nexus_static.h"
#include "nexus_avx512.h"
#include "nexus_network.h"
#include "nexus_windowheap.h"
#include "nexus_sourcemap.h"
#include "nexus_pageprotect.h"
#include "nexus_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Code & DLL Injection
 * ============================================================================ */

/* Injection method flags */
typedef enum NexusInjectionMethod {
    NEXUS_INJECT_LOADLIBRARY = 0,       /* CreateRemoteThread + LoadLibraryW */
    NEXUS_INJECT_MANUAL_MAP = 1,        /* Manual mapping (no LoadLibrary) */
    NEXUS_INJECT_THREAD_HIJACK = 2,     /* Hijack existing thread */
    NEXUS_INJECT_APC = 3                /* Queue APC to alertable thread */
} NexusInjectionMethod;

/* Injection flags */
typedef enum NexusInjectionFlags {
    NEXUS_INJECT_FLAG_NONE = 0,
    NEXUS_INJECT_FLAG_WAIT = 0x0001,            /* Wait for injection to complete */
    NEXUS_INJECT_FLAG_HIDE_FROM_PEB = 0x0002,   /* Unlink from PEB (manual map only) */
    NEXUS_INJECT_FLAG_ERASE_HEADERS = 0x0004,   /* Erase PE headers after mapping */
    NEXUS_INJECT_FLAG_NO_TLS = 0x0008,          /* Skip TLS callbacks (manual map) */
    NEXUS_INJECT_FLAG_STEALTH = 0x0010,         /* Use NtCreateThreadEx instead of CreateRemoteThread */
    NEXUS_INJECT_FLAG_SKIP_ATTACH = 0x0020,     /* Skip DLL_THREAD_ATTACH notifications (stealth) */
    NEXUS_INJECT_FLAG_HIDE_THREAD = 0x0040      /* Hide thread from debugger (stealth) */
} NexusInjectionFlags;

/* Injection result information */
typedef struct NexusInjectionResult {
    uint64_t baseAddress;           /* Base address of injected code/DLL */
    uint64_t entryPoint;            /* Entry point address (for DLLs: DllMain) */
    uint32_t threadId;              /* Thread ID used for injection */
    uint32_t exitCode;              /* Thread exit code (if waited) */
    uint32_t success;               /* 1 if successful */
    uint32_t reserved;              /* Padding */
} NexusInjectionResult;

/**
 * @brief Inject raw shellcode into a target process.
 *
 * Allocates executable memory in the target, writes the shellcode,
 * and creates a remote thread (or uses the method implied by flags)
 * to execute it.
 *
 * @param handle        Process handle (must have FULL access).
 * @param shellcode     Pointer to shellcode bytes.
 * @param shellcodeSize Size of the shellcode buffer in bytes.
 * @param parameter     64-bit value passed as the thread parameter.
 * @param flags         Bitwise OR of NexusInjectionFlags.
 * @param[out] result   Receives injection result details (may be NULL).
 * @return NEXUS_OK on success.
 */
NEXUS_API NexusResult Nexus_InjectShellcode(
    NexusProcessHandle handle,
    const void* shellcode,
    size_t shellcodeSize,
    uint64_t parameter,
    uint32_t flags,
    NexusInjectionResult* result
);

/**
 * @brief Inject a DLL using the LoadLibrary method.
 *
 * Writes the DLL path into the target process and calls
 * LoadLibraryW via CreateRemoteThread (or NtCreateThreadEx
 * if NEXUS_INJECT_FLAG_STEALTH is set).
 *
 * @param handle   Process handle (FULL access).
 * @param dllPath  Absolute path to the DLL (UTF-16).
 * @param flags    Bitwise OR of NexusInjectionFlags.
 * @param[out] result  Injection result details (may be NULL).
 * @return NEXUS_OK on success.
 */
NEXUS_API NexusResult Nexus_InjectDll(
    NexusProcessHandle handle,
    const wchar_t* dllPath,
    uint32_t flags,
    NexusInjectionResult* result
);

/**
 * @brief Inject a DLL via manual mapping (no LoadLibrary).
 *
 * Reads the DLL from disk, maps PE sections into the target,
 * processes relocations and imports, then calls DllMain.
 * The DLL will not appear in the PEB module list.
 *
 * @param handle   Process handle (FULL access).
 * @param dllPath  Absolute path to the DLL (UTF-16).
 * @param flags    Bitwise OR of NexusInjectionFlags.
 * @param[out] result  Injection result details (may be NULL).
 * @return NEXUS_OK on success.
 */
NEXUS_API NexusResult Nexus_InjectDllManualMap(
    NexusProcessHandle handle,
    const wchar_t* dllPath,
    uint32_t flags,
    NexusInjectionResult* result
);

/**
 * @brief Execute a function at the given address in the target process.
 *
 * Creates a remote thread whose start address is @p functionAddress.
 * The single 64-bit parameter is passed as the thread parameter.
 *
 * @param handle           Process handle (FULL access).
 * @param functionAddress  Address of the function to call.
 * @param parameter        Argument passed to the function.
 * @param flags            Bitwise OR of NexusInjectionFlags.
 * @param[out] result      Injection result details (may be NULL).
 * @return NEXUS_OK on success.
 */
NEXUS_API NexusResult Nexus_CallRemoteFunction(
    NexusProcessHandle handle,
    uint64_t functionAddress,
    uint64_t parameter,
    uint32_t flags,
    NexusInjectionResult* result
);

/**
 * @brief Free memory previously allocated by an injection operation.
 *
 * @param handle   Process handle.
 * @param address  Base address returned by the injection.
 * @return NEXUS_OK on success.
 */
NEXUS_API NexusResult Nexus_FreeInjectedMemory(
    NexusProcessHandle handle,
    uint64_t address
);

/* ============================================================================
 * Cheat Table (.nst - Nexus Sentinel Table)
 * ============================================================================ */

/* Memory record types */
typedef enum NexusRecordType {
    NEXUS_RECORD_ADDRESS = 0,       /* Simple address entry */
    NEXUS_RECORD_POINTER = 1,       /* Pointer with offsets */
    NEXUS_RECORD_GROUP = 2,         /* Group/folder for organization */
    NEXUS_RECORD_SCRIPT = 3,        /* Auto-assembler script */
    NEXUS_RECORD_HEADER = 4         /* Header/separator */
} NexusRecordType;

/* Memory record flags */
typedef enum NexusRecordFlags {
    NEXUS_RECORD_FLAG_NONE = 0,
    NEXUS_RECORD_FLAG_FROZEN = 0x0001,          /* Value is frozen */
    NEXUS_RECORD_FLAG_ALLOW_DECREASE = 0x0002,  /* Allow decrease while frozen */
    NEXUS_RECORD_FLAG_ALLOW_INCREASE = 0x0004,  /* Allow increase while frozen */
    NEXUS_RECORD_FLAG_ACTIVE = 0x0008,          /* Script/record is active */
    NEXUS_RECORD_FLAG_HIDDEN = 0x0010,          /* Hidden from view */
    NEXUS_RECORD_FLAG_COLLAPSED = 0x0020        /* Group is collapsed */
} NexusRecordFlags;

/* Memory record for cheat table */
typedef struct NexusTableRecord {
    uint64_t id;                    /* Unique record ID */
    uint64_t parentId;              /* Parent group ID (0 = root) */
    uint32_t recordType;            /* NexusRecordType */
    uint32_t valueType;             /* NexusValueType for data */
    uint32_t flags;                 /* NexusRecordFlags */
    uint32_t hotkey;                /* Virtual key code for toggle */
    uint64_t address;               /* Base address or static address */
    int64_t offsets[16];            /* Pointer offsets (if pointer type) */
    uint32_t offsetCount;           /* Number of offsets used */
    uint32_t reserved;
    wchar_t description[128];       /* User description */
    wchar_t moduleName[64];         /* Module name for relative addresses */
    wchar_t groupName[64];          /* Group name (if group type) */
    uint8_t frozenValue[32];        /* Value to freeze to */
    uint32_t frozenValueSize;       /* Size of frozen value */
    uint32_t displayType;           /* How to display the value (hex, decimal, etc.) */
} NexusTableRecord;

/* Script entry for cheat table */
typedef struct NexusTableScript {
    uint64_t id;                    /* Unique script ID */
    uint64_t parentId;              /* Parent group ID (0 = root) */
    uint32_t flags;                 /* NexusRecordFlags */
    uint32_t hotkey;                /* Virtual key code for toggle */
    wchar_t name[128];              /* Script name/description */
} NexusTableScript;

/* Table metadata */
typedef struct NexusTableInfo {
    wchar_t name[128];              /* Table name */
    wchar_t author[64];             /* Author name */
    wchar_t targetProcess[260];     /* Target process name */
    wchar_t gameVersion[32];        /* Game version string */
    uint32_t schemaVersion;         /* Table schema version */
    uint32_t recordCount;           /* Number of memory records */
    uint32_t scriptCount;           /* Number of scripts */
    uint32_t groupCount;            /* Number of groups */
    uint64_t createdTime;           /* Creation timestamp */
    uint64_t modifiedTime;          /* Last modified timestamp */
} NexusTableInfo;

/** @brief Create a new, empty cheat table. */
NEXUS_API NexusResult Nexus_TableCreate(NexusTableHandle* table);
/** @brief Destroy a cheat table and free all associated resources. */
NEXUS_API void Nexus_TableDestroy(NexusTableHandle table);
/** @brief Load a cheat table from a .nst file on disk. */
NEXUS_API NexusResult Nexus_TableLoad(const wchar_t* path, NexusTableHandle* table);
/** @brief Save a cheat table to a .nst file. */
NEXUS_API NexusResult Nexus_TableSave(NexusTableHandle table, const wchar_t* path);
/** @brief Retrieve metadata (name, author, counts) for a table. */
NEXUS_API NexusResult Nexus_TableGetInfo(NexusTableHandle table, NexusTableInfo* info);
/** @brief Update table metadata. */
NEXUS_API NexusResult Nexus_TableSetInfo(NexusTableHandle table, const NexusTableInfo* info);
/** @brief Add a memory record to the table and receive its unique ID. */
NEXUS_API NexusResult Nexus_TableAddRecord(NexusTableHandle table, const NexusTableRecord* record, uint64_t* id);
/** @brief Retrieve a memory record by its unique ID. */
NEXUS_API NexusResult Nexus_TableGetRecord(NexusTableHandle table, uint64_t id, NexusTableRecord* record);
/** @brief Update an existing memory record (matched by record->id). */
NEXUS_API NexusResult Nexus_TableUpdateRecord(NexusTableHandle table, const NexusTableRecord* record);
/** @brief Remove a memory record by ID. */
NEXUS_API NexusResult Nexus_TableRemoveRecord(NexusTableHandle table, uint64_t id);
/** @brief Retrieve all memory records into a caller-supplied buffer. */
NEXUS_API NexusResult Nexus_TableGetRecords(NexusTableHandle table, NexusTableRecord* buffer, size_t bufferCount, size_t* recordCount);
/** @brief Add an Auto-Assembler script to the table. */
NEXUS_API NexusResult Nexus_TableAddScript(NexusTableHandle table, const NexusTableScript* script, const char* content, uint64_t* id);
/** @brief Retrieve the source code of a table script by ID. */
NEXUS_API NexusResult Nexus_TableGetScriptContent(NexusTableHandle table, uint64_t id, char* buffer, size_t bufferSize, size_t* contentLength);
/** @brief Replace the source code of an existing table script. */
NEXUS_API NexusResult Nexus_TableUpdateScriptContent(NexusTableHandle table, uint64_t id, const char* content);
/** @brief Remove a script from the table by ID. */
NEXUS_API NexusResult Nexus_TableRemoveScript(NexusTableHandle table, uint64_t id);
/** @brief Retrieve all scripts in the table. */
NEXUS_API NexusResult Nexus_TableGetScripts(NexusTableHandle table, NexusTableScript* buffer, size_t bufferCount, size_t* scriptCount);

/* ============================================================================
 * Auto-Assembler Script Parsing API (v0.22.0)
 * ============================================================================ */

/* AA script section positions */
typedef struct NexusAAScriptSections {
    int32_t enableStart;            /* Line number of [ENABLE] (-1 if not found) */
    int32_t enableEnd;              /* Line number of [ENABLE] section end */
    int32_t disableStart;           /* Line number of [DISABLE] (-1 if not found) */
    int32_t disableEnd;             /* Line number of [DISABLE] section end */
    int32_t globalEnd;              /* Line number where global section ends */
    int32_t totalLines;             /* Total number of lines in script */
    uint32_t hasEnable;             /* 1 if [ENABLE] section exists */
    uint32_t hasDisable;            /* 1 if [DISABLE] section exists */
    uint32_t isValid;               /* 1 if script structure is valid */
    char errorMessage[256];         /* Error message if not valid */
} NexusAAScriptSections;

/* AA script execution state (for tracking allocations) */
typedef struct NexusAAScriptState {
    uint64_t id;                    /* State ID */
    uint64_t scriptId;              /* Associated script ID */
    uint32_t isEnabled;             /* 1 if currently enabled */
    uint32_t allocationCount;       /* Number of memory allocations */
    uint32_t symbolCount;           /* Number of registered symbols */
    uint64_t allocations[64];       /* Allocated memory addresses */
    uint64_t allocationSizes[64];   /* Allocation sizes */
    char symbols[64][64];           /* Registered symbol names */
    uint64_t symbolAddresses[64];   /* Symbol addresses */
} NexusAAScriptState;

/** @brief Parse an AA script to locate [ENABLE]/[DISABLE] section boundaries. */
NEXUS_API NexusResult Nexus_AAScriptParseSections(const char* script, NexusAAScriptSections* sections);
/** @brief Extract the [ENABLE] section text from a full AA script. */
NEXUS_API NexusResult Nexus_AAScriptGetEnableSection(const char* script, char* buffer, size_t bufferSize, size_t* scriptLength);
/** @brief Extract the [DISABLE] section text from a full AA script. */
NEXUS_API NexusResult Nexus_AAScriptGetDisableSection(const char* script, char* buffer, size_t bufferSize, size_t* scriptLength);
/** @brief Validate an AA script for structural correctness. */
NEXUS_API NexusResult Nexus_AAScriptValidate(const char* script, int32_t* isValid, char* errorBuffer, size_t errorBufferSize);
/** @brief Combine separate enable, disable, and global code into a single AA script. */
NEXUS_API NexusResult Nexus_AAScriptCombine(const char* enableCode, const char* disableCode, const char* globalCode, char* buffer, size_t bufferSize, size_t* scriptLength);

/* ============================================================================
 * Speedhack
 * ============================================================================ */

/* Speedhack method */
typedef enum NexusSpeedhackMethod {
    NEXUS_SPEEDHACK_AUTO = 0,               /* Auto-detect best method */
    NEXUS_SPEEDHACK_QPC = 1,                /* Hook QueryPerformanceCounter */
    NEXUS_SPEEDHACK_GETTICKCOUNT = 2,       /* Hook GetTickCount/64 */
    NEXUS_SPEEDHACK_TIMEGETTIME = 3,        /* Hook timeGetTime */
    NEXUS_SPEEDHACK_ALL = 4                 /* Hook all timing functions */
} NexusSpeedhackMethod;

/* Speedhack status */
typedef struct NexusSpeedhackStatus {
    uint32_t isActive;              /* 1 if speedhack is active */
    uint32_t method;                /* Current method being used */
    double currentSpeed;            /* Current speed multiplier */
    uint64_t hookCount;             /* Number of times hooks were called */
    uint64_t baseTime;              /* Base time when speedhack started */
} NexusSpeedhackStatus;

/** @brief Create a speedhack instance targeting a process. */
NEXUS_API NexusResult Nexus_SpeedhackCreate(NexusProcessHandle process, uint32_t method, NexusSpeedhackHandle* speedhack);
/** @brief Destroy a speedhack instance and unhook all timing functions. */
NEXUS_API void Nexus_SpeedhackDestroy(NexusSpeedhackHandle speedhack);
/** @brief Set the speed multiplier (e.g. 2.0 = double speed, 0.5 = half speed). */
NEXUS_API NexusResult Nexus_SpeedhackSetSpeed(NexusSpeedhackHandle speedhack, double speed);
/** @brief Get the current speed multiplier. */
NEXUS_API NexusResult Nexus_SpeedhackGetSpeed(NexusSpeedhackHandle speedhack, double* speed);
/** @brief Enable or disable the speedhack without destroying the hooks. */
NEXUS_API NexusResult Nexus_SpeedhackSetEnabled(NexusSpeedhackHandle speedhack, uint32_t enable);
/** @brief Query the current speedhack status (active, method, hook count). */
NEXUS_API NexusResult Nexus_SpeedhackGetStatus(NexusSpeedhackHandle speedhack, NexusSpeedhackStatus* status);

/* ============================================================================
 * Auto-Assembler
 * ============================================================================ */

/* Assembler target architecture */
typedef enum NexusAssemblerArch {
    NEXUS_ASM_X86 = 0,              /* 32-bit x86 */
    NEXUS_ASM_X64 = 1               /* 64-bit x86-64 */
} NexusAssemblerArch;

/* Assembler error codes */
typedef enum NexusAssemblerError {
    NEXUS_ASM_OK = 0,
    NEXUS_ASM_ERROR_SYNTAX = 1,
    NEXUS_ASM_ERROR_UNKNOWN_OPCODE = 2,
    NEXUS_ASM_ERROR_INVALID_OPERAND = 3,
    NEXUS_ASM_ERROR_UNDEFINED_SYMBOL = 4,
    NEXUS_ASM_ERROR_DUPLICATE_SYMBOL = 5,
    NEXUS_ASM_ERROR_ALLOC_FAILED = 6,
    NEXUS_ASM_ERROR_INJECTION_FAILED = 7,
    NEXUS_ASM_ERROR_RELOCATION = 8,
    NEXUS_ASM_ERROR_RANGE = 9,
    NEXUS_ASM_ERROR_ASSERT_FAILED = 10,
    NEXUS_ASM_ERROR_AOB_NOT_FOUND = 11,
    NEXUS_ASM_ERROR_MODULE_NOT_FOUND = 12,
    NEXUS_ASM_ERROR_READ_FAILED = 13,
    NEXUS_ASM_ERROR_THREAD_FAILED = 14,
    NEXUS_ASM_ERROR_LOADLIB_FAILED = 15
} NexusAssemblerError;

/* Symbol types */
typedef enum NexusSymbolType {
    NEXUS_SYM_LABEL = 0,            /* Code label */
    NEXUS_SYM_ALLOC = 1,            /* Allocated memory */
    NEXUS_SYM_ADDRESS = 2,          /* Static address */
    NEXUS_SYM_REGISTER = 3          /* Registered symbol (global) */
} NexusSymbolType;

/* Symbol information */
typedef struct NexusSymbol {
    char name[128];                 /* Symbol name */
    uint64_t address;               /* Symbol address */
    uint32_t type;                  /* NexusSymbolType */
    uint32_t size;                  /* Size (for allocations) */
} NexusSymbol;

/* Assembler error information */
typedef struct NexusAssemblerErrorInfo {
    uint32_t errorCode;             /* NexusAssemblerError */
    uint32_t lineNumber;            /* Line number (1-based, 0 if unknown) */
    uint32_t columnNumber;          /* Column number (1-based, 0 if unknown) */
    uint32_t reserved;
    char message[256];              /* Human-readable error message */
    char lineText[256];             /* The offending line text */
} NexusAssemblerErrorInfo;

/* Assembled code block */
typedef struct NexusAssembledCode {
    uint64_t baseAddress;           /* Base address where code is assembled */
    uint8_t* code;                  /* Assembled machine code */
    size_t codeSize;                /* Size of assembled code */
    NexusSymbol* symbols;           /* Symbol table */
    size_t symbolCount;             /* Number of symbols */
} NexusAssembledCode;

/* Allocation entry for script */
typedef struct NexusAllocEntry {
    char name[128];
    uint64_t address;
    size_t size;
    uint32_t protection;
    uint32_t reserved;
} NexusAllocEntry;

/** @brief Create an assembler context bound to a process and architecture. */
NEXUS_API NexusResult Nexus_AssemblerCreate(NexusProcessHandle process, NexusAssemblerArch arch, NexusAssemblerHandle* assembler);
/** @brief Destroy an assembler context and free all tracked allocations. */
NEXUS_API void Nexus_AssemblerDestroy(NexusAssemblerHandle assembler);
/** @brief Assemble a single instruction at the given virtual address. */
NEXUS_API NexusResult Nexus_AssembleInstruction(NexusAssemblerHandle assembler, uint64_t address, const char* instruction, uint8_t* output, size_t outputSize, size_t* bytesWritten);
/** @brief Assemble multiple newline-separated instructions starting at the given address. */
NEXUS_API NexusResult Nexus_AssembleInstructions(NexusAssemblerHandle assembler, uint64_t address, const char* instructions, uint8_t* output, size_t outputSize, size_t* bytesWritten);
/** @brief Execute a full Auto-Assembler script (enable=1 runs [ENABLE], enable=0 runs [DISABLE]). */
NEXUS_API NexusResult Nexus_AssemblerExecuteScript(NexusAssemblerHandle assembler, const char* script, int enable);
/** @brief Get detailed error information from the last failed assembler operation. */
NEXUS_API NexusResult Nexus_AssemblerGetLastError(NexusAssemblerHandle assembler, NexusAssemblerErrorInfo* error);
/** @brief Register a named symbol at the given address for use in scripts. */
NEXUS_API NexusResult Nexus_AssemblerAddSymbol(NexusAssemblerHandle assembler, const char* name, uint64_t address);
/** @brief Remove a previously registered symbol by name. */
NEXUS_API NexusResult Nexus_AssemblerRemoveSymbol(NexusAssemblerHandle assembler, const char* name);
/** @brief Look up a symbol by name and return its address and metadata. */
NEXUS_API NexusResult Nexus_AssemblerGetSymbol(NexusAssemblerHandle assembler, const char* name, NexusSymbol* symbol);
/** @brief Enumerate all registered symbols. */
NEXUS_API NexusResult Nexus_AssemblerGetSymbols(NexusAssemblerHandle assembler, NexusSymbol* buffer, size_t bufferCount, size_t* symbolCount);
/** @brief Enumerate all memory allocations tracked by this assembler context. */
NEXUS_API NexusResult Nexus_AssemblerGetAllocations(NexusAssemblerHandle assembler, NexusAllocEntry* buffer, size_t bufferCount, size_t* allocCount);
/** @brief Free all memory allocations tracked by this assembler context in the target process. */
NEXUS_API NexusResult Nexus_AssemblerFreeAllAllocations(NexusAssemblerHandle assembler);
/** @brief Write raw machine code bytes into the target process at the given address. */
NEXUS_API NexusResult Nexus_AssemblerWriteCode(NexusAssemblerHandle assembler, uint64_t address, const uint8_t* code, size_t codeSize);
/** @brief Allocate a named code cave near a target address (within +/-2GB for rel32). */
NEXUS_API NexusResult Nexus_AssemblerAllocCodeCave(NexusAssemblerHandle assembler, const char* name, size_t size, uint64_t nearAddress, uint64_t* address);
/** @brief Disassemble instructions from the target process into a text buffer. */
NEXUS_API NexusResult Nexus_Disassemble(NexusAssemblerHandle assembler, uint64_t address, char* buffer, size_t bufferSize, size_t instructionCount, size_t* bytesDisassembled);
/** @brief Get the length in bytes of a single instruction at the given address. */
NEXUS_API NexusResult Nexus_GetInstructionLength(NexusAssemblerHandle assembler, uint64_t address, size_t* length);
/** @brief Install a JMP hook, saving original bytes for later restoration. */
NEXUS_API NexusResult Nexus_CreateHook(NexusAssemblerHandle assembler, uint64_t hookAddress, uint64_t targetAddress, uint8_t* originalBytes, size_t originalBytesSize, size_t* bytesOverwritten);
/** @brief Remove a previously installed hook by restoring original bytes. */
NEXUS_API NexusResult Nexus_RemoveHook(NexusAssemblerHandle assembler, uint64_t hookAddress, const uint8_t* originalBytes, size_t bytesCount);

/* ============================================================================
 * Signature Scanner
 * ============================================================================ */

/* Signature scan flags */
typedef enum NexusSignatureFlags {
    NEXUS_SIG_FLAG_NONE = 0x0000,
    NEXUS_SIG_FLAG_FIRST_MATCH = 0x0001,
    NEXUS_SIG_FLAG_MODULE_ONLY = 0x0002,
    NEXUS_SIG_FLAG_EXECUTABLE = 0x0004,
    NEXUS_SIG_FLAG_WRITABLE = 0x0008,
    NEXUS_SIG_FLAG_CASE_INSENSITIVE = 0x0010
} NexusSignatureFlags;

/* Signature match result */
typedef struct NexusSignatureMatch {
    uint64_t address;
    uint64_t moduleBase;
    wchar_t moduleName[64];
    uint32_t matchIndex;
    uint32_t reserved;
} NexusSignatureMatch;

/* Signature definition */
typedef struct NexusSignatureInfo {
    char name[64];
    char pattern[256];
    char moduleName[64];
    int32_t offset;
    uint32_t flags;
    uint32_t extraData;
    uint32_t reserved;
} NexusSignatureInfo;

/* Signature scan progress */
typedef struct NexusSignatureScanProgress {
    uint64_t bytesScanned;
    uint64_t bytesTotal;
    uint64_t matchesFound;
    uint32_t isComplete;
    uint32_t wasCancelled;
} NexusSignatureScanProgress;

/** @brief Create a signature scanner bound to a process. */
NEXUS_API NexusResult Nexus_SignatureCreate(NexusProcessHandle process, NexusSignatureScannerHandle* scanner);
/** @brief Destroy a signature scanner and free all results. */
NEXUS_API void Nexus_SignatureDestroy(NexusSignatureScannerHandle scanner);
/** @brief Register a named signature pattern for batch scanning. */
NEXUS_API NexusResult Nexus_SignatureAdd(NexusSignatureScannerHandle scanner, const NexusSignatureInfo* sig, uint32_t* sigId);
/** @brief Remove a registered signature by ID. */
NEXUS_API NexusResult Nexus_SignatureRemove(NexusSignatureScannerHandle scanner, uint32_t sigId);
/** @brief Remove all registered signatures. */
NEXUS_API void Nexus_SignatureClear(NexusSignatureScannerHandle scanner);
/** @brief Scan for a single pattern (ad-hoc, does not require prior registration). */
NEXUS_API NexusResult Nexus_SignatureScanPattern(NexusSignatureScannerHandle scanner, const char* pattern, const char* moduleName, uint32_t flags, NexusSignatureMatch* matches, size_t maxMatches, size_t* matchCount);
/** @brief Scan all registered signatures in one pass over process memory. */
NEXUS_API NexusResult Nexus_SignatureScanAll(NexusSignatureScannerHandle scanner);
/** @brief Cancel an in-progress batch signature scan. */
NEXUS_API void Nexus_SignatureScanCancel(NexusSignatureScannerHandle scanner);
/** @brief Get progress information for a running batch scan. */
NEXUS_API NexusResult Nexus_SignatureGetProgress(NexusSignatureScannerHandle scanner, NexusSignatureScanProgress* progress);
/** @brief Retrieve match results for a specific signature after scanning. */
NEXUS_API NexusResult Nexus_SignatureGetMatches(NexusSignatureScannerHandle scanner, uint32_t sigId, NexusSignatureMatch* matches, size_t maxMatches, size_t* matchCount);
/** @brief Resolve a signature to a single address (first match + offset). */
NEXUS_API NexusResult Nexus_SignatureResolve(NexusSignatureScannerHandle scanner, uint32_t sigId, uint64_t* resolvedAddress);
/** @brief Parse a hex/wildcard pattern string into byte and mask arrays. */
NEXUS_API NexusResult Nexus_SignatureParsePattern(const char* pattern, uint8_t* bytes, uint8_t* mask, size_t maxLen, size_t* patternLen);
/** @brief Search for a byte pattern within a local buffer (no process memory access). */
NEXUS_API NexusResult Nexus_SignatureFindInBuffer(const uint8_t* buffer, size_t bufferSize, const uint8_t* pattern, const uint8_t* mask, size_t patternLen, size_t* offset);
/** @brief Register a resolved signature address as a named symbol in an assembler context. */
NEXUS_API NexusResult Nexus_SignatureRegisterAsSymbol(NexusSignatureScannerHandle scanner, uint32_t sigId, const char* symbolName, NexusAssemblerHandle assembler);

/* ============================================================================
 * Trace Logger
 * ============================================================================ */

/* Trace event types */
typedef enum NexusTraceEventType {
    NEXUS_TRACE_INSTRUCTION = 0,
    NEXUS_TRACE_CALL = 1,
    NEXUS_TRACE_RET = 2,
    NEXUS_TRACE_BRANCH = 3,
    NEXUS_TRACE_EXCEPTION = 4,
    NEXUS_TRACE_MEMORY_READ = 5,
    NEXUS_TRACE_MEMORY_WRITE = 6
} NexusTraceEventType;

/* Trace flags */
typedef enum NexusTraceFlags {
    NEXUS_TRACE_FLAG_NONE = 0x0000,
    NEXUS_TRACE_FLAG_INSTRUCTIONS = 0x0001,
    NEXUS_TRACE_FLAG_CALLS = 0x0002,
    NEXUS_TRACE_FLAG_BRANCHES = 0x0004,
    NEXUS_TRACE_FLAG_MEMORY = 0x0008,
    NEXUS_TRACE_FLAG_REGISTERS = 0x0010,
    NEXUS_TRACE_FLAG_STACK = 0x0020,
    NEXUS_TRACE_FLAG_SYMBOLS = 0x0040,
    NEXUS_TRACE_FLAG_DISASM = 0x0080
} NexusTraceFlags;

/* Trace stop condition */
typedef enum NexusTraceStopCondition {
    NEXUS_TRACE_STOP_NEVER = 0,
    NEXUS_TRACE_STOP_COUNT = 1,
    NEXUS_TRACE_STOP_ADDRESS = 2,
    NEXUS_TRACE_STOP_CALL_DEPTH = 3,
    NEXUS_TRACE_STOP_EXCEPTION = 4
} NexusTraceStopCondition;

/* Register state snapshot (x64) */
typedef struct NexusTraceRegisters {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip, rflags;
    uint32_t cs, ss, ds, es, fs, gs;
    uint32_t reserved[2];
} NexusTraceRegisters;

/* Single trace entry */
typedef struct NexusTraceEntry {
    uint64_t index;
    uint64_t timestamp;
    uint64_t address;
    uint64_t targetAddress;
    uint32_t threadId;
    uint32_t eventType;
    uint32_t instructionSize;
    uint32_t callDepth;
    uint8_t instructionBytes[16];
    char disassembly[64];
    char symbolName[64];
    uint32_t symbolOffset;
    uint32_t flags;
} NexusTraceEntry;

/* Trace configuration */
typedef struct NexusTraceConfig {
    uint32_t flags;
    uint32_t maxEntries;
    uint32_t stopCondition;
    uint32_t reserved;
    uint64_t stopValue;
    uint64_t startAddress;
    uint64_t endAddress;
    wchar_t moduleFilter[64];
} NexusTraceConfig;

/* Trace statistics */
typedef struct NexusTraceStats {
    uint64_t totalInstructions;
    uint64_t totalCalls;
    uint64_t totalReturns;
    uint64_t totalBranches;
    uint64_t totalExceptions;
    uint64_t entriesInBuffer;
    uint64_t entriesDropped;
    uint64_t startTime;
    uint64_t endTime;
    uint32_t isRunning;
    uint32_t maxCallDepth;
} NexusTraceStats;

/** @brief Create a trace logger attached to a debugger session. */
NEXUS_API NexusResult Nexus_TraceCreate(NexusDebuggerHandle debugger, NexusTraceHandle* tracer);
/** @brief Destroy a trace logger and free its ring buffer. */
NEXUS_API void Nexus_TraceDestroy(NexusTraceHandle tracer);
/** @brief Configure trace flags, stop conditions, and address filters. */
NEXUS_API NexusResult Nexus_TraceConfigure(NexusTraceHandle tracer, const NexusTraceConfig* config);
/** @brief Begin tracing a specific thread. */
NEXUS_API NexusResult Nexus_TraceStart(NexusTraceHandle tracer, uint32_t threadId);
/** @brief Stop an active trace. */
NEXUS_API NexusResult Nexus_TraceStop(NexusTraceHandle tracer);
/** @brief Check whether a trace is currently running. */
NEXUS_API NexusResult Nexus_TraceIsRunning(NexusTraceHandle tracer, uint32_t* isRunning);
/** @brief Retrieve aggregate statistics for the trace session. */
NEXUS_API NexusResult Nexus_TraceGetStats(NexusTraceHandle tracer, NexusTraceStats* stats);
/** @brief Read a range of trace entries from the ring buffer. */
NEXUS_API NexusResult Nexus_TraceGetEntries(NexusTraceHandle tracer, uint64_t startIndex, NexusTraceEntry* entries, size_t maxEntries, size_t* entryCount);
/** @brief Read a single trace entry by index. */
NEXUS_API NexusResult Nexus_TraceGetEntry(NexusTraceHandle tracer, uint64_t index, NexusTraceEntry* entry);
/** @brief Clear all entries from the trace buffer. */
NEXUS_API NexusResult Nexus_TraceClear(NexusTraceHandle tracer);
/** @brief Export the trace log to a file (text or binary format). */
NEXUS_API NexusResult Nexus_TraceExport(NexusTraceHandle tracer, const wchar_t* filePath, uint32_t format);
/** @brief Retrieve the register snapshot associated with a trace entry. */
NEXUS_API NexusResult Nexus_TraceGetRegisters(NexusTraceHandle tracer, uint64_t index, NexusTraceRegisters* regs);
/** @brief Search trace entries for a specific event type and/or address. */
NEXUS_API NexusResult Nexus_TraceFind(NexusTraceHandle tracer, int32_t eventType, uint64_t address, uint64_t startIndex, uint64_t* indices, size_t maxResults, size_t* resultCount);

/* ============================================================================
 * Address File Format (.nsa - Nexus Sentinel Address)
 * ============================================================================ */

/* Address file entry for NSA file (module-relative addresses) */
typedef struct NexusAddressFileEntry {
    int32_t moduleIndex;            /* Module index (-1 for absolute address) */
    uint64_t offset;                /* Offset from module base (or absolute if moduleIndex == -1) */
    uint64_t resolvedAddress;       /* Resolved runtime address (filled during load) */
    char description[256];          /* User description */
    char moduleName[260];           /* Module name (for display/debugging) */
    int32_t isValid;                /* 1 if address resolved successfully, 0 if module not found */
} NexusAddressFileEntry;

/** @brief Create a new, empty address file (.nsa). */
NEXUS_API NexusResult Nexus_AddressFileCreate(NexusAddressFileHandle* file);
/** @brief Destroy an address file handle and free its entries. */
NEXUS_API void Nexus_AddressFileDestroy(NexusAddressFileHandle file);
/** @brief Load an .nsa file from disk and resolve addresses against a process. */
NEXUS_API NexusResult Nexus_AddressFileLoad(const char* path, NexusProcessHandle process, NexusAddressFileHandle* file);
/** @brief Save the address file to disk in .nsa format. */
NEXUS_API NexusResult Nexus_AddressFileSave(NexusAddressFileHandle file, const char* path);
/** @brief Register a module name and receive its index for entry references. */
NEXUS_API NexusResult Nexus_AddressFileAddModule(NexusAddressFileHandle file, const char* moduleName, int32_t* moduleIndex);
/** @brief Get the number of registered modules. */
NEXUS_API NexusResult Nexus_AddressFileGetModuleCount(NexusAddressFileHandle file, size_t* count);
/** @brief Get the name of a registered module by index. */
NEXUS_API NexusResult Nexus_AddressFileGetModule(NexusAddressFileHandle file, int32_t index, char* name, size_t nameSize);
/** @brief Add a module-relative address entry with a description. */
NEXUS_API NexusResult Nexus_AddressFileAddEntry(NexusAddressFileHandle file, int32_t moduleIndex, uint64_t offset, const char* description);
/** @brief Get the number of address entries. */
NEXUS_API NexusResult Nexus_AddressFileGetEntryCount(NexusAddressFileHandle file, size_t* count);
/** @brief Retrieve an address entry by index. */
NEXUS_API NexusResult Nexus_AddressFileGetEntry(NexusAddressFileHandle file, size_t index, NexusAddressFileEntry* entry);
/** @brief Remove an address entry by index. */
NEXUS_API NexusResult Nexus_AddressFileRemoveEntry(NexusAddressFileHandle file, size_t index);
/** @brief Remove all address entries (modules are retained). */
NEXUS_API NexusResult Nexus_AddressFileClearEntries(NexusAddressFileHandle file);
/** @brief Re-resolve all entries against the current module layout of a process. */
NEXUS_API NexusResult Nexus_AddressFileResolve(NexusAddressFileHandle file, NexusProcessHandle process);
/** @brief Import a Cheat Engine .CEA address file. */
NEXUS_API NexusResult Nexus_AddressFileImportCEA(const char* path, NexusProcessHandle process, NexusAddressFileHandle* file);
/** @brief Export as a Cheat Engine .CEA address file. */
NEXUS_API NexusResult Nexus_AddressFileExportCEA(NexusAddressFileHandle file, const char* path);

/* ============================================================================
 * Trainer Generation
 * ============================================================================ */

/* Trainer cheat action types */
typedef enum NexusTrainerAction {
    NEXUS_TRAINER_TOGGLE = 0,           /* Toggle on/off */
    NEXUS_TRAINER_SET_VALUE = 1,        /* Set to specific value */
    NEXUS_TRAINER_FREEZE = 2,           /* Freeze at current/specified value */
    NEXUS_TRAINER_INCREMENT = 3,        /* Increase value */
    NEXUS_TRAINER_DECREMENT = 4,        /* Decrease value */
    NEXUS_TRAINER_EXECUTE_SCRIPT = 5    /* Execute script/assembly */
} NexusTrainerAction;

/* Virtual key codes for hotkeys (matches Windows VK codes) */
typedef uint32_t NexusVirtualKey;

/* Hotkey modifiers */
typedef enum NexusHotkeyModifier {
    NEXUS_HOTKEY_NONE = 0,
    NEXUS_HOTKEY_CTRL = 0x0001,
    NEXUS_HOTKEY_ALT = 0x0002,
    NEXUS_HOTKEY_SHIFT = 0x0004
} NexusHotkeyModifier;

/* Trainer cheat entry */
typedef struct NexusTrainerCheat {
    uint32_t id;                        /* Unique cheat ID */
    char name[128];                     /* Cheat name/description */
    NexusTrainerAction action;          /* Action type */
    NexusVirtualKey hotkey;             /* Virtual key code */
    uint32_t modifiers;                 /* Hotkey modifiers (OR'd NexusHotkeyModifier) */

    /* Address information */
    int32_t moduleIndex;                /* Module index (-1 for absolute) */
    uint64_t offset;                    /* Offset or absolute address */
    int64_t pointerOffsets[16];         /* Pointer chain offsets */
    uint32_t pointerCount;              /* Number of pointer offsets */

    /* Value information */
    int32_t valueType;                  /* NexusAddressValueType */
    int64_t setValue;                   /* Value for set/increment/decrement */

    /* Script (for EXECUTE_SCRIPT action) */
    char scriptName[64];                /* Script reference name */

    /* State */
    int32_t isActive;                   /* Current activation state */
} NexusTrainerCheat;

/* Trainer project configuration */
typedef struct NexusTrainerConfig {
    char name[128];                     /* Trainer name */
    char author[64];                    /* Author name */
    char version[32];                   /* Trainer version */
    char targetProcess[260];            /* Target process name */
    char aboutText[1024];               /* About dialog text */

    /* Options */
    int32_t autoAttach;                 /* Auto-attach to target process */
    int32_t closeWithGame;              /* Close trainer when game exits */
    int32_t minimizeToTray;             /* Minimize to system tray */
    int32_t playSounds;                 /* Play sounds on activate/deactivate */
} NexusTrainerConfig;

/** @brief Create a new, empty trainer project. */
NEXUS_API NexusResult Nexus_TrainerCreate(NexusTrainerHandle* trainer);
/** @brief Destroy a trainer project and free its resources. */
NEXUS_API void Nexus_TrainerDestroy(NexusTrainerHandle trainer);
/** @brief Set the trainer configuration (name, author, target process, options). */
NEXUS_API NexusResult Nexus_TrainerSetConfig(NexusTrainerHandle trainer, const NexusTrainerConfig* config);
/** @brief Get the current trainer configuration. */
NEXUS_API NexusResult Nexus_TrainerGetConfig(NexusTrainerHandle trainer, NexusTrainerConfig* config);
/** @brief Add a cheat entry to the trainer. */
NEXUS_API NexusResult Nexus_TrainerAddCheat(NexusTrainerHandle trainer, const NexusTrainerCheat* cheat, uint32_t* id);
/** @brief Remove a cheat entry by ID. */
NEXUS_API NexusResult Nexus_TrainerRemoveCheat(NexusTrainerHandle trainer, uint32_t id);
/** @brief Get the number of cheat entries. */
NEXUS_API NexusResult Nexus_TrainerGetCheatCount(NexusTrainerHandle trainer, size_t* count);
/** @brief Retrieve a cheat entry by index. */
NEXUS_API NexusResult Nexus_TrainerGetCheat(NexusTrainerHandle trainer, size_t index, NexusTrainerCheat* cheat);
/** @brief Register a module name and receive its index for cheat address references. */
NEXUS_API NexusResult Nexus_TrainerAddModule(NexusTrainerHandle trainer, const char* moduleName, int32_t* moduleIndex);
/** @brief Add an Auto-Assembler script with enable and disable sections. */
NEXUS_API NexusResult Nexus_TrainerAddScript(NexusTrainerHandle trainer, const char* name, const char* enableScript, const char* disableScript);
/** @brief Save the trainer project to a JSON file. */
NEXUS_API NexusResult Nexus_TrainerSave(NexusTrainerHandle trainer, const char* path);
/** @brief Load a trainer project from a JSON file. */
NEXUS_API NexusResult Nexus_TrainerLoad(const char* path, NexusTrainerHandle* trainer);
/** @brief Import cheats from a .nst cheat table into this trainer. */
NEXUS_API NexusResult Nexus_TrainerImportFromTable(NexusTrainerHandle trainer, const char* tablePath);
/** @brief Generate standalone C source code for the trainer. */
NEXUS_API NexusResult Nexus_TrainerGenerateSource(NexusTrainerHandle trainer, const char* outputPath);

/* ============================================================================
 * Value Parsing & Formatting (v0.28.0)
 * ============================================================================ */

/** Value format flags for Nexus_FormatValue (distinct from NexusDisplayMethod) */
typedef enum NexusValueFormatFlags {
    NEXUS_FORMAT_DEFAULT = 0,           /* Default format for type */
    NEXUS_FORMAT_HEX = 0x0001,          /* Display as hexadecimal */
    NEXUS_FORMAT_SIGNED = 0x0002,       /* Display signed (for integers) */
    NEXUS_FORMAT_UNSIGNED = 0x0004,     /* Display unsigned (for integers) */
    NEXUS_FORMAT_SCIENTIFIC = 0x0008,   /* Scientific notation (for floats) */
    NEXUS_FORMAT_TRUNCATE = 0x0010      /* Truncate floating point */
} NexusValueFormatFlags;

/**
 * Parse a string value into a scan value.
 * Handles all value types including AOB patterns with wildcards.
 *
 * @param text Input string to parse
 * @param valueType Target value type (NexusScanValueType)
 * @param isHex 1 if input should be interpreted as hexadecimal
 * @param result Output: parsed value
 * @return NEXUS_OK on success, NEXUS_ERROR_INVALID_PARAMETER on parse failure
 */
NEXUS_API NexusResult Nexus_ParseValue(
    const char* text,
    uint32_t valueType,
    int isHex,
    NexusScanValue* result
);

/**
 * Format a value as a display string.
 *
 * @param value Pointer to the value data
 * @param valueType Value type (NexusScanValueType)
 * @param displayFlags Display format flags (NexusValueFormatFlags)
 * @param buffer Output buffer for formatted string
 * @param bufferSize Size of output buffer
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_FormatValue(
    const void* value,
    uint32_t valueType,
    uint32_t displayFlags,
    char* buffer,
    size_t bufferSize
);

/**
 * Get the byte size for a value type.
 *
 * @param valueType Value type (NexusScanValueType)
 * @return Size in bytes (0 for variable-length types like string/AOB)
 */
NEXUS_API size_t Nexus_GetTypeSize(uint32_t valueType);

/**
 * Calculate float tolerance for CE-compatible comparison.
 * Uses the number of decimal places in the input to determine tolerance.
 *
 * @param text Input string (e.g., "1.5" -> 0.05 tolerance)
 * @param tolerance Output: calculated tolerance
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_CalculateFloatTolerance(
    const char* text,
    double* tolerance
);

/* ============================================================================
 * Batch Address Operations (v0.28.0)
 * ============================================================================ */

/** Batch operation entry (for Nexus_BatchReadValues/WriteFrozen) */
typedef struct NexusBatchEntry {
    uint64_t baseAddress;           /* Base address or module+offset resolved address */
    int64_t offsets[16];            /* Pointer offsets (if isPointer) */
    uint32_t offsetCount;           /* Number of offsets (0 = direct address) */
    uint32_t valueType;             /* NexusScanValueType */
    uint32_t isFrozen;              /* 1 if value should be written */
    uint32_t reserved;
    uint8_t frozenValue[32];        /* Value to write if frozen */
} NexusBatchEntry;

/** Result entry for batch read */
typedef struct NexusBatchReadResult {
    uint64_t resolvedAddress;       /* Final resolved address */
    uint8_t value[32];              /* Read value (up to 32 bytes) */
    uint32_t valueSize;             /* Actual size of value */
    int32_t success;                /* 1 if read succeeded */
} NexusBatchReadResult;

/**
 * Batch read values from multiple addresses.
 * Efficiently reads multiple addresses with pointer resolution.
 *
 * @param handle Process handle
 * @param entries Array of batch entries
 * @param count Number of entries
 * @param results Output array for results
 * @return NEXUS_OK if all succeeded, NEXUS_ERROR_PARTIAL_READ if some failed
 */
NEXUS_API NexusResult Nexus_BatchReadValues(
    NexusProcessHandle handle,
    const NexusBatchEntry* entries,
    size_t count,
    NexusBatchReadResult* results
);

/**
 * Batch write frozen values.
 * Efficiently writes values to multiple addresses with pointer resolution.
 *
 * @param handle Process handle
 * @param entries Array of batch entries (only frozen entries are written)
 * @param count Number of entries
 * @param successCount Output: number of successful writes
 * @return NEXUS_OK if all succeeded, NEXUS_ERROR_PARTIAL_WRITE if some failed
 */
NEXUS_API NexusResult Nexus_BatchWriteFrozen(
    NexusProcessHandle handle,
    const NexusBatchEntry* entries,
    size_t count,
    size_t* successCount
);

/* ============================================================================
 * Utility
 * ============================================================================ */

/**
 * Free memory allocated by the engine.
 * @param ptr Pointer to free
 */
NEXUS_API void Nexus_Free(void* ptr);

/**
 * Get a human-readable error message for a result code.
 * @param result Result code
 * @return Static string describing the error
 */
NEXUS_API const char* Nexus_GetErrorString(NexusResult result);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_API_H */
