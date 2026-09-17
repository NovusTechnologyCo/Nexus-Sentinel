/**
 * @file nexus_assembler.h
 * @brief Disassembler, symbol handler, and flow-control analysis.
 *
 * Provides x86/x64 instruction disassembly powered by Zydis, including
 * single and multi-instruction decode, process-memory decode, backward/forward
 * navigation, flow-control classification, and branch-prediction evaluation.
 * Also includes a full DbgHelp-based symbol handler with PDB loading,
 * symbol servers, user-defined symbols, and source-line resolution.
 * Thread-safe disassembler contexts are available for concurrent use.
 */

#ifndef NEXUS_ASSEMBLER_H
#define NEXUS_ASSEMBLER_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Disassembler Types
 * ============================================================================ */

/* Machine modes for disassembly */
typedef enum NexusMachineMode {
    NEXUS_MODE_LONG_64 = 0,      /* 64-bit mode */
    NEXUS_MODE_LONG_COMPAT_32,   /* 32-bit compatibility mode */
    NEXUS_MODE_LONG_COMPAT_16,   /* 16-bit compatibility mode */
    NEXUS_MODE_LEGACY_32,        /* 32-bit legacy mode */
    NEXUS_MODE_LEGACY_16,        /* 16-bit legacy mode */
    NEXUS_MODE_REAL_16           /* Real mode (16-bit) */
} NexusMachineMode;

/* Disassembly syntax style */
typedef enum NexusDisasmSyntax {
    NEXUS_SYNTAX_INTEL = 0,      /* Intel syntax (default) */
    NEXUS_SYNTAX_ATT             /* AT&T syntax */
} NexusDisasmSyntax;

/* Operand types */
typedef enum NexusOperandType {
    NEXUS_OPERAND_UNUSED = 0,
    NEXUS_OPERAND_REGISTER,
    NEXUS_OPERAND_MEMORY,
    NEXUS_OPERAND_POINTER,
    NEXUS_OPERAND_IMMEDIATE
} NexusOperandType;

/* Disassembled instruction operand */
typedef struct NexusDisasmOperand {
    uint32_t type;               /* NexusOperandType */
    uint32_t size;               /* Operand size in bits */
    union {
        struct {
            uint16_t id;         /* Register ID */
        } reg;
        struct {
            uint16_t segment;    /* Segment register (0 if none) */
            uint16_t base;       /* Base register (0 if none) */
            uint16_t index;      /* Index register (0 if none) */
            uint8_t scale;       /* Scale factor (1, 2, 4, 8) */
            int64_t disp;        /* Displacement */
            uint8_t hasDisp;     /* Has displacement */
        } mem;
        struct {
            uint64_t value;      /* Immediate value */
            uint8_t isSigned;    /* Is signed value */
            uint8_t isRelative;  /* Is relative (for branches) */
        } imm;
    };
} NexusDisasmOperand;

/* Disassembled instruction */
typedef struct NexusDisasmInstruction {
    uint64_t address;            /* Runtime address */
    uint8_t length;              /* Instruction length in bytes */
    uint8_t bytes[15];           /* Raw instruction bytes */
    char mnemonic[32];           /* Instruction mnemonic */
    char text[128];              /* Full formatted instruction text */
    uint8_t operandCount;        /* Number of operands */
    NexusDisasmOperand operands[5]; /* Operands (max 5) */
    uint64_t branchTarget;       /* Branch target address (0 if not a branch) */
    uint32_t isBranch;           /* Is a branch instruction */
    uint32_t isCall;             /* Is a call instruction */
    uint32_t isReturn;           /* Is a return instruction */
    uint32_t isConditional;      /* Is conditional */
} NexusDisasmInstruction;

/* ============================================================================
 * Symbol Handler Types
 * ============================================================================ */

/** Opaque handle for symbol handler */
typedef struct NexusSymbolHandler* NexusSymbolHandle;

/** Symbol search options */
typedef enum NexusSymbolOptions {
    NEXUS_SYM_NONE = 0,
    NEXUS_SYM_UNDNAME = 0x0001,           /* Undecorate C++ names */
    NEXUS_SYM_DEFERRED_LOADS = 0x0002,    /* Defer symbol loading */
    NEXUS_SYM_LOAD_LINES = 0x0004,        /* Load line number info */
    NEXUS_SYM_LOAD_ANYTHING = 0x0008,     /* Load any symbol type */
    NEXUS_SYM_PUBLICS_ONLY = 0x0010,      /* Only public symbols */
    NEXUS_SYM_NO_PUBLICS = 0x0020,        /* Skip public symbols */
    NEXUS_SYM_AUTO_PUBLICS = 0x0040,      /* Automatic public fallback */
    NEXUS_SYM_INCLUDE_32BIT = 0x0080      /* Include 32-bit modules */
} NexusSymbolOptions;

/** Debug symbol types (DbgHelp) */
typedef enum NexusDbgSymbolType {
    NEXUS_DBGSYM_NONE = 0,
    NEXUS_DBGSYM_EXPORT,                 /* PE export */
    NEXUS_DBGSYM_PDB,                    /* PDB symbol */
    NEXUS_DBGSYM_COFF,                   /* COFF symbol */
    NEXUS_DBGSYM_CV,                     /* CodeView */
    NEXUS_DBGSYM_SYM,                    /* .SYM file */
    NEXUS_DBGSYM_VIRTUAL,                /* Virtual symbol (manually added) */
    NEXUS_DBGSYM_DIA                     /* DIA SDK */
} NexusDbgSymbolType;

/** Symbol information */
typedef struct NexusSymbolInfo {
    uint64_t address;                     /* Symbol address */
    uint64_t size;                        /* Symbol size (if known) */
    uint32_t flags;                       /* Symbol flags */
    uint32_t tag;                         /* Symbol tag (function, data, etc.) */
    NexusDbgSymbolType type;              /* Symbol type */
    char name[512];                       /* Symbol name */
    char undecoratedName[512];            /* Undecorated name (C++) */
    char moduleName[260];                 /* Module name */
    uint64_t moduleBase;                  /* Module base address */
} NexusSymbolInfo;

/** Line number information */
typedef struct NexusLineInfo {
    uint64_t address;                     /* Address */
    uint32_t lineNumber;                  /* Line number */
    char fileName[260];                   /* Source file name */
} NexusLineInfo;

/** Module symbol status */
typedef struct NexusModuleSymbolInfo {
    uint64_t baseAddress;                 /* Module base */
    uint64_t imageSize;                   /* Module size */
    uint32_t timeDateStamp;               /* PE timestamp */
    uint32_t checkSum;                    /* PE checksum */
    uint32_t numSymbols;                  /* Number of symbols loaded */
    NexusDbgSymbolType symType;           /* Symbol type loaded */
    char moduleName[260];                 /* Module name */
    char imageName[260];                  /* Image path */
    char loadedImageName[260];            /* Loaded image path */
    char loadedPdbName[260];              /* Loaded PDB path */
    uint32_t pdbAge;                      /* PDB age */
    uint8_t pdbGuid[16];                  /* PDB GUID */
    int32_t symbolsLoaded;                /* 1 if symbols loaded */
} NexusModuleSymbolInfo;

/* ============================================================================
 * Disassembler Context (Thread-Safe) v0.24.0
 * ============================================================================ */

/** Opaque handle for thread-safe disassembler context */
typedef struct NexusDisasmContext* NexusDisasmContextHandle;

/** Flow control types for instruction analysis */
typedef enum NexusFlowControlType {
    NEXUS_FLOW_NONE = 0,             /* No flow control (sequential) */
    NEXUS_FLOW_UNCONDITIONAL_JMP,    /* Unconditional jump (jmp) */
    NEXUS_FLOW_CONDITIONAL_JMP,      /* Conditional jump (jcc) */
    NEXUS_FLOW_CALL,                 /* Call instruction */
    NEXUS_FLOW_RET,                  /* Return instruction */
    NEXUS_FLOW_IRET,                 /* Interrupt return */
    NEXUS_FLOW_SYSCALL,              /* Syscall/sysenter */
    NEXUS_FLOW_SYSRET,               /* Sysret/sysexit */
    NEXUS_FLOW_INT,                  /* Software interrupt */
    NEXUS_FLOW_LOOP,                 /* Loop instruction */
    NEXUS_FLOW_XBEGIN,               /* Transaction begin */
    NEXUS_FLOW_XABORT,               /* Transaction abort */
    NEXUS_FLOW_EXCEPTION             /* Instruction may cause exception */
} NexusFlowControlType;

/** Extended flow control information */
typedef struct NexusFlowControlInfo {
    NexusFlowControlType type;       /* Flow control type */
    uint32_t isConditional;          /* 1 if conditional */
    uint32_t isIndirect;             /* 1 if target is indirect (register/memory) */
    uint64_t targetAddress;          /* Target address (0 if indirect) */
    uint64_t fallthrough;            /* Fallthrough address (next instruction) */
    uint32_t conditionCode;          /* Condition code (for conditional) */
    uint32_t reserved;
} NexusFlowControlInfo;

/** Branch prediction result */
typedef enum NexusBranchPrediction {
    NEXUS_BRANCH_UNKNOWN = 0,        /* Cannot determine */
    NEXUS_BRANCH_TAKEN,              /* Branch will be taken */
    NEXUS_BRANCH_NOT_TAKEN,          /* Branch will not be taken */
    NEXUS_BRANCH_ALWAYS,             /* Unconditional - always taken */
    NEXUS_BRANCH_NEVER               /* Invalid/never taken */
} NexusBranchPrediction;

/* ============================================================================
 * Disassembler API
 * ============================================================================ */

/**
 * Disassemble a single instruction.
 *
 * @param mode Machine mode (32-bit, 64-bit, etc.)
 * @param address Runtime address of the instruction
 * @param buffer Pointer to instruction bytes
 * @param bufferSize Size of buffer
 * @param instruction Output: disassembled instruction
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DisasmDecode(
    NexusMachineMode mode,
    uint64_t address,
    const void* buffer,
    size_t bufferSize,
    NexusDisasmInstruction* instruction
);

/**
 * Disassemble multiple instructions.
 *
 * @param mode Machine mode
 * @param address Starting runtime address
 * @param buffer Pointer to instruction bytes
 * @param bufferSize Size of buffer
 * @param maxInstructions Maximum instructions to disassemble
 * @param instructions Output array of instructions
 * @param instructionCount Output: number of instructions disassembled
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DisasmDecodeMultiple(
    NexusMachineMode mode,
    uint64_t address,
    const void* buffer,
    size_t bufferSize,
    size_t maxInstructions,
    NexusDisasmInstruction* instructions,
    size_t* instructionCount
);

/**
 * Disassemble from a process's memory.
 *
 * @param process Process handle
 * @param address Address to disassemble from
 * @param maxInstructions Maximum instructions to disassemble
 * @param instructions Output array of instructions
 * @param instructionCount Output: number of instructions disassembled
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DisasmDecodeProcess(
    NexusProcessHandle process,
    uint64_t address,
    size_t maxInstructions,
    NexusDisasmInstruction* instructions,
    size_t* instructionCount
);

/**
 * Set disassembly syntax style (Intel or AT&T).
 *
 * @param syntax Syntax style
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DisasmSetSyntax(
    NexusDisasmSyntax syntax
);

/**
 * Get register name from register ID.
 *
 * @param regId Register ID
 * @return Static string with register name, or NULL if invalid
 */
NEXUS_API const char* Nexus_DisasmGetRegisterName(
    uint16_t regId
);

/**
 * Find the start of an instruction at or before the given address (x64dbg pattern).
 * Useful for backward navigation in disassembly views.
 *
 * @param process Process handle
 * @param address Address to search backwards from
 * @param count Number of instructions to go backwards
 * @param resultAddress Output: address of the instruction 'count' instructions before
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DisasmBack(
    NexusProcessHandle process,
    uint64_t address,
    int count,
    uint64_t* resultAddress
);

/**
 * Find the address of the next instruction (x64dbg pattern).
 * Useful for forward navigation in disassembly views.
 *
 * @param process Process handle
 * @param address Current address
 * @param count Number of instructions to go forward
 * @param resultAddress Output: address of the instruction 'count' instructions after
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DisasmNext(
    NexusProcessHandle process,
    uint64_t address,
    int count,
    uint64_t* resultAddress
);

/**
 * Fast disassembly for UI responsiveness (lightweight output).
 * Returns only essential info without full formatting.
 *
 * @param process Process handle
 * @param address Address to disassemble
 * @param length Output: instruction length
 * @param isBranch Output: is branch/jump (optional, can be NULL)
 * @param isCall Output: is call (optional, can be NULL)
 * @param isReturn Output: is return (optional, can be NULL)
 * @param branchTarget Output: branch target if branch/call (optional, can be NULL)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DisasmFast(
    NexusProcessHandle process,
    uint64_t address,
    uint8_t* length,
    int* isBranch,
    int* isCall,
    int* isReturn,
    uint64_t* branchTarget
);

/* ============================================================================
 * Thread-Safe Disassembler Context API (v0.24.0)
 * ============================================================================ */

/**
 * Create a thread-safe disassembler context.
 * Each thread should have its own context to avoid synchronization overhead.
 *
 * @param mode Machine mode for disassembly
 * @param syntax Syntax style (Intel or AT&T)
 * @param context Output: disassembler context handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DisasmCreateContext(
    NexusMachineMode mode,
    NexusDisasmSyntax syntax,
    NexusDisasmContextHandle* context
);

/**
 * Destroy a disassembler context.
 *
 * @param context Disassembler context handle
 */
NEXUS_API void Nexus_DisasmDestroyContext(
    NexusDisasmContextHandle context
);

/**
 * Disassemble using a thread-safe context.
 *
 * @param context Disassembler context
 * @param address Runtime address
 * @param buffer Instruction bytes
 * @param bufferSize Buffer size
 * @param instruction Output: disassembled instruction
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DisasmDecodeWithContext(
    NexusDisasmContextHandle context,
    uint64_t address,
    const void* buffer,
    size_t bufferSize,
    NexusDisasmInstruction* instruction
);

/**
 * Get flow control information for an instruction.
 * Provides detailed analysis of how the instruction affects control flow.
 *
 * @param context Disassembler context (optional, can be NULL for global state)
 * @param address Runtime address
 * @param buffer Instruction bytes
 * @param bufferSize Buffer size
 * @param flowInfo Output: flow control information
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DisasmGetFlowControl(
    NexusDisasmContextHandle context,
    uint64_t address,
    const void* buffer,
    size_t bufferSize,
    NexusFlowControlInfo* flowInfo
);

/**
 * Predict whether a conditional branch will be taken based on flags register.
 * Useful for debugger stepping and trace analysis.
 *
 * @param instruction Disassembled instruction (must be a conditional branch)
 * @param rflags Current RFLAGS/EFLAGS register value
 * @param rcx Current RCX/ECX value (for LOOP instructions)
 * @param prediction Output: branch prediction result
 * @return NEXUS_OK on success, NEXUS_ERROR_INVALID_PARAMETER if not a branch
 */
NEXUS_API NexusResult Nexus_DisasmWillBranchExecute(
    const NexusDisasmInstruction* instruction,
    uint64_t rflags,
    uint64_t rcx,
    NexusBranchPrediction* prediction
);

/**
 * Get flow control info from an already-disassembled instruction.
 *
 * @param instruction Disassembled instruction
 * @param flowInfo Output: flow control information
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_DisasmGetFlowControlFromInstruction(
    const NexusDisasmInstruction* instruction,
    NexusFlowControlInfo* flowInfo
);

/* ============================================================================
 * Symbol Handler API
 * ============================================================================ */

/**
 * Create a symbol handler for a process.
 *
 * @param process Process handle
 * @param options Symbol options
 * @param handler Output: symbol handler
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolCreate(
    NexusProcessHandle process,
    uint32_t options,
    NexusSymbolHandle* handler
);

/**
 * Destroy a symbol handler.
 *
 * @param handler Symbol handler
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolDestroy(
    NexusSymbolHandle handler
);

/**
 * Set symbol search path.
 *
 * @param handler Symbol handler
 * @param searchPath Search path (semicolon separated)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolSetSearchPath(
    NexusSymbolHandle handler,
    const char* searchPath
);

/**
 * Get current symbol search path.
 *
 * @param handler Symbol handler
 * @param buffer Output buffer
 * @param bufferSize Buffer size
 * @param length Output: actual length
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolGetSearchPath(
    NexusSymbolHandle handler,
    char* buffer,
    size_t bufferSize,
    size_t* length
);

/**
 * Add a symbol server to the search path.
 *
 * @param handler Symbol handler
 * @param serverUrl Symbol server URL (e.g., "https://msdl.microsoft.com/download/symbols")
 * @param cacheDir Local cache directory
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolAddServer(
    NexusSymbolHandle handler,
    const char* serverUrl,
    const char* cacheDir
);

/**
 * Load symbols for a module.
 *
 * @param handler Symbol handler
 * @param moduleBase Module base address
 * @param moduleSize Module size
 * @param moduleName Module name (optional, can be NULL)
 * @param imagePath Image path (optional, can be NULL)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolLoadModule(
    NexusSymbolHandle handler,
    uint64_t moduleBase,
    uint32_t moduleSize,
    const char* moduleName,
    const char* imagePath
);

/**
 * Unload symbols for a module.
 *
 * @param handler Symbol handler
 * @param moduleBase Module base address
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolUnloadModule(
    NexusSymbolHandle handler,
    uint64_t moduleBase
);

/**
 * Load symbols for all modules in the process.
 *
 * @param handler Symbol handler
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolLoadAll(
    NexusSymbolHandle handler
);

/**
 * Get symbol from address.
 *
 * @param handler Symbol handler
 * @param address Address to look up
 * @param symbol Output: symbol info
 * @param displacement Output: displacement from symbol (optional, can be NULL)
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if no symbol
 */
NEXUS_API NexusResult Nexus_SymbolFromAddress(
    NexusSymbolHandle handler,
    uint64_t address,
    NexusSymbolInfo* symbol,
    uint64_t* displacement
);

/**
 * Get address from symbol name.
 *
 * @param handler Symbol handler
 * @param name Symbol name (can include module: "ntdll!NtQueryInformationProcess")
 * @param symbol Output: symbol info
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if no symbol
 */
NEXUS_API NexusResult Nexus_SymbolFromName(
    NexusSymbolHandle handler,
    const char* name,
    NexusSymbolInfo* symbol
);

/**
 * Enumerate symbols matching a pattern.
 *
 * @param handler Symbol handler
 * @param mask Pattern mask (e.g., "ntdll!*", "*!*Query*")
 * @param symbols Output array
 * @param maxSymbols Maximum symbols to return
 * @param symbolCount Output: number of symbols found
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolEnumerate(
    NexusSymbolHandle handler,
    const char* mask,
    NexusSymbolInfo* symbols,
    size_t maxSymbols,
    size_t* symbolCount
);

/**
 * Get line information for an address.
 *
 * @param handler Symbol handler
 * @param address Address
 * @param line Output: line info
 * @param displacement Output: displacement from line (optional)
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if no line info
 */
NEXUS_API NexusResult Nexus_SymbolGetLineFromAddress(
    NexusSymbolHandle handler,
    uint64_t address,
    NexusLineInfo* line,
    uint32_t* displacement
);

/**
 * Get address from source file and line.
 *
 * @param handler Symbol handler
 * @param fileName Source file name
 * @param lineNumber Line number
 * @param address Output: address
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolGetAddressFromLine(
    NexusSymbolHandle handler,
    const char* fileName,
    uint32_t lineNumber,
    uint64_t* address
);

/**
 * Get module symbol information.
 *
 * @param handler Symbol handler
 * @param moduleBase Module base address
 * @param info Output: module symbol info
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolGetModuleInfo(
    NexusSymbolHandle handler,
    uint64_t moduleBase,
    NexusModuleSymbolInfo* info
);

/**
 * Undecorate a C++ symbol name.
 *
 * @param decoratedName Decorated name
 * @param buffer Output buffer
 * @param bufferSize Buffer size
 * @param flags Undecoration flags
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolUndecorate(
    const char* decoratedName,
    char* buffer,
    size_t bufferSize,
    uint32_t flags
);

/**
 * Refresh symbols (reload from disk).
 *
 * @param handler Symbol handler
 * @param moduleBase Module base (0 for all modules)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolRefresh(
    NexusSymbolHandle handler,
    uint64_t moduleBase
);

/* ============================================================================
 * User-Defined Symbols (v0.24.0)
 * ============================================================================ */

/**
 * Add a user-defined symbol.
 * User symbols take precedence over auto-loaded symbols for address lookups.
 *
 * @param handler Symbol handler
 * @param name Symbol name
 * @param address Symbol address
 * @param size Symbol size (0 if unknown)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolAddUserDefined(
    NexusSymbolHandle handler,
    const char* name,
    uint64_t address,
    uint64_t size
);

/**
 * Remove a user-defined symbol.
 *
 * @param handler Symbol handler
 * @param name Symbol name
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if symbol doesn't exist
 */
NEXUS_API NexusResult Nexus_SymbolRemoveUserDefined(
    NexusSymbolHandle handler,
    const char* name
);

/**
 * Remove a user-defined symbol by address.
 *
 * @param handler Symbol handler
 * @param address Symbol address
 * @return NEXUS_OK on success, NEXUS_ERROR_NOT_FOUND if symbol doesn't exist
 */
NEXUS_API NexusResult Nexus_SymbolRemoveUserDefinedByAddress(
    NexusSymbolHandle handler,
    uint64_t address
);

/**
 * Clear all user-defined symbols.
 *
 * @param handler Symbol handler
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolClearUserDefined(
    NexusSymbolHandle handler
);

/**
 * Get all user-defined symbols.
 *
 * @param handler Symbol handler
 * @param symbols Output array
 * @param maxSymbols Maximum symbols to return
 * @param symbolCount Output: number of symbols
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_SymbolGetUserDefined(
    NexusSymbolHandle handler,
    NexusSymbolInfo* symbols,
    size_t maxSymbols,
    size_t* symbolCount
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_ASSEMBLER_H */
