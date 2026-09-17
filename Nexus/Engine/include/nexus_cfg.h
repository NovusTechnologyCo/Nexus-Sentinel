/**
 * @file nexus_cfg.h
 * @brief Control flow graph (CFG) analysis: basic-block detection and edge construction.
 *
 * Disassembles a function or address range, partitions it into basic blocks,
 * and builds edges (fall-through, conditional, unconditional, call) between
 * them.  Supports predecessor/successor queries and is used by the UI's
 * graph view and static-analysis panels.
 */

#ifndef NEXUS_CFG_H
#define NEXUS_CFG_H

#include "nexus_common.h"
#include "nexus_assembler.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Basic Block Flags
 * ============================================================================ */

typedef enum NexusBBFlags {
    NEXUS_BB_FLAG_NONE = 0,
    NEXUS_BB_FLAG_ENTRY = 0x0001,           /* Function entry point */
    NEXUS_BB_FLAG_EXIT = 0x0002,            /* Function exit (ret/jmp out) */
    NEXUS_BB_FLAG_CALL = 0x0004,            /* Contains a call instruction */
    NEXUS_BB_FLAG_COND_BRANCH = 0x0008,     /* Ends with conditional branch */
    NEXUS_BB_FLAG_UNCOND_BRANCH = 0x0010,   /* Ends with unconditional jump */
    NEXUS_BB_FLAG_INDIRECT = 0x0020,        /* Has indirect control flow */
    NEXUS_BB_FLAG_FALLTHROUGH = 0x0040,     /* Falls through to next block */
    NEXUS_BB_FLAG_LOOP_HEADER = 0x0080,     /* Loop header (back edge target) */
    NEXUS_BB_FLAG_LOOP_TAIL = 0x0100,       /* Loop tail (back edge source) */
    NEXUS_BB_FLAG_EXCEPTION = 0x0200        /* Exception handler */
} NexusBBFlags;

/* ============================================================================
 * CFG Edge Types
 * ============================================================================ */

typedef enum NexusCFGEdgeType {
    NEXUS_EDGE_NORMAL = 0,          /* Normal control flow */
    NEXUS_EDGE_TRUE_BRANCH = 1,     /* Conditional true branch */
    NEXUS_EDGE_FALSE_BRANCH = 2,    /* Conditional false/fallthrough */
    NEXUS_EDGE_CALL = 3,            /* Call edge */
    NEXUS_EDGE_RETURN = 4,          /* Return edge */
    NEXUS_EDGE_EXCEPTION = 5,       /* Exception handler edge */
    NEXUS_EDGE_BACK = 6             /* Back edge (loop) */
} NexusCFGEdgeType;

/* ============================================================================
 * CFG Structures
 * ============================================================================ */

/**
 * Basic block in the control flow graph.
 */
typedef struct NexusBasicBlock {
    uint64_t startAddress;          /* Start address of the block */
    uint64_t endAddress;            /* End address (exclusive) */
    uint32_t flags;                 /* NexusBBFlags */
    uint32_t instructionCount;      /* Number of instructions */
    uint64_t trueTarget;            /* Target for true/unconditional branch */
    uint64_t falseTarget;           /* Target for false/fallthrough */
    uint32_t loopDepth;             /* Nesting level of loops */
    uint32_t blockIndex;            /* Index in block array */
    uint32_t predecessorCount;      /* Number of predecessor blocks */
    uint32_t successorCount;        /* Number of successor blocks */
} NexusBasicBlock;

/**
 * Edge in the control flow graph.
 */
typedef struct NexusCFGEdge {
    uint32_t sourceBlock;           /* Index of source block */
    uint32_t targetBlock;           /* Index of target block */
    uint32_t edgeType;              /* NexusCFGEdgeType */
    uint32_t reserved;              /* Reserved for future use */
} NexusCFGEdge;

/**
 * CFG analysis result.
 */
typedef struct NexusCFGResult {
    uint64_t functionStart;         /* Function entry point */
    uint64_t functionEnd;           /* Function end address */
    uint32_t blockCount;            /* Number of basic blocks */
    uint32_t edgeCount;             /* Number of edges */
    uint32_t instructionCount;      /* Total instructions in function */
    uint32_t maxLoopDepth;          /* Maximum loop nesting depth */
    uint32_t isComplete;            /* 1 if analysis completed */
    uint32_t reserved;              /* Reserved for future use */
} NexusCFGResult;

/* ============================================================================
 * CFG API Functions
 * ============================================================================ */

/**
 * Create a CFG analyzer.
 */
NEXUS_API NexusResult Nexus_CFGCreate(
    NexusProcessHandle process,
    NexusCFGHandle* cfg
);

/**
 * Destroy a CFG analyzer.
 */
NEXUS_API void Nexus_CFGDestroy(NexusCFGHandle cfg);

/**
 * Analyze a function and build its CFG.
 */
NEXUS_API NexusResult Nexus_CFGAnalyze(
    NexusCFGHandle cfg,
    uint64_t entryAddress,
    uint64_t maxSize,
    NexusCFGResult* result
);

/**
 * Get basic blocks from the CFG.
 */
NEXUS_API NexusResult Nexus_CFGGetBlocks(
    NexusCFGHandle cfg,
    NexusBasicBlock* blocks,
    size_t maxBlocks,
    size_t* blockCount
);

/**
 * Get edges from the CFG.
 */
NEXUS_API NexusResult Nexus_CFGGetEdges(
    NexusCFGHandle cfg,
    NexusCFGEdge* edges,
    size_t maxEdges,
    size_t* edgeCount
);

/**
 * Get a specific basic block by address.
 */
NEXUS_API NexusResult Nexus_CFGGetBlockByAddress(
    NexusCFGHandle cfg,
    uint64_t address,
    NexusBasicBlock* block
);

/**
 * Get instructions for a basic block.
 */
NEXUS_API NexusResult Nexus_CFGGetBlockInstructions(
    NexusCFGHandle cfg,
    uint32_t blockIndex,
    NexusDisasmInstruction* instructions,
    size_t maxInstructions,
    size_t* instructionCount
);

/**
 * Get predecessor blocks.
 */
NEXUS_API NexusResult Nexus_CFGGetPredecessors(
    NexusCFGHandle cfg,
    uint32_t blockIndex,
    uint32_t* predecessorIndices,
    size_t maxCount,
    size_t* count
);

/**
 * Get successor blocks.
 */
NEXUS_API NexusResult Nexus_CFGGetSuccessors(
    NexusCFGHandle cfg,
    uint32_t blockIndex,
    uint32_t* successorIndices,
    size_t maxCount,
    size_t* count
);

/**
 * Detect loops in the CFG.
 */
NEXUS_API NexusResult Nexus_CFGDetectLoops(NexusCFGHandle cfg);

/**
 * Export CFG to DOT format for visualization.
 */
NEXUS_API NexusResult Nexus_CFGExportDOT(
    NexusCFGHandle cfg,
    char* buffer,
    size_t bufferSize,
    size_t* written
);

/**
 * Clear the CFG analysis.
 */
NEXUS_API void Nexus_CFGClear(NexusCFGHandle cfg);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_CFG_H */
