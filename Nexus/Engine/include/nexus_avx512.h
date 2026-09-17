/**
 * @file nexus_avx512.h
 * @brief AVX-512 extended register context support.
 *
 * Detection of AVX-512 capability and reading/writing of ZMM/opmask
 * registers via XSAVE area manipulation.  Used by the debugger to
 * display the full SIMD register state on supported processors.
 */

#ifndef NEXUS_AVX512_H
#define NEXUS_AVX512_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * AVX-512 Constants
 * ============================================================================ */

#define NEXUS_ZMM_COUNT         32      /* Number of ZMM registers */
#define NEXUS_ZMM_SIZE          64      /* Size of each ZMM register (512 bits) */
#define NEXUS_YMM_SIZE          32      /* Size of YMM (256 bits) */
#define NEXUS_XMM_SIZE          16      /* Size of XMM (128 bits) */
#define NEXUS_OPMASK_COUNT      8       /* Number of opmask registers (k0-k7) */

/* ============================================================================
 * AVX-512 Structures
 * ============================================================================ */

typedef struct NexusZmmRegister {
    uint8_t bytes[64];                  /* 512-bit ZMM register */
} NexusZmmRegister;

typedef struct NexusAvx512Context {
    /* ZMM registers (ZMM0-ZMM31) */
    NexusZmmRegister zmm[32];

    /* Opmask registers (k0-k7) */
    uint64_t opmask[8];

    /* Control registers */
    uint32_t mxcsr;                     /* MXCSR register */
    uint32_t mxcsrMask;                 /* MXCSR mask */

    /* Status */
    uint32_t hasAvx512;                 /* 1 if AVX-512 is available */
    uint32_t hasAvx512F;                /* Foundation */
    uint32_t hasAvx512Dq;               /* Doubleword/Quadword */
    uint32_t hasAvx512Ifma;             /* Integer Fused Multiply-Add */
    uint32_t hasAvx512Pf;               /* Prefetch */
    uint32_t hasAvx512Er;               /* Exponential and Reciprocal */
    uint32_t hasAvx512Cd;               /* Conflict Detection */
    uint32_t hasAvx512Bw;               /* Byte/Word */
    uint32_t hasAvx512Vl;               /* Vector Length Extensions */
    uint32_t reserved[7];
} NexusAvx512Context;

typedef struct NexusSimdContext {
    /* Legacy x87 FPU state */
    uint8_t fpuState[512];

    /* XMM registers (XMM0-XMM15) */
    uint8_t xmm[16][16];

    /* YMM registers upper halves (YMM0-YMM15) */
    uint8_t ymmHigh[16][16];

    /* AVX-512 state (if available) */
    NexusAvx512Context avx512;

    /* What state is valid */
    uint32_t hasX87;
    uint32_t hasXmm;
    uint32_t hasYmm;
    uint32_t hasZmm;
} NexusSimdContext;

/* ============================================================================
 * AVX-512 Detection
 * ============================================================================ */

/**
 * Check if CPU supports AVX-512.
 */
NEXUS_API NexusResult Nexus_Avx512IsSupported(
    uint32_t* isSupported
);

/**
 * Get AVX-512 feature flags.
 */
NEXUS_API NexusResult Nexus_Avx512GetFeatures(
    NexusAvx512Context* context
);

/**
 * Check if OS supports AVX-512 state saving.
 */
NEXUS_API NexusResult Nexus_Avx512IsOsSupported(
    uint32_t* isSupported
);

/* ============================================================================
 * AVX-512 Context Operations
 * ============================================================================ */

/**
 * Get AVX-512 context for thread.
 */
NEXUS_API NexusResult Nexus_Avx512GetContext(
    NexusProcessHandle process,
    uint32_t threadId,
    NexusAvx512Context* context
);

/**
 * Set AVX-512 context for thread.
 */
NEXUS_API NexusResult Nexus_Avx512SetContext(
    NexusProcessHandle process,
    uint32_t threadId,
    const NexusAvx512Context* context
);

/**
 * Get single ZMM register.
 */
NEXUS_API NexusResult Nexus_Avx512GetZmm(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t regIndex,
    NexusZmmRegister* value
);

/**
 * Set single ZMM register.
 */
NEXUS_API NexusResult Nexus_Avx512SetZmm(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t regIndex,
    const NexusZmmRegister* value
);

/**
 * Get opmask register.
 */
NEXUS_API NexusResult Nexus_Avx512GetOpmask(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t regIndex,
    uint64_t* value
);

/**
 * Set opmask register.
 */
NEXUS_API NexusResult Nexus_Avx512SetOpmask(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t regIndex,
    uint64_t value
);

/* ============================================================================
 * Full SIMD Context
 * ============================================================================ */

/**
 * Get full SIMD context (x87, XMM, YMM, ZMM).
 */
NEXUS_API NexusResult Nexus_SimdGetContext(
    NexusProcessHandle process,
    uint32_t threadId,
    NexusSimdContext* context
);

/**
 * Set full SIMD context.
 */
NEXUS_API NexusResult Nexus_SimdSetContext(
    NexusProcessHandle process,
    uint32_t threadId,
    const NexusSimdContext* context
);

/**
 * Get XMM register.
 */
NEXUS_API NexusResult Nexus_SimdGetXmm(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t regIndex,
    uint8_t* value
);

/**
 * Set XMM register.
 */
NEXUS_API NexusResult Nexus_SimdSetXmm(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t regIndex,
    const uint8_t* value
);

/**
 * Get YMM register.
 */
NEXUS_API NexusResult Nexus_SimdGetYmm(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t regIndex,
    uint8_t* value
);

/**
 * Set YMM register.
 */
NEXUS_API NexusResult Nexus_SimdSetYmm(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t regIndex,
    const uint8_t* value
);

/* ============================================================================
 * MXCSR Operations
 * ============================================================================ */

/**
 * Get MXCSR register.
 */
NEXUS_API NexusResult Nexus_SimdGetMxcsr(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t* mxcsr
);

/**
 * Set MXCSR register.
 */
NEXUS_API NexusResult Nexus_SimdSetMxcsr(
    NexusProcessHandle process,
    uint32_t threadId,
    uint32_t mxcsr
);

/**
 * Parse MXCSR flags to string.
 */
NEXUS_API NexusResult Nexus_SimdMxcsrToString(
    uint32_t mxcsr,
    char* buffer,
    size_t bufferSize
);

/* ============================================================================
 * Register Formatting
 * ============================================================================ */

/**
 * Format ZMM register as string.
 */
NEXUS_API NexusResult Nexus_Avx512FormatZmm(
    const NexusZmmRegister* reg,
    uint32_t format,
    char* buffer,
    size_t bufferSize
);

/**
 * Parse string to ZMM register.
 */
NEXUS_API NexusResult Nexus_Avx512ParseZmm(
    const char* str,
    uint32_t format,
    NexusZmmRegister* reg
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_AVX512_H */
