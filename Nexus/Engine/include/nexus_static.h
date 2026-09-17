/**
 * @file nexus_static.h
 * @brief Static analysis utilities: hashing, entropy, string extraction, and crypto detection.
 *
 * Compute cryptographic hashes (MD5, SHA-1, SHA-256), measure section entropy,
 * extract embedded strings, and detect common packers and cryptors.
 * Modelled on the TitanEngine static analysis API.
 */

#ifndef NEXUS_STATIC_H
#define NEXUS_STATIC_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Hash Types
 * ============================================================================ */

typedef enum NexusHashType {
    NEXUS_HASH_MD5 = 0,                 /* MD5 (128-bit) */
    NEXUS_HASH_SHA1 = 1,                /* SHA-1 (160-bit) */
    NEXUS_HASH_SHA256 = 2,              /* SHA-256 (256-bit) */
    NEXUS_HASH_SHA512 = 3,              /* SHA-512 (512-bit) */
    NEXUS_HASH_CRC32 = 4,               /* CRC32 */
    NEXUS_HASH_XXHASH64 = 5,            /* xxHash64 */
    NEXUS_HASH_IMPHASH = 6,             /* Import hash (MD5 of imports) */
    NEXUS_HASH_SSDEEP = 7               /* Fuzzy hash */
} NexusHashType;

typedef enum NexusCompressionType {
    NEXUS_COMPRESS_NONE = 0,
    NEXUS_COMPRESS_ZLIB = 1,
    NEXUS_COMPRESS_GZIP = 2,
    NEXUS_COMPRESS_LZMA = 3,
    NEXUS_COMPRESS_LZ4 = 4,
    NEXUS_COMPRESS_ZSTD = 5,
    NEXUS_COMPRESS_APLIB = 6,           /* aPLib */
    NEXUS_COMPRESS_LZNT1 = 7            /* Windows LZNT1 */
} NexusCompressionType;

typedef enum NexusEncryptionType {
    NEXUS_ENCRYPT_NONE = 0,
    NEXUS_ENCRYPT_XOR = 1,              /* Simple XOR */
    NEXUS_ENCRYPT_XOR_KEY = 2,          /* XOR with key */
    NEXUS_ENCRYPT_ROL = 3,              /* Rotate left */
    NEXUS_ENCRYPT_ROR = 4,              /* Rotate right */
    NEXUS_ENCRYPT_ADD = 5,              /* Add constant */
    NEXUS_ENCRYPT_RC4 = 6,              /* RC4 */
    NEXUS_ENCRYPT_AES = 7,              /* AES */
    NEXUS_ENCRYPT_CUSTOM = 255          /* Custom/unknown */
} NexusEncryptionType;

/* ============================================================================
 * Static Analysis Structures
 * ============================================================================ */

typedef struct NexusHashResult {
    uint32_t hashType;                  /* NexusHashType */
    uint32_t hashSize;                  /* Size of hash in bytes */
    uint8_t hash[64];                   /* Hash bytes */
    char hashString[129];               /* Hex string representation */
} NexusHashResult;

typedef struct NexusEntropyInfo {
    double entropy;                     /* Overall entropy (0.0-8.0) */
    double normalizedEntropy;           /* Normalized (0.0-1.0) */
    uint32_t isPacked;                  /* Likely packed (entropy > 7.0) */
    uint32_t isEncrypted;               /* Likely encrypted (entropy > 7.5) */
    uint32_t sectionCount;              /* Sections analyzed */
    uint32_t highEntropyCount;          /* High entropy sections */
} NexusEntropyInfo;

typedef struct NexusSectionEntropy {
    char name[8];                       /* Section name */
    double entropy;                     /* Section entropy */
    double normalizedEntropy;           /* Normalized entropy */
    uint32_t virtualAddress;            /* Section RVA */
    uint32_t virtualSize;               /* Section size */
    uint32_t isHighEntropy;             /* Above threshold */
    uint32_t reserved;
} NexusSectionEntropy;

typedef struct NexusStringInfo {
    uint64_t address;                   /* Address of string */
    uint32_t length;                    /* String length */
    uint32_t isWide;                    /* 1 if Unicode */
    uint32_t encoding;                  /* String encoding */
    uint32_t reserved;
    char preview[256];                  /* String preview (truncated) */
} NexusStringInfo;

typedef struct NexusXrefInfo {
    uint64_t fromAddress;               /* Reference from */
    uint64_t toAddress;                 /* Reference to */
    uint32_t xrefType;                  /* Type (call, jump, data) */
    uint32_t reserved;
} NexusXrefInfo;

/* ============================================================================
 * Hashing
 * ============================================================================ */

/**
 * Hash a buffer.
 */
NEXUS_API NexusResult Nexus_StaticHash(
    const uint8_t* data,
    size_t dataSize,
    uint32_t hashType,
    NexusHashResult* result
);

/**
 * Hash a file.
 */
NEXUS_API NexusResult Nexus_StaticHashFile(
    const wchar_t* filePath,
    uint32_t hashType,
    NexusHashResult* result
);

/**
 * Hash a memory region in process.
 */
NEXUS_API NexusResult Nexus_StaticHashMemory(
    NexusProcessHandle process,
    uint64_t address,
    size_t size,
    uint32_t hashType,
    NexusHashResult* result
);

/**
 * Calculate import hash (ImpHash).
 */
NEXUS_API NexusResult Nexus_StaticCalcImpHash(
    intptr_t peHandle,
    NexusHashResult* result
);

/**
 * Calculate fuzzy hash (ssdeep).
 */
NEXUS_API NexusResult Nexus_StaticCalcFuzzyHash(
    const uint8_t* data,
    size_t dataSize,
    char* hashBuffer,
    size_t bufferSize
);

/**
 * Compare fuzzy hashes (returns similarity 0-100).
 */
NEXUS_API NexusResult Nexus_StaticCompareFuzzyHash(
    const char* hash1,
    const char* hash2,
    uint32_t* similarity
);

/* ============================================================================
 * Entropy Analysis
 * ============================================================================ */

/**
 * Calculate entropy of buffer.
 */
NEXUS_API NexusResult Nexus_StaticCalcEntropy(
    const uint8_t* data,
    size_t dataSize,
    double* entropy
);

/**
 * Get entropy info for PE file.
 */
NEXUS_API NexusResult Nexus_StaticGetEntropy(
    intptr_t peHandle,
    NexusEntropyInfo* info
);

/**
 * Get per-section entropy.
 */
NEXUS_API NexusResult Nexus_StaticGetSectionEntropy(
    intptr_t peHandle,
    NexusSectionEntropy* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Calculate entropy histogram.
 */
NEXUS_API NexusResult Nexus_StaticCalcEntropyHistogram(
    const uint8_t* data,
    size_t dataSize,
    uint32_t* histogram,
    size_t histogramSize
);

/* ============================================================================
 * Decompression
 * ============================================================================ */

/**
 * Detect compression type.
 */
NEXUS_API NexusResult Nexus_StaticDetectCompression(
    const uint8_t* data,
    size_t dataSize,
    uint32_t* compressionType
);

/**
 * Decompress data.
 */
NEXUS_API NexusResult Nexus_StaticDecompress(
    const uint8_t* compressedData,
    size_t compressedSize,
    uint32_t compressionType,
    uint8_t* outputBuffer,
    size_t outputSize,
    size_t* decompressedSize
);

/**
 * Decompress data with auto-detection.
 */
NEXUS_API NexusResult Nexus_StaticDecompressAuto(
    const uint8_t* compressedData,
    size_t compressedSize,
    uint8_t* outputBuffer,
    size_t outputSize,
    size_t* decompressedSize,
    uint32_t* detectedType
);

/**
 * Compress data.
 */
NEXUS_API NexusResult Nexus_StaticCompress(
    const uint8_t* data,
    size_t dataSize,
    uint32_t compressionType,
    uint32_t level,
    uint8_t* outputBuffer,
    size_t outputSize,
    size_t* compressedSize
);

/* ============================================================================
 * Decryption
 * ============================================================================ */

/**
 * Detect encryption type (heuristic).
 */
NEXUS_API NexusResult Nexus_StaticDetectEncryption(
    const uint8_t* data,
    size_t dataSize,
    uint32_t* encryptionType
);

/**
 * XOR decrypt with single byte key.
 */
NEXUS_API NexusResult Nexus_StaticXorDecrypt(
    const uint8_t* data,
    size_t dataSize,
    uint8_t key,
    uint8_t* output
);

/**
 * XOR decrypt with multi-byte key.
 */
NEXUS_API NexusResult Nexus_StaticXorDecryptKey(
    const uint8_t* data,
    size_t dataSize,
    const uint8_t* key,
    size_t keySize,
    uint8_t* output
);

/**
 * Find XOR key (try to detect single-byte key).
 */
NEXUS_API NexusResult Nexus_StaticFindXorKey(
    const uint8_t* data,
    size_t dataSize,
    uint8_t* key,
    uint32_t* confidence
);

/**
 * RC4 decrypt.
 */
NEXUS_API NexusResult Nexus_StaticRc4Decrypt(
    const uint8_t* data,
    size_t dataSize,
    const uint8_t* key,
    size_t keySize,
    uint8_t* output
);

/* ============================================================================
 * String Extraction
 * ============================================================================ */

/**
 * Extract strings from buffer.
 */
NEXUS_API NexusResult Nexus_StaticExtractStrings(
    const uint8_t* data,
    size_t dataSize,
    uint32_t minLength,
    NexusStringInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Extract strings from PE file.
 */
NEXUS_API NexusResult Nexus_StaticExtractStringsFromPe(
    intptr_t peHandle,
    uint32_t minLength,
    NexusStringInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Extract strings from process memory.
 */
NEXUS_API NexusResult Nexus_StaticExtractStringsFromMemory(
    NexusProcessHandle process,
    uint64_t address,
    size_t size,
    uint32_t minLength,
    NexusStringInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/* ============================================================================
 * Cross-Reference Analysis
 * ============================================================================ */

/**
 * Find cross-references to address.
 */
NEXUS_API NexusResult Nexus_StaticFindXrefsTo(
    intptr_t peHandle,
    uint64_t targetRva,
    NexusXrefInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Find cross-references from address.
 */
NEXUS_API NexusResult Nexus_StaticFindXrefsFrom(
    intptr_t peHandle,
    uint64_t sourceRva,
    NexusXrefInfo* buffer,
    size_t bufferCount,
    size_t* count
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_STATIC_H */
