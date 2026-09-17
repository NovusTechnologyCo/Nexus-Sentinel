/**
 * @file nexus_pemanip.h
 * @brief Low-level PE file manipulation, section management, and header editing.
 *
 * Open, create, and modify PE files on disk: add/remove/resize sections,
 * edit headers, realign the file, and validate PE structure.
 * Modelled on the TitanEngine PE manipulation API.
 */

#ifndef NEXUS_PEMANIP_H
#define NEXUS_PEMANIP_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * PE Manipulation Enums
 * ============================================================================ */

typedef enum NexusPeSectionFlags {
    NEXUS_SECTION_CODE = 0x20,                  /* Contains code */
    NEXUS_SECTION_INITIALIZED = 0x40,           /* Contains initialized data */
    NEXUS_SECTION_UNINITIALIZED = 0x80,         /* Contains uninitialized data */
    NEXUS_SECTION_DISCARDABLE = 0x02000000,     /* Can be discarded */
    NEXUS_SECTION_NOT_CACHED = 0x04000000,      /* Cannot be cached */
    NEXUS_SECTION_NOT_PAGED = 0x08000000,       /* Cannot be paged */
    NEXUS_SECTION_SHARED = 0x10000000,          /* Can be shared */
    NEXUS_SECTION_EXECUTE = 0x20000000,         /* Can be executed */
    NEXUS_SECTION_READ = 0x40000000,            /* Can be read */
    NEXUS_SECTION_WRITE = 0x80000000            /* Can be written */
} NexusPeSectionFlags;

typedef enum NexusPeDataDirectory {
    NEXUS_DIR_EXPORT = 0,
    NEXUS_DIR_IMPORT = 1,
    NEXUS_DIR_RESOURCE = 2,
    NEXUS_DIR_EXCEPTION = 3,
    NEXUS_DIR_SECURITY = 4,
    NEXUS_DIR_BASERELOC = 5,
    NEXUS_DIR_DEBUG = 6,
    NEXUS_DIR_ARCHITECTURE = 7,
    NEXUS_DIR_GLOBALPTR = 8,
    NEXUS_DIR_TLS = 9,
    NEXUS_DIR_LOAD_CONFIG = 10,
    NEXUS_DIR_BOUND_IMPORT = 11,
    NEXUS_DIR_IAT = 12,
    NEXUS_DIR_DELAY_IMPORT = 13,
    NEXUS_DIR_CLR = 14,
    NEXUS_DIR_RESERVED = 15
} NexusPeDataDirectory;

/* ============================================================================
 * PE Structures
 * ============================================================================ */

typedef struct NexusPeSectionInfo {
    char name[8];                       /* Section name */
    uint32_t virtualSize;               /* Virtual size */
    uint32_t virtualAddress;            /* RVA */
    uint32_t rawSize;                   /* Size of raw data */
    uint32_t rawAddress;                /* Pointer to raw data */
    uint32_t characteristics;           /* Section flags */
    uint32_t index;                     /* Section index */
    uint32_t reserved;
} NexusPeSectionInfo;

typedef struct NexusPeDataDirInfo {
    uint32_t virtualAddress;            /* RVA of directory */
    uint32_t size;                      /* Size of directory */
    uint32_t isPresent;                 /* 1 if directory exists */
    uint32_t reserved;
} NexusPeDataDirInfo;

typedef struct NexusPeOverlayInfo {
    uint64_t offset;                    /* Offset in file */
    uint64_t size;                      /* Size of overlay */
    uint32_t isPresent;                 /* 1 if overlay exists */
    uint32_t reserved;
} NexusPeOverlayInfo;

/* ============================================================================
 * PE File Operations
 * ============================================================================ */

/**
 * Open a PE file for manipulation.
 */
NEXUS_API NexusResult Nexus_PeOpen(
    const wchar_t* filePath,
    intptr_t* peHandle
);

/**
 * Close a PE file handle.
 */
NEXUS_API void Nexus_PeClose(intptr_t peHandle);

/**
 * Save changes to PE file.
 */
NEXUS_API NexusResult Nexus_PeSave(
    intptr_t peHandle,
    const wchar_t* outputPath
);

/* ============================================================================
 * Header Access
 * ============================================================================ */

/**
 * Get PE header field value.
 */
NEXUS_API NexusResult Nexus_PeGetHeaderField(
    intptr_t peHandle,
    const char* fieldName,
    uint64_t* value
);

/**
 * Set PE header field value.
 */
NEXUS_API NexusResult Nexus_PeSetHeaderField(
    intptr_t peHandle,
    const char* fieldName,
    uint64_t value
);

/**
 * Get entry point RVA.
 */
NEXUS_API NexusResult Nexus_PeGetEntryPoint(
    intptr_t peHandle,
    uint64_t* entryPoint
);

/**
 * Set entry point RVA.
 */
NEXUS_API NexusResult Nexus_PeSetEntryPoint(
    intptr_t peHandle,
    uint64_t entryPoint
);

/**
 * Get image base.
 */
NEXUS_API NexusResult Nexus_PeGetImageBase(
    intptr_t peHandle,
    uint64_t* imageBase
);

/**
 * Set image base.
 */
NEXUS_API NexusResult Nexus_PeSetImageBase(
    intptr_t peHandle,
    uint64_t imageBase
);

/* ============================================================================
 * Section Management
 * ============================================================================ */

/**
 * Get number of sections.
 */
NEXUS_API NexusResult Nexus_PeGetSectionCount(
    intptr_t peHandle,
    uint32_t* count
);

/**
 * Get section information by index.
 */
NEXUS_API NexusResult Nexus_PeGetSection(
    intptr_t peHandle,
    uint32_t index,
    NexusPeSectionInfo* info
);

/**
 * Get section information by name.
 */
NEXUS_API NexusResult Nexus_PeGetSectionByName(
    intptr_t peHandle,
    const char* name,
    NexusPeSectionInfo* info
);

/**
 * Get section containing RVA.
 */
NEXUS_API NexusResult Nexus_PeGetSectionByRva(
    intptr_t peHandle,
    uint32_t rva,
    NexusPeSectionInfo* info
);

/**
 * Add a new section.
 */
NEXUS_API NexusResult Nexus_PeAddSection(
    intptr_t peHandle,
    const char* name,
    uint32_t virtualSize,
    uint32_t characteristics,
    uint32_t* sectionIndex
);

/**
 * Add a new section with data.
 */
NEXUS_API NexusResult Nexus_PeAddSectionWithData(
    intptr_t peHandle,
    const char* name,
    const uint8_t* data,
    size_t dataSize,
    uint32_t characteristics,
    uint32_t* sectionIndex
);

/**
 * Delete a section.
 */
NEXUS_API NexusResult Nexus_PeDeleteSection(
    intptr_t peHandle,
    uint32_t index
);

/**
 * Rename a section.
 */
NEXUS_API NexusResult Nexus_PeRenameSection(
    intptr_t peHandle,
    uint32_t index,
    const char* newName
);

/**
 * Resize a section.
 */
NEXUS_API NexusResult Nexus_PeResizeSection(
    intptr_t peHandle,
    uint32_t index,
    uint32_t newVirtualSize,
    uint32_t newRawSize
);

/**
 * Set section characteristics.
 */
NEXUS_API NexusResult Nexus_PeSetSectionFlags(
    intptr_t peHandle,
    uint32_t index,
    uint32_t characteristics
);

/**
 * Read data from section.
 */
NEXUS_API NexusResult Nexus_PeReadSectionData(
    intptr_t peHandle,
    uint32_t index,
    uint8_t* buffer,
    size_t bufferSize,
    size_t* bytesRead
);

/**
 * Write data to section.
 */
NEXUS_API NexusResult Nexus_PeWriteSectionData(
    intptr_t peHandle,
    uint32_t index,
    const uint8_t* data,
    size_t dataSize,
    uint32_t offset
);

/* ============================================================================
 * Data Directory Access
 * ============================================================================ */

/**
 * Get data directory information.
 */
NEXUS_API NexusResult Nexus_PeGetDataDirectory(
    intptr_t peHandle,
    uint32_t index,
    NexusPeDataDirInfo* info
);

/**
 * Set data directory RVA and size.
 */
NEXUS_API NexusResult Nexus_PeSetDataDirectory(
    intptr_t peHandle,
    uint32_t index,
    uint32_t rva,
    uint32_t size
);

/**
 * Clear a data directory.
 */
NEXUS_API NexusResult Nexus_PeClearDataDirectory(
    intptr_t peHandle,
    uint32_t index
);

/* ============================================================================
 * Overlay Handling
 * ============================================================================ */

/**
 * Get overlay information.
 */
NEXUS_API NexusResult Nexus_PeGetOverlay(
    intptr_t peHandle,
    NexusPeOverlayInfo* info
);

/**
 * Extract overlay to file.
 */
NEXUS_API NexusResult Nexus_PeExtractOverlay(
    intptr_t peHandle,
    const wchar_t* outputPath
);

/**
 * Extract overlay to buffer.
 */
NEXUS_API NexusResult Nexus_PeExtractOverlayToBuffer(
    intptr_t peHandle,
    uint8_t* buffer,
    size_t bufferSize,
    size_t* bytesWritten
);

/**
 * Add/replace overlay from file.
 */
NEXUS_API NexusResult Nexus_PeSetOverlay(
    intptr_t peHandle,
    const wchar_t* overlayPath
);

/**
 * Add/replace overlay from buffer.
 */
NEXUS_API NexusResult Nexus_PeSetOverlayFromBuffer(
    intptr_t peHandle,
    const uint8_t* data,
    size_t dataSize
);

/**
 * Remove overlay.
 */
NEXUS_API NexusResult Nexus_PeRemoveOverlay(intptr_t peHandle);

/* ============================================================================
 * Address Conversion
 * ============================================================================ */

/**
 * Convert RVA to file offset.
 */
NEXUS_API NexusResult Nexus_PeRvaToOffset(
    intptr_t peHandle,
    uint32_t rva,
    uint32_t* offset
);

/**
 * Convert file offset to RVA.
 */
NEXUS_API NexusResult Nexus_PeOffsetToRva(
    intptr_t peHandle,
    uint32_t offset,
    uint32_t* rva
);

/**
 * Convert RVA to VA.
 */
NEXUS_API NexusResult Nexus_PeRvaToVa(
    intptr_t peHandle,
    uint32_t rva,
    uint64_t* va
);

/**
 * Convert VA to RVA.
 */
NEXUS_API NexusResult Nexus_PeVaToRva(
    intptr_t peHandle,
    uint64_t va,
    uint32_t* rva
);

/* ============================================================================
 * PE Validation
 * ============================================================================ */

/**
 * Validate PE structure.
 */
NEXUS_API NexusResult Nexus_PeValidate(
    intptr_t peHandle,
    uint32_t* isValid,
    char* errorBuffer,
    size_t errorBufferSize
);

/**
 * Check if PE is 64-bit.
 */
NEXUS_API NexusResult Nexus_PeIs64Bit(
    intptr_t peHandle,
    uint32_t* is64Bit
);

/**
 * Check if PE is DLL.
 */
NEXUS_API NexusResult Nexus_PeIsDll(
    intptr_t peHandle,
    uint32_t* isDll
);

/**
 * Check if PE is .NET assembly.
 */
NEXUS_API NexusResult Nexus_PeIsDotNet(
    intptr_t peHandle,
    uint32_t* isDotNet
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_PEMANIP_H */
