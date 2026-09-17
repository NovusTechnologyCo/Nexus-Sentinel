/**
 * @file nexus_resource.h
 * @brief PE resource enumeration, extraction, and modification.
 *
 * Enumerate, extract, add, and remove resources in PE files.
 * Modelled on the TitanEngine resource API.
 */

#ifndef NEXUS_RESOURCE_H
#define NEXUS_RESOURCE_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Resource Types
 * ============================================================================ */

typedef enum NexusResourceType {
    NEXUS_RESOURCE_CURSOR = 1,
    NEXUS_RESOURCE_BITMAP = 2,
    NEXUS_RESOURCE_ICON = 3,
    NEXUS_RESOURCE_MENU = 4,
    NEXUS_RESOURCE_DIALOG = 5,
    NEXUS_RESOURCE_STRING = 6,
    NEXUS_RESOURCE_FONTDIR = 7,
    NEXUS_RESOURCE_FONT = 8,
    NEXUS_RESOURCE_ACCELERATOR = 9,
    NEXUS_RESOURCE_RCDATA = 10,
    NEXUS_RESOURCE_MESSAGETABLE = 11,
    NEXUS_RESOURCE_GROUP_CURSOR = 12,
    NEXUS_RESOURCE_GROUP_ICON = 14,
    NEXUS_RESOURCE_VERSION = 16,
    NEXUS_RESOURCE_DLGINCLUDE = 17,
    NEXUS_RESOURCE_PLUGPLAY = 19,
    NEXUS_RESOURCE_VXD = 20,
    NEXUS_RESOURCE_ANICURSOR = 21,
    NEXUS_RESOURCE_ANIICON = 22,
    NEXUS_RESOURCE_HTML = 23,
    NEXUS_RESOURCE_MANIFEST = 24
} NexusResourceType;

/* ============================================================================
 * Resource Structures
 * ============================================================================ */

typedef struct NexusResourceInfo {
    uint32_t typeId;                    /* Resource type ID */
    uint32_t nameId;                    /* Resource name ID */
    uint32_t languageId;                /* Resource language ID */
    uint32_t dataRva;                   /* RVA of resource data */
    uint32_t dataSize;                  /* Size of resource data */
    uint32_t codePage;                  /* Code page */
    wchar_t typeName[64];               /* Type name (if string) */
    wchar_t name[64];                   /* Resource name (if string) */
    uint32_t isTypeString;              /* 1 if type is string */
    uint32_t isNameString;              /* 1 if name is string */
} NexusResourceInfo;

typedef struct NexusVersionInfo {
    uint16_t fileVersionMajor;
    uint16_t fileVersionMinor;
    uint16_t fileVersionBuild;
    uint16_t fileVersionRevision;
    uint16_t productVersionMajor;
    uint16_t productVersionMinor;
    uint16_t productVersionBuild;
    uint16_t productVersionRevision;
    uint32_t fileFlagsMask;
    uint32_t fileFlags;
    uint32_t fileOs;
    uint32_t fileType;
    uint32_t fileSubtype;
    wchar_t fileDescription[256];
    wchar_t fileVersion[64];
    wchar_t internalName[128];
    wchar_t legalCopyright[256];
    wchar_t originalFilename[128];
    wchar_t productName[128];
    wchar_t productVersion[64];
    wchar_t companyName[128];
} NexusVersionInfo;

typedef struct NexusManifestInfo {
    wchar_t identity[128];              /* Assembly identity */
    wchar_t description[256];           /* Assembly description */
    uint32_t requestedExecutionLevel;   /* UAC level */
    uint32_t uiAccess;                  /* UI access */
    uint32_t dpiAware;                  /* DPI awareness */
    uint32_t longPathAware;             /* Long path support */
    wchar_t supportedOs[16][32];        /* Supported OS GUIDs */
    uint32_t supportedOsCount;          /* Number of supported OS entries */
    uint32_t reserved;
} NexusManifestInfo;

typedef struct NexusResourceStats {
    uint32_t totalResources;            /* Total resource count */
    uint32_t typeCount;                 /* Unique type count */
    uint32_t totalSize;                 /* Total resource data size */
    uint32_t iconCount;                 /* Number of icons */
    uint32_t stringCount;               /* Number of string tables */
    uint32_t dialogCount;               /* Number of dialogs */
    uint32_t hasVersion;                /* Has version info */
    uint32_t hasManifest;               /* Has manifest */
} NexusResourceStats;

/* ============================================================================
 * Resource Enumeration
 * ============================================================================ */

/**
 * Get resource statistics.
 */
NEXUS_API NexusResult Nexus_ResGetStats(
    intptr_t peHandle,
    NexusResourceStats* stats
);

/**
 * Get all resources.
 */
NEXUS_API NexusResult Nexus_ResGetAll(
    intptr_t peHandle,
    NexusResourceInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get resources by type.
 */
NEXUS_API NexusResult Nexus_ResGetByType(
    intptr_t peHandle,
    uint32_t typeId,
    NexusResourceInfo* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get specific resource.
 */
NEXUS_API NexusResult Nexus_ResGet(
    intptr_t peHandle,
    uint32_t typeId,
    uint32_t nameId,
    uint32_t languageId,
    NexusResourceInfo* info
);

/**
 * Get resource by name string.
 */
NEXUS_API NexusResult Nexus_ResGetByName(
    intptr_t peHandle,
    const wchar_t* typeName,
    const wchar_t* name,
    uint32_t languageId,
    NexusResourceInfo* info
);

/* ============================================================================
 * Resource Extraction
 * ============================================================================ */

/**
 * Extract resource data to buffer.
 */
NEXUS_API NexusResult Nexus_ResExtract(
    intptr_t peHandle,
    uint32_t typeId,
    uint32_t nameId,
    uint32_t languageId,
    uint8_t* buffer,
    size_t bufferSize,
    size_t* bytesWritten
);

/**
 * Extract resource to file.
 */
NEXUS_API NexusResult Nexus_ResExtractToFile(
    intptr_t peHandle,
    uint32_t typeId,
    uint32_t nameId,
    uint32_t languageId,
    const wchar_t* outputPath
);

/**
 * Extract all icons to directory.
 */
NEXUS_API NexusResult Nexus_ResExtractIcons(
    intptr_t peHandle,
    const wchar_t* outputDir
);

/**
 * Extract main icon to file.
 */
NEXUS_API NexusResult Nexus_ResExtractMainIcon(
    intptr_t peHandle,
    const wchar_t* outputPath
);

/* ============================================================================
 * Resource Modification
 * ============================================================================ */

/**
 * Add or replace resource.
 */
NEXUS_API NexusResult Nexus_ResAdd(
    intptr_t peHandle,
    uint32_t typeId,
    uint32_t nameId,
    uint32_t languageId,
    const uint8_t* data,
    size_t dataSize
);

/**
 * Add resource from file.
 */
NEXUS_API NexusResult Nexus_ResAddFromFile(
    intptr_t peHandle,
    uint32_t typeId,
    uint32_t nameId,
    uint32_t languageId,
    const wchar_t* filePath
);

/**
 * Delete a resource.
 */
NEXUS_API NexusResult Nexus_ResDelete(
    intptr_t peHandle,
    uint32_t typeId,
    uint32_t nameId,
    uint32_t languageId
);

/**
 * Delete all resources of type.
 */
NEXUS_API NexusResult Nexus_ResDeleteType(
    intptr_t peHandle,
    uint32_t typeId
);

/**
 * Clear all resources.
 */
NEXUS_API NexusResult Nexus_ResClear(intptr_t peHandle);

/* ============================================================================
 * Version Info
 * ============================================================================ */

/**
 * Get version info.
 */
NEXUS_API NexusResult Nexus_ResGetVersionInfo(
    intptr_t peHandle,
    NexusVersionInfo* info
);

/**
 * Set version info.
 */
NEXUS_API NexusResult Nexus_ResSetVersionInfo(
    intptr_t peHandle,
    const NexusVersionInfo* info
);

/**
 * Get version string.
 */
NEXUS_API NexusResult Nexus_ResGetVersionString(
    intptr_t peHandle,
    const wchar_t* stringName,
    wchar_t* buffer,
    size_t bufferSize
);

/**
 * Set version string.
 */
NEXUS_API NexusResult Nexus_ResSetVersionString(
    intptr_t peHandle,
    const wchar_t* stringName,
    const wchar_t* value
);

/* ============================================================================
 * Manifest
 * ============================================================================ */

/**
 * Get manifest info.
 */
NEXUS_API NexusResult Nexus_ResGetManifest(
    intptr_t peHandle,
    NexusManifestInfo* info
);

/**
 * Get raw manifest XML.
 */
NEXUS_API NexusResult Nexus_ResGetManifestXml(
    intptr_t peHandle,
    char* buffer,
    size_t bufferSize,
    size_t* length
);

/**
 * Set manifest from XML.
 */
NEXUS_API NexusResult Nexus_ResSetManifestXml(
    intptr_t peHandle,
    const char* manifestXml
);

/**
 * Set UAC execution level.
 */
NEXUS_API NexusResult Nexus_ResSetUacLevel(
    intptr_t peHandle,
    uint32_t level,
    uint32_t uiAccess
);

/**
 * Set DPI awareness in manifest.
 */
NEXUS_API NexusResult Nexus_ResSetDpiAwareness(
    intptr_t peHandle,
    uint32_t dpiAware
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_RESOURCE_H */
