/**
 * @file nexus_structure.h
 * @brief Structure dissection: definition, element management, and memory analysis.
 *
 * Define named structures with typed fields at specific offsets, then bind
 * instances to addresses in a live process to read/write individual fields.
 * Supports pointers to child structures, arrays, bit fields, enumeration
 * types, auto-gap filling, auto-guess from raw memory, and persistence
 * in XML (.nxs) or CE-compatible (.cs) formats.
 */

#ifndef NEXUS_STRUCTURE_H
#define NEXUS_STRUCTURE_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Structure Dissection Types
 * ============================================================================ */

/* Variable types for structure elements (matches CE TVariableType) */
typedef enum NexusElementType {
    NEXUS_ELEM_BYTE = 0,           /* 1-byte unsigned */
    NEXUS_ELEM_WORD = 1,           /* 2-byte unsigned */
    NEXUS_ELEM_DWORD = 2,          /* 4-byte unsigned */
    NEXUS_ELEM_QWORD = 3,          /* 8-byte unsigned */
    NEXUS_ELEM_FLOAT = 4,          /* 4-byte float */
    NEXUS_ELEM_DOUBLE = 5,         /* 8-byte double */
    NEXUS_ELEM_STRING = 6,         /* ANSI string */
    NEXUS_ELEM_UNICODE = 7,        /* Unicode string */
    NEXUS_ELEM_BYTE_ARRAY = 8,     /* Raw byte array */
    NEXUS_ELEM_BINARY = 9,         /* Binary display */
    NEXUS_ELEM_ENUMERATION = 10,   /* Enumerated type (v0.28.0) */
    NEXUS_ELEM_POINTER = 12,       /* Pointer to another struct */
    NEXUS_ELEM_CUSTOM = 13,        /* Custom type */
    NEXUS_ELEM_INT8 = 20,          /* 1-byte signed */
    NEXUS_ELEM_INT16 = 21,         /* 2-byte signed */
    NEXUS_ELEM_INT32 = 22,         /* 4-byte signed */
    NEXUS_ELEM_INT64 = 23          /* 8-byte signed */
} NexusElementType;

/* Display method for structure elements */
typedef enum NexusDisplayMethod {
    NEXUS_DISPLAY_UNSIGNED = 0,    /* Display as unsigned integer */
    NEXUS_DISPLAY_SIGNED = 1,      /* Display as signed integer */
    NEXUS_DISPLAY_HEX = 2          /* Display as hexadecimal */
} NexusDisplayMethod;

/* Structure element information */
typedef struct NexusStructElement {
    uint32_t id;                   /* Unique element ID */
    int32_t offset;                /* Byte offset in structure */
    int32_t byteSize;              /* Size in bytes */
    NexusElementType varType;      /* Data type */
    NexusDisplayMethod displayMethod; /* Display format */
    char name[128];                /* Element name/description */
    char customTypeName[64];       /* Custom type name (if NEXUS_ELEM_CUSTOM) */
    uint32_t childStructId;        /* Child structure ID (for pointers, 0 if none) */
    int32_t childStructOffset;     /* Offset into child structure */
    uint32_t backgroundColor;      /* Display color (0xAARRGGBB, 0 = default) */
    int32_t arrayCount;            /* Array count (1 = not array) */
    int32_t bitOffset;             /* Bit offset for bit fields (0-7) */
    int32_t bitSize;               /* Bit size for bit fields (0 = full bytes) */
    uint32_t flags;                /* Element flags */
    uint32_t enumDefinitionId;     /* Enum definition ID (for NEXUS_ELEM_ENUMERATION) */
} NexusStructElement;

/* Structure element flags */
typedef enum NexusElementFlags {
    NEXUS_ELEM_FLAG_NONE = 0x0000,
    NEXUS_ELEM_FLAG_HIDDEN = 0x0001,      /* Element is hidden in UI */
    NEXUS_ELEM_FLAG_READONLY = 0x0002,    /* Element is read-only */
    NEXUS_ELEM_FLAG_COLLAPSED = 0x0004,   /* Collapsed in tree view */
    NEXUS_ELEM_FLAG_EXPAND_ADDR = 0x0008  /* Expanding changes address */
} NexusElementFlags;

/* Structure definition information */
typedef struct NexusStructInfo {
    uint32_t id;                   /* Unique structure ID */
    char name[128];                /* Structure name */
    int32_t size;                  /* Total structure size (0 = auto) */
    uint32_t elementCount;         /* Number of elements */
    uint32_t flags;                /* Structure flags */
} NexusStructInfo;

/* Structure flags */
typedef enum NexusStructFlags {
    NEXUS_STRUCT_FLAG_NONE = 0x0000,
    NEXUS_STRUCT_FLAG_AUTOFILL = 0x0001,  /* Auto-fill gaps with bytes */
    NEXUS_STRUCT_FLAG_HEXDEFAULT = 0x0002, /* Default to hex display */
    NEXUS_STRUCT_FLAG_LOCAL = 0x0004,     /* Local/nested struct (not global) */
    NEXUS_STRUCT_FLAG_RLE = 0x0008        /* Use RLE compression in saves */
} NexusStructFlags;

/* Structure instance (address binding) */
typedef struct NexusStructInstance {
    uint32_t id;                   /* Instance ID */
    uint32_t structId;             /* Structure definition ID */
    uint64_t baseAddress;          /* Base address in memory */
    char name[64];                 /* Instance name/label */
    int32_t frozen;                /* 1 if frozen (snapshot), 0 if live */
} NexusStructInstance;

/* Element value reading result */
typedef struct NexusElementValue {
    uint32_t elementId;            /* Element ID */
    uint64_t address;              /* Resolved address */
    int32_t valid;                 /* 1 if read succeeded, 0 if failed */
    union {
        uint8_t byteVal;
        uint16_t wordVal;
        uint32_t dwordVal;
        uint64_t qwordVal;
        float floatVal;
        double doubleVal;
        int8_t int8Val;
        int16_t int16Val;
        int32_t int32Val;
        int64_t int64Val;
        char stringVal[256];
        wchar_t unicodeVal[128];
        uint8_t bytesVal[64];
    } data;
    int32_t dataSize;              /* Actual size of data read */
} NexusElementValue;

/* ============================================================================
 * Structure Dissection API
 * ============================================================================ */

/**
 * Create a new empty structure definition.
 *
 * @param name Structure name
 * @param structure Output: structure handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureCreate(
    const char* name,
    NexusStructureHandle* structure
);

/**
 * Destroy a structure and free all resources.
 *
 * @param structure Structure handle
 */
NEXUS_API void Nexus_StructureDestroy(NexusStructureHandle structure);

/**
 * Get structure information.
 *
 * @param structure Structure handle
 * @param info Output: structure info
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureGetInfo(
    NexusStructureHandle structure,
    NexusStructInfo* info
);

/**
 * Set structure properties.
 *
 * @param structure Structure handle
 * @param name New name (NULL to keep current)
 * @param size Structure size (0 for auto-size)
 * @param flags Structure flags
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureSetProperties(
    NexusStructureHandle structure,
    const char* name,
    int32_t size,
    uint32_t flags
);

/**
 * Add an element to the structure.
 *
 * @param structure Structure handle
 * @param offset Byte offset
 * @param varType Element data type
 * @param name Element name/description
 * @param byteSize Size in bytes (0 = auto based on type)
 * @param elementId Output: assigned element ID
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureAddElement(
    NexusStructureHandle structure,
    int32_t offset,
    NexusElementType varType,
    const char* name,
    int32_t byteSize,
    uint32_t* elementId
);

/**
 * Remove an element from the structure.
 *
 * @param structure Structure handle
 * @param elementId Element ID to remove
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureRemoveElement(
    NexusStructureHandle structure,
    uint32_t elementId
);

/**
 * Get element by ID.
 *
 * @param structure Structure handle
 * @param elementId Element ID
 * @param element Output: element data
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureGetElement(
    NexusStructureHandle structure,
    uint32_t elementId,
    NexusStructElement* element
);

/**
 * Get element by index (sorted by offset).
 *
 * @param structure Structure handle
 * @param index Element index (0-based)
 * @param element Output: element data
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureGetElementByIndex(
    NexusStructureHandle structure,
    uint32_t index,
    NexusStructElement* element
);

/**
 * Get element at specific offset.
 *
 * @param structure Structure handle
 * @param offset Byte offset
 * @param element Output: element data (NULL if just checking existence)
 * @return NEXUS_OK if found, NEXUS_ERROR_NOT_FOUND if no element at offset
 */
NEXUS_API NexusResult Nexus_StructureGetElementByOffset(
    NexusStructureHandle structure,
    int32_t offset,
    NexusStructElement* element
);

/**
 * Update an existing element.
 *
 * @param structure Structure handle
 * @param element Updated element data (uses elementId to identify)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureUpdateElement(
    NexusStructureHandle structure,
    const NexusStructElement* element
);

/**
 * Get the number of elements in the structure.
 *
 * @param structure Structure handle
 * @param count Output: element count
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureGetElementCount(
    NexusStructureHandle structure,
    uint32_t* count
);

/**
 * Set child structure for a pointer element.
 *
 * @param structure Structure handle
 * @param elementId Element ID (must be NEXUS_ELEM_POINTER)
 * @param childStruct Child structure handle (NULL to clear)
 * @param childOffset Offset into child structure
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureSetChildStruct(
    NexusStructureHandle structure,
    uint32_t elementId,
    NexusStructureHandle childStruct,
    int32_t childOffset
);

/**
 * Auto-fill gaps in structure with byte elements.
 *
 * @param structure Structure handle
 * @param process Process handle (for reading memory to guess types)
 * @param baseAddress Base address (for type guessing, 0 to skip)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureFillGaps(
    NexusStructureHandle structure,
    NexusProcessHandle process,
    uint64_t baseAddress
);

/**
 * Auto-guess structure from memory.
 * Creates elements based on data patterns.
 *
 * @param structure Structure handle (must be empty or will be cleared)
 * @param process Process handle
 * @param address Base address to analyze
 * @param size Size in bytes to analyze
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureAutoGuess(
    NexusStructureHandle structure,
    NexusProcessHandle process,
    uint64_t address,
    size_t size
);

/**
 * Sort elements by offset.
 *
 * @param structure Structure handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureSortElements(
    NexusStructureHandle structure
);

/* ============================================================================
 * Structure Instance API
 * ============================================================================ */

/**
 * Create a structure instance at an address.
 *
 * @param structure Structure handle
 * @param baseAddress Base address in target process
 * @param name Instance name (optional, can be NULL)
 * @param instance Output: instance info
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureCreateInstance(
    NexusStructureHandle structure,
    uint64_t baseAddress,
    const char* name,
    NexusStructInstance* instance
);

/**
 * Read element value from a structure instance.
 *
 * @param structure Structure handle
 * @param process Process handle
 * @param baseAddress Base address of instance
 * @param elementId Element ID
 * @param value Output: element value
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureReadElement(
    NexusStructureHandle structure,
    NexusProcessHandle process,
    uint64_t baseAddress,
    uint32_t elementId,
    NexusElementValue* value
);

/**
 * Write element value to a structure instance.
 *
 * @param structure Structure handle
 * @param process Process handle
 * @param baseAddress Base address of instance
 * @param elementId Element ID
 * @param value Value to write
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureWriteElement(
    NexusStructureHandle structure,
    NexusProcessHandle process,
    uint64_t baseAddress,
    uint32_t elementId,
    const NexusElementValue* value
);

/**
 * Read all element values from a structure instance.
 *
 * @param structure Structure handle
 * @param process Process handle
 * @param baseAddress Base address of instance
 * @param values Array to receive values
 * @param maxValues Size of values array
 * @param valuesRead Output: number of values read
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureReadAllElements(
    NexusStructureHandle structure,
    NexusProcessHandle process,
    uint64_t baseAddress,
    NexusElementValue* values,
    size_t maxValues,
    size_t* valuesRead
);

/**
 * Follow a pointer element to get the target address.
 *
 * @param structure Structure handle
 * @param process Process handle
 * @param baseAddress Base address of instance
 * @param elementId Pointer element ID
 * @param targetAddress Output: target address (0 if null pointer)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureFollowPointer(
    NexusStructureHandle structure,
    NexusProcessHandle process,
    uint64_t baseAddress,
    uint32_t elementId,
    uint64_t* targetAddress
);

/* ============================================================================
 * Structure Persistence API
 * ============================================================================ */

/**
 * Save structure to XML file (.nxs - Nexus Structure).
 *
 * @param structure Structure handle
 * @param path Output file path
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureSave(
    NexusStructureHandle structure,
    const char* path
);

/**
 * Load structure from XML file.
 *
 * @param path Input file path
 * @param structure Output: structure handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureLoad(
    const char* path,
    NexusStructureHandle* structure
);

/**
 * Save multiple structures to a single file.
 *
 * @param structures Array of structure handles
 * @param count Number of structures
 * @param path Output file path
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureSaveMultiple(
    NexusStructureHandle* structures,
    size_t count,
    const char* path
);

/**
 * Load multiple structures from a file.
 *
 * @param path Input file path
 * @param structures Array to receive structure handles
 * @param maxStructures Size of structures array
 * @param structuresLoaded Output: number of structures loaded
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureLoadMultiple(
    const char* path,
    NexusStructureHandle* structures,
    size_t maxStructures,
    size_t* structuresLoaded
);

/**
 * Import structure from CE structure file (.cs).
 *
 * @param path CE structure file path
 * @param structure Output: structure handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureImportCE(
    const char* path,
    NexusStructureHandle* structure
);

/**
 * Export structure to CE-compatible format.
 *
 * @param structure Structure handle
 * @param path Output file path
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureExportCE(
    NexusStructureHandle structure,
    const char* path
);

/**
 * Clone a structure (deep copy).
 *
 * @param source Source structure handle
 * @param newName New name for clone (NULL to keep same name)
 * @param clone Output: cloned structure handle
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureClone(
    NexusStructureHandle source,
    const char* newName,
    NexusStructureHandle* clone
);

/* ============================================================================
 * Enumeration Definitions (v0.28.0)
 * ============================================================================ */

/** Single enum value mapping */
typedef struct NexusEnumValue {
    int64_t numericValue;          /* The integer value */
    char name[64];                 /* Display name */
} NexusEnumValue;

/** Enum definition */
typedef struct NexusEnumDefinition {
    uint32_t id;                   /* Unique enum ID */
    char name[128];                /* Enum type name */
    NexusElementType baseType;     /* Underlying type: BYTE, WORD, DWORD, QWORD */
    uint32_t valueCount;           /* Number of defined values */
    uint32_t flags;                /* Enum flags */
} NexusEnumDefinition;

/** Enum definition flags */
typedef enum NexusEnumFlags {
    NEXUS_ENUM_FLAG_NONE = 0x0000,
    NEXUS_ENUM_FLAG_BITMASK = 0x0001,     /* Values are bit flags, can combine */
    NEXUS_ENUM_FLAG_HEXDEFAULT = 0x0002   /* Default to hex display for unknown values */
} NexusEnumFlags;

/**
 * Create a new enum definition.
 *
 * @param name Enum type name
 * @param baseType Underlying integer type (BYTE, WORD, DWORD, QWORD)
 * @param enumId Output: assigned enum ID
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EnumCreate(
    const char* name,
    NexusElementType baseType,
    uint32_t* enumId
);

/**
 * Destroy an enum definition.
 *
 * @param enumId Enum ID
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EnumDestroy(uint32_t enumId);

/**
 * Add a value to an enum definition.
 *
 * @param enumId Enum ID
 * @param value Numeric value
 * @param name Display name
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EnumAddValue(
    uint32_t enumId,
    int64_t value,
    const char* name
);

/**
 * Remove a value from an enum definition.
 *
 * @param enumId Enum ID
 * @param value Numeric value to remove
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EnumRemoveValue(
    uint32_t enumId,
    int64_t value
);

/**
 * Get enum definition info.
 *
 * @param enumId Enum ID
 * @param definition Output: enum definition
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EnumGetDefinition(
    uint32_t enumId,
    NexusEnumDefinition* definition
);

/**
 * Get all values for an enum.
 *
 * @param enumId Enum ID
 * @param values Output array
 * @param maxValues Size of values array
 * @param valueCount Output: actual value count
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EnumGetValues(
    uint32_t enumId,
    NexusEnumValue* values,
    size_t maxValues,
    size_t* valueCount
);

/**
 * Look up name for a numeric value.
 *
 * @param enumId Enum ID
 * @param value Numeric value
 * @param name Output: name buffer
 * @param nameSize Size of name buffer
 * @return NEXUS_OK if found, NEXUS_ERROR_NOT_FOUND if no match
 */
NEXUS_API NexusResult Nexus_EnumValueToName(
    uint32_t enumId,
    int64_t value,
    char* name,
    size_t nameSize
);

/**
 * Look up numeric value for a name.
 *
 * @param enumId Enum ID
 * @param name Value name
 * @param value Output: numeric value
 * @return NEXUS_OK if found, NEXUS_ERROR_NOT_FOUND if no match
 */
NEXUS_API NexusResult Nexus_EnumNameToValue(
    uint32_t enumId,
    const char* name,
    int64_t* value
);

/**
 * Get all registered enum IDs.
 *
 * @param enumIds Output array
 * @param maxEnums Size of enumIds array
 * @param enumCount Output: actual count
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EnumGetAll(
    uint32_t* enumIds,
    size_t maxEnums,
    size_t* enumCount
);

/**
 * Find enum by name.
 *
 * @param name Enum name
 * @param enumId Output: enum ID
 * @return NEXUS_OK if found
 */
NEXUS_API NexusResult Nexus_EnumFindByName(
    const char* name,
    uint32_t* enumId
);

/**
 * Set flags on an enum definition.
 *
 * @param enumId Enum ID
 * @param flags Flags to set
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_EnumSetFlags(
    uint32_t enumId,
    uint32_t flags
);

/**
 * Link a structure element to an enum definition.
 *
 * @param structure Structure handle
 * @param elementId Element ID (should be NEXUS_ELEM_ENUMERATION type)
 * @param enumId Enum definition ID (0 to unlink)
 * @return NEXUS_OK on success
 */
NEXUS_API NexusResult Nexus_StructureSetElementEnum(
    NexusStructureHandle structure,
    uint32_t elementId,
    uint32_t enumId
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_STRUCTURE_H */
