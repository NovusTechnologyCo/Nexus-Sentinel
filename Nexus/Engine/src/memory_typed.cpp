/**
 * @file memory_typed.cpp
 * @brief Typed memory read/write helpers and multi-level pointer resolution.
 *
 * Convenience wrappers (Nexus_ReadU8..F64, ReadCString, ReadWString,
 * WriteU8..F64) that call through to Nexus_ReadMemory/WriteMemory with
 * the correct size.  Also implements Nexus_ResolvePointer for walking
 * multi-level pointer chains and batch resolution.
 *
 * Core read/write in memory.cpp; page cache in memory_cache.cpp.
 */

#include "memory_internal.h"

/* ============================================================================
 * Typed Memory Read Helpers
 * ============================================================================ */

extern "C" {

NEXUS_API NexusResult Nexus_ReadU8(
    NexusProcessHandle handle,
    uint64_t address,
    uint8_t* value
) {
    if (!value) return NEXUS_ERROR_INVALID_PARAMETER;
    return Nexus_ReadMemory(handle, address, value, sizeof(uint8_t), nullptr);
}

NEXUS_API NexusResult Nexus_ReadU16(
    NexusProcessHandle handle,
    uint64_t address,
    uint16_t* value
) {
    if (!value) return NEXUS_ERROR_INVALID_PARAMETER;
    return Nexus_ReadMemory(handle, address, value, sizeof(uint16_t), nullptr);
}

NEXUS_API NexusResult Nexus_ReadU32(
    NexusProcessHandle handle,
    uint64_t address,
    uint32_t* value
) {
    if (!value) return NEXUS_ERROR_INVALID_PARAMETER;
    return Nexus_ReadMemory(handle, address, value, sizeof(uint32_t), nullptr);
}

NEXUS_API NexusResult Nexus_ReadU64(
    NexusProcessHandle handle,
    uint64_t address,
    uint64_t* value
) {
    if (!value) return NEXUS_ERROR_INVALID_PARAMETER;
    return Nexus_ReadMemory(handle, address, value, sizeof(uint64_t), nullptr);
}

NEXUS_API NexusResult Nexus_ReadF32(
    NexusProcessHandle handle,
    uint64_t address,
    float* value
) {
    if (!value) return NEXUS_ERROR_INVALID_PARAMETER;
    return Nexus_ReadMemory(handle, address, value, sizeof(float), nullptr);
}

NEXUS_API NexusResult Nexus_ReadF64(
    NexusProcessHandle handle,
    uint64_t address,
    double* value
) {
    if (!value) return NEXUS_ERROR_INVALID_PARAMETER;
    return Nexus_ReadMemory(handle, address, value, sizeof(double), nullptr);
}

NEXUS_API NexusResult Nexus_ReadPointer(
    NexusProcessHandle handle,
    uint64_t address,
    uint64_t* value
) {
    if (!handle || !value) return NEXUS_ERROR_INVALID_PARAMETER;

    auto* data = static_cast<NexusProcessHandleData*>(handle);

    if (data->is32Bit) {
        uint32_t ptr32 = 0;
        NexusResult res = Nexus_ReadMemory(handle, address, &ptr32, sizeof(uint32_t), nullptr);
        if (res == NEXUS_OK) {
            *value = ptr32;  /* Zero-extend to 64-bit */
        }
        return res;
    } else {
        return Nexus_ReadMemory(handle, address, value, sizeof(uint64_t), nullptr);
    }
}

NEXUS_API NexusResult Nexus_ReadCString(
    NexusProcessHandle handle,
    uint64_t address,
    char* buffer,
    size_t bufferSize,
    size_t* charsRead
) {
    if (!handle || !buffer || bufferSize == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t totalRead = 0;
    bool foundNull = false;
    static const size_t STRING_CHUNK_SIZE = 256;  /* Increased for syscall amortization */

    while (totalRead < bufferSize - 1 && !foundNull) {
        size_t toRead = min(STRING_CHUNK_SIZE, bufferSize - 1 - totalRead);
        size_t bytesRead = 0;

        NexusResult res = Nexus_ReadMemory(
            handle,
            address + totalRead,
            buffer + totalRead,
            toRead,
            &bytesRead
        );

        if (res != NEXUS_OK && res != NEXUS_ERROR_PARTIAL_READ) {
            buffer[totalRead] = '\0';
            if (charsRead) *charsRead = totalRead;
            return res;
        }

        /* Check for null terminator in what we just read */
        for (size_t i = 0; i < bytesRead; i++) {
            if (buffer[totalRead + i] == '\0') {
                foundNull = true;
                totalRead += i;
                break;
            }
        }

        if (!foundNull) {
            totalRead += bytesRead;
        }

        if (bytesRead < toRead) {
            break;  /* Couldn't read more */
        }
    }

    buffer[totalRead] = '\0';
    if (charsRead) *charsRead = totalRead;

    if (!foundNull && totalRead >= bufferSize - 1) {
        return NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ReadWString(
    NexusProcessHandle handle,
    uint64_t address,
    wchar_t* buffer,
    size_t bufferSize,
    size_t* charsRead
) {
    if (!handle || !buffer || bufferSize == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t totalRead = 0;
    bool foundNull = false;
    static const size_t WSTRING_CHUNK_SIZE = 128;  /* Read 128 wide chars at a time */

    while (totalRead < bufferSize - 1 && !foundNull) {
        size_t toRead = min(WSTRING_CHUNK_SIZE, bufferSize - 1 - totalRead);
        size_t bytesRead = 0;

        NexusResult res = Nexus_ReadMemory(
            handle,
            address + totalRead * sizeof(wchar_t),
            buffer + totalRead,
            toRead * sizeof(wchar_t),
            &bytesRead
        );

        if (res != NEXUS_OK && res != NEXUS_ERROR_PARTIAL_READ) {
            buffer[totalRead] = L'\0';
            if (charsRead) *charsRead = totalRead;
            return res;
        }

        size_t charsJustRead = bytesRead / sizeof(wchar_t);

        /* Check for null terminator in what we just read */
        for (size_t i = 0; i < charsJustRead; i++) {
            if (buffer[totalRead + i] == L'\0') {
                foundNull = true;
                totalRead += i;
                break;
            }
        }

        if (!foundNull) {
            totalRead += charsJustRead;
        }

        if (charsJustRead < toRead) {
            break;  /* Couldn't read more */
        }
    }

    buffer[totalRead] = L'\0';
    if (charsRead) *charsRead = totalRead;

    if (!foundNull && totalRead >= bufferSize - 1) {
        return NEXUS_ERROR_INSUFFICIENT_BUFFER;
    }

    return NEXUS_OK;
}

/* ============================================================================
 * Typed Memory Write Helpers
 * ============================================================================ */

NEXUS_API NexusResult Nexus_WriteU8(
    NexusProcessHandle handle,
    uint64_t address,
    uint8_t value
) {
    return Nexus_WriteMemory(handle, address, &value, sizeof(uint8_t), nullptr);
}

NEXUS_API NexusResult Nexus_WriteU16(
    NexusProcessHandle handle,
    uint64_t address,
    uint16_t value
) {
    return Nexus_WriteMemory(handle, address, &value, sizeof(uint16_t), nullptr);
}

NEXUS_API NexusResult Nexus_WriteU32(
    NexusProcessHandle handle,
    uint64_t address,
    uint32_t value
) {
    return Nexus_WriteMemory(handle, address, &value, sizeof(uint32_t), nullptr);
}

NEXUS_API NexusResult Nexus_WriteU64(
    NexusProcessHandle handle,
    uint64_t address,
    uint64_t value
) {
    return Nexus_WriteMemory(handle, address, &value, sizeof(uint64_t), nullptr);
}

NEXUS_API NexusResult Nexus_WriteF32(
    NexusProcessHandle handle,
    uint64_t address,
    float value
) {
    return Nexus_WriteMemory(handle, address, &value, sizeof(float), nullptr);
}

NEXUS_API NexusResult Nexus_WriteF64(
    NexusProcessHandle handle,
    uint64_t address,
    double value
) {
    return Nexus_WriteMemory(handle, address, &value, sizeof(double), nullptr);
}

/* ============================================================================
 * Pointer Resolution
 * ============================================================================ */

NEXUS_API NexusResult Nexus_ResolvePointer(
    NexusProcessHandle handle,
    uint64_t baseAddress,
    const int64_t* offsets,
    size_t offsetCount,
    uint64_t* resultAddress
) {
    if (!handle || !resultAddress) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Handle empty offset array - just return base address */
    if (offsetCount == 0 || offsets == nullptr) {
        *resultAddress = baseAddress;
        return NEXUS_OK;
    }

    uint64_t currentAddress = baseAddress;

    /* Follow the pointer chain */
    for (size_t i = 0; i < offsetCount; i++) {
        /* Add the current offset */
        currentAddress = static_cast<uint64_t>(
            static_cast<int64_t>(currentAddress) + offsets[i]
        );

        /* For all but the last offset, we need to read the pointer */
        if (i < offsetCount - 1) {
            NexusResult res = Nexus_ReadPointer(handle, currentAddress, &currentAddress);
            if (res != NEXUS_OK) {
                *resultAddress = 0;
                return res;
            }

            /* Check for null pointer */
            if (currentAddress == 0) {
                *resultAddress = 0;
                return NEXUS_ERROR_ACCESS_DENIED;
            }
        }
    }

    *resultAddress = currentAddress;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_ResolvePointerAndRead(
    NexusProcessHandle handle,
    uint64_t baseAddress,
    const int64_t* offsets,
    size_t offsetCount,
    void* buffer,
    size_t size,
    size_t* bytesRead
) {
    if (!handle || !buffer || size == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* First resolve the pointer chain */
    uint64_t finalAddress = 0;
    NexusResult res = Nexus_ResolvePointer(handle, baseAddress, offsets, offsetCount, &finalAddress);
    if (res != NEXUS_OK) {
        if (bytesRead) *bytesRead = 0;
        return res;
    }

    /* Then read the value at the final address */
    return Nexus_ReadMemory(handle, finalAddress, buffer, size, bytesRead);
}

NEXUS_API NexusResult Nexus_ResolvePointerBatch(
    NexusProcessHandle handle,
    const uint64_t* baseAddresses,
    const int64_t* const* offsetArrays,
    const size_t* offsetCounts,
    size_t count,
    uint64_t* resultAddresses,
    int* successFlags
) {
    if (!handle || !baseAddresses || !offsetArrays || !offsetCounts ||
        !resultAddresses || !successFlags || count == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    size_t successCount = 0;

    for (size_t i = 0; i < count; i++) {
        NexusResult res = Nexus_ResolvePointer(
            handle,
            baseAddresses[i],
            offsetArrays[i],
            offsetCounts[i],
            &resultAddresses[i]
        );

        if (res == NEXUS_OK) {
            successFlags[i] = 1;
            successCount++;
        } else {
            successFlags[i] = 0;
            resultAddresses[i] = 0;
        }
    }

    if (successCount == count) {
        return NEXUS_OK;
    } else if (successCount > 0) {
        return NEXUS_ERROR_PARTIAL_READ;
    } else {
        return NEXUS_ERROR_ACCESS_DENIED;
    }
}

} /* extern "C" */
