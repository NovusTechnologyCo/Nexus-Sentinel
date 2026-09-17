/**
 * @file signature.cpp
 * @brief Signature scanner API: create/destroy, add/remove, scan, and match retrieval.
 *
 * Manages a collection of named byte-pattern signatures that can be
 * scanned individually or in batch.  Each signature stores a pattern,
 * module filter, and offset for resolving to a final address.
 *
 * Pattern parsing and memory-scanning logic are in signature_scan.cpp.
 */

#include "signature_internal.h"

/* ============================================================================
 * Global Container
 * ============================================================================ */

static std::mutex g_signatureMutex;
static std::unordered_map<void*, std::unique_ptr<SignatureContext>> g_signatures;

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_SignatureCreate(
    NexusProcessHandle process,
    NexusSignatureHandle* scanner)
{
    if (!process || !scanner) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto ctx = std::make_unique<SignatureContext>();
    ctx->process = process;
    ctx->nextSigId = 1;
    ctx->modulesCached = false;
    ctx->scanCancelled = false;
    ctx->scanComplete = true;
    ctx->bytesScanned = 0;
    ctx->bytesTotal = 0;
    ctx->matchesFound = 0;

    /* Store unique_ptr in global container and return raw pointer */
    auto* rawPtr = ctx.get();
    {
        std::lock_guard<std::mutex> lock(g_signatureMutex);
        g_signatures[rawPtr] = std::move(ctx);
    }

    *scanner = rawPtr;
    return NEXUS_OK;
}

NEXUS_API void Nexus_SignatureDestroy(NexusSignatureHandle scanner) {
    if (scanner) {
        SignatureContext* ctx = static_cast<SignatureContext*>(scanner);
        ctx->scanCancelled = true;

        /* Remove from global container (unique_ptr handles deletion) */
        std::lock_guard<std::mutex> lock(g_signatureMutex);
        g_signatures.erase(scanner);
    }
}

NEXUS_API NexusResult Nexus_SignatureAdd(
    NexusSignatureHandle scanner,
    const NexusSignatureInfo* sig,
    uint32_t* sigId)
{
    if (!scanner || !sig) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    SignatureContext* ctx = static_cast<SignatureContext*>(scanner);

    /* Parse pattern */
    ParsedPattern parsed;
    if (!ParsePatternInternal(sig->pattern, parsed)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Create entry */
    SignatureEntry entry;
    entry.id = ctx->nextSigId++;
    entry.info = *sig;
    entry.pattern = std::move(parsed);

    ctx->signatures[entry.id] = std::move(entry);

    if (sigId) {
        *sigId = entry.id;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SignatureRemove(
    NexusSignatureHandle scanner,
    uint32_t sigId)
{
    if (!scanner) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    SignatureContext* ctx = static_cast<SignatureContext*>(scanner);

    if (ctx->signatures.erase(sigId) == 0) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    return NEXUS_OK;
}

NEXUS_API void Nexus_SignatureClear(NexusSignatureHandle scanner) {
    if (scanner) {
        SignatureContext* ctx = static_cast<SignatureContext*>(scanner);
        ctx->signatures.clear();
    }
}

NEXUS_API NexusResult Nexus_SignatureScanPattern(
    NexusSignatureHandle scanner,
    const char* pattern,
    const char* moduleName,
    uint32_t flags,
    NexusSignatureMatch* matches,
    size_t maxMatches,
    size_t* matchCount)
{
    if (!scanner || !pattern) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    SignatureContext* ctx = static_cast<SignatureContext*>(scanner);

    /* Parse pattern */
    ParsedPattern parsed;
    if (!ParsePatternInternal(pattern, parsed)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    /* Create temporary signature entry */
    SignatureEntry entry;
    entry.id = 0;
    entry.info = {};
    entry.info.flags = flags;
    entry.pattern = std::move(parsed);

    /* Reset counters */
    ctx->scanCancelled = false;
    ctx->scanComplete = false;
    ctx->bytesScanned = 0;
    ctx->bytesTotal = 0;
    ctx->matchesFound = 0;

    bool firstOnly = (flags & NEXUS_SIG_FLAG_FIRST_MATCH) != 0;

    /* Scan */
    if (moduleName && moduleName[0] != '\0') {
        const NexusModuleInfo* mod = FindModule(ctx, moduleName);
        if (mod) {
            ctx->bytesTotal = mod->size;
            ScanModule(ctx, entry, mod, firstOnly);
        }
    } else {
        ScanAllMemory(ctx, entry, flags, firstOnly);
    }

    ctx->scanComplete = true;

    /* Return results */
    if (matchCount) {
        *matchCount = entry.matches.size();
    }

    if (matches && maxMatches > 0) {
        size_t toCopy = std::min(entry.matches.size(), maxMatches);
        memcpy(matches, entry.matches.data(), toCopy * sizeof(NexusSignatureMatch));
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SignatureScanAll(NexusSignatureHandle scanner) {
    if (!scanner) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    SignatureContext* ctx = static_cast<SignatureContext*>(scanner);

    std::lock_guard<std::mutex> lock(ctx->scanMutex);

    /* Reset state */
    ctx->scanCancelled = false;
    ctx->scanComplete = false;
    ctx->bytesScanned = 0;
    ctx->bytesTotal = 0;
    ctx->matchesFound = 0;

    /* Clear previous matches */
    for (auto& pair : ctx->signatures) {
        pair.second.matches.clear();
    }

    /* Scan each signature */
    for (auto& pair : ctx->signatures) {
        if (ctx->scanCancelled) break;

        SignatureEntry& sig = pair.second;
        bool firstOnly = (sig.info.flags & NEXUS_SIG_FLAG_FIRST_MATCH) != 0;

        if (sig.info.moduleName[0] != '\0') {
            const NexusModuleInfo* mod = FindModule(ctx, sig.info.moduleName);
            if (mod) {
                ScanModule(ctx, sig, mod, firstOnly);
            }
        } else {
            ScanAllMemory(ctx, sig, sig.info.flags, firstOnly);
        }
    }

    ctx->scanComplete = true;
    return NEXUS_OK;
}

NEXUS_API void Nexus_SignatureScanCancel(NexusSignatureHandle scanner) {
    if (scanner) {
        SignatureContext* ctx = static_cast<SignatureContext*>(scanner);
        ctx->scanCancelled = true;
    }
}

NEXUS_API NexusResult Nexus_SignatureGetProgress(
    NexusSignatureHandle scanner,
    NexusSignatureScanProgress* progress)
{
    if (!scanner || !progress) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    SignatureContext* ctx = static_cast<SignatureContext*>(scanner);

    progress->bytesScanned = ctx->bytesScanned;
    progress->bytesTotal = ctx->bytesTotal;
    progress->matchesFound = ctx->matchesFound;
    progress->isComplete = ctx->scanComplete ? 1 : 0;
    progress->wasCancelled = ctx->scanCancelled ? 1 : 0;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SignatureGetMatches(
    NexusSignatureHandle scanner,
    uint32_t sigId,
    NexusSignatureMatch* matches,
    size_t maxMatches,
    size_t* matchCount)
{
    if (!scanner) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    SignatureContext* ctx = static_cast<SignatureContext*>(scanner);

    /* Get all matches */
    if (sigId == 0xFFFFFFFF) {
        size_t total = 0;
        for (const auto& pair : ctx->signatures) {
            total += pair.second.matches.size();
        }

        if (matchCount) {
            *matchCount = total;
        }

        if (matches && maxMatches > 0) {
            size_t copied = 0;
            for (const auto& pair : ctx->signatures) {
                for (const auto& match : pair.second.matches) {
                    if (copied >= maxMatches) break;
                    matches[copied++] = match;
                }
                if (copied >= maxMatches) break;
            }
        }

        return NEXUS_OK;
    }

    /* Get specific signature matches */
    auto it = ctx->signatures.find(sigId);
    if (it == ctx->signatures.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    if (matchCount) {
        *matchCount = it->second.matches.size();
    }

    if (matches && maxMatches > 0) {
        size_t toCopy = std::min(it->second.matches.size(), maxMatches);
        memcpy(matches, it->second.matches.data(), toCopy * sizeof(NexusSignatureMatch));
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SignatureResolve(
    NexusSignatureHandle scanner,
    uint32_t sigId,
    uint64_t* resolvedAddress)
{
    if (!scanner || !resolvedAddress) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    SignatureContext* ctx = static_cast<SignatureContext*>(scanner);

    auto it = ctx->signatures.find(sigId);
    if (it == ctx->signatures.end()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    if (it->second.matches.empty()) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    *resolvedAddress = it->second.matches[0].address;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SignatureParsePattern(
    const char* pattern,
    uint8_t* bytes,
    uint8_t* mask,
    size_t maxLen,
    size_t* patternLen)
{
    if (!pattern) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    ParsedPattern parsed;
    if (!ParsePatternInternal(pattern, parsed)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (patternLen) {
        *patternLen = parsed.bytes.size();
    }

    if (bytes && mask && maxLen > 0) {
        size_t toCopy = std::min(parsed.bytes.size(), maxLen);
        memcpy(bytes, parsed.bytes.data(), toCopy);
        memcpy(mask, parsed.mask.data(), toCopy);
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_SignatureFindInBuffer(
    const uint8_t* buffer,
    size_t bufferSize,
    const uint8_t* pattern,
    const uint8_t* mask,
    size_t patternLen,
    size_t* offset)
{
    if (!buffer || !pattern || !mask || patternLen == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    if (bufferSize < patternLen) {
        return NEXUS_ERROR_NOT_FOUND;
    }

    size_t maxOffset = bufferSize - patternLen;

    for (size_t i = 0; i <= maxOffset; i++) {
        bool match = true;
        for (size_t j = 0; j < patternLen; j++) {
            if (mask[j] != 0x00 && buffer[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            if (offset) {
                *offset = i;
            }
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

NEXUS_API NexusResult Nexus_SignatureRegisterAsSymbol(
    NexusSignatureHandle scanner,
    uint32_t sigId,
    const char* symbolName,
    NexusAssemblerHandle assembler)
{
    if (!scanner || !symbolName || !assembler) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    uint64_t address;
    NexusResult result = Nexus_SignatureResolve(scanner, sigId, &address);
    if (result != NEXUS_OK) {
        return result;
    }

    return Nexus_AssemblerAddSymbol(assembler, symbolName, address);
}
