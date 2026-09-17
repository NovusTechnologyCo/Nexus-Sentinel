/**
 * @file trace.cpp
 * @brief Trace logger: create/destroy, configure, start/stop, entry retrieval, export, and search.
 *
 * Records per-instruction execution traces via single-step debugging.
 * Maintains a ring buffer of NexusTraceEntry records with timestamps,
 * register snapshots, call-depth tracking, and symbol annotations.
 *
 * Instruction classification and disassembly helpers are in trace_classify.cpp.
 */

#include "trace_internal.h"

/* ============================================================================
 * Global Trace Container
 * ============================================================================ */

std::mutex g_traceMutex;
std::unordered_map<void*, std::unique_ptr<TraceContext>> g_traces;

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_TraceCreate(
    NexusDebuggerHandle debugger,
    NexusTraceHandle* tracer)
{
    if (!debugger || !tracer) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    auto ctx = std::make_unique<TraceContext>();
    ctx->debugger = debugger;
    ctx->process = nullptr;
    ctx->rawProcessHandle = nullptr;
    ctx->isRunning = false;
    ctx->shouldStop = false;
    ctx->nextIndex = 0;
    ctx->currentCallDepth = 0;
    ctx->tracingThreadId = 0;

    // Default configuration
    ctx->config.flags = NEXUS_TRACE_FLAG_INSTRUCTIONS;
    ctx->config.maxEntries = 10000;
    ctx->config.stopCondition = NEXUS_TRACE_STOP_NEVER;
    ctx->config.stopValue = 0;
    ctx->config.startAddress = 0;
    ctx->config.endAddress = 0;
    ctx->config.moduleFilter[0] = L'\0';

    memset(&ctx->stats, 0, sizeof(ctx->stats));

    auto* rawPtr = ctx.get();
    {
        std::lock_guard<std::mutex> lock(g_traceMutex);
        g_traces[rawPtr] = std::move(ctx);
    }

    *tracer = rawPtr;
    return NEXUS_OK;
}

NEXUS_API void Nexus_TraceDestroy(NexusTraceHandle tracer) {
    if (tracer) {
        TraceContext* ctx = static_cast<TraceContext*>(tracer);

        {
            std::lock_guard<std::mutex> ctxLock(ctx->mutex);
            ctx->shouldStop = true;
            ctx->isRunning = false;
        }

        std::lock_guard<std::mutex> lock(g_traceMutex);
        g_traces.erase(tracer);
    }
}

NEXUS_API NexusResult Nexus_TraceConfigure(
    NexusTraceHandle tracer,
    const NexusTraceConfig* config)
{
    if (!tracer || !config) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    if (ctx->isRunning) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    ctx->config = *config;

    if (ctx->config.maxEntries == 0) {
        ctx->config.maxEntries = 10000;
    }
    if (ctx->config.maxEntries > 1000000) {
        ctx->config.maxEntries = 1000000;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TraceStart(
    NexusTraceHandle tracer,
    uint32_t threadId)
{
    if (!tracer || threadId == 0) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    if (ctx->isRunning) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    ctx->tracingThreadId = threadId;
    ctx->isRunning = true;
    ctx->shouldStop = false;
    ctx->nextIndex = 0;
    ctx->currentCallDepth = 0;
    ctx->entries.clear();
    ctx->registerSnapshots.clear();

    memset(&ctx->stats, 0, sizeof(ctx->stats));

    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    ctx->stats.startTime = qpc.QuadPart;
    ctx->stats.isRunning = 1;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TraceStop(NexusTraceHandle tracer) {
    if (!tracer) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    ctx->shouldStop = true;
    ctx->isRunning = false;
    ctx->stats.isRunning = 0;

    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    ctx->stats.endTime = qpc.QuadPart;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TraceIsRunning(
    NexusTraceHandle tracer,
    uint32_t* isRunning)
{
    if (!tracer || !isRunning) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    *isRunning = ctx->isRunning ? 1 : 0;

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TraceGetStats(
    NexusTraceHandle tracer,
    NexusTraceStats* stats)
{
    if (!tracer || !stats) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    *stats = ctx->stats;
    stats->entriesInBuffer = ctx->entries.size();

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TraceGetEntries(
    NexusTraceHandle tracer,
    uint64_t startIndex,
    NexusTraceEntry* entries,
    size_t maxEntries,
    size_t* entryCount)
{
    if (!tracer || !entries || maxEntries == 0 || !entryCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    *entryCount = 0;

    if (ctx->entries.empty()) {
        return NEXUS_OK;
    }

    size_t startPos = 0;
    if (startIndex > 0) {
        for (size_t i = 0; i < ctx->entries.size(); i++) {
            if (ctx->entries[i].index >= startIndex) {
                startPos = i;
                break;
            }
        }
    }

    size_t count = 0;
    for (size_t i = startPos; i < ctx->entries.size() && count < maxEntries; i++) {
        entries[count++] = ctx->entries[i];
    }

    *entryCount = count;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TraceGetEntry(
    NexusTraceHandle tracer,
    uint64_t index,
    NexusTraceEntry* entry)
{
    if (!tracer || !entry) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    for (const auto& e : ctx->entries) {
        if (e.index == index) {
            *entry = e;
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

NEXUS_API NexusResult Nexus_TraceClear(NexusTraceHandle tracer) {
    if (!tracer) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    ctx->entries.clear();
    ctx->registerSnapshots.clear();
    ctx->nextIndex = 0;

    bool wasRunning = ctx->stats.isRunning != 0;
    uint64_t startTime = ctx->stats.startTime;
    memset(&ctx->stats, 0, sizeof(ctx->stats));
    if (wasRunning) {
        ctx->stats.isRunning = 1;
        ctx->stats.startTime = startTime;
    }

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TraceExport(
    NexusTraceHandle tracer,
    const wchar_t* filePath,
    uint32_t format)
{
    if (!tracer || !filePath) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    std::wstring path(filePath);
    uint32_t actualFormat = format;

    if (actualFormat == 0) {
        if (path.ends_with(L".csv")) actualFormat = 2;
        else if (path.ends_with(L".json")) actualFormat = 3;
        else actualFormat = 1;
    }

    std::ofstream file(filePath);
    if (!file.is_open()) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    if (actualFormat == 2) {
        // CSV format
        file << "Index,Timestamp,Address,ThreadId,EventType,CallDepth,Disassembly,Symbol\n";
        for (const auto& e : ctx->entries) {
            file << e.index << ","
                 << e.timestamp << ","
                 << "0x" << std::hex << e.address << std::dec << ","
                 << e.threadId << ","
                 << e.eventType << ","
                 << e.callDepth << ","
                 << "\"" << e.disassembly << "\","
                 << "\"" << e.symbolName << "\"\n";
        }
    } else if (actualFormat == 3) {
        // JSON format
        file << "{\n  \"entries\": [\n";
        bool first = true;
        for (const auto& e : ctx->entries) {
            if (!first) file << ",\n";
            first = false;
            file << "    {\"index\":" << e.index
                 << ",\"timestamp\":" << e.timestamp
                 << ",\"address\":\"0x" << std::hex << e.address << std::dec << "\""
                 << ",\"threadId\":" << e.threadId
                 << ",\"eventType\":" << e.eventType
                 << ",\"callDepth\":" << e.callDepth
                 << ",\"disassembly\":\"" << e.disassembly << "\""
                 << ",\"symbol\":\"" << e.symbolName << "\"}";
        }
        file << "\n  ]\n}\n";
    } else {
        // TXT format
        file << "Nexus Trace Log\n";
        file << "===============\n\n";
        file << "Total entries: " << ctx->entries.size() << "\n\n";

        for (const auto& e : ctx->entries) {
            file << "[" << e.index << "] ";
            file << "0x" << std::hex << e.address << std::dec << " ";

            switch (e.eventType) {
                case NEXUS_TRACE_INSTRUCTION: break;
                case NEXUS_TRACE_CALL: file << "[CALL] "; break;
                case NEXUS_TRACE_RET: file << "[RET] "; break;
                case NEXUS_TRACE_BRANCH: file << "[BRANCH] "; break;
                case NEXUS_TRACE_EXCEPTION: file << "[EXCEPTION] "; break;
                default: break;
            }

            for (uint32_t d = 0; d < e.callDepth && d < 20; d++) {
                file << "  ";
            }

            file << e.disassembly;

            if (e.symbolName[0]) {
                file << " ; " << e.symbolName;
                if (e.symbolOffset > 0) {
                    file << "+0x" << std::hex << e.symbolOffset << std::dec;
                }
            }

            file << "\n";
        }
    }

    file.close();
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_TraceGetRegisters(
    NexusTraceHandle tracer,
    uint64_t index,
    NexusTraceRegisters* regs)
{
    if (!tracer || !regs) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    for (const auto& snap : ctx->registerSnapshots) {
        if (snap.entryIndex == index) {
            *regs = snap.regs;
            return NEXUS_OK;
        }
    }

    return NEXUS_ERROR_NOT_FOUND;
}

NEXUS_API NexusResult Nexus_TraceFind(
    NexusTraceHandle tracer,
    int32_t eventType,
    uint64_t address,
    uint64_t startIndex,
    uint64_t* indices,
    size_t maxResults,
    size_t* resultCount)
{
    if (!tracer || !indices || maxResults == 0 || !resultCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    *resultCount = 0;
    size_t count = 0;

    for (const auto& e : ctx->entries) {
        if (e.index < startIndex) continue;

        bool match = true;

        if (eventType >= 0 && e.eventType != static_cast<uint32_t>(eventType)) {
            match = false;
        }

        if (address != 0 && e.address != address) {
            match = false;
        }

        if (match) {
            indices[count++] = e.index;
            if (count >= maxResults) break;
        }
    }

    *resultCount = count;
    return NEXUS_OK;
}

/* ============================================================================
 * Internal: Add trace entry (called from debugger callback)
 * ============================================================================ */

extern "C" NEXUS_API NexusResult Nexus_TraceAddEntry(
    NexusTraceHandle tracer,
    uint32_t threadId,
    const CONTEXT* context)
{
    if (!tracer || !context) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    if (!ctx->isRunning || ctx->shouldStop) {
        return NEXUS_OK;
    }

    if (ctx->tracingThreadId != 0 && threadId != ctx->tracingThreadId) {
        return NEXUS_OK;
    }

    uint64_t rip = context->Rip;

    if (ctx->config.startAddress != 0 || ctx->config.endAddress != 0) {
        if (rip < ctx->config.startAddress || rip > ctx->config.endAddress) {
            return NEXUS_OK;
        }
    }

    // Read instruction bytes
    uint8_t instrBytes[16] = {0};
    size_t bytesRead = 0;

    HANDLE hProcess = ctx->rawProcessHandle;
    if (hProcess) {
        ReadProcessMemory(hProcess, (LPCVOID)rip, instrBytes, 16, (SIZE_T*)&bytesRead);
    }

    size_t instrLen = TraceGetInstructionLength(instrBytes, bytesRead, true);
    if (instrLen == 0) instrLen = 1;

    // Classify instruction
    NexusTraceEventType eventType = NEXUS_TRACE_INSTRUCTION;
    uint64_t targetAddr = 0;

    if (IsCallInstruction(instrBytes, instrLen)) {
        eventType = NEXUS_TRACE_CALL;
        targetAddr = GetTargetAddress(rip, instrBytes, instrLen);
        ctx->currentCallDepth++;
        ctx->stats.totalCalls++;
    } else if (IsRetInstruction(instrBytes, instrLen)) {
        eventType = NEXUS_TRACE_RET;
        if (ctx->currentCallDepth > 0) ctx->currentCallDepth--;
        ctx->stats.totalReturns++;
    } else if (IsBranchInstruction(instrBytes, instrLen)) {
        eventType = NEXUS_TRACE_BRANCH;
        targetAddr = GetTargetAddress(rip, instrBytes, instrLen);
        ctx->stats.totalBranches++;
    }

    // Check flags filter
    bool shouldLog = false;
    if (ctx->config.flags & NEXUS_TRACE_FLAG_INSTRUCTIONS) {
        shouldLog = true;
    }
    if ((ctx->config.flags & NEXUS_TRACE_FLAG_CALLS) &&
        (eventType == NEXUS_TRACE_CALL || eventType == NEXUS_TRACE_RET)) {
        shouldLog = true;
    }
    if ((ctx->config.flags & NEXUS_TRACE_FLAG_BRANCHES) && eventType == NEXUS_TRACE_BRANCH) {
        shouldLog = true;
    }

    if (!shouldLog) {
        ctx->stats.totalInstructions++;
        return NEXUS_OK;
    }

    // Create entry
    NexusTraceEntry entry = {};
    entry.index = ctx->nextIndex++;

    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    entry.timestamp = qpc.QuadPart;

    entry.address = rip;
    entry.targetAddress = targetAddr;
    entry.threadId = threadId;
    entry.eventType = eventType;
    entry.instructionSize = static_cast<uint32_t>(instrLen);
    entry.callDepth = ctx->currentCallDepth;

    memcpy(entry.instructionBytes, instrBytes, std::min(instrLen, (size_t)16));

    // Disassemble if requested
    if (ctx->config.flags & NEXUS_TRACE_FLAG_DISASM) {
        DisassembleInstruction(rip, instrBytes, instrLen, entry.disassembly, sizeof(entry.disassembly));
    }

    // Add to buffer (ring buffer behavior)
    if (ctx->entries.size() >= ctx->config.maxEntries) {
        ctx->entries.pop_front();
        ctx->stats.entriesDropped++;
    }
    ctx->entries.push_back(entry);

    // Save registers if requested
    if (ctx->config.flags & NEXUS_TRACE_FLAG_REGISTERS) {
        TraceRegisterEntry regEntry;
        regEntry.entryIndex = entry.index;
        regEntry.regs.rax = context->Rax;
        regEntry.regs.rbx = context->Rbx;
        regEntry.regs.rcx = context->Rcx;
        regEntry.regs.rdx = context->Rdx;
        regEntry.regs.rsi = context->Rsi;
        regEntry.regs.rdi = context->Rdi;
        regEntry.regs.rbp = context->Rbp;
        regEntry.regs.rsp = context->Rsp;
        regEntry.regs.r8 = context->R8;
        regEntry.regs.r9 = context->R9;
        regEntry.regs.r10 = context->R10;
        regEntry.regs.r11 = context->R11;
        regEntry.regs.r12 = context->R12;
        regEntry.regs.r13 = context->R13;
        regEntry.regs.r14 = context->R14;
        regEntry.regs.r15 = context->R15;
        regEntry.regs.rip = context->Rip;
        regEntry.regs.rflags = context->EFlags;
        regEntry.regs.cs = static_cast<uint32_t>(context->SegCs);
        regEntry.regs.ss = static_cast<uint32_t>(context->SegSs);
        regEntry.regs.ds = static_cast<uint32_t>(context->SegDs);
        regEntry.regs.es = static_cast<uint32_t>(context->SegEs);
        regEntry.regs.fs = static_cast<uint32_t>(context->SegFs);
        regEntry.regs.gs = static_cast<uint32_t>(context->SegGs);

        ctx->registerSnapshots.push_back(regEntry);

        while (ctx->registerSnapshots.size() > ctx->config.maxEntries) {
            ctx->registerSnapshots.erase(ctx->registerSnapshots.begin());
        }
    }

    ctx->stats.totalInstructions++;

    if (ctx->currentCallDepth > ctx->stats.maxCallDepth) {
        ctx->stats.maxCallDepth = ctx->currentCallDepth;
    }

    // Check stop conditions
    bool stopNow = false;

    switch (ctx->config.stopCondition) {
        case NEXUS_TRACE_STOP_COUNT:
            if (ctx->stats.totalInstructions >= ctx->config.stopValue) {
                stopNow = true;
            }
            break;
        case NEXUS_TRACE_STOP_ADDRESS:
            if (rip == ctx->config.stopValue) {
                stopNow = true;
            }
            break;
        case NEXUS_TRACE_STOP_CALL_DEPTH:
            if (eventType == NEXUS_TRACE_RET && ctx->currentCallDepth == 0) {
                stopNow = true;
            }
            break;
        default:
            break;
    }

    if (stopNow) {
        ctx->shouldStop = true;
        ctx->isRunning = false;
        ctx->stats.isRunning = 0;
        QueryPerformanceCounter(&qpc);
        ctx->stats.endTime = qpc.QuadPart;
    }

    return NEXUS_OK;
}

// Helper to set the process handle (called during initialization)
extern "C" NEXUS_API NexusResult Nexus_TraceSetProcessHandle(
    NexusTraceHandle tracer,
    HANDLE processHandle)
{
    if (!tracer) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    TraceContext* ctx = static_cast<TraceContext*>(tracer);

    std::lock_guard<std::mutex> lock(ctx->mutex);
    ctx->rawProcessHandle = processHandle;

    return NEXUS_OK;
}
