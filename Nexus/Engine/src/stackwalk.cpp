/**
 * @file stackwalk.cpp
 * @brief Stack walker public API: create/destroy, walk, resolve, and refresh.
 *
 * Manages stack-walker instances and dispatches to the StackWalk64-based
 * walking implementations.  Supports walking by thread ID, from a
 * supplied CONTEXT, single-address resolution, and all-thread batch walks.
 *
 * Walking implementations are in stackwalk_walk.cpp.
 */

#include "stackwalk_internal.h"

/* ============================================================================
 * Global Container
 * ============================================================================ */

std::mutex g_stackWalkerMutex;
std::unordered_map<void*, std::unique_ptr<StackWalkerContext>> g_stackWalkers;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static bool InitializeSymbols(StackWalkerContext* ctx) {
    if (ctx->symbolsInitialized) return true;

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_NO_PROMPTS);

    if (!SymInitialize(ctx->rawHandle, nullptr, FALSE)) {
        return false;
    }

    ctx->symbolsInitialized = true;
    return true;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

NEXUS_API NexusResult Nexus_StackWalkerCreate(
    NexusProcessHandle process,
    NexusStackWalkerHandle* walker)
{
    if (!process || !walker) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    HANDLE rawHandle = nullptr;
    if (Nexus_GetRawHandle(process, (void**)&rawHandle) != NEXUS_OK) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    NexusProcessInfo procInfo;
    if (Nexus_GetProcessInfo(process, &procInfo) != NEXUS_OK) {
        return NEXUS_ERROR_INVALID_HANDLE;
    }

    auto ctx = std::make_unique<StackWalkerContext>();
    ctx->process = process;
    ctx->rawHandle = rawHandle;
    ctx->is32BitProcess = (procInfo.is32Bit != 0);
    ctx->modulesCached = false;
    ctx->symbolsInitialized = false;

    InitializeSymbols(ctx.get());

    auto* rawPtr = ctx.get();
    {
        std::lock_guard<std::mutex> lock(g_stackWalkerMutex);
        g_stackWalkers[rawPtr] = std::move(ctx);
    }

    *walker = rawPtr;
    return NEXUS_OK;
}

NEXUS_API void Nexus_StackWalkerDestroy(NexusStackWalkerHandle walker) {
    if (walker) {
        StackWalkerContext* ctx = static_cast<StackWalkerContext*>(walker);

        if (ctx->symbolsInitialized) {
            SymCleanup(ctx->rawHandle);
        }

        std::lock_guard<std::mutex> lock(g_stackWalkerMutex);
        g_stackWalkers.erase(walker);
    }
}

NEXUS_API NexusResult Nexus_StackWalk(
    NexusStackWalkerHandle walker,
    uint32_t threadId,
    uint32_t flags,
    NexusStackFrame* frames,
    size_t maxFrames,
    size_t* frameCount)
{
    if (!walker || !frames || maxFrames == 0 || !frameCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    StackWalkerContext* ctx = static_cast<StackWalkerContext*>(walker);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    *frameCount = 0;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                 FALSE, threadId);
    if (!hThread) {
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    DWORD suspendCount = SuspendThread(hThread);
    if (suspendCount == (DWORD)-1) {
        CloseHandle(hThread);
        return NEXUS_ERROR_ACCESS_DENIED;
    }

    NexusResult result = NEXUS_OK;

#ifdef _WIN64
    if (ctx->is32BitProcess) {
        WOW64_CONTEXT wow64Context = {};
        wow64Context.ContextFlags = WOW64_CONTEXT_FULL;

        if (Wow64GetThreadContext(hThread, &wow64Context)) {
            result = StackWalkImpl32(ctx, &wow64Context, flags, frames, maxFrames, frameCount);
        } else {
            result = NEXUS_ERROR_ACCESS_DENIED;
        }
    } else {
        CONTEXT context = {};
        context.ContextFlags = CONTEXT_FULL;

        if (GetThreadContext(hThread, &context)) {
            result = StackWalkImpl64(ctx, &context, flags, frames, maxFrames, frameCount);
        } else {
            result = NEXUS_ERROR_ACCESS_DENIED;
        }
    }
#else
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_FULL;

    if (GetThreadContext(hThread, &context)) {
        size_t count = 0;
        uint32_t ebp = context.Ebp;
        uint32_t eip = context.Eip;
        uint32_t esp = context.Esp;

        while (count < maxFrames && ebp != 0) {
            NexusStackFrame& frame = frames[count];
            memset(&frame, 0, sizeof(frame));

            frame.instructionPointer = eip;
            frame.frameAddress = ebp;
            frame.stackPointer = esp;
            frame.frameIndex = static_cast<uint32_t>(count);

            if (flags & (NEXUS_STACK_RESOLVE_SYMBOLS | NEXUS_STACK_RESOLVE_MODULES)) {
                StackResolveSymbolForFrame(ctx, frame.instructionPointer, &frame, flags);
            }

            uint32_t stackData[2];
            size_t bytesRead;
            if (Nexus_ReadMemory(ctx->process, ebp, stackData, sizeof(stackData), &bytesRead) != NEXUS_OK) {
                break;
            }

            frame.returnAddress = stackData[1];
            count++;

            esp = ebp + 8;
            ebp = stackData[0];
            eip = stackData[1];

            if (ebp == 0 || stackData[1] == 0) break;
        }

        *frameCount = count;
        result = NEXUS_OK;
    } else {
        result = NEXUS_ERROR_ACCESS_DENIED;
    }
#endif

    ResumeThread(hThread);
    CloseHandle(hThread);

    return result;
}

NEXUS_API NexusResult Nexus_StackWalkFromContext(
    NexusStackWalkerHandle walker,
    const void* context,
    size_t contextSize,
    int is32Bit,
    uint32_t flags,
    NexusStackFrame* frames,
    size_t maxFrames,
    size_t* frameCount)
{
    if (!walker || !context || !frames || maxFrames == 0 || !frameCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    StackWalkerContext* ctx = static_cast<StackWalkerContext*>(walker);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    *frameCount = 0;

#ifdef _WIN64
    if (is32Bit) {
        if (contextSize < sizeof(WOW64_CONTEXT)) {
            return NEXUS_ERROR_INVALID_PARAMETER;
        }

        WOW64_CONTEXT wow64Context;
        memcpy(&wow64Context, context, sizeof(WOW64_CONTEXT));
        return StackWalkImpl32(ctx, &wow64Context, flags, frames, maxFrames, frameCount);
    } else {
        if (contextSize < sizeof(CONTEXT)) {
            return NEXUS_ERROR_INVALID_PARAMETER;
        }

        CONTEXT ctx64;
        memcpy(&ctx64, context, sizeof(CONTEXT));
        return StackWalkImpl64(ctx, &ctx64, flags, frames, maxFrames, frameCount);
    }
#else
    if (contextSize < sizeof(CONTEXT)) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    CONTEXT ctx32;
    memcpy(&ctx32, context, sizeof(CONTEXT));

    size_t count = 0;
    uint32_t ebp = ctx32.Ebp;
    uint32_t eip = ctx32.Eip;
    uint32_t esp = ctx32.Esp;

    while (count < maxFrames && ebp != 0) {
        NexusStackFrame& frame = frames[count];
        memset(&frame, 0, sizeof(frame));

        frame.instructionPointer = eip;
        frame.frameAddress = ebp;
        frame.stackPointer = esp;
        frame.frameIndex = static_cast<uint32_t>(count);

        if (flags & (NEXUS_STACK_RESOLVE_SYMBOLS | NEXUS_STACK_RESOLVE_MODULES)) {
            StackResolveSymbolForFrame(ctx, frame.instructionPointer, &frame, flags);
        }

        uint32_t stackData[2];
        size_t bytesRead;
        if (Nexus_ReadMemory(ctx->process, ebp, stackData, sizeof(stackData), &bytesRead) != NEXUS_OK) {
            break;
        }

        frame.returnAddress = stackData[1];
        count++;

        esp = ebp + 8;
        ebp = stackData[0];
        eip = stackData[1];

        if (ebp == 0 || stackData[1] == 0) break;
    }

    *frameCount = count;
    return NEXUS_OK;
#endif
}

NEXUS_API NexusResult Nexus_StackResolveAddress(
    NexusStackWalkerHandle walker,
    uint64_t address,
    uint32_t flags,
    NexusStackFrame* frame)
{
    if (!walker || !frame) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    StackWalkerContext* ctx = static_cast<StackWalkerContext*>(walker);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    memset(frame, 0, sizeof(NexusStackFrame));
    frame->instructionPointer = address;

    StackResolveSymbolForFrame(ctx, address, frame, flags);

    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StackWalkAllThreads(
    NexusStackWalkerHandle walker,
    uint32_t flags,
    size_t maxFramesPerThread,
    NexusStackFrame* frames,
    uint32_t* threadIds,
    size_t* frameCounts,
    size_t maxThreads,
    size_t* threadCount)
{
    if (!walker || !frames || !threadIds || !frameCounts || !threadCount) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    StackWalkerContext* ctx = static_cast<StackWalkerContext*>(walker);

    size_t count = 0;
    Nexus_EnumerateThreads(ctx->process, nullptr, 0, &count);

    if (count == 0) {
        *threadCount = 0;
        return NEXUS_OK;
    }

    std::vector<NexusThreadInfo> threads(count);
    Nexus_EnumerateThreads(ctx->process, threads.data(), count, &count);

    size_t processed = 0;
    size_t frameOffset = 0;

    for (size_t i = 0; i < count && processed < maxThreads; i++) {
        threadIds[processed] = threads[i].threadId;

        size_t thisFrameCount = 0;
        NexusResult result = Nexus_StackWalk(
            walker,
            threads[i].threadId,
            flags,
            frames + frameOffset,
            maxFramesPerThread,
            &thisFrameCount
        );

        if (result == NEXUS_OK) {
            frameCounts[processed] = thisFrameCount;
            frameOffset += thisFrameCount;
        } else {
            frameCounts[processed] = 0;
        }
        processed++;
    }

    *threadCount = processed;
    return NEXUS_OK;
}

NEXUS_API NexusResult Nexus_StackWalkerRefreshSymbols(NexusStackWalkerHandle walker) {
    if (!walker) {
        return NEXUS_ERROR_INVALID_PARAMETER;
    }

    StackWalkerContext* ctx = static_cast<StackWalkerContext*>(walker);
    std::lock_guard<std::mutex> lock(ctx->mutex);

    ctx->modulesCached = false;
    ctx->modules.clear();

    if (ctx->symbolsInitialized) {
        SymRefreshModuleList(ctx->rawHandle);
    }

    return NEXUS_OK;
}
