/**
 * @file stackwalk_walk.cpp
 * @brief Stack walking implementations: x64 and WOW64 StackWalk64, module/symbol caching.
 *
 * Caches loaded modules for fast address-to-module lookup, uses
 * StackWalk64 (with ReadProcessMemoryProc64 and FunctionTableAccessProc64
 * callbacks) for native x64 and WOW64 walks, and resolves symbols via
 * the DbgHelp symbol handler.
 */

#include "stackwalk_internal.h"

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static void StackCacheModules(StackWalkerContext* ctx) {
    if (ctx->modulesCached) return;

    size_t count = 0;
    Nexus_EnumerateModules(ctx->process, nullptr, 0, &count);

    if (count > 0) {
        std::vector<NexusModuleInfo> mods(count);
        Nexus_EnumerateModules(ctx->process, mods.data(), count, &count);

        ctx->modules.clear();
        ctx->modules.reserve(count);

        for (size_t i = 0; i < count; i++) {
            ModuleCache mc;
            mc.baseAddress = mods[i].baseAddress;
            mc.size = mods[i].size;
            mc.name = mods[i].name;
            mc.path = mods[i].path;
            ctx->modules.push_back(std::move(mc));
        }
    }

    ctx->modulesCached = true;
}

static const ModuleCache* StackFindModuleByAddress(StackWalkerContext* ctx, uint64_t address) {
    StackCacheModules(ctx);

    for (const auto& mod : ctx->modules) {
        if (address >= mod.baseAddress && address < mod.baseAddress + mod.size) {
            return &mod;
        }
    }

    return nullptr;
}

void StackResolveSymbolForFrame(StackWalkerContext* ctx, uint64_t address,
                                NexusStackFrame* frame, uint32_t flags) {
    const ModuleCache* mod = StackFindModuleByAddress(ctx, address);
    if (mod) {
        frame->moduleBase = mod->baseAddress;
        wcsncpy_s(frame->moduleName, mod->name.c_str(), 63);
    }

    if ((flags & NEXUS_STACK_RESOLVE_SYMBOLS) && ctx->symbolsInitialized) {
        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        PSYMBOL_INFO symbol = (PSYMBOL_INFO)buffer;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (SymFromAddr(ctx->rawHandle, address, &displacement, symbol)) {
            strncpy_s(frame->functionName, symbol->Name, 127);
            frame->functionOffset = static_cast<uint32_t>(displacement);
        }
    }
}

/* ============================================================================
 * x64 Stack Walking
 * ============================================================================ */

NexusResult StackWalkImpl64(StackWalkerContext* ctx, CONTEXT* context,
                            uint32_t flags, NexusStackFrame* frames,
                            size_t maxFrames, size_t* frameCount) {
    size_t count = 0;

    STACKFRAME64 stackFrame = {};
    stackFrame.AddrPC.Offset = context->Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;

    while (count < maxFrames) {
        if (!StackWalk64(
            IMAGE_FILE_MACHINE_AMD64,
            ctx->rawHandle,
            nullptr,
            &stackFrame,
            context,
            nullptr,
            SymFunctionTableAccess64,
            SymGetModuleBase64,
            nullptr
        )) {
            break;
        }

        if (stackFrame.AddrPC.Offset == 0) {
            break;
        }

        NexusStackFrame& frame = frames[count];
        memset(&frame, 0, sizeof(frame));

        frame.instructionPointer = stackFrame.AddrPC.Offset;
        frame.returnAddress = stackFrame.AddrReturn.Offset;
        frame.frameAddress = stackFrame.AddrFrame.Offset;
        frame.stackPointer = stackFrame.AddrStack.Offset;
        frame.frameIndex = static_cast<uint32_t>(count);

        if (flags & (NEXUS_STACK_RESOLVE_SYMBOLS | NEXUS_STACK_RESOLVE_MODULES)) {
            StackResolveSymbolForFrame(ctx, frame.instructionPointer, &frame, flags);
        }

        count++;

        if (stackFrame.AddrReturn.Offset == 0) {
            break;
        }
    }

    *frameCount = count;
    return NEXUS_OK;
}

/* ============================================================================
 * x86/WOW64 Stack Walking
 * ============================================================================ */

#ifdef _WIN64
NexusResult StackWalkImpl32(StackWalkerContext* ctx, WOW64_CONTEXT* context,
                            uint32_t flags, NexusStackFrame* frames,
                            size_t maxFrames, size_t* frameCount) {
    size_t count = 0;

    uint32_t ebp = context->Ebp;
    uint32_t eip = context->Eip;
    uint32_t esp = context->Esp;

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

        uint32_t nextEbp = stackData[0];
        uint32_t retAddr = stackData[1];

        frame.returnAddress = retAddr;
        count++;

        if (nextEbp == 0 || nextEbp <= ebp || retAddr == 0) {
            break;
        }

        esp = ebp + 8;
        ebp = nextEbp;
        eip = retAddr;
    }

    *frameCount = count;
    return NEXUS_OK;
}
#endif
