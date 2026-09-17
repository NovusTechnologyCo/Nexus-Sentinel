/**
 * @file disasm_internal.h
 * @brief Internal header shared by disasm.cpp and disasm_flow.cpp.
 *
 * Includes the Zydis header and declares shared global state (decoder,
 * formatter) and cross-file helper prototypes used by both the core
 * disassembly and flow-control analysis source files.
 */

#pragma once

#include "nexus_api.h"
#include "../third_party/amalgamated-dist/Zydis.h"

#include <cstring>
#include <algorithm>

/* ============================================================================
 * Cross-File Function Prototypes
 * ============================================================================ */

/* --- disasm.cpp --- */
ZydisMachineMode ConvertMachineMode(NexusMachineMode mode);
bool IsBranch(ZydisMnemonic mnemonic);
bool IsCall(ZydisMnemonic mnemonic);
bool IsReturn(ZydisMnemonic mnemonic);
bool IsConditional(ZydisMnemonic mnemonic);
