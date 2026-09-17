/**
 * @file ldisasm.h
 * @brief Minimal x86/x64 length disassembler for hook trampolines.
 *
 * Determines the byte length of an instruction without full decode.
 * Used internally by the hooking subsystem to copy whole instructions
 * into trampoline buffers without splitting them mid-instruction.
 */

#pragma once

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get the length of a single x86/x64 instruction.
 *
 * @param code Pointer to the instruction bytes
 * @param is64Bit True for 64-bit mode, false for 32-bit
 * @return Instruction length in bytes, or 0 on error
 */
size_t GetInstructionLength(const uint8_t* code, bool is64Bit);

/**
 * Calculate minimum bytes needed to copy for a hook.
 * Ensures we copy complete instructions.
 *
 * @param code Pointer to the code to analyze
 * @param minBytes Minimum number of bytes needed for the hook jump
 * @param is64Bit True for 64-bit code
 * @return Number of bytes to copy (>= minBytes), or 0 on error
 */
size_t GetHookSize(const uint8_t* code, size_t minBytes, bool is64Bit);

#ifdef __cplusplus
}
#endif
