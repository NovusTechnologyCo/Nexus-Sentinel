/*
 * Ssdt.h -- reach a syscall body ntoskrnl does not export. Reasoning lives in Ssdt.c.
 *
 * The registry family (NtSetValueKey, NtCreateKey, NtDeleteKey, ...) is Zw-only, and the Zw stub is
 * NOT the function -- a usermode caller never executes it. This is the route to the body a `syscall`
 * actually lands in.
 */

#pragma once

#include <ntddk.h>

void*
NxcResolveSyscallByIndex(
	_In_ UINT32 Index
	);

void*
NxcResolveSyscallRoutine(
	_In_z_ CONST CHAR* NtName
	);

void
NxcSsdtStats(
	_Out_ UINT64* OutTable,
	_Out_ UINT32* OutLimit
	);
