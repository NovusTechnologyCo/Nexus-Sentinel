using System.Runtime.InteropServices;
using System.Text;
using Nexus.UI.Interop;

namespace Nexus.UI.Services;

public partial class ApiMonitorService
{
    #region Injection Methods

    /// <summary>
    /// Direct injection via P/Invoke — opens its own handle, tries each injection step
    /// individually, and reports detailed Win32 errors at each failure point.
    /// Returns null on success, or an error string describing exactly what failed.
    /// </summary>
    private static string? DirectInjectDll(uint pid, string dllPath)
    {
        // Step 1: Open process with PROCESS_ALL_ACCESS
        var hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return $"DirectInject: OpenProcess(ALL_ACCESS) failed, Win32 error={err} (0x{err:X})";
        }

        try
        {
            // Step 2: Get LoadLibraryW address
            var hKernel32 = GetModuleHandle("kernel32.dll");
            if (hKernel32 == IntPtr.Zero)
                return "DirectInject: GetModuleHandle(kernel32.dll) returned null";

            var pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
            if (pLoadLibraryW == IntPtr.Zero)
                return "DirectInject: GetProcAddress(LoadLibraryW) returned null";

            // Step 3: Allocate memory for DLL path in target process
            byte[] pathBytes = System.Text.Encoding.Unicode.GetBytes(dllPath + '\0');
            var remoteMem = VirtualAllocEx(hProcess, IntPtr.Zero, (nuint)pathBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (remoteMem == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return $"DirectInject: VirtualAllocEx failed, Win32 error={err} (0x{err:X})";
            }

            try
            {
                // Step 4: Write DLL path to target process
                if (!WriteProcessMemory(hProcess, remoteMem, pathBytes, (nuint)pathBytes.Length, out _))
                {
                    int err = Marshal.GetLastWin32Error();
                    return $"DirectInject: WriteProcessMemory failed, Win32 error={err} (0x{err:X})";
                }

                // Step 5: Create remote thread calling LoadLibraryW
                var hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, pLoadLibraryW, remoteMem, 0, out _);
                if (hThread == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    return $"DirectInject: CreateRemoteThread failed, Win32 error={err} (0x{err:X})";
                }

                // Step 6: Wait for LoadLibraryW to complete
                WaitForSingleObject(hThread, 30000);
                GetExitCodeThread(hThread, out uint exitCode);
                CloseHandle(hThread);

                if (exitCode == 0)
                    return $"DirectInject: LoadLibraryW returned 0 — DLL failed to load (CIG/signature policy may block unsigned DLLs)";

                // Success!
                return null;
            }
            finally
            {
                VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Manual-maps a DLL into the target process, bypassing CIG/signature policy.
    /// Parses the PE, applies relocations + resolves imports locally (system DLLs share
    /// base addresses across processes), writes the mapped image, then calls DllMain
    /// via a small shellcode stub.
    /// Returns null on success, or an error string.
    /// </summary>
    private static string? ManualMapInject(uint pid, string dllPath)
    {
        byte[] dllBytes;
        try { dllBytes = File.ReadAllBytes(dllPath); }
        catch (Exception ex) { return $"ManualMap: Failed to read DLL: {ex.Message}"; }

        // Validate DOS header
        if (dllBytes.Length < 64 || BitConverter.ToUInt16(dllBytes, 0) != 0x5A4D)
            return "ManualMap: Invalid PE — bad DOS signature";

        int e_lfanew = BitConverter.ToInt32(dllBytes, 0x3C);
        if (e_lfanew <= 0 || e_lfanew + 264 >= dllBytes.Length)
            return "ManualMap: Invalid PE — bad e_lfanew";

        if (BitConverter.ToUInt32(dllBytes, e_lfanew) != 0x00004550)
            return "ManualMap: Invalid PE — bad NT signature";

        int optHdr = e_lfanew + 24;
        ushort magic = BitConverter.ToUInt16(dllBytes, optHdr);
        bool isPE64 = magic == 0x20B;

        if (!isPE64)
            return "ManualMap: Only PE32+ (x64) supported for this target";

        // PE64 optional header fields
        uint entryPointRva = BitConverter.ToUInt32(dllBytes, optHdr + 16);
        ulong peImageBase = BitConverter.ToUInt64(dllBytes, optHdr + 24);
        uint sizeOfImage = BitConverter.ToUInt32(dllBytes, optHdr + 56);
        uint sizeOfHeaders = BitConverter.ToUInt32(dllBytes, optHdr + 60);
        ushort numSections = BitConverter.ToUInt16(dllBytes, e_lfanew + 6);
        ushort sizeOfOptHdr = BitConverter.ToUInt16(dllBytes, e_lfanew + 20);

        // DataDirectory: [1]=IMPORT (optHdr+120), [5]=BASERELOC (optHdr+152)
        uint importRva = BitConverter.ToUInt32(dllBytes, optHdr + 120);
        uint relocRva = BitConverter.ToUInt32(dllBytes, optHdr + 152);
        uint relocSize = BitConverter.ToUInt32(dllBytes, optHdr + 156);

        // Open our own handle with PROCESS_ALL_ACCESS
        var hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return $"ManualMap: OpenProcess failed, Win32={err} (0x{err:X})";
        }

        try
        {
            // Allocate RWX memory for the mapped image
            var remoteBase = VirtualAllocEx(hProcess, IntPtr.Zero, (nuint)sizeOfImage,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remoteBase == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return $"ManualMap: VirtualAllocEx({sizeOfImage} bytes, RWX) failed, Win32={err} (0x{err:X}) — ACG may be enabled";
            }

            try
            {
                // Build mapped image locally
                byte[] mapped = new byte[sizeOfImage];

                // Copy headers
                Array.Copy(dllBytes, 0, mapped, 0, Math.Min((int)sizeOfHeaders, dllBytes.Length));

                // Copy sections
                int secBase = e_lfanew + 24 + sizeOfOptHdr;
                for (int i = 0; i < numSections; i++)
                {
                    int sh = secBase + i * 40;
                    if (sh + 40 > dllBytes.Length) break;
                    uint va = BitConverter.ToUInt32(dllBytes, sh + 12);
                    uint rawSize = BitConverter.ToUInt32(dllBytes, sh + 16);
                    uint rawPtr = BitConverter.ToUInt32(dllBytes, sh + 20);

                    if (rawSize > 0 && rawPtr > 0 &&
                        rawPtr + rawSize <= (uint)dllBytes.Length &&
                        va + rawSize <= sizeOfImage)
                    {
                        Array.Copy(dllBytes, (int)rawPtr, mapped, (int)va, (int)rawSize);
                    }
                }

                // Apply base relocations
                long delta = (long)(ulong)remoteBase - (long)peImageBase;
                if (delta != 0 && relocRva > 0 && relocSize > 0)
                {
                    int pos = (int)relocRva;
                    int end = (int)(relocRva + relocSize);
                    while (pos + 8 <= end && pos + 8 <= mapped.Length)
                    {
                        uint blockVa = BitConverter.ToUInt32(mapped, pos);
                        uint blockSz = BitConverter.ToUInt32(mapped, pos + 4);
                        if (blockSz < 8) break;

                        int entries = ((int)blockSz - 8) / 2;
                        for (int i = 0; i < entries; i++)
                        {
                            ushort entry = BitConverter.ToUInt16(mapped, pos + 8 + i * 2);
                            int type = entry >> 12;
                            int offset = entry & 0xFFF;
                            int patchOff = (int)blockVa + offset;

                            if (type == 10 && patchOff + 8 <= mapped.Length) // IMAGE_REL_BASED_DIR64
                            {
                                long val = BitConverter.ToInt64(mapped, patchOff);
                                BitConverter.TryWriteBytes(mapped.AsSpan(patchOff), val + delta);
                            }
                            else if (type == 3 && patchOff + 4 <= mapped.Length) // IMAGE_REL_BASED_HIGHLOW
                            {
                                int val = BitConverter.ToInt32(mapped, patchOff);
                                BitConverter.TryWriteBytes(mapped.AsSpan(patchOff), val + (int)delta);
                            }
                        }
                        pos += (int)blockSz;
                    }
                }

                // Resolve imports — system DLLs have the same base in all processes
                if (importRva > 0)
                {
                    int pos = (int)importRva;
                    while (pos + 20 <= mapped.Length)
                    {
                        uint oft = BitConverter.ToUInt32(mapped, pos);
                        uint nameRva = BitConverter.ToUInt32(mapped, pos + 12);
                        uint ft = BitConverter.ToUInt32(mapped, pos + 16);
                        if (nameRva == 0) break;

                        string modName = ReadCString(mapped, (int)nameRva);
                        IntPtr hMod = GetModuleHandle(modName);
                        if (hMod == IntPtr.Zero)
                            hMod = LoadLibraryW(modName);
                        if (hMod == IntPtr.Zero)
                            return $"ManualMap: Cannot resolve import module '{modName}'";

                        uint iltRva = oft != 0 ? oft : ft;
                        int iltPos = (int)iltRva;
                        int iatPos = (int)ft;

                        while (iltPos + 8 <= mapped.Length)
                        {
                            ulong thunk = BitConverter.ToUInt64(mapped, iltPos);
                            if (thunk == 0) break;

                            IntPtr funcAddr;
                            if ((thunk & 0x8000000000000000) != 0)
                            {
                                funcAddr = GetProcAddressOrdinal(hMod, (IntPtr)(thunk & 0xFFFF));
                            }
                            else
                            {
                                int hintOff = (int)(thunk & 0x7FFFFFFF);
                                string funcName = ReadCString(mapped, hintOff + 2);
                                funcAddr = GetProcAddress(hMod, funcName);
                            }

                            if (funcAddr == IntPtr.Zero)
                                return $"ManualMap: Cannot resolve import from '{modName}'";

                            BitConverter.TryWriteBytes(mapped.AsSpan(iatPos), (ulong)funcAddr);
                            iltPos += 8;
                            iatPos += 8;
                        }
                        pos += 20;
                    }
                }

                // Write the fully-mapped image to the target
                if (!WriteProcessMemory(hProcess, remoteBase, mapped, (nuint)mapped.Length, out _))
                {
                    int err = Marshal.GetLastWin32Error();
                    return $"ManualMap: WriteProcessMemory(image) failed, Win32={err} (0x{err:X})";
                }

                FlushInstructionCache(hProcess, remoteBase, (nuint)sizeOfImage);

                // Build x64 shellcode to call DllMain(remoteBase, DLL_PROCESS_ATTACH, NULL)
                ulong entryAddr = (ulong)remoteBase + entryPointRva;
                byte[] shellcode =
                [
                    0x48, 0x83, 0xEC, 0x28,                     // sub rsp, 0x28
                    0xBA, 0x01, 0x00, 0x00, 0x00,               // mov edx, 1 (DLL_PROCESS_ATTACH)
                    0x45, 0x31, 0xC0,                            // xor r8d, r8d (lpReserved = NULL)
                    0x48, 0xB8, 0,0,0,0, 0,0,0,0,               // mov rax, <entry point>
                    0xFF, 0xD0,                                  // call rax
                    0x48, 0x83, 0xC4, 0x28,                     // add rsp, 0x28
                    0xC3                                         // ret
                ];
                BitConverter.TryWriteBytes(shellcode.AsSpan(14), entryAddr);

                var remoteCode = VirtualAllocEx(hProcess, IntPtr.Zero, (nuint)shellcode.Length,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (remoteCode == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    return $"ManualMap: VirtualAllocEx(shellcode) failed, Win32={err} (0x{err:X})";
                }

                try
                {
                    if (!WriteProcessMemory(hProcess, remoteCode, shellcode, (nuint)shellcode.Length, out _))
                    {
                        int err = Marshal.GetLastWin32Error();
                        return $"ManualMap: WriteProcessMemory(shellcode) failed, Win32={err} (0x{err:X})";
                    }

                    FlushInstructionCache(hProcess, remoteCode, (nuint)shellcode.Length);

                    var hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, remoteCode, remoteBase, 0, out _);
                    if (hThread == IntPtr.Zero)
                    {
                        int err = Marshal.GetLastWin32Error();
                        return $"ManualMap: CreateRemoteThread failed, Win32={err} (0x{err:X})";
                    }

                    WaitForSingleObject(hThread, 30000);
                    GetExitCodeThread(hThread, out uint exitCode);
                    CloseHandle(hThread);

                    if (exitCode == 0)
                        return "ManualMap: DllMain returned FALSE — DLL init failed";

                    // Erase PE headers so memory scanners can't identify the mapped region
                    var zeros = new byte[Math.Min(4096, (int)sizeOfHeaders)];
                    WriteProcessMemory(hProcess, remoteBase, zeros, (nuint)zeros.Length, out _);
                }
                finally
                {
                    VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
                }

                return null; // Success!
            }
            catch
            {
                VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
                throw;
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Executes DllMain in the target process by hijacking an existing thread.
    /// Avoids CreateRemoteThread (detected by EAC's kernel NtCreateThreadEx hook).
    /// Suspends a thread, redirects RIP to shellcode, resumes, waits for completion.
    /// </summary>
    private static string? ExecuteViaThreadHijack(IntPtr hProcess, uint pid, IntPtr remoteBase, uint entryPointRva)
    {
        // Find a thread in the target process to hijack
        var hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap == IntPtr.Zero || hSnap == (IntPtr)(-1))
            return $"ManualMap: CreateToolhelp32Snapshot(THREAD) failed, Win32={Marshal.GetLastWin32Error()}";

        uint targetTid = 0;
        try
        {
            var te = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };
            if (Thread32First(hSnap, ref te))
            {
                do
                {
                    if (te.th32OwnerProcessID == pid)
                    {
                        targetTid = te.th32ThreadID;
                        break;
                    }
                } while (Thread32Next(hSnap, ref te));
            }
        }
        finally { CloseHandle(hSnap); }

        if (targetTid == 0)
            return "ManualMap: No threads found in target process";

        // Open and suspend the thread
        var hThread = OpenThread(THREAD_ALL_ACCESS, false, targetTid);
        if (hThread == IntPtr.Zero)
            return $"ManualMap: OpenThread({targetTid}) failed, Win32={Marshal.GetLastWin32Error()}";

        try
        {
            if (SuspendThread(hThread) == 0xFFFFFFFF)
                return $"ManualMap: SuspendThread failed, Win32={Marshal.GetLastWin32Error()}";

            // Get thread context (must be 16-byte aligned for CONTEXT structure)
            // CONTEXT_AMD64 structure is 1232 bytes, needs 16-byte alignment
            const int CONTEXT_SIZE = 1232;
            var ctxBuf = Marshal.AllocHGlobal(CONTEXT_SIZE + 16);
            var ctxAligned = (IntPtr)(((long)ctxBuf + 15) & ~15L);

            try
            {
                // Zero the context and set ContextFlags
                for (int i = 0; i < CONTEXT_SIZE; i++)
                    Marshal.WriteByte(ctxAligned, i, 0);
                Marshal.WriteInt32(ctxAligned, 0x30, (int)CONTEXT_FULL); // ContextFlags at offset 0x30

                if (!GetThreadContext(hThread, ctxAligned))
                {
                    ResumeThread(hThread);
                    return $"ManualMap: GetThreadContext failed, Win32={Marshal.GetLastWin32Error()}";
                }

                // Read original RIP (offset 0xF8 in CONTEXT_AMD64)
                ulong originalRip = (ulong)Marshal.ReadInt64(ctxAligned, 0xF8);

                // Build hijack shellcode: save all volatile registers, call DllMain,
                // restore registers, jump back to original RIP.
                // The shellcode also writes 1 to a "done" flag so we know when it completes.
                ulong entryAddr = (ulong)remoteBase + entryPointRva;
                ulong dllBase = (ulong)remoteBase;

                // We'll put a "done flag" (8 bytes) right after the shellcode in the same allocation
                // Shellcode layout:
                //   [0x00..shellcode_end]: code
                //   [shellcode_end..+8]: done flag (0 initially, set to 1 after DllMain returns)
                var sc = new List<byte>();

                // push all volatile registers (caller-saved in Win64 ABI)
                sc.AddRange([0x50]);                              // push rax
                sc.AddRange([0x51]);                              // push rcx
                sc.AddRange([0x52]);                              // push rdx
                sc.AddRange([0x41, 0x50]);                        // push r8
                sc.AddRange([0x41, 0x51]);                        // push r9
                sc.AddRange([0x41, 0x52]);                        // push r10
                sc.AddRange([0x41, 0x53]);                        // push r11

                // sub rsp, 0x28 (shadow space + alignment)
                sc.AddRange([0x48, 0x83, 0xEC, 0x28]);

                // mov rcx, dllBase (hInstance = DLL base)
                sc.AddRange([0x48, 0xB9]);
                sc.AddRange(BitConverter.GetBytes(dllBase));

                // mov edx, 1 (DLL_PROCESS_ATTACH)
                sc.AddRange([0xBA, 0x01, 0x00, 0x00, 0x00]);

                // xor r8d, r8d (lpReserved = NULL)
                sc.AddRange([0x45, 0x31, 0xC0]);

                // mov rax, entryAddr
                sc.AddRange([0x48, 0xB8]);
                sc.AddRange(BitConverter.GetBytes(entryAddr));

                // call rax
                sc.AddRange([0xFF, 0xD0]);

                // add rsp, 0x28
                sc.AddRange([0x48, 0x83, 0xC4, 0x28]);

                // Set done flag: mov rax, <flagAddr> ; mov dword [rax], 1
                int flagOffset = sc.Count + 10 + 10 + 7 + 7 + 4 + 2 + 10 + 2; // approximate, recalculate below

                // We'll calculate the exact flag position after assembling the rest.
                // For now, use a placeholder approach: put flag at a known offset.
                // Simpler: allocate extra space, flag is at code_alloc + 256
                const int FLAG_OFFSET = 256;

                // mov rax, <code_alloc + FLAG_OFFSET>  (placeholder — patched below)
                int flagPatchPos = sc.Count + 2; // offset of the 8-byte address in mov rax
                sc.AddRange([0x48, 0xB8]);
                sc.AddRange(new byte[8]); // placeholder for flag address

                // mov dword [rax], 1
                sc.AddRange([0xC7, 0x00, 0x01, 0x00, 0x00, 0x00]);

                // pop all volatile registers (reverse order)
                sc.AddRange([0x41, 0x5B]);                        // pop r11
                sc.AddRange([0x41, 0x5A]);                        // pop r10
                sc.AddRange([0x41, 0x59]);                        // pop r9
                sc.AddRange([0x41, 0x58]);                        // pop r8
                sc.AddRange([0x5A]);                              // pop rdx
                sc.AddRange([0x59]);                              // pop rcx
                sc.AddRange([0x58]);                              // pop rax

                // jmp originalRip
                sc.AddRange([0x48, 0xB8]);                        // mov rax, <originalRip> -- use r11 instead to avoid clobbering rax
                // Actually we already restored rax. Use an indirect jmp:
                // We need to jump without clobbering any register. Use push + ret:
                // But we already restored all registers. Let's use push/ret pattern:
                sc.RemoveRange(sc.Count - 10, 10); // remove the last mov rax line

                // pop rax (restore)
                sc.AddRange([0x58]);

                // push <originalRip_lo32> won't work for 64-bit. Use:
                // mov [rsp-8], <low32>; mov [rsp-4], <high32>; sub rsp, 8; ret
                // Or simpler: just push the 64-bit value in two halves
                uint ripLo = (uint)(originalRip & 0xFFFFFFFF);
                uint ripHi = (uint)(originalRip >> 32);

                // push low32 (this pushes sign-extended, but we fix with mov)
                // Better approach: sub rsp, 8; mov dword [rsp], lo; mov dword [rsp+4], hi; ret
                sc.AddRange([0x48, 0x83, 0xEC, 0x08]);           // sub rsp, 8
                sc.AddRange([0xC7, 0x04, 0x24]);                 // mov dword [rsp], ripLo
                sc.AddRange(BitConverter.GetBytes(ripLo));
                sc.AddRange([0xC7, 0x44, 0x24, 0x04]);           // mov dword [rsp+4], ripHi
                sc.AddRange(BitConverter.GetBytes(ripHi));
                sc.AddRange([0xC3]);                              // ret (pops rsp -> rip)

                byte[] shellcode = [.. sc];

                // Allocate shellcode + flag space in target
                int allocSize = Math.Max(shellcode.Length + 64, FLAG_OFFSET + 8);
                var remoteCode = VirtualAllocEx(hProcess, IntPtr.Zero, (nuint)allocSize,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (remoteCode == IntPtr.Zero)
                {
                    ResumeThread(hThread);
                    return $"ManualMap: VirtualAllocEx(shellcode) failed, Win32={Marshal.GetLastWin32Error()}";
                }

                // Patch the flag address in shellcode
                ulong flagAddr = (ulong)remoteCode + FLAG_OFFSET;
                BitConverter.TryWriteBytes(shellcode.AsSpan(flagPatchPos), flagAddr);

                // Write shellcode to target
                if (!WriteProcessMemory(hProcess, remoteCode, shellcode, (nuint)shellcode.Length, out _))
                {
                    ResumeThread(hThread);
                    VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
                    return $"ManualMap: WriteProcessMemory(shellcode) failed, Win32={Marshal.GetLastWin32Error()}";
                }

                // Zero the done flag
                WriteProcessMemory(hProcess, (IntPtr)((long)remoteCode + FLAG_OFFSET), new byte[8], 8, out _);

                FlushInstructionCache(hProcess, remoteCode, (nuint)allocSize);

                // Redirect RIP to our shellcode
                Marshal.WriteInt64(ctxAligned, 0xF8, (long)(ulong)remoteCode);

                if (!SetThreadContext(hThread, ctxAligned))
                {
                    // Restore original RIP on failure
                    Marshal.WriteInt64(ctxAligned, 0xF8, (long)originalRip);
                    SetThreadContext(hThread, ctxAligned);
                    ResumeThread(hThread);
                    VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
                    return $"ManualMap: SetThreadContext failed, Win32={Marshal.GetLastWin32Error()}";
                }

                // Resume the hijacked thread
                ResumeThread(hThread);

                // Wait for the done flag to be set (poll every 10ms, up to 30 seconds)
                var flagBuf = new byte[4];
                bool done = false;
                for (int i = 0; i < 3000; i++)
                {
                    Thread.Sleep(10);
                    if (ReadProcessMemory(hProcess, (IntPtr)((long)remoteCode + FLAG_OFFSET),
                        flagBuf, 4, out _))
                    {
                        if (BitConverter.ToUInt32(flagBuf, 0) != 0)
                        {
                            done = true;
                            break;
                        }
                    }
                }

                // Clean up shellcode memory (DllMain spawned its own worker thread)
                VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);

                if (!done)
                    return "ManualMap: Thread hijack — DllMain did not complete within 30 seconds";

                return null; // Success
            }
            finally
            {
                Marshal.FreeHGlobal(ctxBuf);
            }
        }
        finally
        {
            CloseHandle(hThread);
        }
    }

    private static string ReadCString(byte[] data, int offset)
    {
        int end = offset;
        while (end < data.Length && data[end] != 0) end++;
        return Encoding.ASCII.GetString(data, offset, end - offset);
    }

    /// <summary>
    /// Attempts all x64 injection methods. Returns null on success, or error string.
    /// </summary>
    private string? TryInjectDll(int pid, IntPtr injectionHandle, bool isTarget32Bit)
    {
        var dllName = isTarget32Bit ? HookDllName32 : HookDllName64;
        var dllPath = FindHookDll(dllName);
        if (dllPath == null)
            return $"{dllName} not found";

        // Priority order for injection — ManualMap FIRST to avoid EAC module detection.
        // LoadLibrary-based methods trigger LdrRegisterDllNotification which EAC monitors,
        // causing immediate PACKER crash. ManualMap bypasses PEB module lists entirely.

        // Method 1: ManualMap (stealth — no PEB entry, no LdrNotification)
        if (!isTarget32Bit)
        {
            var mapErr = ManualMapInject((uint)pid, dllPath);
            if (mapErr == null) return null;
            OnError?.Invoke($"ManualMap failed: {mapErr} — trying LoadLibrary fallbacks");
        }

        // Method 2: Engine injection methods (uses LoadLibrary — detectable by anti-cheat)
        var injResult = new NexusEngine.NexusInjectResult();
        var engineResult = NexusEngine.Nexus_InjectDll(injectionHandle, dllPath, 0, out injResult);
        if (engineResult == NexusResult.OK && injResult.Success != 0) return null;

        injResult = default;
        engineResult = NexusEngine.Nexus_InjectDll(injectionHandle, dllPath,
            (uint)(NexusEngine.NexusInjectFlags.Stealth | NexusEngine.NexusInjectFlags.Wait), out injResult);
        if (engineResult == NexusResult.OK && injResult.Success != 0) return null;

        injResult = default;
        engineResult = NexusEngine.Nexus_InjectDll(injectionHandle, dllPath,
            (uint)(NexusEngine.NexusInjectFlags.Stealth | NexusEngine.NexusInjectFlags.SkipAttach | NexusEngine.NexusInjectFlags.Wait), out injResult);
        if (engineResult == NexusResult.OK && injResult.Success != 0) return null;

        // Method 3: Direct LoadLibrary injection (last resort)
        if (!isTarget32Bit)
        {
            var directErr = DirectInjectDll((uint)pid, dllPath);
            if (directErr == null) return null;
            return $"ManualMap+Engine+Direct all failed: {directErr}";
        }

        return "All injection methods failed";
    }

    /// <summary>
    /// WoW64-aware injection: injects a 32-bit DLL into a WoW64 (32-bit) target process
    /// from our 64-bit host. Finds the 32-bit kernel32!LoadLibraryW in the target using
    /// CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32) and PE export table parsing.
    /// Returns null on success, error string on failure.
    /// </summary>
    private static string? DirectInjectDllWow64(uint pid, string dllPath)
    {
        // Step 1: Find the 32-bit kernel32.dll base address in the target process
        // using TH32CS_SNAPMODULE32 which enumerates WoW64 modules
        IntPtr kernel32Base = IntPtr.Zero;
        var hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap == IntPtr.Zero || hSnap == (IntPtr)(-1))
        {
            int err = Marshal.GetLastWin32Error();
            return $"WoW64Inject: CreateToolhelp32Snapshot failed, Win32={err} (0x{err:X})";
        }

        try
        {
            var me = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32W>() };
            if (Module32FirstW(hSnap, ref me))
            {
                do
                {
                    if (me.szModule.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase) ||
                        me.szModule.Equals("KERNEL32.DLL", StringComparison.OrdinalIgnoreCase))
                    {
                        // Only take the 32-bit kernel32 (base address < 4GB)
                        if ((ulong)me.modBaseAddr < 0x100000000UL)
                        {
                            kernel32Base = me.modBaseAddr;
                            break;
                        }
                    }
                } while (Module32NextW(hSnap, ref me));
            }
        }
        finally
        {
            CloseHandle(hSnap);
        }

        if (kernel32Base == IntPtr.Zero)
            return "WoW64Inject: Could not find 32-bit kernel32.dll in target process";

        // Step 2: Parse the 32-bit kernel32.dll PE export table to find LoadLibraryW RVA.
        // Read from SysWOW64 on disk (faster + cleaner than reading from target memory).
        string kernel32Path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "SysWOW64", "kernel32.dll");

        uint loadLibraryRva = 0;
        try
        {
            byte[] pe = File.ReadAllBytes(kernel32Path);
            if (pe.Length < 64 || BitConverter.ToUInt16(pe, 0) != 0x5A4D)
                return "WoW64Inject: Invalid kernel32 PE";

            int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
            if (e_lfanew + 120 >= pe.Length)
                return "WoW64Inject: Invalid PE headers";

            // PE32 optional header: export directory at optHdr + 96
            int optHdr = e_lfanew + 24;
            uint exportRva = BitConverter.ToUInt32(pe, optHdr + 96);
            uint exportSize = BitConverter.ToUInt32(pe, optHdr + 100);

            if (exportRva == 0)
                return "WoW64Inject: No export directory";

            // Convert export RVA to file offset using section table
            ushort numSections = BitConverter.ToUInt16(pe, e_lfanew + 6);
            ushort sizeOfOptHdr = BitConverter.ToUInt16(pe, e_lfanew + 20);
            int secBase = e_lfanew + 24 + sizeOfOptHdr;

            int exportFileOff = RvaToFileOffset(pe, exportRva, secBase, numSections);
            if (exportFileOff < 0 || exportFileOff + 40 > pe.Length)
                return "WoW64Inject: Export directory not found";

            uint numberOfNames = BitConverter.ToUInt32(pe, exportFileOff + 24);
            uint addressOfFunctions = BitConverter.ToUInt32(pe, exportFileOff + 28);
            uint addressOfNames = BitConverter.ToUInt32(pe, exportFileOff + 32);
            uint addressOfOrdinals = BitConverter.ToUInt32(pe, exportFileOff + 36);

            int funcTableOff = RvaToFileOffset(pe, addressOfFunctions, secBase, numSections);
            int nameTableOff = RvaToFileOffset(pe, addressOfNames, secBase, numSections);
            int ordTableOff = RvaToFileOffset(pe, addressOfOrdinals, secBase, numSections);

            if (funcTableOff < 0 || nameTableOff < 0 || ordTableOff < 0)
                return "WoW64Inject: Invalid export table pointers";

            for (uint i = 0; i < numberOfNames; i++)
            {
                uint nameRva = BitConverter.ToUInt32(pe, nameTableOff + (int)(i * 4));
                int nameOff = RvaToFileOffset(pe, nameRva, secBase, numSections);
                if (nameOff < 0) continue;

                string name = ReadCString(pe, nameOff);
                if (name == "LoadLibraryW")
                {
                    ushort ordinal = BitConverter.ToUInt16(pe, ordTableOff + (int)(i * 2));
                    loadLibraryRva = BitConverter.ToUInt32(pe, funcTableOff + ordinal * 4);
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            return $"WoW64Inject: PE parse error: {ex.Message}";
        }

        if (loadLibraryRva == 0)
            return "WoW64Inject: LoadLibraryW not found in kernel32 exports";

        // Step 3: Compute the 32-bit LoadLibraryW address in target process
        IntPtr pLoadLibraryW32 = (IntPtr)((uint)(long)kernel32Base + loadLibraryRva);

        // Step 4: Standard CreateRemoteThread injection with the 32-bit address
        var hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return $"WoW64Inject: OpenProcess failed, Win32={err}";
        }

        try
        {
            byte[] pathBytes = Encoding.Unicode.GetBytes(dllPath + '\0');
            var remoteMem = VirtualAllocEx(hProcess, IntPtr.Zero, (nuint)pathBytes.Length,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (remoteMem == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return $"WoW64Inject: VirtualAllocEx failed, Win32={err}";
            }

            try
            {
                if (!WriteProcessMemory(hProcess, remoteMem, pathBytes, (nuint)pathBytes.Length, out _))
                {
                    int err = Marshal.GetLastWin32Error();
                    return $"WoW64Inject: WriteProcessMemory failed, Win32={err}";
                }

                var hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0,
                    pLoadLibraryW32, remoteMem, 0, out _);
                if (hThread == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    return $"WoW64Inject: CreateRemoteThread failed, Win32={err} (0x{err:X}) — kernel32Base=0x{(uint)(long)kernel32Base:X8} LoadLibraryW=0x{(uint)(long)pLoadLibraryW32:X8}";
                }

                WaitForSingleObject(hThread, 30000);
                GetExitCodeThread(hThread, out uint exitCode);
                CloseHandle(hThread);

                if (exitCode == 0)
                    return "WoW64Inject: LoadLibraryW returned 0 — DLL failed to load";

                return null; // Success!
            }
            finally
            {
                VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Converts a PE RVA to file offset using the section table.
    /// </summary>
    private static int RvaToFileOffset(byte[] pe, uint rva, int secBase, int numSections)
    {
        for (int i = 0; i < numSections; i++)
        {
            int sh = secBase + i * 40;
            if (sh + 40 > pe.Length) break;
            uint secVa = BitConverter.ToUInt32(pe, sh + 12);
            uint secRawSize = BitConverter.ToUInt32(pe, sh + 16);
            uint secRawPtr = BitConverter.ToUInt32(pe, sh + 20);
            uint secVirtSize = BitConverter.ToUInt32(pe, sh + 8);

            if (rva >= secVa && rva < secVa + Math.Max(secVirtSize, secRawSize))
                return (int)(secRawPtr + (rva - secVa));
        }
        return -1;
    }

    #endregion
}
