# Changelog

All notable changes to this project are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.2.0] - 2026-05-31

### Added
- Preloader ASLR mode -- runs the preloader at the real hardware ASLR base.
- Read-tracking instrumentation with JSON export.
- Recon mode with module-name resolution from a base address.

### Fixed
- `MmIsAddressValid` correctness in NexusCore, rebuilt into the DXE image.

---

## [1.1.0] - 2026-04-25

### Added
- **EPT read-trapping extended to the TPM CRB window** (0xFED40000) alongside
  the existing FIFO trap.
- `--ept-hook`, with CPUID-based virtual-to-physical resolution for hook
  installation.
- GPA-matched EPT switching, dormant until hooks are installed.
- Multi-snapshot process dumper.
- TPM registry access logging in the kernel callback.

### Fixed
- Use-after-free in the snapshot dumper.

---

## [1.0.0] - 2026-03-31

### Hardware Identity Virtualisation — validated end-to-end (2026-03-31)
- **Identity surface mapped**: the registry-readable identifiers a host exposes to
  user-mode code (MachineGuid, ComputerName, ContainerIDs, machine SID, USB serials)
- **Sustained-run validation**: 24h+ continuous operation against a live commercial
  detection driver with registry substitution active, no identity leak observed
- **Negative control**: disabling registry substitution while leaving kernel hooks in
  place caused the host's real identity to be recovered, confirming the registry layer
  carries the load rather than the hooks
- **Root cause of an earlier gap**: the `--mapper-init` guard skipped registry
  substitution when DXE auto-init had already set state=3. Split the guard so it skips
  kernel init only and always runs registry substitution.
- **Tiered architecture validated**:
  - Tier 1: Registry-level identity substitution (carries most of the coverage)
  - Tier 2: Tier 1 + kernel hooks — runtime MAC/disk/TPM interception
  - Tier 3: Tier 2 + SentinelHV EPT — hardware-level defence in depth

### Added
- **SentinelHV Hypervisor** - Standalone WDM kernel driver Type 2 hypervisor (2026-03)
  - Virtualizes ALL processors via KeIpiGenericCall (not just BSP)
  - Identity-mapped EPT: 8TB coverage (PML4[0] 2MB MTRR-aware + PML4[1-15] 1GB UC)
  - EPT TPM FIFO page split: 2MB→4KB at 0xFED00000, 0xFED10000 remapped to shadow
  - VM exit handling: CR4 (hide VMXE), VMCALL, MSR, WBINVD, XSETBV, NMI, UMWAIT/TPAUSE
  - ENABLE_USER_WAIT_PAUSE (secondary bit 26) — required for Arrow Lake idle (UMWAIT)
  - Clean devirtualization via IPI with callee-saved register preservation
  - Manual mapping via `--load-driver` with deferred VMX init (system thread)
  - CPUID leaf 0x40000000 presence check ("Sntl" signature)
  - CMOS NVRAM diagnostics: DXE reads, kernel writes (kernel reads return stale data)
  - Emergency devirt on unhandled VM-exits (no bugcheck from VMX root)
  - MacSeed wired to EPT FIFO shadow identity registers
  - INVEPT after EPT page split (flush stale TLB across CPUs)
  - Files: Nexus/Hypervisor/SentinelHV/ — entry.c, vmx.c, vmcs.c, ept.c, exit_dispatch.c, exit_*.c, vmx_asm.asm

- **TPM Identity Virtualisation** - Full TPM identity substitution; sustained 8h+ runs with no identity leak (2026-02/03)
  - \Driver\tpm IRP hook on all TPM submit IOCTLs (0x0022C00C, 0x0022C194)
  - ReadPublic/CreatePrimary: RSA modulus replacement + TPM2B_NAME recomputation
  - GetCapability: blanket spoof of all TPM_PT properties (0x100-0x214) with real vendor table profiles
  - NV_Read: full blob transformation via GenerateSpoofedBinaryId
  - Registry EkPub spoof (283-byte BCRYPT_RSAKEY_BLOB)
  - ReadPublic response cache (prevents real data re-caching)
  - CRB shadow buffer via DXE MmMapIoSpace hook — anti-cheat gets shadow, tpm.sys gets real
  - FIFO shadow (0xFED10000) — the observed target uses FIFO exclusively
  - DXE hooks: MmMapIoSpace, MmMapIoSpaceEx, MmGetVirtualForPhysical, MmCopyMemory, MmMapLockedPagesSpecifyCache
  - Inline hook prologue fix: short Jcc (0x70-0x7F) conversion to near Jcc in trampoline
  - ShadowPhysAddr approach: tail-call original with shadow physical address (safe for MmUnmapIoSpace)
  - TPM memory rescan thread: periodic scan for original modulus leaks
  - TBS inline hook on Tbsip_Submit_Command as secondary interception

- **MAC Address Spoofing** - Multi-layer MAC spoofing for all adapters (2026-02)
  - DXE NdisMSetMiniportAttributes compute-in-wrapper hook (GenerateSpoofedMac LCG)
  - nsiproxy.sys dispatch hook — NSI ENUMERATE/GETALL/GETPARAM intercepted
  - NDIS.sys dispatch hook (runtime OID query spoofing)
  - tcpip.sys dispatch hook (adapter info query spoofing)
  - Ndisuio.sys dispatch hook (NDIS OID query spoofing)
  - BTHPORT.sys dispatch hook (Bluetooth BD_ADDR spoofing)
  - User-mode SpoofAllAdapters() via IOCTL + registry NetworkAddress
  - NSI MDL-lock approach for IRQL/process context safety
  - LA-bit virtual adapter fix (Wi-Fi 4/5 LA bit preservation)

- **HWID Registry Spoofing** - Comprehensive registry identity replacement (2026-02)
  - Machine SID spoofing (ProfileList + HKCU paths)
  - USB/USBSTOR/PCI device serial spoofing
  - ContainerID spoofing (REG_SZ format, PnP Enum tree with BACKUP_RESTORE)
  - HID/USB device spoofing via kernel hooks (hidusb/mshidkmdf/mshidumdf)
  - MachineGuid, ProductId, ComputerName, HwProfileGuid, ComputerHardwareId
  - SCSI DeviceMap, BIOS registry, EDID monitor serials, volume serials
  - Disk PnP GUIDs (Partmgr DiskId)
  - MountPoints2 cleanup, network profiles, BAM history, AppCompatCache, prefetch
  - SMBIOS Type 17 (RAM DIMM serials)
  - BuildGUID spoofing

- **Anti-Cheat Binary Intelligence** - commercial anti-cheat driver analysis (2026-03)
  - Griffin VM deobfuscation (phase 1-4 analysis tools)
  - String decryption: 29 key tables, 59 inline decryptors, ~1150 strings
  - Encrypted IAT: 2-layer hash+XOR scheme, 4188 calls, 227 entries
  - Hook detector mapped at 0x872C40 (31 callers)
  - Page table walker at 0x680000 (15 MmCopyMemory physical calls)
  - TPM identity vector mapped: OfflineUniqueIDEKPub
  - \Device\PhysicalMemory direct mapping path discovered

- **API Monitor** - NexusApiHook.dll for real-time API call capture (2026-02)
  - Ring buffer IPC (1024 slots x 4096 bytes, MPSC)
  - ~200 API whitelist
  - Named event stop signaling (pipe deadlock fix)
  - Child process injection support

- **HVCI Compatibility** - MDL-based writes for mapped driver under VBS (2026-02)
  - WriteProtectedMemory (MDL-based) for all NexusCore static writes
  - Two-phase import resolution (boot-time + runtime)
  - RtlLookupFunctionEntry hook + module cache for exception tables
  - State machine: NOT_MAPPED → MAPPED → IMPORTS_RESOLVED → INITIALIZED

- **Disk Serial Spoofing** - Kernel disk identity hooks (2026-02)
  - SCSI miniport dispatch hooks (disk serial in INQUIRY/VPD responses)
  - Disk hook retry mechanism (DISK_HOOKS_MAX_RETRIES = 100)
  - HID hook alongside disk hooks via MAPPER_CMD_HWID_RETRY_DISK

- **SMBIOS Activation Migration** - Gradual Windows license fingerprint migration (2026-02)
  - Phase-by-phase SMBIOS field randomization (chassis → system → board → UUID)
  - Deterministic spoofed values from MasterSeed
  - Recovery plan for activation failures

- **UEFI TCG Log Substitution** - Boot-attestation surface control via TCG log transformation (2026-01-21)
  - Hooks GetTcgLog runtime service to return spoofed PCR values
  - Validated against the target's environment-detection path (`IOCTL_TBS_GET_TCG_LOG`)
  - Located in `Nexus/UEFI/NexusBootDxe/TcgLogSpoof.c`

- **Boot Automation** - Startup task for automatic HWID spoofing (2026-03)
  - `nexus_startup.cmd` + `install_autorun.ps1` (NexusStartup scheduled task)
  - 30-second boot delay, runs as SYSTEM
  - `--mapper-init` auto-runs every boot; `--load-driver SentinelHV.sys` optional
  - Toggle files: `%ProgramData%\NexusSentinel\disable_all`, `disable_hv`

- **ZwMapViewOfSection Hook** - \Device\PhysicalMemory interception (2026-03)
  - DXE export table hook on NtMapViewOfSection in ntoskrnl
  - 64KB neighborhood PFN check (FIFO 0xFED10-0xFED1F, CRB 0xFED40-0xFED4F)
  - ViewSize guard: only redirect single-page (<=4KB) mappings to shadow
  - Excludes HPET at 0xFED00000 (2MB range caused CLOCK_WATCHDOG_TIMEOUT)
  - Defense in depth for Tier 2 (0 hits observed — the target does not use the export-table path)

### Changed
- **Codebase split** - All monolithic files split into manageable sizes (2026-03)
  - UI: 15 C# files split into partial classes (KernelProvider, NexusEngine.Bootkit, etc.)
  - NexusCore: 4 files split via unity build #include
  - NexusBootDxe: 2 files split (SmbiosSpoof, PatchNtoskrnl)
  - ApiHook: hook_engine.cpp split into 4 files
  - NexusDSEFix: main.cpp commands extracted to separate files
- **Dead code removed** - v1 release prep (2026-03)
  - Deleted: ndis_protocol.c/h, wifi_mac_patch.c/h (entire unused modules)
  - Deleted: hwid_spoof_tpm_pte.c (deprecated PTE swap), hwid_spoof_tpm_mapview.c (deprecated)
  - Removed 11 dead functions across 7 source files + header declarations
  - GPU UUID spoofing kept (disabled, planned for reimplementation)
- **`/OPT:NOREF` removed** - Linker properly eliminates dead code, binary 194KB → 167KB
- **64-issue code review** - Full codebase audit and fix (2026-03)
  - 7 critical (64KB stack overflow, backdoor size cap, duplicate InitializeCore, etc.)
  - 12 high (deprecated pool API, null checks, stale comments, GDI leaks)
  - 17 medium (dead code, copy-paste, ASSERT in Release)
  - 28 low (comments, documentation, unused usings)
- **NexusHV removed from DXE** - SentinelHV is now standalone (2026-03)
  - Removed FEATURE_HYPERVISOR from Loader menu and DXE
  - All NexusHV references renamed to SentinelHV
- **NexusCore replaces NexusMapper** - Embedded in NexusBootDxe.efi, manually mapped at boot
- **AUTO_INIT_MIN_CALLS**: Reverted from 2 to 5 after boot freeze with larger NexusCore binary
- **CRB cave size**: Must stay at 450 bytes (FindCodeCaveNt fails at 600)
- **GPU UUID spoofing disabled** - Device extension scanning causes CRITICAL_PROCESS_DIED BSOD
- **VA swap and CRB PTE swap disabled** - Both broke tpm.sys protocol state
- **CRB write-back deprecated** - the target reads FIFO (0xFED10000), not CRB (0xFED40000)
- **Kernel Driver Modernization** - Updated memory allocation API (2026-01-21)
  - Migrated all `ExAllocatePoolWithTag` calls to `ExAllocatePool2`
  - Zero-initialized memory by default (improved security)
  - Eliminated 17 deprecation warnings
  - Updated 16 instances across 9 source files
- Migration plan consolidated to v4.2 (reduced from ~41k tokens to ~4k tokens)
- Standardized on .NET 10 target for all managed components
- Split source model decision recorded (open core, closed plugins)

### Fixed
- **Identity-leak root cause** - `--mapper-init` guard skipped registry substitution at state>=3 (2026-03)
- **SentinelHV manual map freeze** - Deferred VMX init to system thread (SetVariable context deadlock)
- **SentinelHV Arrow Lake freeze** - UMWAIT/TPAUSE idle caused #UD without ENABLE_USER_WAIT_PAUSE
- **SentinelHV ACK_INTERRUPT_ON_EXIT** - Was silently dropping all external interrupts (not needed)
- **SentinelHV ASM exit stub RAX** - `[rsp+8]` not `[rsp+10h]` to recover guest RAX after two pushes
- **SentinelHV devirt BSOD** - ShvDoVmcall must save/restore callee-saved regs for VMXOFF path
- **SentinelHV devirt deadlock** - DbgPrintEx at IPI_LEVEL in devirt callbacks
- **SentinelHV EPT GPU crash** - GPU large BAR at ~4TB, 512GB PML4[0] insufficient → BSOD 0x113
- **SentinelHV CMOS reads** - Kernel-context reads return stale BIOS data; DXE-context reads work
- **ZVS HPET crash** - 2MB PFN range caught HPET (0xFED00000) → CLOCK_WATCHDOG_TIMEOUT
- **64KB stack overflow** - `mapper_cmd_memory.c` 64KB stack buffer replaced with pool alloc
- **Backdoor size cap** - SetVariable R/W backdoor now capped at 64KB
- **Duplicate InitializeCore** - Removed static copy from CoreCommands.c
- **Font GDI leak** - ShellForm created `new Font()` on every tab switch without disposing
- **Event handler leaks** - 3 unsubscribed event handlers in ShellForm
- **TPM IOCTL code** - Was 0x0022200C, correct is 0x0022C00C
- **TPM2 response format BSOD** - ReadPublic vs CreatePrimary offset differences
- **NSI hook IRQL/process bug** - MDL-lock at PASSIVE_LEVEL, system addresses in completion
- **UEFI Print() deadlock** - No Print() from winload context, use BlStatusPrint
- **MLP boot freeze** - MDL size check + export-table-only hook (no inline)
- **Inline hook prologue** - Short Jcc handling for Win11 24H2 MmMapIoSpace
- **Windows activation** - SpoofDigitalProductId disabled, license re-bound via slmgr
- **Kernel Driver Linker Errors** - Dynamic function resolution (2026-01-21)
  - Resolved undocumented functions via `MmGetSystemRoutineAddress`:
    - `PsSuspendThread`, `PsResumeThread`, `PsGetNextProcessThread`
    - `ZwGetContextThread`, `ZwSetContextThread`
  - Fixed `ntstrsafe.h` CRT dependency with `NTSTRSAFE_LIB` define
  - Added `ntstrsafe.lib` to Debug configuration linker dependencies
  - Initialization functions called in `DriverEntry`

- **Structure Dissector Complete** - Full ReClass.NET-style structure analysis (2026-01-17)
  - Core field types: Int8-64, UInt8-64, Float, Double, Bool, Pointer, String, WString, Bytes
  - Advanced types: Nested structures, Arrays, Bitfields, Enums, GUID, Timestamp, Union
  - Memory write-back support for all field types
  - Auto-dissect using `Nexus_StructureAutoGuess` engine API
  - Fill gaps functionality via `Nexus_StructureFillGaps`
  - Copy/paste fields between structures
  - Structure library with JSON persistence
  - Alignment validation and padding support
  - Pointer chain following (multi-level resolution)
  - Field search/filter
  - Structure comparison/diffing dialog
  - Visual byte-map layout view
  - VTable detection and enumeration
  - RTTI parsing (MSVC x64)
  - Scan for strings and pointers
  - Clone structure and sort elements
  - PDB import placeholder (stub for future SDK integration)

- **Plugin Manager Integration** - Full plugin system now wired into ShellForm (2026-01-17)
  - `InitializePluginSystem()` creates PluginLoader and PluginHost on startup
  - "Manage Plugins..." menu item now opens PluginManagerForm
  - Plugin approval dialogs for unsigned plugins
  - Process attach/detach events notify plugin host
  - Plugin lifecycle management (load, unload, dispose)
  - Trust settings persistence (JSON)
  - Signature verification (Authenticode)

- **Dark mode** - Complete implementation across all 83 form constructors
  - `ThemeManager.ApplyTheme()` applied to all forms including nested forms
  - Dark/light color palettes with DwmSetWindowAttribute for title bar
  - Toggle via Settings menu
- **Debugger enhancements** (cleanroom implementation):
  - Software breakpoint step-over logic (restore byte → single-step → re-set INT3)
  - Initial system breakpoint handling (skip Windows loader breakpoint)
  - Hardware breakpoint application to new threads
  - Module name population in DLL load events
  - Fixed `g_debuggers` static map bug (was declared in two functions)

---


## Releases before 1.0.0

Versions 0.1.0 through 0.28.0 (December 2025 -- January 2026) covered the
project's original memory-inspection and debugging tooling, including a Windows
Forms user interface written in C#.

That interface was **inspired by Cheat Engine, not ported from it**. Cheat
Engine's Pascal sources were used as a reference for what the tooling should do
— which dialogs a memory editor needs, what belongs on each one — and the C#
was then written against that understanding. Every form was subsequently
reviewed and adjusted by hand, because a layout derived from a description does
not come out looking right, and the functionality behind them was implemented
independently rather than translated.

The distinction matters for licensing, so it is stated plainly: no Cheat Engine
source was copied into this tree. Where anything of theirs did reach the
codebase it has been removed rather than relicensed.

That code is preserved in this repository under `Nexus/UI` and `Nexus/Engine`.
It is unmaintained rather than removed, and still builds.

Per-version entries for that period remain in this file's git history. They are
not reproduced here, so that this file documents the codebase as it now stands.
See the scope note at the top for how the project's focus changed.
