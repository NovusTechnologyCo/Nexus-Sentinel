<p align="center">
  <img src="Nexus/Assists/logo.png" alt="Nexus Sentinel" width="256">
</p>

<h1 align="center">Nexus Sentinel</h1>

<p align="center">
  <strong>Security Introspection Framework for Windows</strong>
</p>

<p align="center">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License">
  </a>
  <img src="https://img.shields.io/badge/version-2.0.0--alpha.3-green.svg" alt="Version">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/.NET-10.0-purple.svg" alt=".NET">
  <img src="https://img.shields.io/badge/UEFI-Bootkit-orange.svg" alt="UEFI">
  <img src="https://img.shields.io/badge/VMX-Hypervisor-red.svg" alt="Hypervisor">
</p>

---

Nexus Sentinel is the core of a multi-project **Security Introspection Framework** -- a platform for safely
inspecting obfuscated, protected, and dangerous processes (including malware) in a sandboxed environment.
Hardware identity spoofing is built in at every privilege level so the target process cannot fingerprint the
host machine.

The framework spans multiple Nexus projects -- **NexusSentinel** (this repository, the framework core) and
**NexusForge** (the emulator). Each is either a piece of the framework, the framework core, or a
demonstration of how to use the intelligence it gathers.

**Validation target.** The framework is developed and validated against a commercial anti-cheat
driver -- a professionally built, safe-to-run system that uses the same techniques as real malware:
VM-based packing, encrypted import tables, anti-debug, hardware fingerprinting, and kernel
self-defence. It is the hardest available adversary that can be run safely and repeatedly, which is
why it is the benchmark: until the framework can reverse-engineer a target of that quality end to
end, it is not ready for genuinely dangerous ones.

Detailed results against specific targets live in a private research repository, not here.

## What is in this repository

This repository is the **shipping framework**. As of September 2026 it holds the v2 capture and
inspection stack and nothing else, so it can be published without filtering.

| | where it lives |
|---|---|
| Capture driver, hypervisor, user-mode, UEFI boot stack | **here**, under `Nexus/` |
| Emulator (Griffin-VM lifting, multi-module chains, anti-emu handling) | **NexusForge** / **NexusForge-Core** -- separate repositories, GPL-2.0 |
| Research corpus, analysis tooling, capture artifacts | **NexusResearch** -- private |
| v1 feature set: memory scanner, debugger, disassembler, structure dissector, process/API monitors, the WinForms UI | **here**, under `Nexus/UI` and `Nexus/Engine` -- unmaintained, still builds |
| v1 UEFI and driver history | **NexusResearch** -- archived, not built |

**Apache-2.0 throughout.** See [LICENSES.md](LICENSES.md). The emulator is permanently GPL-2.0
because QEMU is, so Sentinel talks to it across a process boundary and never links it.

> Features listed below marked **(v1)** describe the original tooling that predates the v2 rewrite.
> That code is still in this repository, under `Nexus/UI` and `Nexus/Engine`, and still builds -- it
> is unmaintained rather than removed. v2 is a rewrite alongside it, not a continuation of it.

## Features

### Core Capabilities
- **Memory Scanner** *(v1, archived)* - Fast value searching with pointer scanning and CE 7.5+ parity
- **Debugger** *(v1, archived)* - Hardware/software breakpoints, stepping, register and memory inspection
- **Disassembler** *(v1, archived)* - x86/x64 instruction decoding via Zydis with CFG visualization
- **Structure Dissector** *(v1, archived)* - ReClass-style memory structure reverse engineering with auto-dissect
- **Process Monitor** *(v1, archived)* - ETW-based API/syscall tracing, file and registry monitoring
- **API Monitor** *(v1, archived)* - Real-time API call interception via NexusApiHook.dll (~200 APIs)

### Behavioral Emulation
- **Multi-module Unicorn emulator** - Faithfully emulates full process chains (launcher + DLLs) using real
  system binaries; no stubs, no patches in the final path
- **Cooperative multi-threading** - Deterministic preemptive cooperative scheduling on a single Unicorn CPU
- **Themida/VM unpacking** - Griffin-VM bytecode lifting for obfuscated modules IDA cannot decompile directly
- **Anti-emulation handling** - Comprehensive cataloging and faithful handling of anti-emu probes
  (RDTSC, CPUID, INT2C, debug artifact checks)
- **Decompile corpus** - Named pseudocode functions, traced memory paths, and detection vectors across all
  archived builds; evolving toward a per-build queryable DB via the IDA MCP

### Hardware Identity Protection (HW Spoofing)
The HW spoofing stack ensures the target process cannot fingerprint the real host machine -- critical when
the target may use hardware identity to detect the analysis environment.

- **Registry Identity** - MachineGuid, ComputerName, SID, ContainerIDs, USB/PCI serials, EDID, volume serials, and 20+ more vectors
- **MAC Addresses** - DXE NdisMSetMiniportAttributes hook + NSI/NDIS/tcpip runtime hooks for all adapters
- **Disk Serials** - Kernel SCSI miniport dispatch hooks (INQUIRY, VPD, ATA, NVMe, StorageQuery)
- **TPM Identity** - IRP completion hooks (ReadPublic, GetCapability, NV_Read) + CRB shadow buffer
- **SMBIOS Tables** - DXE-level spoofing of board serial, BIOS serial, system UUID, RAM DIMMs
- **Bluetooth** - BTHPORT.sys dispatch hook for BD_ADDR spoofing
- **HID/USB Devices** - Kernel hooks on hidusb/mshidkmdf + ContainerID spoofing
- **Identity Cache Cleanup** - EA fingerprint cache, browser IDs, prefetch, DiagTrack, BAM, network profiles

### Privilege Tiers
| Tier | Component | What it provides |
|------|-----------|-----------------|
| **Ring 3** | engine.dll + UI | Memory scanning, debugging, disassembly, scripting |
| **Ring 0** | NexusCore.sys | Runtime hook spoofing (MAC, disk, TPM, HID, BT) |
| **Pre-OS** | NexusBootDxe.efi | DSE/PG bypass, SMBIOS spoof, driver mapper, DXE hooks |
| **Ring -1** | SentinelHV | EPT page remapping, hardware-level identity control |

> **On DSE/PG bypass.** Loading an unsigned instrumentation driver requires suspending Driver
> Signature Enforcement and PatchGuard. This is standard practice for kernel-level analysis
> tooling and is confined to the dedicated analysis host, which is a disposable test machine.


### Technical Highlights
- Modern dark-themed WinForms UI with tab-based module panels
- C# scripting via Roslyn for automation
- Plugin system with signature verification
- Abstracted provider interfaces (User Mode, Kernel, Hypervisor)
- HVCI/VBS compatible (MDL-based WriteProtectedMemory)
- Boot automation via scheduled task (30s delay, SYSTEM context)
- Windows 10/11 x64 native

## Architecture

```
+-----------------------------------------------------------------+
|                     Nexus UI (C# / .NET 10)                     |
|                Shell | Modules | Plugins                        |
+-----------------------------+-----------------------------------+
                              |
+-----------------------------v-----------------------------------+
|                    Abstraction Layer                            |
|    UserModeProvider | KernelProvider | HypervisorProvider       |
+----------+-----------------+------------------+----------------+
           |                 |                  |
+----------v------+ +--------v-------+ +--------v-------+
|  engine.dll     | | NexusCore.sys  | | SentinelHV     |
|  (Ring 3)       | | (Ring 0)       | | (Ring -1)      |
+-----------------+ +-------+--------+ +----------------+
                            |
                    +-------v--------+
                    | NexusBootDxe   |
                    | (UEFI Pre-OS)  |
                    +----------------+

Boot chain: Loader.efi -> NexusBootDxe.efi -> Windows
            NexusCore.sys embedded, manually mapped at boot
            SentinelHV loaded via --load-driver (manual map)
```

## Building

### Requirements
- Visual Studio 2022 or later (2026 recommended)
- .NET 10 SDK
- CMake 3.20+ (for engine)
- Windows SDK 10.0.22621.0+
- Windows Driver Kit (for kernel components)

### Build UI (v1, unmaintained)
```bash
dotnet build Nexus/UI/Nexus.UI.csproj -c Release
```

### Build Engine (v1, unmaintained)
```bash
cd Nexus/Engine
cmake -B build -A x64
cmake --build build --config Release
```

### Build the v2 stack

```bat
build.cmd
```

That produces all three artifacts, in the order that matters:

| | |
|---|---|
| `Nexus\Drivers\NexusCore\bin\NexusCore.sys` | the kernel driver |
| `Nexus\UEFI\build\x64\Release\PlatformRuntimeDxe.efi` | the UEFI DXE driver |
| `Nexus\Usermode\PlatformCtl\bin\PlatformCtl.exe` | the control utility |

**The order is not a convenience.** `NexusCore.sys` is embedded *into* the DXE as a generated
header, so building only the DXE after changing the driver silently ships the old driver.
`build.cmd` enforces the sequence; building the projects individually does not.

Secure Boot signing is opt-in — see [docs/SECURE_BOOT.md](docs/SECURE_BOOT.md). Without a key
the build still succeeds and produces an **unsigned** `.efi`, which firmware refuses silently
when Secure Boot is enabled.

### Build the remaining components
```bash
# NexusBootProbe (boot-channel diagnostic)
cd Nexus/UEFI/Application/NexusBootProbe/src
MSBuild NexusBootProbe.vcxproj -p:Configuration=Release -p:Platform=x64

# NexusApiHook (API monitor DLL)
cd Nexus/Native/ApiHook
MSBuild NexusApiHook.vcxproj -p:Configuration=Release -p:Platform=x64
```

## Usage

### Basic (Ring 3)
1. Run `Nexus.exe`
2. Select a target process via Process menu
3. Use the module panels to scan memory, set breakpoints, analyze structures, or monitor activity

### Full stack (Ring 0 + Pre-OS)
1. Deploy `PlatformRuntimeDxe.efi` to the EFI System Partition. It must be signed by a key the
   firmware trusts, or Secure Boot refuses it **silently** — see
   [docs/SECURE_BOOT.md](docs/SECURE_BOOT.md).
2. Reboot. `NexusCore.sys` is embedded in the DXE and mapped automatically; it does not go
   through Windows' driver-load path.
3. `PlatformCtl status` — confirms the driver answered, and reports the `dxe ident` of the
   image actually running.
4. `NexusBootProbe.exe --check` — confirms the EFI runtime channel is live.

Compare the `dxe ident` from step 3 against the file you deployed with
`python tools/pe_timestamp.py <path-to-PlatformRuntimeDxe.efi>`. A mismatch means the firmware
loaded an older image than the one you just built.

### Boot Automation
```powershell
# Install startup task (runs --mapper-init at every boot)
powershell -File tools/install_autorun.ps1
```

## Project Status

| Component | Status |
|-----------|--------|
| Engine (engine.dll) | Complete -- 117 API functions, full CE 7.5+ parity |
| Memory Scanner | Complete -- all value types, AOB, pointer scanning |
| Debugger | Complete -- HW/SW breakpoints, stepping, registers |
| Disassembler | Complete -- Zydis-based, CFG, assembly editing |
| Structure Dissector | Complete -- ReClass-style with auto-dissect, RTTI, VTable |
| Process Monitor (ETW) | Complete -- 12 providers, filtering, correlation |
| API Monitor | Complete -- ring buffer IPC, ~200 APIs, child injection |
| Plugin System | Complete -- signature verification, trust model |
| C# Scripting (Roslyn) | Complete |
| Unified Shell UI | Complete -- dark theme, tab-based modules |
| NexusKernel.sys | Complete -- IOCTLs, callbacks, minifilter |
| NexusCore.sys (Mapped) | Complete -- HW identity spoofing, TPM hooks, DXE hook management |
| UEFI Bootkit | Complete -- boot menu, DSE/PG bypass, SMBIOS spoof, driver mapper |
| HW Identity Spoofing | Complete -- all identity vectors spoofed, validated end to end |
| SentinelHV Hypervisor | Complete -- VMX all CPUs, EPT, TPM FIFO remap, manual map |
| Behavioral Emulator | Active development -- QEMU-11 core reproduces the target's verdict bit-exactly against the hardware oracle |

## Hardware Identity -- Validation

The hardware identity stack has been validated end to end against a commercial anti-cheat driver:

- **All identity vectors confirmed spoofed** -- registry identifiers, runtime hooks (MAC, disk, TPM, HID), and SMBIOS
- **Primary identity vector identified** -- the registry-readable identifiers, not TPM FIFO physical memory
- **Tiered protection** -- Tier 1 (registry) is the primary vector, Tier 2 (kernel hooks) adds runtime interception, Tier 3 (hypervisor EPT) provides hardware-level defense in depth

See [CHANGELOG.md](CHANGELOG.md) for the full technical breakdown.

## Use Cases

- Security research and malware analysis in a controlled sandbox
- Reverse engineering obfuscated or protected software
- Hardware identity management for analysis environments
- Anti-cheat reverse engineering as a framework validation target
- Software debugging and diagnostics
- Educational purposes

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [API Reference](docs/API_REFERENCE.md)
- [User Guide](docs/USER_GUIDE.md)
- [Plugin Development](docs/PLUGIN_DEVELOPMENT.md)
- [Changelog](CHANGELOG.md)

## Repository history

This repository publishes Nexus Sentinel's **releases**, not its development. Commits correspond to
tagged versions -- one commit per release, dated when that release was made. Day-to-day development
happens in a private repository and is not mirrored here.

**Source is published from `v2.0.0-beta.1` onward.** That is the first release free of third-party
GPL-3.0 code. Earlier releases incorporated code derived from
[EfiGuard](https://github.com/Mattiwatti/EfiGuard), and rather than redistribute that derivative
work they are documented here without their source. What each earlier release changed is recorded
in [CHANGELOG.md](CHANGELOG.md); [LICENSES.md](LICENSES.md) states which licence applied to which
version, and `Nexus/UEFI/NOTICE` lists what was replaced and when.

## License

Nexus Sentinel is licensed **per component**. Full detail in [LICENSES.md](LICENSES.md).

Everything in this repository is [Apache-2.0](LICENSE), including `Nexus/UEFI/`.

`Nexus/UEFI/` was GPL-3.0 until 17 September 2026, as a derivative of
[EfiGuard](https://github.com/Mattiwatti/EfiGuard). Every derived file has since been replaced
with an independent implementation or removed; `Nexus/UEFI/NOTICE` lists them. Releases up to
`v2.0.0-alpha.4` remain GPL-3.0 and nothing withdraws the rights granted with them.

The emulator (**NexusForge**, **NexusForge-Core**) is GPL-2.0 and permanently so, because
QEMU is. GPL-2.0 is incompatible with Apache-2.0, so Sentinel exchanges capture artifacts
with it across a process boundary and never links it.

> An earlier revision offered AGPL-3.0 plus a commercial licence, retired in September 2026:
> the plugin-sales model it existed for was never realised, and dual licensing requires sole
> ownership of the whole work -- which the EfiGuard derivation made impossible at the time.

### Third-Party Components
Third-party code is permissive throughout: HDE64 and MinHook (BSD-2-Clause), Zydis (MIT),
EDK2 (BSD-2-Clause-Patent). See [LICENSES.md](LICENSES.md) for locations and terms.

## Contributing

Contributions are welcome. Under Apache-2.0 inbound contributions are covered by section 5
of the licence itself, so the [CLA](CLA.md) is no longer required for the Apache-2.0
components; it is retained for the record.

## Disclaimer

This software is provided for legitimate purposes including security research, malware analysis, software debugging, and educational use. Users are responsible for ensuring their use complies with applicable laws and terms of service.

## Links

- Website: https://nexus-sentinel.org
- Issues: [GitHub Issues](../../issues)
- Discussions: [GitHub Discussions](../../discussions)
