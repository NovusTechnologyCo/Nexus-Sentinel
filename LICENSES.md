# Licensing

Nexus Sentinel is licensed **per component**, not as a single blanket work. The
components ship as separate binaries with no in-process linkage between them, so
each carries the licence its own provenance requires.

| Component | Licence | Why |
|---|---|---|
| `Nexus/Drivers/`, `Nexus/Kernel/`, `Nexus/Native/`, `Nexus/Usermode/`, `Nexus/UserHook/`, `Nexus/Engine/`, `Nexus/UI/`, tooling, docs | **Apache 2.0** (root `LICENSE`) | Original work. All vendored third-party code in these trees is permissive (BSD/MIT). |
| `Nexus/UEFI/` | **GPL-3.0** (`Nexus/UEFI/LICENSE`) | Derivative of EfiGuard (GPLv3). See `Nexus/UEFI/NOTICE`. |

## Why the boundary holds

`Nexus/UEFI/` builds to standalone UEFI images (`.efi`) loaded by firmware. It
communicates with the kernel driver across a firmware/OS boundary through the
protocol declared in `Nexus/UEFI/Include/Protocol/NexusBoot.h` — separate
binaries, separate address spaces, separate load events. GPLv3's copyleft
applies to that work; it does not reach the separately-distributed driver and
user-mode components.

**The same rule governs the emulator.** NexusForge and NexusForge-Core are
GPL-2.0 (QEMU-derived) and are *permanently* GPL-2.0 — QEMU as a whole work is
GPLv2, so no future cleanup can change it. GPL-2.0 is incompatible with both
Apache-2.0 and GPL-3.0, which means:

> **Nexus Sentinel must never import, link, or in-process load NexusForge or
> NexusForge-Core.** Data may flow between them — Sentinel writes capture
> artifacts, Forge reads them — but the process boundary is load-bearing and is
> the only configuration in which these projects can legally coexist.

Forge consuming a Sentinel capture file creates no obligation in either
direction. Linking would.

## Third-party components

All permissive; none imposes copyleft on the Apache-2.0 trees.

| Component | Location | Licence |
|---|---|---|
| HDE64 (Vyacheslav Patkov) | `Nexus/Drivers/NexusCore/hde/` | BSD-2-Clause (`LICENSE`) |
| MinHook (Tsuda Kageyu) | `Nexus/Native/ApiHook/minhook/` | BSD-2-Clause (`LICENSE.txt`) |
| Zydis (Florian Bernd, Joel Höner) | `Nexus/Engine/third_party/`, `Nexus/UEFI/SDK/Zydis/` | MIT (`LICENSE.Zydis`) |
| EDK2 (Intel / TianoCore) | `Nexus/UEFI/SDK/EDK2/` | BSD-2-Clause-Patent |
| EfiGuard (Mattiwatti) | `Nexus/UEFI/NexusBootDxe/` | **GPL-3.0** — see `Nexus/UEFI/NOTICE` |

## History

Earlier revisions of this repository carried a single AGPL-3.0 licence with a
commercial dual-licensing offer. That was retired in September 2026: the
plugin-sales model it existed to support was never realised, and dual licensing
requires sole ownership of the whole work, which the EfiGuard-derived UEFI tree
made impossible. Per-component licensing states the actual position accurately
and leaves more commercial room, not less.

`CLA.md` existed to support that dual-licensing model. Under Apache 2.0,
contributions are covered by section 5 of the licence itself; the CLA is
retained for reference but is no longer required for the Apache-2.0 components.
