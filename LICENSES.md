# Licensing

**Nexus Sentinel is Apache 2.0 throughout.** See the `LICENSE` file at the
repository root.

That is a change. Until 17 September 2026 this project was licensed per
component, because `Nexus/UEFI/` was a derivative work of EfiGuard and therefore
GPL-3.0 while everything else was Apache 2.0. `Nexus/UEFI/` no longer contains
derivative code, so the split has no reason to exist and is gone.

`Nexus/UEFI/NOTICE` records what was replaced and when.

## What that changed, concretely

The GPL-3.0 boundary ran along a directory, not along the code inside it — so it
also covered `Nexus/UEFI/NexusTpmDxe/`, the TPM 2.0 implementation, which is
original work and was only ever copylefted by sharing a build with the
derivative files. Both compile into the same `.efi`, which made them one work.
Removing the derivative half is what separated them.

## Versions

| Versions | Licence |
|---|---|
| up to and including `v2.0.0-alpha.4` | **GPL-3.0** for `Nexus/UEFI/`, Apache 2.0 elsewhere |
| `v2.0.0-beta.1` and later | **Apache 2.0** throughout |

Nothing here withdraws or alters rights granted with earlier releases. GPLv3
grants are irrevocable, and anyone who obtained those versions keeps them under
the terms they were published with. The `v2.0.0-alpha.3` and `v2.0.0-alpha.4`
artifacts have been withdrawn from distribution — which stops the project
distributing them, and does not and cannot reach copies already taken.

## The emulator boundary still holds, and is not negotiable

NexusForge and NexusForge-Core are GPL-2.0 (QEMU-derived) and are *permanently*
GPL-2.0 — QEMU as a whole work is GPLv2, so no future cleanup can change it.
GPL-2.0 is incompatible with Apache 2.0, which means:

> **Nexus Sentinel must never import, link, or in-process load NexusForge or
> NexusForge-Core.** Data may flow between them — Sentinel writes capture
> artifacts, Forge reads them — but the process boundary is load-bearing and is
> the only configuration in which these projects can legally coexist.

Forge consuming a Sentinel capture file creates no obligation in either
direction. Linking would. This was true under the old per-component licensing
and is equally true now; if anything it matters more, since Apache 2.0 and
GPL-2.0 are incompatible in a way Apache 2.0 and GPL-3.0 were not.

## Third-party components

All permissive; none imposes copyleft on this project.

| Component | Location | Licence |
|---|---|---|
| HDE64 (Vyacheslav Patkov) | `Nexus/Drivers/NexusCore/hde/` | BSD-2-Clause (`LICENSE`) |
| MinHook (Tsuda Kageyu) | `Nexus/Native/ApiHook/minhook/` | BSD-2-Clause (`LICENSE.txt`) |
| Zydis / Zycore (Florian Bernd, Joel Höner) | `Nexus/Engine/third_party/`, `Nexus/UEFI/SDK/Zydis/` | MIT (`LICENSE`) |
| EDK2 (Intel / TianoCore) | `Nexus/UEFI/SDK/EDK2/` | BSD-2-Clause-Patent (`LICENSE`) |

## History

Earlier revisions carried a single AGPL-3.0 licence with a commercial
dual-licensing offer. That was retired in September 2026: the plugin-sales model
it existed to support was never realised, and dual licensing requires sole
ownership of the whole work, which the EfiGuard-derived UEFI tree made
impossible. It was replaced by per-component licensing, which stated the actual
position accurately while that derivation existed.

With the derivation gone, sole ownership holds again and a single Apache 2.0
licence states the position more simply than the table it replaces.

`CLA.md` existed to support the dual-licensing model. Under Apache 2.0,
contributions are covered by section 5 of the licence itself; the CLA is
retained for reference but is not required.
