# Secure Boot, driver signing, and how Nexus actually loads

Nexus Sentinel includes a UEFI component (`PlatformRuntimeDxe.efi`) and a kernel driver
(`NexusCore.sys`). Both sit below the OS trust boundary, so how they get loaded is not an
implementation detail — it is the first thing you have to decide about your setup.

**Short version: run with Secure Boot disabled. That is the normal, supported configuration.**

---

## Why Microsoft will not sign this driver

Microsoft classifies as a critical vulnerability any driver able to *map arbitrary kernel,
physical, or device memory to user mode, or read and write arbitrary kernel, physical, or device
memory from user mode.*

That is a precise description of what a memory-inspection framework does. It is the feature, not a
flaw — you cannot inspect a hostile process's memory without reading arbitrary memory.

So the usual signing routes are closed to this class of tool:

- **Attestation signing** through Partner Center would be refused on those grounds.
- A driver that somehow got through would be added to the **vulnerable driver blocklist** and stop
  loading anyway.
- Since **April 2026**, Windows only accepts drivers signed through WHCP; legacy cross-signed
  drivers are rejected by default.

This is not specific to Nexus. Cheat Engine's DBK driver, ReClass.NET's driver, and every
comparable analysis tool hit the same wall for the same reason. There is no version of this project
that ships a Microsoft-signed kernel driver, and there never will be.

An **EV code-signing certificate is still useful** for the user-mode components — the tools, the
installer, SmartScreen reputation. It does nothing for the driver.

---

## The three configurations

### 1. Secure Boot disabled — the supported default

What almost everyone should do.

- Build normally. With no signing key present the build produces an **unsigned**
  `PlatformRuntimeDxe.efi` and tells you so. This is not an error.
- Disable Secure Boot in firmware setup.
- Enable test signing for the kernel driver: `bcdedit /set testsigning on`, then reboot.

Trade-off: the machine boots with Secure Boot off. On a dedicated analysis box that is fine and is
what most malware-analysis rigs do anyway. Do not do this on a machine you also use for banking.

### 2. Secure Boot enabled, with your own certificate enrolled — advanced

What the development machine runs. It keeps Secure Boot genuinely on, which matters when the thing
you are analysing inspects the boot state.

It requires firmware that exposes **Setup Mode**, a willingness to replace the platform trust
store, and the ability to restore it. **Most users cannot and should not do this.** If your firmware
does not offer Setup Mode, or you are not confident restoring the factory PK, use configuration 1.

Broad shape — consult your firmware's documentation, because the details differ per vendor:

1. Generate a key pair and certificate for signing.
2. Enter Setup Mode (usually "erase all Secure Boot keys" / "clear PK" in firmware setup).
3. Enroll your own PK, and append your certificate to `db`.
4. **Back up the factory keys first**, and keep the restore files. This is the step people regret
   skipping.
5. Point the build at your key (below) so the `.efi` is signed with it.

### 3. Secure Boot enabled, stock keys — does not work

The `.efi` is not signed by anything the factory trust store recognises, so **the firmware refuses
it silently** and falls through to Windows Boot Manager. The machine boots normally and Nexus is
simply absent.

⚠ This failure is quiet. There is no error message. If Nexus seems to do nothing after install,
check Secure Boot before you go looking for a bug — this is the single most common cause, and it
costs a reboot to find out.

---

## Building

### Without a signing key (default)

Nothing to do. Run `build.cmd`. It signs only when you ask it to, so with no key configured it
prints `NEXUS_SB_PFX not set -- the .efi is UNSIGNED`, keeps the artifact, and continues.

It will not reach for a key it happens to find on the machine. Signing is explicit or it does not
happen — a build that quietly signed with whatever key was lying around, or that reported success
without signing, would be worse than one that says plainly what it did.

### With a signing key

Private key material is **never committed**, so a fresh clone has none. Point the build at your
own `.pfx`:

```bat
set NEXUS_SB_PFX=D:\keys\nexus-sb\NexusSB.pfx
set NEXUS_SB_PASS=your-pfx-password
```

`NEXUS_SB_PASS` may be omitted if the `.pfx` has no password.

Behaviour is deliberately asymmetric:

- **No key** → build unsigned and say so. Not an error.
- **Key present but signing fails** → hard failure, and the artifact is deleted. On a machine where
  Secure Boot *is* enforcing your certificate, an unsigned `.efi` would fail silently at boot
  (configuration 3), so leaving one on disk would be worse than failing the build.

⚠ **Never commit the key or the password**, and never put the password into the build script —
that script is committed. Keep key material outside every repository and point `NEXUS_SB_PFX` at
it.

---

## A note on the Secure Boot presentation layer

`NexusBootDxe` can present `SecureBoot = 1` to the OS. That exists for **analysis-environment
hardening**: malware fingerprints its host to decide whether it is being watched, and boot state is
part of that fingerprint. An analysis rig that looks like a normal machine sees more representative
behaviour.

It **fails closed**. `SecureBootSpoofIsCoherent()` reads the live `SetupMode` and `AuditMode`
variables and declines unless the platform is genuinely provisioned and outside Audit Mode. Per the
UEFI specification, `SecureBoot = 1` is only defined outside those modes — presenting it on a
machine in Setup Mode would manufacture a state that cannot exist on real hardware, which is *more*
detectable than not presenting it at all.

So on a machine in configuration 1, this layer simply stays out of the way.
