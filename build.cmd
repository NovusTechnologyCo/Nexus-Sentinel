@echo off
setlocal EnableExtensions
REM ============================================================================
REM build.cmd -- build Nexus Sentinel from source.
REM
REM Produces three artifacts:
REM
REM   Nexus\Drivers\NexusCore\bin\NexusCore.sys          the kernel driver
REM   Nexus\UEFI\build\x64\Release\PlatformRuntimeDxe.efi  the UEFI DXE driver
REM   Nexus\Usermode\PlatformCtl\bin\PlatformCtl.exe     the control utility
REM
REM ORDER MATTERS AND THIS SCRIPT ENFORCES IT. NexusCore.sys is EMBEDDED into the
REM DXE as a generated C header, so building only the DXE after changing the
REM driver silently ships the OLD driver. Steps 1-3 always run together.
REM
REM Requirements:
REM   - Visual Studio 2022 or later, "Desktop development with C++"
REM   - Windows Driver Kit (WDK) matching your Visual Studio version
REM   - Python 3.8 or later on PATH
REM
REM Optional, for Secure Boot:
REM   set NEXUS_SB_PFX=C:\path\to\your.pfx
REM   set NEXUS_SB_PASS=your-pfx-password
REM
REM   A UEFI DXE driver must be signed by a key the firmware trusts, or Secure
REM   Boot will refuse to load it -- silently. Without these variables the build
REM   still succeeds and produces an UNSIGNED .efi, which is useful for
REM   inspection and useless for booting with Secure Boot enabled. See
REM   docs/SECURE_BOOT.md.
REM ============================================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "CORESYS=%ROOT%\Nexus\Drivers\NexusCore\bin\NexusCore.sys"
set "PAYLOAD=%ROOT%\Nexus\UEFI\NexusBootDxe\NexusCorePayload.h"
set "DXEOUT=%ROOT%\Nexus\UEFI\build\x64\Release\PlatformRuntimeDxe.efi"
set "CTLOUT=%ROOT%\Nexus\Usermode\PlatformCtl\bin\PlatformCtl.exe"

REM ---------------------------------------------------------------- toolchain
REM VsDevCmd puts msbuild and the WDK targets on PATH. Searching rather than
REM hardcoding one path so this works on Community, Professional and Enterprise.
set "VSDEV="
for %%E in (18 2022) do (
  for %%D in (Community Professional Enterprise BuildTools) do (
    if not defined VSDEV (
      if exist "%ProgramFiles%\Microsoft Visual Studio\%%E\%%D\Common7\Tools\VsDevCmd.bat" (
        set "VSDEV=%ProgramFiles%\Microsoft Visual Studio\%%E\%%D\Common7\Tools\VsDevCmd.bat"
      )
    )
  )
)
if not defined VSDEV (
  echo ERROR: Visual Studio not found.
  echo        Install VS 2022 or later with "Desktop development with C++",
  echo        plus the Windows Driver Kit.
  exit /b 1
)
call "%VSDEV%" -arch=amd64 >nul
if errorlevel 1 ( echo ERROR: VsDevCmd failed. & exit /b 1 )

where python >nul 2>&1
if errorlevel 1 ( echo ERROR: python not found on PATH. & exit /b 1 )

echo.
echo === [1/4] NexusCore.sys ===
msbuild "%ROOT%\Nexus\Drivers\NexusCore\NexusCore.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
if errorlevel 1 ( echo FAILED: NexusCore build. & exit /b 2 )
if not exist "%CORESYS%" ( echo FAILED: NexusCore.sys was not produced. & exit /b 2 )

REM (!) NOT A STYLE CHECK. The DXE maps this driver itself, before Windows
REM exists to resolve imports, so an import table means the payload references
REM addresses nothing will fill in. It fails at boot, not at build, which is why
REM it is checked here rather than left to be discovered.
python "%ROOT%\tools\check_no_imports.py" "%CORESYS%"
if errorlevel 1 ( echo FAILED: NexusCore.sys has an import table. & exit /b 2 )

echo.
echo === [2/4] Embedding the driver into the DXE ===
python "%ROOT%\tools\embed_driver.py" "%CORESYS%" "%PAYLOAD%"
if errorlevel 1 ( echo FAILED: could not embed NexusCore.sys. & exit /b 3 )

echo.
echo === [3/4] PlatformRuntimeDxe.efi ===
msbuild "%ROOT%\Nexus\UEFI\NexusBoot.sln" /p:Configuration=Release /p:Platform=x64 /t:NexusBootDxe /v:minimal /nologo
if errorlevel 1 ( echo FAILED: DXE build. & exit /b 4 )
if not exist "%DXEOUT%" (
  echo   incremental build produced no output -- forcing a full relink
  msbuild "%ROOT%\Nexus\UEFI\NexusBoot.sln" /p:Configuration=Release /p:Platform=x64 /t:NexusBootDxe:Rebuild /v:minimal /nologo
  if errorlevel 1 ( echo FAILED: DXE rebuild. & exit /b 4 )
)
if not exist "%DXEOUT%" ( echo FAILED: DXE output missing after rebuild. & exit /b 4 )

REM ------------------------------------------------------------------ signing
REM Explicit opt-in only. This never falls back to a key path on the developer's
REM machine: a build that quietly signs with someone else's key, or that claims
REM to have signed when it did not, is worse than an honestly unsigned one.
if not defined NEXUS_SB_PFX goto :unsigned
if not exist "%NEXUS_SB_PFX%" (
  echo ERROR: NEXUS_SB_PFX is set but "%NEXUS_SB_PFX%" does not exist.
  exit /b 4
)
REM (!) THE ARCHITECTURE FILTER IS NOT OPTIONAL, AND TAKING THE FIRST MATCH IS WRONG.
REM A Windows Kits install carries signtool.exe for arm64, x64 and x86 under each
REM SDK version. `dir /b /s` returns them alphabetically, so "first match wins"
REM selects the ARM64 binary, which cannot execute here -- signing fails with an
REM error that says nothing about architecture. Filter to x64 and let the LAST
REM match win, which sorts to the newest SDK.
set "SIGNTOOL="
for /f "delims=" %%S in ('dir /b /s "%ProgramFiles(x86)%\Windows Kits\10\bin\signtool.exe" 2^>nul ^| findstr /i "x64"') do set "SIGNTOOL=%%S"
if not defined SIGNTOOL (
  echo ERROR: no x64 signtool.exe found. Install the Windows SDK signing tools.
  exit /b 4
)
REM signtool's own diagnostics are not suppressed: when signing fails the reason is
REM the only useful thing on screen.
if defined NEXUS_SB_PASS (
  "%SIGNTOOL%" sign /fd sha256 /f "%NEXUS_SB_PFX%" /p "%NEXUS_SB_PASS%" "%DXEOUT%"
) else (
  "%SIGNTOOL%" sign /fd sha256 /f "%NEXUS_SB_PFX%" "%DXEOUT%"
)
REM (!) A FAILED SIGNING DELETES THE ARTIFACT, and the asymmetry with the unsigned
REM path above is deliberate. No key at all is a choice, and an unsigned .efi is
REM still useful for inspection. But asking for a signature and not getting one,
REM on a machine whose firmware enforces your certificate, leaves a file that
REM fails SILENTLY at boot -- the machine boots, Nexus is absent, and nothing
REM points at signing. Leaving it on disk is worse than failing the build.
if errorlevel 1 (
  if exist "%DXEOUT%" del /q "%DXEOUT%"
  echo FAILED: signing failed -- the unsigned .efi has been deleted.
  exit /b 4
)
echo   signed with %NEXUS_SB_PFX%
goto :ctl

:unsigned
echo   NEXUS_SB_PFX not set -- the .efi is UNSIGNED.
echo   (!) Firmware will refuse to load it while Secure Boot is ENABLED, and it
echo       refuses SILENTLY: the system boots normally and Nexus is simply absent.

:ctl
echo.
echo === [4/4] PlatformCtl.exe ===
msbuild "%ROOT%\Nexus\Usermode\PlatformCtl\PlatformCtl.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
if errorlevel 1 ( echo FAILED: PlatformCtl build. & exit /b 5 )

echo.
echo === BUILD OK ===
echo   %CORESYS%
echo   %DXEOUT%
echo   %CTLOUT%
echo.
echo Deploying the .efi and rebooting is a manual step. See docs/SECURE_BOOT.md.
exit /b 0
