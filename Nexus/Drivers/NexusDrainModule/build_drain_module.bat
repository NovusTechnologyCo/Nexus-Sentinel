@echo off
setlocal
REM ============================================================================================
REM Build NexusDrainModule.sys -- the module whose PREPARE and COMMIT both SUCCEED while a
REM caller is still inside it, so NxcMapUnmap's DRAIN TIMEOUT can actually be executed.
REM ISSUES.md I-01: the last teardown branch that had never run.
REM
REM It had NO build script at all: it was built ad-hoc once, which meant a source change could sit
REM on disk while the .sys that gets mapped stayed stale, and the only symptom would be a test
REM that "passes" against code nobody edited. Same class as the stale-DXE problem PayloadIdent was
REM added to catch, one layer down.
REM
REM VS discovery is copied from build.cmd deliberately -- one place to fix
REM if the toolchain moves is better than one script silently using a different compiler.
REM ============================================================================================

set "ROOT=%~dp0..\..\.."

REM (!) EVERY EDITION, NOT JUST COMMUNITY. This used to test two hardcoded
REM Community paths and fail outright on Professional, Enterprise or
REM BuildTools -- which works on one machine and on nobody else's.
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
    echo ERROR: Visual Studio not found ^(2022 or later, with C++ tools^).
    exit /b 1
)

call "%VSDEV%" -arch=amd64 >nul
if errorlevel 1 ( echo ERROR: VsDevCmd failed & exit /b 1 )

echo === Building NexusDrainModule ===
msbuild "%ROOT%\Nexus\Drivers\NexusDrainModule\NexusDrainModule.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
if errorlevel 1 ( echo ERROR: build failed & exit /b 1 )

echo.
echo === DRAIN TEST MODULE OK ===
echo   %ROOT%\Nexus\Drivers\NexusDrainModule\bin\NexusDrainModule.sys
endlocal
