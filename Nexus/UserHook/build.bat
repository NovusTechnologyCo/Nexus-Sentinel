@echo off
REM Build script for SecureBootHook DLL and Injector
REM Run from x64 Native Tools Command Prompt for VS

echo === Building SecureBootHook ===

REM Check if cl.exe is available
where cl.exe >nul 2>&1
if errorlevel 1 (
    echo Error: cl.exe not found. Run from "x64 Native Tools Command Prompt for VS"
    exit /b 1
)

REM Create output directory
if not exist bin mkdir bin

echo.
echo [1/2] Building SecureBootHook.dll...
cl /nologo /LD /O2 /GS- /W3 /EHsc ^
    /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_USRDLL" ^
    SecureBootHook.cpp ^
    /link /OUT:bin\SecureBootHook.dll /DLL ^
    kernel32.lib user32.lib ntdll.lib

if errorlevel 1 (
    echo [!] Failed to build SecureBootHook.dll
    exit /b 1
)
echo [+] SecureBootHook.dll built successfully

echo.
echo [2/2] Building Injector.exe...
cl /nologo /O2 /GS- /W3 /EHsc ^
    /D "WIN32" /D "NDEBUG" /D "_CONSOLE" ^
    Injector.cpp ^
    /link /OUT:bin\Injector.exe ^
    kernel32.lib user32.lib advapi32.lib

if errorlevel 1 (
    echo [!] Failed to build Injector.exe
    exit /b 1
)
echo [+] Injector.exe built successfully

echo.
echo === Build Complete ===
echo Output files in: %CD%\bin
echo.
echo Usage:
echo   bin\Injector.exe ^<PID or ProcessName^>
echo.
echo Example:
echo   bin\Injector.exe notepad.exe
echo   bin\Injector.exe 1234
echo.
echo Log output: %%TEMP%%\SecureBootHook.log

del *.obj 2>nul
