@echo off
setlocal

set "VSTOOLS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207"
set "WINSDK=C:\Program Files (x86)\Windows Kits\10"
set "SDKVER=10.0.26100.0"

set "INCLUDE=%VSTOOLS%\include;%WINSDK%\Include\%SDKVER%\ucrt;%WINSDK%\Include\%SDKVER%\um;%WINSDK%\Include\%SDKVER%\shared"
set "LIB=%VSTOOLS%\lib\x64;%WINSDK%\Lib\%SDKVER%\ucrt\x64;%WINSDK%\Lib\%SDKVER%\um\x64"

cd /d "%~dp0"

del /q tutorial_native.dll 2>nul
del /q tutorial_native.obj 2>nul
del /q step7_hit.obj 2>nul
del /q step8_hit.obj 2>nul
del /q step9_damage.obj 2>nul

echo Compiling step7_hit.asm...
"%VSTOOLS%\bin\Hostx64\x64\ml64.exe" /c /Fo step7_hit.obj step7_hit.asm
if errorlevel 1 (
    echo ASM compilation failed for step7!
    goto :end
)

echo Compiling step8_hit.asm...
"%VSTOOLS%\bin\Hostx64\x64\ml64.exe" /c /Fo step8_hit.obj step8_hit.asm
if errorlevel 1 (
    echo ASM compilation failed for step8!
    goto :end
)

echo Compiling step9_damage.asm...
"%VSTOOLS%\bin\Hostx64\x64\ml64.exe" /c /Fo step9_damage.obj step9_damage.asm
if errorlevel 1 (
    echo ASM compilation failed for step9!
    goto :end
)

echo Compiling tutorial_native.dll...
"%VSTOOLS%\bin\Hostx64\x64\cl.exe" /O2 /W3 /LD tutorial_native.c step7_hit.obj step8_hit.obj step9_damage.obj /link /OUT:tutorial_native.dll /EXPORT:Step7_Hit /EXPORT:Step8_Hit /EXPORT:Step9_DealDamage /EXPORT:Step9_Attack

if exist tutorial_native.dll (
    echo Build successful!
    copy /Y tutorial_native.dll "..\..\..\bin\tutorial_native.dll"
    copy /Y tutorial_native.dll "..\..\..\bin\win-x64\tutorial_native.dll"
    echo Copied to bin folders.
) else (
    echo Build failed!
)

:end
endlocal
