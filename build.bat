@echo off
set WDK=C:\Program Files (x86)\Windows Kits\10
set WDKV=10.0.22621.0
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

cl /nologo /kernel /GS- /O2 /W3 /c NvRmDrv.c ^
   /I"%WDK%\Include\%WDKV%\km" ^
   /I"%WDK%\Include\%WDKV%\shared" ^
   /I"%WDK%\Include\%WDKV%\ucrt"
if errorlevel 1 exit /b 1

link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry ^
   /OUT:NvRmDrv.sys NvRmDrv.obj ^
   /LIBPATH:"%WDK%\Lib\%WDKV%\km\x64" ^
   ntoskrnl.lib hal.lib ntstrsafe.lib BufferOverflowK.lib
if errorlevel 1 exit /b 1

inf2cat /driver:. /os:10_X64
echo [+] NvRmDrv.sys + NvRmDrv.cat готовы
