:: lua.bat: Generates lua.til type library for Hex Rays Decompiler
:: lua.bat: Generates lua.til type library for Hex Rays Decompiler

@echo off

:: Set version and folders
set ver=10.0.26100.0
set winfolder=%ProgramFiles(x86)%\Windows Kits\10\Include\%ver%
set luafolder=D:\re\wow\lua-5.1.4\src
set idafolder=C:\Program Files\IDA Pro 8.3\tilib83\win

:: Call tilib64.exe with the required options
"%idafolder%\tilib64.exe" -c ^
-Cc1 ^
-Ci4 ^
-Cl4 ^
-Cvr ^
-D_WIN32 ^
-DMSC_NOOPT ^
-D_MSC_VER=1940 ^
-D_MSC_FULL_VER=194033811 ^
-DWINNT=1 ^
-DWINVER=_WIN32_WINNT ^
-D_WIN32_WINNT=0x0A00 ^
-D_WIN32_IE=0x0A00 ^
-D_inline=inline ^
-D__inline=inline ^
-D__forceinline=inline ^
-D__volatile=volatile ^
-Dbool=uint8_t ^
-DSIZE_T=uint32_t ^
-DPSIZE_T=uint32_t* ^
-h"%luafolder%\luaimport.h" ^
-I"%winfolder%\cppwinrt\winrt" ^
-I"%winfolder%\km" ^
-I"%winfolder%\km\crt" ^
-I"%winfolder%\shared" ^
-I"%winfolder%\ucrt" ^
-I"%winfolder%\um" ^
-I"%winfolder%\winrt" ^
-e ^
lua514.til

endlocal