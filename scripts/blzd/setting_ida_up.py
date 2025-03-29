"""

1. Set up Compiler options to use latest supported clang msvc version which is 14.33.31629

include directories: /Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.33.31629/include
arguments: -target x86_64-pc-win32 -x c++ -isystem "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.33.31629/include"

2. IDAClang options:
check  "Apply tinfo to mangled names"
check "Parse static decls"
check "Print compiler warnings"
check "Print UDT warnings"
check "Print file paths"
check "Print clang argv"
check "Print target info"

3. IDA change decompiler defautl radix to 16
"""
