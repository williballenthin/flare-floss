#!/bin/sh
# build sample.exe (32-bit) with clang and lld, like tests/programs/build.sh.
set -e
cd "$(dirname "$0")"
llvm-dlltool -m i386 -d ../../tests/programs/kernel32.def -l kernel32.lib -k
clang --target=i686-pc-windows-msvc -O2 -ffreestanding -fno-builtin -fno-stack-protector -c sample.c -o sample.obj
lld-link /nologo /entry:main /subsystem:console /nodefaultlib /out:sample.exe sample.obj kernel32.lib
rm -f sample.obj kernel32.lib
