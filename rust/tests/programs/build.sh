#!/bin/sh
# build the test programs with clang and lld, for x86 and x64.
set -e
cd "$(dirname "$0")"
mkdir -p bin
llvm-dlltool -m i386 -d kernel32.def -l bin/kernel32-32.lib -k
llvm-dlltool -m i386:x86-64 -d kernel32-64.def -l bin/kernel32-64.lib
for src in *.c; do
    name="${src%.c}"
    for opt in O0 O2; do
        clang --target=i686-pc-windows-msvc -$opt -ffreestanding -fno-builtin -fno-stack-protector -c "$src" -o "bin/$name-$opt.obj"
        lld-link /nologo /entry:main /subsystem:console /nodefaultlib /out:"bin/$name-32-$opt.exe" "bin/$name-$opt.obj" bin/kernel32-32.lib
        clang --target=x86_64-pc-windows-msvc -$opt -ffreestanding -fno-builtin -fno-stack-protector -c "$src" -o "bin/$name-$opt.obj"
        lld-link /nologo /entry:main /subsystem:console /nodefaultlib /out:"bin/$name-64-$opt.exe" "bin/$name-$opt.obj" bin/kernel32-64.lib
    done
done
rm -f bin/*.obj bin/*.lib
