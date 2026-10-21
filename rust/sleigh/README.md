# SLEIGH specifications

The files in `x86/` are the x86 and x86-64 processor specifications from
Ghidra (`Ghidra/Processors/x86/data/languages`), Apache License 2.0,
copied from NationalSecurityAgency/ghidra at commit
b8e9917e4c01959fe97ba94954731ed8cf2d201c.

icicle compiles these at startup (about 200ms) to get the instruction
semantics for the emulator. They are embedded into the floss binary
(see `src/emu/sleigh.rs`), so no Ghidra installation is needed at runtime.
