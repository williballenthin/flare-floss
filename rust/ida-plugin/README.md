# FLOSS for IDA Pro

[FLOSS](https://github.com/mandiant/flare-floss), the FLARE Obfuscated String
Solver, as a plugin for IDA Pro 9.5. It finds the strings that a program
builds or decodes when it runs: stack strings, tight strings, and the strings
that decoding routines return. The plugin emulates the code of the program to
get them, and doesn't run the program.

When IDA finishes the analysis of a file, the plugin extracts the strings and
stores them in the database as synthetic strings of the provider "FLOSS". IDA
shows them in the Strings window, and as comments in the listing, at the
instructions that use each string:

```
.text:0000000140001079   lea     rcx, OutputString  ; lpOutputString
.text:0000000140001079                              ; "C:\\malware.exe"
.text:0000000140001080   call    cs:OutputDebugStringA ; kernel32
.text:0000000140001080                              ; "C:\\malware.exe"
```

IDA saves the strings with the database, so the plugin runs once for a
database. Edit > Plugins > FLOSS extracts the strings again, and replaces
them. The output window has a summary:

```
FLOSS: extracting obfuscated strings
FLOSS: 1 stack strings, 0 tight strings, and 1 decoded strings, as 1 synthetic strings in the Strings window, in 0.07s
```

The plugin works on x86 and x64 programs. It's a native library, written in
Rust, with no dependencies other than IDA. IDA waits while the plugin runs,
which takes from under a second to about a minute for a large program.

[The documentation of floss-rs](https://github.com/mandiant/flare-floss/blob/master/rust/README.md#in-ida)
has the details: where each kind of string shows, which strings the plugin
leaves out, and how to build the plugin.
