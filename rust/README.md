# floss-rs: FLOSS in Rust, on icicle

A port of [FLOSS](https://github.com/mandiant/flare-floss) to Rust,
using [lancelot](https://github.com/williballenthin/lancelot) for program analysis
and [icicle](https://github.com/icicle-emu/icicle-emu) (MIT/Apache-2.0) for emulation.

Status: research prototype. See `doc/` for the design and evaluation.

```
cargo build --release
./target/release/floss-rs --signatures /path/to/floss/sigs sample.exe
./target/release/floss-rs -j sample.exe > results.json
```

Supports PE files (x86 and x64): static, stack, tight, and decoded strings.
