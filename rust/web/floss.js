// floss-rs, compiled to WebAssembly (see src/lib.rs), for browsers and Node.
//
//     import { load } from "./floss.js";
//     const floss = await load(wasmBytesOrModule, (level, message) => console.log(level, message));
//     const results = floss.analyze(fileBytes, { timeBudget: 5 });   // like `floss-rs -j`
//
// The module is built for WASI (wasm32-wasip1), for the standard library's clock,
// and imports only a few WASI functions, which are provided here.

export async function load(wasm, onLog = () => {}) {
  let instance;
  const memory = () => new DataView(instance.exports.memory.buffer);
  const bytes = (ptr, len) => new Uint8Array(instance.exports.memory.buffer, ptr, len);
  const text = (ptr, len) => new TextDecoder().decode(bytes(ptr, len));

  const wasi = {
    random_get(ptr, len) {
      // getRandomValues fills at most 64KB at a time.
      for (let i = 0; i < len; i += 65536) {
        crypto.getRandomValues(bytes(ptr + i, Math.min(65536, len - i)));
      }
      return 0;
    },
    environ_sizes_get(countPtr, sizePtr) {
      memory().setUint32(countPtr, 0, true);
      memory().setUint32(sizePtr, 0, true);
      return 0;
    },
    environ_get() {
      return 0;
    },
    clock_time_get(id, _precision, timePtr) {
      // 0 is the wall clock, the others are monotonic; in nanoseconds.
      const ms = id === 0 ? Date.now() : performance.now();
      memory().setBigUint64(timePtr, BigInt(Math.round(ms * 1e6)), true);
      return 0;
    },
    fd_write(fd, iovs, iovsLen, writtenPtr) {
      // stdout and stderr: Rust's panic messages, which go to the log.
      let written = 0;
      let message = "";
      for (let i = 0; i < iovsLen; i++) {
        const ptr = memory().getUint32(iovs + 8 * i, true);
        const len = memory().getUint32(iovs + 8 * i + 4, true);
        message += text(ptr, len);
        written += len;
      }
      onLog(fd === 2 ? "error" : "info", message.trimEnd());
      memory().setUint32(writtenPtr, written, true);
      return 0;
    },
    proc_exit(code) {
      throw new Error(`floss-rs exited (${code})`);
    },
  };
  const floss = {
    log(levelPtr, levelLen, messagePtr, messageLen) {
      onLog(text(levelPtr, levelLen), text(messagePtr, messageLen));
    },
  };

  // `wasm` is the module's bytes, or a compiled WebAssembly.Module (then this is a fresh instance).
  const loaded = await WebAssembly.instantiate(wasm, { wasi_snapshot_preview1: wasi, floss });
  instance = loaded instanceof WebAssembly.Instance ? loaded : loaded.instance;

  return {
    /// run floss-rs on a file's bytes; returns its results, as `floss-rs -j` prints them.
    analyze(file, { timeBudget = 5, shellcode = false } = {}) {
      const { floss_alloc, floss_analyze, floss_free } = instance.exports;
      const ptr = floss_alloc(file.length);
      bytes(ptr, file.length).set(file);
      const result = floss_analyze(ptr, file.length, timeBudget, shellcode);
      const [outPtr, outLen] = [Number(result >> 32n), Number(result & 0xffffffffn)];
      const json = text(outPtr, outLen);
      floss_free(outPtr, outLen);
      const doc = JSON.parse(json);
      if (doc.error) throw new Error(doc.error);
      return doc;
    },
  };
}
