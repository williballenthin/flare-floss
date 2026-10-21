// runs floss-rs (floss_web.wasm) off the page's thread, one file at a time.
//
//   page -> worker: { file: ArrayBuffer, timeBudget: seconds, module?: WebAssembly.Module }
//   worker -> page: { type: "log", level, message }, then { type: "done", doc, seconds } or { type: "error", message }
import { load } from "./floss.js";

let module;

onmessage = async ({ data }) => {
  const log = (level, message) => postMessage({ type: "log", level, message });
  try {
    // the page may send the module (a single-file page has no floss_web.wasm beside it).
    module ??= data.module ?? (await WebAssembly.compile(await (await fetch(new URL("floss_web.wasm", import.meta.url))).arrayBuffer()));
    // a fresh instance for each file: one that failed is never reused, and memory doesn't pile up.
    const floss = await load(module, log);
    const start = performance.now();
    const doc = floss.analyze(new Uint8Array(data.file), { timeBudget: data.timeBudget });
    postMessage({ type: "done", doc, seconds: (performance.now() - start) / 1000 });
  } catch (e) {
    postMessage({ type: "error", message: String(e?.message ?? e) });
  }
};
