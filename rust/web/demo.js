// the drop zone: runs floss-rs (worker.js) on a dropped or chosen file, and shows what it found.
//
// a page that can't serve worker.js and floss_web.wasm beside it (a single file) defines
// window.flossWorker() -> Worker and window.flossModule() -> Promise<WebAssembly.Module>,
// and gives the sample as "#id": an element holding it in base64.
// results to show before anything runs can come in a <script type="application/json" id="demo-example">.
(() => {
  const $ = (id) => document.getElementById(id);
  const demo = $("demo");
  // results for the sample, so the page shows what the tool does before anything runs.
  const EXAMPLE = JSON.parse(document.getElementById("demo-example")?.textContent || "null");
  let worker = null;
  let running = false;
  let doc = EXAMPLE?.doc ?? null;

  const hex = (n) => "0x" + Number(n).toString(16);
  const size = (n) => (n < 1024 ? `${n}B` : n < 1048576 ? `${Math.round(n / 1024)}KB` : `${(n / 1048576).toFixed(1)}MB`);
  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  };

  function setState(text, cls) {
    $("demo-state").textContent = text;
    $("demo-state").className = "run-state " + cls;
  }

  function log(level, message) {
    const line = el("span", level === "warn" || level === "error" ? level : "", message + "\n");
    $("demo-log").append(line);
  }

  // one row per string: how floss-rs found it (stack, tight, decoded, and where), and which routines.
  function rows(strings) {
    const byString = new Map();
    const add = (s, how, routine) => {
      let row = byString.get(s.string);
      if (!row) byString.set(s.string, (row = { string: s.string, wide: s.encoding !== "ASCII", how: new Map(), by: new Set() }));
      row.how.set(how, (row.how.get(how) ?? 0) + 1);
      row.by.add(routine);
    };
    for (const s of strings.stack_strings) add(s, "stack string", s.function);
    for (const s of strings.tight_strings) add(s, "tight string", s.function);
    for (const s of strings.decoded_strings) add(s, `decoded, ${s.address_type.toLowerCase()}`, s.decoding_routine);
    return [...byString.values()];
  }

  function render(doc, seconds) {
    const s = doc.strings;
    const found = rows(s);
    const facts = [
      [found.length, "strings found", "stack, tight, and decoded, without repeats"],
      [s.decoded_strings.length, "decoded", "by emulating decoding routines"],
      [s.stack_strings.length + s.tight_strings.length, "stack and tight", "built or decoded on the stack"],
      [seconds.toFixed(1) + "s", "in this browser", `${doc.analysis.functions_analyzed_decoded_strings} routines emulated`],
    ];
    $("demo-facts").replaceChildren(
      ...facts.map(([value, key, note]) => {
        const f = el("div", "fact");
        f.append(el("span", "fact-value", String(value)), el("span", "fact-key", key), el("span", "fact-note", note));
        return f;
      })
    );

    const body = $("demo-strings");
    body.replaceChildren();
    if (!found.length) {
      const tr = el("tr");
      const td = el("td", "empty", "no hidden strings found");
      td.colSpan = 3;
      tr.append(td);
      body.append(tr);
    }
    for (const row of found) {
      const tr = el("tr");
      tr.append(el("td", "str", row.string));
      const how = el("td", "how");
      for (const [kind, n] of row.how) how.append(el("span", "badge", n > 1 ? `${kind} ×${n}` : kind));
      if (row.wide) how.append(el("span", "badge", "UTF-16"));
      tr.append(how);
      const by = [...row.by].map(hex);
      tr.append(el("td", "by", by.slice(0, 3).join(" ") + (by.length > 3 ? ` +${by.length - 3}` : "")));
      body.append(tr);
    }

    const statics = s.static_strings.map((x) => x.string);
    $("demo-static-head").textContent = `static strings (${statics.length})`;
    $("demo-static").textContent = statics.slice(0, 5000).join("\n") + (statics.length > 5000 ? `\n… and ${statics.length - 5000} more` : "");
  }

  async function bytes(url) {
    if (!url.startsWith("#")) return (await fetch(url)).arrayBuffer();
    return Uint8Array.from(atob(document.getElementById(url.slice(1)).textContent.trim()), (c) => c.charCodeAt(0)).buffer;
  }

  async function run(name, buffer) {
    if (running) return;
    running = true;
    $("demo-name").textContent = name;
    $("demo-size").textContent = size(buffer.byteLength);
    $("demo-log").replaceChildren();
    for (const b of demo.querySelectorAll("button, select")) b.disabled = true;
    const start = performance.now();
    setState("loading floss-rs…", "busy");
    const tick = setInterval(() => setState(`analyzing… ${((performance.now() - start) / 1000).toFixed(1)}s`, "busy"), 200);

    const finish = (state, cls) => {
      clearInterval(tick);
      running = false;
      for (const b of demo.querySelectorAll("button, select")) b.disabled = false;
      setState(state, cls);
    };
    try {
      worker ??= window.flossWorker ? window.flossWorker() : new Worker("worker.js", { type: "module" });
      worker.onmessage = ({ data }) => {
        if (data.type === "log") return log(data.level, data.message);
        if (data.type === "done") {
          doc = data.doc;
          render(data.doc, data.seconds);
          finish(`done in ${data.seconds.toFixed(1)}s`, "ok");
        } else {
          log("error", data.message);
          finish(`failed: ${data.message}`, "fail");
        }
      };
      worker.onerror = (e) => {
        worker = null;
        finish(`failed to start floss-rs: ${e.message || "this browser can't run its worker"}`, "fail");
      };
      const module = window.flossModule ? await window.flossModule() : undefined;
      worker.postMessage({ file: buffer, timeBudget: Number($("demo-budget").value), module }, [buffer]);
    } catch (e) {
      worker = null;
      finish(`failed to start floss-rs: ${e.message}`, "fail");
    }
  }

  async function runFile(file) {
    if (file) run(file.name, await file.arrayBuffer());
  }

  $("demo-file").addEventListener("change", (e) => runFile(e.target.files[0]));
  $("demo-sample").addEventListener("click", async () => run("sample.exe", await bytes(demo.dataset.sample)));
  const drop = $("drop");
  drop.addEventListener("dragover", (e) => {
    e.preventDefault();
    drop.classList.add("over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    runFile(e.dataTransfer.files[0]);
  });
  $("demo-copy").addEventListener("click", async () => {
    const text = JSON.stringify(doc, null, 2);
    try {
      await navigator.clipboard.writeText(text);
      $("demo-copy").textContent = "copied";
    } catch {
      $("demo-static").textContent = text;
      $("demo-static-head").textContent = "results as JSON: select and copy";
      $("demo-static-head").parentElement.open = true;
    }
    setTimeout(() => ($("demo-copy").textContent = "copy results as JSON"), 1500);
  });

  if (EXAMPLE) render(EXAMPLE.doc, EXAMPLE.seconds);
  else if (demo.dataset.autorun) $("demo-sample").click();
})();
