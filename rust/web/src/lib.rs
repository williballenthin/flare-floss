//! floss-rs in the browser, for `web/index.html`.
//!
//! A WebAssembly module (wasm32-wasip1, so the standard library has a clock)
//! with a small C-style interface, which `web/floss.js` wraps:
//!
//!   - `floss_alloc(len) -> ptr` and `floss_free(ptr, len)`, for passing bytes in and out;
//!   - `floss_analyze(ptr, len, time_budget, shellcode) -> result`: run floss-rs on the
//!     file at `ptr`, and return its results as JSON (like `floss-rs -j`), or an error
//!     as `{"error": "..."}`, in a buffer at `result >> 32`, of length `result & 0xffffffff`.
//!
//! It runs on one thread (in a web worker, so the page stays responsive), and sends
//! floss-rs's log messages, like its progress through the candidate decoding routines,
//! to the imported function `floss.log(level, message)`.

#[link(wasm_import_module = "floss")]
extern "C" {
    /// `level` and `message` are UTF-8, at the given pointers and lengths.
    #[link_name = "log"]
    fn host_log(level: *const u8, level_len: usize, message: *const u8, message_len: usize);
}

struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info && metadata.target().starts_with("floss")
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let level = record.level().as_str().to_lowercase();
            let message = record.args().to_string();
            // SAFETY: the host only reads the two strings, during the call.
            unsafe { host_log(level.as_ptr(), level.len(), message.as_ptr(), message.len()) };
        }
    }

    fn flush(&self) {}
}

static LOGGER: Logger = Logger;

#[no_mangle]
pub extern "C" fn floss_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` and `len` are from `floss_alloc`, or a result of `floss_analyze`.
#[no_mangle]
pub unsafe extern "C" fn floss_free(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len));
}

/// Extract strings from a PE file (or 32-bit shellcode, with `shellcode`),
/// emulating candidate decoding routines for up to `time_budget` seconds after the top 20.
///
/// # Safety
/// `ptr` and `len` are a buffer from `floss_alloc`, which this frees.
#[no_mangle]
pub unsafe extern "C" fn floss_analyze(ptr: *mut u8, len: usize, time_budget: f64, shellcode: bool) -> u64 {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
    let buf = Vec::from_raw_parts(ptr, len, len);
    let opts = floss::Options {
        format: if shellcode { floss::Format::Shellcode32 } else { floss::Format::Pe },
        time_budget: std::time::Duration::from_secs_f64(time_budget.max(0.0)),
        // the browser gives a module one thread, without extra setup (shared memory, cross-origin isolation).
        threads: 1,
        ..Default::default()
    };
    let json = match floss::analyze(&buf, &opts) {
        Ok(doc) => serde_json::to_string(&doc),
        Err(e) => serde_json::to_string(&serde_json::json!({ "error": format!("{e:#}") })),
    }
    .expect("results serialize");

    let mut out = json.into_bytes().into_boxed_slice();
    let (ptr, len) = (out.as_mut_ptr(), out.len());
    std::mem::forget(out);
    ((ptr as u64) << 32) | len as u64
}
