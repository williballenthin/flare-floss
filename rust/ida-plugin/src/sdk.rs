//! The parts of the IDA SDK that the plugin uses and that idalib doesn't bind:
//! synthetic strings (`strlist.hpp`), event hooks (`ida.hpp`), and netnodes (`netnode.hpp`).
//!
//! These are C functions that IDA's library exports. The structures here have the layout of
//! the SDK's, and only ever go to IDA as `const` arguments, so they point at memory that
//! Rust owns, and IDA never frees or grows them.
use std::{
    ffi::{c_char, c_int, c_void, CStr, CString},
    marker::PhantomData,
};

use crate::synth::SyntheticString;

/// `qvector<T>`, borrowed from a slice.
#[repr(C)]
struct QVector<'a, T> {
    array:   *const T,
    n:       usize,
    alloc:   usize,
    _marker: PhantomData<&'a [T]>,
}

impl<'a, T> QVector<'a, T> {
    fn new(items: &'a [T]) -> Self {
        QVector {
            array:   if items.is_empty() { std::ptr::null() } else { items.as_ptr() },
            n:       items.len(),
            alloc:   items.len(),
            _marker: PhantomData,
        }
    }
}

/// `synth_string_t`.
#[repr(C)]
struct SynthString<'a> {
    ea:       u64,
    /// a `qstring`: its size counts the terminator.
    text:     QVector<'a, u8>,
    flags:    u32,
    provider: u8,
    uses:     QVector<'a, u64>,
    parts:    QVector<'a, u64>,
}

const _: () = assert!(std::mem::size_of::<SynthString>() == 88);

const SYNTHSTR_REPEATABLE: u32 = 0x0002;

/// `hook_type_t::HT_IDB`.
const HT_IDB: c_int = 3;
/// `idb_event::auto_empty_finally`.
pub const AUTO_EMPTY_FINALLY: c_int = 4;

/// `hook_cb_t`. The `va_list` is one pointer on the platforms that IDA runs on.
pub type HookCallback = extern "C" fn(user_data: *mut c_void, code: c_int, va: *mut c_void) -> isize;

extern "C" {
    fn synth_string_register_provider(id: u8, name: *const c_char) -> bool;
    fn synth_string_forget(provider: u8, ea1: u64, ea2: u64);
    fn synth_string_set_strings(provider: u8, ea: u64, strings: *const QVector<SynthString>) -> bool;
    fn hook_to_notification_point(hook_type: c_int, cb: HookCallback, user_data: *mut c_void) -> bool;
    fn unhook_from_notification_point(hook_type: c_int, cb: HookCallback, user_data: *mut c_void) -> c_int;
    fn auto_is_ok() -> bool;
    fn netnode_check(node: *mut u64, name: *const c_char, namlen: usize, create: bool) -> bool;
}

/// Name the provider of synthetic strings, for the Strings window. This lasts until the database closes.
pub fn register_provider(id: u8, name: &CStr) -> bool {
    // SAFETY: IDA copies the name.
    unsafe { synth_string_register_provider(id, name.as_ptr()) }
}

/// Remove all the synthetic strings of the provider.
pub fn forget_strings(provider: u8) {
    // SAFETY: plain values.
    unsafe { synth_string_forget(provider, 0, u64::MAX) }
}

/// Replace the provider's synthetic strings at the address with at most `max_uses` uses
/// and `max_parts` parts each. IDA refuses strings that don't fit in what it stores for one address.
pub fn set_strings(provider: u8, ea: u64, strings: &[SyntheticString], max_uses: usize, max_parts: usize) -> bool {
    let texts: Vec<CString> = strings
        .iter()
        .map(|s| CString::new(s.text.replace('\0', " ")).expect("no terminators"))
        .collect();
    let strings: Vec<SynthString> = strings
        .iter()
        .zip(&texts)
        .map(|(s, text)| SynthString {
            ea,
            text: QVector::new(text.as_bytes_with_nul()),
            flags: if s.repeatable { SYNTHSTR_REPEATABLE } else { 0 },
            provider,
            uses: QVector::new(&s.uses[..s.uses.len().min(max_uses)]),
            parts: QVector::new(&s.parts[..s.parts.len().min(max_parts)]),
        })
        .collect();
    // SAFETY: the vector and what it points at have the SDK's layout, and outlive the call,
    // which only reads them.
    unsafe { synth_string_set_strings(provider, ea, &QVector::new(&strings)) }
}

/// Call `cb` for each event of the database, like `AUTO_EMPTY_FINALLY`.
pub fn hook_database_events(cb: HookCallback) -> bool {
    // SAFETY: the callback is a function of this library, which unhooks it before IDA unloads it.
    unsafe { hook_to_notification_point(HT_IDB, cb, std::ptr::null_mut()) }
}

pub fn unhook_database_events(cb: HookCallback) {
    // SAFETY: unhooking a callback that isn't hooked does nothing.
    unsafe { unhook_from_notification_point(HT_IDB, cb, std::ptr::null_mut()) };
}

/// whether IDA's analysis of the database is complete.
pub fn is_analysis_complete() -> bool {
    // SAFETY: no arguments.
    unsafe { auto_is_ok() }
}

/// whether the database has a netnode with this name, creating it when `create`.
pub fn has_netnode(name: &CStr, create: bool) -> bool {
    let mut node = u64::MAX;
    // SAFETY: a `netnode` is its number, and IDA measures the name itself for a length of zero.
    unsafe { netnode_check(&mut node, name.as_ptr(), 0, create) }
}
