use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use floss::program::{Arch, Program};

/// in a static build, musl's allocator makes floss-rs 70% slower, and mimalloc 10%.
/// (with glibc, its allocator is a little faster than mimalloc.)
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StringType {
    Static,
    Stack,
    Tight,
    Decoded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// what the backend detects, and shellcode by extension (.sc32, .raw32, .sc64, .raw64)
    Auto,
    Pe,
    /// 32-bit shellcode
    Sc32,
    /// 64-bit shellcode
    Sc64,
}

/// The program analysis backend: it finds the functions and control flow of the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Backend {
    /// IDA Pro, when it's installed and has a license, and otherwise lancelot
    Auto,
    /// IDA Pro: whatever IDA loads, and IDA databases
    Ida,
    /// lancelot, which is built in: PE files and shellcode
    Lancelot,
}

#[cfg(not(any(feature = "ida", feature = "lancelot")))]
compile_error!("enable a program analysis backend: the feature `ida` or `lancelot`");

/// FLOSS, the FLARE Obfuscated String Solver: extract obfuscated strings from malware.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// path to the file to analyze: a program, shellcode, or (with IDA) an IDA database
    sample: PathBuf,

    /// the kind of input
    #[arg(short = 'f', long, value_enum, default_value_t = Format::Auto)]
    format: Format,

    /// the program analysis backend
    #[arg(long, value_enum, default_value_t = Backend::Auto)]
    backend: Backend,

    /// with IDA: use this database, which is opened when it exists, and otherwise created and kept
    /// (default: a temporary database)
    #[cfg(feature = "ida")]
    #[arg(long, value_name = "PATH")]
    idb: Option<PathBuf>,

    /// minimum string length
    #[arg(short = 'n', long, default_value_t = 4)]
    minimum_length: usize,

    /// only extract these string types (default: all)
    #[arg(long, value_enum, num_args = 1..)]
    only: Vec<StringType>,

    /// don't extract these string types
    #[arg(long, value_enum, num_args = 1..)]
    no: Vec<StringType>,

    /// with lancelot: recognize library functions with FLOSS's FLIRT signatures, which are built in
    /// (loading them takes ~5s)
    #[cfg(feature = "lancelot")]
    #[arg(long)]
    flirt: bool,

    /// with lancelot: recognize library functions with these FLIRT signature files (.sig/.pat),
    /// or directories of them, instead
    #[cfg(feature = "lancelot")]
    #[arg(long)]
    signatures: Vec<PathBuf>,

    /// only analyze these functions (hex addresses)
    #[arg(long, value_parser = parse_hex, num_args = 1..)]
    functions: Vec<u64>,

    /// how many of the top-scoring candidate decoding routines to emulate, at least
    #[arg(long, default_value_t = 20)]
    top_functions: usize,

    /// after the top functions, keep emulating more candidates until decoding has taken
    /// this many seconds (0: just the top functions, for reproducible results)
    #[arg(long, default_value_t = 5.0)]
    time_budget: f64,

    /// threads for emulation, on larger files (default: the number of CPUs)
    #[arg(long)]
    threads: Option<usize>,

    /// emit JSON
    #[arg(short = 'j', long)]
    json: bool,
}

fn parse_hex(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

#[cfg(feature = "lancelot")]
fn expand_signatures(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut sigs = vec![];
    for path in paths {
        if path.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(path)?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("sig") | Some("pat")))
                .collect();
            entries.sort();
            sigs.extend(entries);
        } else {
            sigs.push(path.clone());
        }
    }
    Ok(sigs)
}

/// the architecture of the shellcode, when the input is shellcode.
fn get_shellcode_arch(args: &Args) -> Option<Arch> {
    let ext = args
        .sample
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match (args.format, ext.as_str()) {
        (Format::Sc32, _) | (Format::Auto, "sc32" | "raw32") => Some(Arch::X32),
        (Format::Sc64, _) | (Format::Auto, "sc64" | "raw64") => Some(Arch::X64),
        _ => None,
    }
}

#[cfg(feature = "ida")]
fn validate_ida_available() -> Result<()> {
    floss::backend::ida::validate_available()
}

#[cfg(not(feature = "ida"))]
fn validate_ida_available() -> Result<()> {
    bail!("this build of floss-rs doesn't have the IDA backend")
}

/// is the sample an IDA database, or is there a database to make from it? then only IDA will do.
#[cfg(feature = "ida")]
fn needs_ida(args: &Args) -> Option<&'static str> {
    if floss::backend::ida::is_database(&args.sample) {
        Some("the file is an IDA database")
    } else if args.idb.is_some() {
        Some("--idb is given")
    } else {
        None
    }
}

#[cfg(not(feature = "ida"))]
fn needs_ida(_args: &Args) -> Option<&'static str> {
    None
}

/// The backend to use: the one that `--backend` names,
/// or else IDA when it can be used, and otherwise lancelot.
///
/// This starts IDA, to check for its license, so it must be called from the main thread.
fn select_backend(args: &Args) -> Result<Backend> {
    let has_lancelot = cfg!(feature = "lancelot");
    match (args.backend, needs_ida(args)) {
        (Backend::Lancelot, _) if !has_lancelot => {
            bail!("this build of floss-rs doesn't have the lancelot backend")
        }
        (Backend::Lancelot, Some(reason)) => bail!("{reason}, which needs the IDA backend"),
        (Backend::Lancelot, None) => Ok(Backend::Lancelot),
        (Backend::Ida, _) => validate_ida_available()
            .map(|()| Backend::Ida)
            .context("can't use IDA"),
        (Backend::Auto, reason) => match (validate_ida_available(), reason) {
            (Ok(()), _) => Ok(Backend::Ida),
            (Err(e), None) if has_lancelot => {
                if cfg!(feature = "ida") {
                    log::info!("using the lancelot backend, because IDA can't be used: {e:#}");
                }
                Ok(Backend::Lancelot)
            }
            (Err(e), Some(reason)) => {
                Err(e.context(format!("{reason}, which needs IDA, and IDA can't be used")))
            }
            (Err(e), None) => Err(e.context("can't use IDA")),
        },
    }
}

#[cfg(feature = "ida")]
fn load_with_ida(args: &Args) -> Result<Program> {
    floss::backend::ida::load(
        &args.sample,
        &floss::backend::ida::Options {
            shellcode: get_shellcode_arch(args),
            database: args.idb.clone(),
        },
    )
}

#[cfg(not(feature = "ida"))]
fn load_with_ida(_args: &Args) -> Result<Program> {
    validate_ida_available().map(|()| unreachable!())
}

#[cfg(feature = "lancelot")]
fn load_with_lancelot(args: &Args, buf: &[u8]) -> Result<Program> {
    use floss::backend::lancelot::{flirt, load_pe, load_shellcode};

    if let Some(arch) = get_shellcode_arch(args) {
        return load_shellcode(buf, arch);
    }

    let signatures = if !args.signatures.is_empty() {
        expand_signatures(&args.signatures)?
            .iter()
            .map(|path| flirt::SignatureFile::read(path))
            .collect::<Result<_>>()?
    } else if args.flirt {
        flirt::builtin()
    } else {
        vec![]
    };
    load_pe(buf, &signatures)
}

#[cfg(not(feature = "lancelot"))]
fn load_with_lancelot(_args: &Args, _buf: &[u8]) -> Result<Program> {
    bail!("this build of floss-rs doesn't have the lancelot backend")
}

/// the path of the file whose bytes have the static strings.
fn get_static_strings_path(args: &Args) -> Option<PathBuf> {
    #[cfg(feature = "ida")]
    if floss::backend::ida::is_database(&args.sample) {
        return floss::backend::ida::find_input_file(&args.sample);
    }
    Some(args.sample.clone())
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn,floss=info,lancelot=error"),
    )
    .init();
    let args = Args::parse();
    let backend = select_backend(&args)?;
    #[cfg(feature = "lancelot")]
    if backend == Backend::Ida && (args.flirt || !args.signatures.is_empty()) {
        log::warn!("--flirt and --signatures are for the lancelot backend: IDA recognizes library functions itself");
    }

    let enabled =
        |t: StringType| (args.only.is_empty() || args.only.contains(&t)) && !args.no.contains(&t);
    let mut opts = floss::Options {
        min_length: args.minimum_length,
        static_strings: enabled(StringType::Static),
        stack_strings: enabled(StringType::Stack),
        tight_strings: enabled(StringType::Tight),
        decoded_strings: enabled(StringType::Decoded),
        top_functions: args.top_functions,
        threads: args.threads.unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)),
        time_budget: std::time::Duration::from_secs_f64(args.time_budget.max(0.0)),
        functions: if args.functions.is_empty() {
            None
        } else {
            Some(args.functions.clone())
        },
    };

    let buf = match get_static_strings_path(&args) {
        Some(path) => std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
        None => {
            if opts.static_strings {
                log::warn!(
                    "can't find the file that {} was made from, so not extracting static strings",
                    args.sample.display()
                );
                opts.static_strings = false;
            }
            vec![]
        }
    };

    let load = || match backend {
        Backend::Ida => load_with_ida(&args),
        Backend::Lancelot => load_with_lancelot(&args, &buf),
        Backend::Auto => unreachable!("select_backend picks a backend"),
    };
    let mut doc = floss::analyze_file(&buf, load, &opts)?;
    doc.metadata.file_path = args.sample.display().to_string();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }

    let s = &doc.strings;
    if opts.static_strings {
        println!("FLOSS STATIC STRINGS ({})", s.static_strings.len());
        for st in s.static_strings.iter() {
            println!("{}", st.string);
        }
        println!();
    }
    if opts.stack_strings {
        println!("FLOSS STACK STRINGS ({})", s.stack_strings.len());
        for st in s.stack_strings.iter() {
            println!("{}", st.string);
        }
        println!();
    }
    if opts.tight_strings {
        println!("FLOSS TIGHT STRINGS ({})", s.tight_strings.len());
        for st in s.tight_strings.iter() {
            println!("{}", st.string);
        }
        println!();
    }
    if opts.decoded_strings {
        println!("FLOSS DECODED STRINGS ({})", s.decoded_strings.len());
        for st in s.decoded_strings.iter() {
            println!("{}", st.string);
        }
        println!();
    }
    eprintln!("finished in {:.2}s", doc.metadata.runtime.total);
    Ok(())
}
