use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StringType {
    Static,
    Stack,
    Tight,
    Decoded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// PE files, and shellcode by extension (.sc32, .raw32, .sc64, .raw64)
    Auto,
    Pe,
    /// 32-bit shellcode
    Sc32,
    /// 64-bit shellcode
    Sc64,
}

/// FLOSS, the FLARE Obfuscated String Solver: extract obfuscated strings from malware.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// path to the PE file to analyze
    sample: PathBuf,

    /// the kind of input
    #[arg(short = 'f', long, value_enum, default_value_t = Format::Auto)]
    format: Format,

    /// minimum string length
    #[arg(short = 'n', long, default_value_t = 4)]
    minimum_length: usize,

    /// only extract these string types (default: all)
    #[arg(long, value_enum, num_args = 1..)]
    only: Vec<StringType>,

    /// don't extract these string types
    #[arg(long, value_enum, num_args = 1..)]
    no: Vec<StringType>,

    /// FLIRT signature files (.sig/.pat) or directories of them, to recognize library functions
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

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn,floss=info,lancelot=error")).init();
    let args = Args::parse();

    let ext = args.sample.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let format = match (args.format, ext.as_str()) {
        (Format::Sc32, _) | (Format::Auto, "sc32" | "raw32") => floss::Format::Shellcode32,
        (Format::Sc64, _) | (Format::Auto, "sc64" | "raw64") => floss::Format::Shellcode64,
        _ => floss::Format::Pe,
    };

    let enabled = |t: StringType| (args.only.is_empty() || args.only.contains(&t)) && !args.no.contains(&t);
    let opts = floss::Options {
        format,
        min_length: args.minimum_length,
        static_strings: enabled(StringType::Static),
        stack_strings: enabled(StringType::Stack),
        tight_strings: enabled(StringType::Tight),
        decoded_strings: enabled(StringType::Decoded),
        signatures: expand_signatures(&args.signatures)?,
        top_functions: args.top_functions,
        threads: args.threads.unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)),
        time_budget: std::time::Duration::from_secs_f64(args.time_budget.max(0.0)),
        functions: if args.functions.is_empty() {
            None
        } else {
            Some(args.functions.clone())
        },
        ..Default::default()
    };

    let buf = std::fs::read(&args.sample).with_context(|| format!("read {}", args.sample.display()))?;
    let mut doc = floss::analyze(&buf, &opts)?;
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
