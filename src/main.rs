extern crate cargo;
extern crate docopt;
extern crate env_logger;
extern crate memmap;
extern crate object;
extern crate rustc_demangle;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate term_size;


mod table;


use std::{env, fs, path};
use std::collections::HashMap;

use object::{Object, SectionKind, SymbolKind};

use cargo::core::shell::Shell;
use cargo::core::Workspace;
use cargo::ops;
use cargo::util::errors::{CargoResult, CargoError};
use cargo::util;
use cargo::{CliResult, Config};

use table::Table;


const STD_CRATES: &[&str] = &[
    "core",
    "std_unicode",
    "alloc",
    "alloc_system",
    "unreachable",
    "unwind",
    "panic_unwind",
];

const USAGE: &'static str = "
Find out what takes most of the space in your executable

Usage: cargo bloat [options]

Options:
    -h, --help              Print this message
    -V, --version           Print version info and exit
    --features FEATURES     Space-separated list of features to also build
    --all-features          Build all available features
    --no-default-features   Do not build the `default` feature
    --manifest-path PATH    Path to the manifest to analyze
    --release               Build artifacts in release mode, with optimizations
    --example NAME          Build only the specified example
    --crates                Per crate bloatedness
    --diff PATH             Diff crates
    --filter CRATE          Filter functions by crate
    --split-std             Split the 'std' crate to original crates like core, alloc, etc.
    --full-fn               Print full function name with hash values
    -n NUM                  Number of lines to show, 0 to show all [default: 20]
    -w, --wide              Do not trim long function names
    -v, --verbose           Use verbose output
    -q, --quiet             No output printed to stdout
    --color WHEN            Coloring: auto, always, never
    --frozen                Require Cargo.lock and cache are up to date
    --locked                Require Cargo.lock is up to date
    -Z FLAG ...             Unstable (nightly-only) flags to Cargo
";

#[derive(Deserialize)]
struct Flags {
    flag_version: bool,
    flag_features: Vec<String>,
    flag_all_features: bool,
    flag_no_default_features: bool,
    flag_manifest_path: Option<String>,
    flag_release: bool,
    flag_example: Option<String>,
    flag_crates: bool,
    flag_diff: Option<String>,
    flag_filter: Option<String>,
    flag_split_std: bool,
    flag_full_fn: bool,
    flag_n: usize,
    flag_wide: bool,
    flag_verbose: u32,
    flag_quiet: Option<bool>,
    flag_color: Option<String>,
    flag_frozen: bool,
    flag_locked: bool,
    #[serde(rename = "flag_Z")] flag_z: Vec<String>,
}

struct SymbolData {
    name: String,
    size: u64,
}

struct Data {
    symbols: Vec<SymbolData>,
    file_size: u64,
    text_size: u64,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum CrateKind {
    Bin,
    Cdynlib,
}

struct CrateData {
    name: String,
    kind: CrateKind,
    data: Data,
    crates: Vec<String>,
}


fn main() {
    env_logger::init().unwrap();

    let cwd = env::current_dir().expect("couldn't get the current directory of the process");
    let mut config = create_config(cwd);

    let args: Vec<_> = env::args().collect();
    let result = cargo::call_main_without_stdin(real_main, &mut config, USAGE, &args, false);
    match result {
        Err(e) => cargo::exit_with_error(e, &mut *config.shell()),
        Ok(()) => {}
    }
}

fn create_config(path: path::PathBuf) -> Config {
    let shell = Shell::new();
    let homedir = util::config::homedir(&path).expect(
        "Cargo couldn't find your home directory. \
         This probably means that $HOME was not set.");
    Config::new(shell, path, homedir)
}

fn real_main(flags: Flags, config: &mut Config) -> CliResult {
    if flags.flag_version {
        println!("cargo-bloat {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let crate_data = process_crate(&flags, config)?;

    let term_width = if !flags.flag_wide { term_size::dimensions().map(|v| v.0) } else { None };

    if let Some(ref crate_path) = flags.flag_diff {
        let crate_path = fs::canonicalize(crate_path).unwrap();
        let mut diff_config = create_config(crate_path);
        let crate_data_2 = process_crate(&flags, &mut diff_config)?;

        if    crate_data.name != crate_data_2.name
           || crate_data.kind != crate_data_2.kind
        {
            return Err(CargoError::from(
                format!("Current crate and reference crate are not the same: {} != {}.",
                        crate_data.name, crate_data_2.name)
            ).into());
        }

        let mut table = Table::new(&["T", "Diff", "After", "Before", "Name"]);
        table.set_width(term_width);

        print_methods_diff(crate_data, crate_data_2, &flags, &mut table);

        print!("{}", table);
    } else {
        let mut table = Table::new(&["File", ".text", "Size", "Name"]);
        table.set_width(term_width);

        if flags.flag_crates {
            print_crates(crate_data, &flags, &mut table);
        } else {
            print_methods(crate_data, &flags, &mut table);
        }

        print!("{}", table);
    }

    Ok(())
}

fn process_crate(flags: &Flags, config: &mut Config) -> CargoResult<CrateData> {
    config.configure(
        flags.flag_verbose,
        flags.flag_quiet,
        &flags.flag_color,
        flags.flag_frozen,
        flags.flag_locked,
        &flags.flag_z,
    )?;

    let root = util::important_paths::find_root_manifest_for_wd(
        flags.flag_manifest_path.clone(),
        config.cwd()
    )?;
    let workspace = Workspace::new(&root, config)?;
    let (pkgs, _) = ops::resolve_ws(&workspace)?;

    let mut crates: Vec<String> = pkgs.package_ids().map(|p| p.name().replace("-", "_")).collect();
    crates.push("std".to_string());
    if flags.flag_split_std {
        for crate_name in STD_CRATES {
            crates.push(crate_name.to_string());
        }
    }

    let mut examples = Vec::new();
    let mut opt = ops::CompileOptions::default(&config, ops::CompileMode::Build);
    opt.features = &flags.flag_features;
    opt.all_features = flags.flag_all_features;
    opt.no_default_features = flags.flag_no_default_features;
    opt.release = flags.flag_release;

    if let Some(ref name) = flags.flag_example {
        examples.push(name.clone());

        opt.filter = ops::CompileFilter::new(
            false,
            &[], false,
            &[], false,
            &examples[..], false,
            &[], false,
            false,
        );
    }

    let pkg_name = workspace.current()?.name();

    let comp = ops::compile(&workspace, &opt)?;

    for (_, lib) in comp.libraries {
        for (_, path) in lib {
            let path_str = path.to_str().unwrap();
            if path_str.ends_with(".so") || path_str.ends_with(".dylib") {
                return Ok(CrateData {
                    name: pkg_name.to_string(),
                    kind: CrateKind::Cdynlib,
                    data: collect_data(&path)?,
                    crates,
                });
            }
        }
    }

    if !comp.binaries.is_empty() {
        return Ok(CrateData {
            name: pkg_name.to_string(),
            kind: CrateKind::Bin,
            data: collect_data(&comp.binaries[0])?,
            crates,
        });
    }

    Err(CargoError::from("Only 'bin' and 'cdylib' targets are supported."))
}

fn collect_data(path: &path::Path) -> CargoResult<Data> {
    let file = fs::File::open(path)?;
    let file = unsafe { memmap::Mmap::map(&file)? };
    let file = object::File::parse(&*file)?;

    let mut total_size = 0;
    let mut list = Vec::new();
    for symbol in file.symbol_map().symbols() {
        match symbol.kind() {
            SymbolKind::Section | SymbolKind::File => continue,
            _ => {}
        }

        if symbol.section_kind() != Some(SectionKind::Text) {
            continue;
        }

        total_size += symbol.size();

        let fn_name = symbol.name().unwrap_or("<unknown>");
        let fn_name = rustc_demangle::demangle(fn_name).to_string();

        list.push(SymbolData {
            name: fn_name,
            size: symbol.size(),
        });
    }

    let d = Data {
        symbols: list,
        file_size: fs::metadata(path)?.len(),
        text_size: total_size,
    };

    Ok(d)
}

fn print_methods(mut d: CrateData, flags: &Flags, table: &mut Table) {
    d.data.symbols.sort_by_key(|v| v.size);

    let dd = &d.data;
    let mut other_size = dd.text_size;

    let n = if flags.flag_n == 0 { dd.symbols.len() } else { flags.flag_n };

    for sym in dd.symbols.iter().rev() {
        let percent_file = sym.size as f64 / dd.file_size as f64 * 100.0;
        let percent_text = sym.size as f64 / dd.text_size as f64 * 100.0;

        if let Some(ref name) = flags.flag_filter {
            if !sym.name.contains(name) {
                continue;
            }
        }

        other_size -= sym.size;

        let name = if !flags.flag_full_fn {
            trim_hash(&sym.name)
        } else {
            &sym.name
        };

        push_row(table, percent_file, percent_text, sym.size, name.to_owned());

        if n != 0 && table.rows_count() == n {
            break;
        }
    }

    {
        let lines_len = table.rows_count();
        let percent_file_s = format_percent(other_size as f64 / dd.file_size as f64 * 100.0);
        let percent_text_s = format_percent(other_size as f64 / dd.text_size as f64 * 100.0);
        let size_s = format_size(other_size);
        let name_s = format!("[{} Others]", dd.symbols.len() - lines_len);
        table.insert(0, &[&percent_file_s, &percent_text_s, &size_s, &name_s]);
    }

    push_total(table, dd);
}

fn print_methods_diff(
    mut crate_1: CrateData,
    mut crate_2: CrateData,
    flags: &Flags,
    table: &mut Table,
) {
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum DiffKind {
//        Equal,
        Added,
        Changed,
        Removed,
    }

    crate_1.data.symbols.sort_by_key(|v| v.size);
    crate_2.data.symbols.sort_by_key(|v| v.size);

    let dd1 = &crate_1.data;
    let dd2 = &crate_2.data;


    let mut methods1 = HashMap::with_capacity(dd1.symbols.len());
    for sym in &dd1.symbols {
        methods1.insert(&sym.name, sym);
    }

    let mut methods2 = HashMap::with_capacity(dd2.symbols.len());
    for sym in &dd2.symbols {
        methods2.insert(&sym.name, sym);
    }

    let mut list1 = Vec::with_capacity(dd1.symbols.len());
    let mut list2 = Vec::with_capacity(dd2.symbols.len());

    // Remove equal.
    'outer1: for sym1 in &dd1.symbols {
        for std_name in STD_CRATES {
            if sym1.name.contains(std_name) {
                continue 'outer1;
            }
        }

        if let Some(sym2) = methods2.get(&sym1.name).cloned() {
            if sym1.size == sym2.size {
                continue;
            }
        }

        list1.push(sym1);
    }

    'outer2: for sym2 in &dd2.symbols {
        for std_name in STD_CRATES {
            if sym2.name.contains(std_name) {
                continue 'outer2;
            }
        }

        if let Some(sym1) = methods1.get(&sym2.name).cloned() {
            if sym1.size == sym2.size {
                continue;
            }
        }

        list2.push(sym2);
    }

    println!("{} {}", list1.len(), list2.len());

    let mut list = Vec::with_capacity(list1.len());
    'outer3: for sym1 in &list1 {
        let mut size2 = 0;

        for sym2 in &list2 {
            if trim_hash(&sym1.name) == trim_hash(&sym2.name) {
                if sym1.size == sym2.size {
                    continue 'outer3;
                } else {
                    size2 = sym2.size;
                }
            }
        }

        let kind = if size2 == 0 { DiffKind::Added } else { DiffKind::Changed };

        list.push((&sym1.name, sym1.size, size2, kind));
    }

//    for sym2 in &list2 {
//        for d in &list {
//
//        }
//    }

    println!("{}", list.len());


    list.sort_by(|a, b| {
        let d1 = (a.1 as i64 - a.2 as i64).abs();
        let d2 = (b.1 as i64 - b.2 as i64).abs();
        d2.cmp(&d1)
    });

    let mut total = 0;
    for &(_, new_size, old_size, _) in list.iter() {
        total += new_size as i64 - old_size as i64;
    }

    let n = if flags.flag_n == 0 { list.len() } else { flags.flag_n };

    for &(name, new_size, old_size, kind) in list.iter().take(n) {
        if let Some(ref crate_name) = flags.flag_filter {
            if !name.contains(crate_name) {
                continue;
            }
        }

        let kind_s = match kind {
            DiffKind::Added => "+",
            DiffKind::Changed => "~",
            DiffKind::Removed => "-",
//            DiffKind::Equal => "=",
        }.to_string();

        let diff = new_size as i64 - old_size as i64;
        let diff_s = format_diff_size(diff);

        let new_size = format_size(new_size);
        let old_size = format_size(old_size);

        let name = if !flags.flag_full_fn {
            trim_hash(&name)
        } else {
            &name
        }.to_string();

        table.push(&[kind_s, diff_s, new_size, old_size, name]);
    }

    table.push(&["".to_string(), format_diff_size(total), "-".to_string(), "-".to_string(), "Total".to_string()]);
}

// crate::mod::fn::h5fbe0f2f0b5c7342 -> crate::mod::fn
fn trim_hash(s: &str) -> &str {
    if let Some(pos) = s.bytes().rposition(|b| b == b':') {
        &s[..(pos - 1)]
    } else {
        s
    }
}

fn print_crates(d: CrateData, flags: &Flags, table: &mut Table) {
    const UNKNOWN: &str = "[Unknown]";

    let dd = &d.data;
    let mut sizes = HashMap::new();

    for sym in dd.symbols.iter() {
        // Skip non-Rust names.
        let mut crate_name = if !sym.name.contains("::") {
            UNKNOWN.to_string()
        } else {
            if let Some(s) = sym.name.split("::").next() {
                s.to_owned()
            } else {
                sym.name.clone()
            }
        };

        if crate_name.starts_with("<") {
            while crate_name.starts_with("<") {
                crate_name.remove(0);
            }

            crate_name = crate_name.split_whitespace().last().unwrap().to_owned();
        }

        if !flags.flag_split_std {
            if STD_CRATES.contains(&crate_name.as_str()) {
                crate_name = "std".to_string();
            }
        }

        if crate_name != UNKNOWN && !d.crates.contains(&crate_name) {
            crate_name = UNKNOWN.to_string();
        }

        if flags.flag_verbose > 0 {
            println!("{} from {}", crate_name, sym.name);
        }

        if let Some(v) = sizes.get(&crate_name).cloned() {
            sizes.insert(crate_name, v + sym.size);
        } else {
            sizes.insert(crate_name, sym.size);
        }
    }

    let mut list: Vec<(&String, &u64)> = sizes.iter().collect();
    list.sort_by_key(|v| v.1);

    let n = if flags.flag_n == 0 { list.len() } else { flags.flag_n };
    for &(k, v) in list.iter().rev().take(n) {
        let percent_file = *v as f64 / dd.file_size as f64 * 100.0;
        let percent_text = *v as f64 / dd.text_size as f64 * 100.0;

        push_row(table, percent_file, percent_text, *v, k.clone());
    }

    push_total(table, dd);
}

fn push_row(table: &mut Table, percent_file: f64, percent_text: f64, size: u64, name: String) {
    let percent_file_s = format_percent(percent_file);
    let percent_text_s = format_percent(percent_text);
    let size_s = format_size(size);

    table.push(&[percent_file_s, percent_text_s, size_s, name]);
}

fn push_total(table: &mut Table, d: &Data) {
    let percent_file = d.text_size as f64 / d.file_size as f64 * 100.0;
    let name = format!(".text section size, the file size is {}", format_size(d.file_size));
    push_row(table, percent_file, 100.0, d.text_size, name);
}

fn format_percent(n: f64) -> String {
    format!("{:.1}%", n)
}

fn format_size(bytes: u64) -> String {
    let kib = 1024;
    let mib = 1024 * kib;

    if bytes >= mib {
        format!("{:.1}MiB", bytes as f64 / mib as f64)
    } else if bytes >= kib {
        format!("{:.1}KiB", bytes as f64 / kib as f64)
    } else {
        format!("{}B", bytes)
    }
}

fn format_diff_size(bytes: i64) -> String {
    let mut s = format_size(bytes.abs() as u64);
    if bytes < 0 {
        s.insert(0, '-');
    } else if bytes > 0 {
        s.insert(0, '+');
    }

    s
}
