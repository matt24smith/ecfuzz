use std::collections::HashSet;
use std::env::set_var;
use std::ffi::OsString;
use std::fs::remove_file;
use std::io::{BufWriter, Write};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::SystemTime;

use serde::Deserialize;
use serde_json::Value as jsonValue;

use crate::corpus::CorpusInput;
use crate::mutator::main as mutate_stdin;
use crate::mutator::{byte_index, Mutation};

fn help() -> String {
    let t = (SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap())
    .as_secs()
    .to_string();
    let defaults = Config::defaults();
    let mut mutator = Mutation::with_seed(None, t.as_bytes().to_vec(), None);
    mutator.data = defaults
        .target_path
        .as_os_str()
        .to_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    mutator.mutate();
    let header = String::from_utf8_lossy(&mutator.data);
    let help = format!(
        r#"
Mutate {}

Options:

  -d, --dictionary-path <file>  Optionally supply a dictionary to enable random
                                dictionary value insertion, and tokenized
                                dictionary replacement

  -s, --seed <seed>             Optionally seed the mutation engine with a given value

  -m, --multiplier <N>          Mutations per byte. Default 0.01

   -, --mutate-stdin            The main loop won't be run. Instead, read data from
                                stdin, and return mutated bytes to stdout. If
                                used, the options below will be ignored.

  -f, --mutate-file             If this flag is set, mutations will be written
                                to './input.mutation' instead of the target stdin

  -t, --target <fuzz_target.c>  Clang input file. Defaults to '{}'

  -x, --compiler <path>         Compiler path. Defaults to '{}'

  --llvm-profdata-path <path>   Path to llvm-profdata. Defaults to '{}'

  --llvm-cov-path <path>        Path to llvm-cov. Defaults to '{}'

  -i, --iterations <N>          Total number of executions. Default {}

  -c, --corpus <file>           Initial corpus file, entries separated by newlines.
                                Defaults to ./input/corpus. May be repeated

  -C, --corpus-dir <directory>  Initialize corpus from a directory of files, one
                                entry per file. May be repeated for multiple directories

  -o, --object <path>           Object file given to llvm-cov. Defaults to '{}'.
                                May be repeated for multiple files.

  -O, --object-files <path1...> Object files given to llvm-cov. Can be specified
                                as a list of object files or by shell expansion

Pass additional args to the compiler by setting $CFLAGS
"#,
        header,
        defaults.target_path.as_os_str().to_str().unwrap(),
        defaults.cc_path.as_os_str().to_str().unwrap(),
        defaults.llvm_profdata_path.as_os_str().to_str().unwrap(),
        defaults.llvm_cov_path.as_os_str().to_str().unwrap(),
        defaults.iterations,
        defaults.objects[0].as_os_str().to_str().unwrap(),
    );
    help
}

pub struct Config {
    pub cc_path: PathBuf,
    pub iter_check: usize,
    pub iterations: usize,
    pub llvm_cov_path: PathBuf,
    pub llvm_profdata_path: PathBuf,
    pub target_path: PathBuf,
    pub dict_path: Option<PathBuf>,
    pub corpus_files: Vec<PathBuf>,
    pub corpus_dirs: Vec<PathBuf>,
    pub seed: Vec<u8>,
    pub objects: Vec<PathBuf>,
    pub mutate_file: bool,
    pub mutate_args: bool,
    pub multiplier: Option<f64>,
}

pub struct Exec {
    pub cfg: Config,
}

/// target executor configurations: clang executable path, set CFLAGS variable,
/// max number of executions, etc.
impl Config {
    /// initialize target execution config with default values
    pub fn defaults() -> Self {
        Config {
            iter_check: 100, // frequency of printed status updates
            iterations: 10000,
            target_path: PathBuf::from("./fuzz_target.c"),

            // default paths for Linux
            #[cfg(target_os = "linux")]
            cc_path: PathBuf::from("/usr/bin/clang"),
            #[cfg(target_os = "linux")]
            llvm_profdata_path: PathBuf::from("/usr/bin/llvm-profdata"),
            #[cfg(target_os = "linux")]
            llvm_cov_path: PathBuf::from("/usr/bin/llvm-cov"),

            // default paths for MacOS
            #[cfg(target_os = "macos")]
            //cc_path: PathBuf::from("/Library/Developer/CommandLineTools/usr/bin/clang"),
            cc_path: PathBuf::from("/usr/bin/clang"),
            #[cfg(target_os = "macos")]
            llvm_profdata_path: PathBuf::from(
                "/Library/Developer/CommandLineTools/usr/bin/llvm-profdata",
            ),
            #[cfg(target_os = "macos")]
            llvm_cov_path: PathBuf::from("/Library/Developer/CommandLineTools/usr/bin/llvm-cov"),

            // default paths for Windows
            #[cfg(target_os = "windows")]
            cc_path: PathBuf::from(r"C:\Program Files\LLVM\bin\clang.exe"),
            #[cfg(target_os = "windows")]
            llvm_profdata_path: PathBuf::from(r"C:\Program Files\LLVM\bin\llvm-profdata.exe"),
            #[cfg(target_os = "windows")]
            llvm_cov_path: PathBuf::from(r"C:\Program Files\LLVM\bin\llvm-cov.exe"),

            dict_path: None,
            seed: vec![],
            corpus_files: vec![],
            corpus_dirs: vec![],
            objects: vec![PathBuf::from("a.out")],
            mutate_file: false,
            mutate_args: false,
            multiplier: Some(0.01),
        }
    }

    /// parse command line options
    pub fn parse_args() -> Result<Self, Box<dyn std::error::Error>> {
        let mut cfg: Config = Config::defaults();

        let mut args: Vec<String> = vec![];
        for arg in std::env::args() {
            for a in arg.splitn(2, '=') {
                args.push(a.to_string());
            }
        }

        // print help text
        if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
            println!("{}", help());
            std::process::exit(0);
        }

        // warn about extra arguments
        let argstring = help().replace(',', " ");
        let known_args: Vec<&str> = argstring
            .split(' ')
            .filter(|a| !a.is_empty() && a.starts_with('-'))
            .collect();
        for arg in args.iter().filter(|a| a.starts_with('-')) {
            if !known_args.iter().any(|a| a.contains(arg)) {
                eprintln!("\x1b[91mWarning\x1b[0m: unknown argument {}", arg);
            }
        }

        // mutator mode
        if std::env::args().any(|x| x == *"--mutate-stdin" || x == *"-") {
            mutate_stdin()?;
            std::process::exit(0);
        }

        if args.contains(&"-f".to_string()) || args.contains(&"--mutate-file".to_string()) {
            cfg.mutate_file = true;
        }

        if args.contains(&"-d".to_string()) || args.contains(&"--dictionary-path".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-d" || arg == "--dictionary-path" {
                    stop = true;
                } else if stop {
                    cfg.dict_path = Some(PathBuf::from(arg));
                    break;
                }
            }
        }

        if args.contains(&"-s".to_string()) || args.contains(&"--seed".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-s" || arg == "--seed" {
                    stop = true
                } else if stop {
                    cfg.seed = arg.as_bytes().to_vec();
                    break;
                }
            }
        }

        if args.contains(&"-t".to_string()) || args.contains(&"--target".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-t" || arg == "--target" {
                    stop = true
                } else if stop {
                    cfg.target_path = PathBuf::from(arg);
                    break;
                }
            }
        }

        if args.contains(&"-x".to_string()) || args.contains(&"--compiler".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-x" || arg == "--compiler" {
                    stop = true
                } else if stop {
                    cfg.cc_path = PathBuf::from(arg);
                    break;
                }
            }
        }

        if args.contains(&"--llvm-profdata-path".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "--llvm-profdata-path" {
                    stop = true
                } else if stop {
                    cfg.llvm_profdata_path = PathBuf::from(arg);
                    break;
                }
            }
        }
        if args.contains(&"--llvm-cov-path".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "--llvm-cov-path" {
                    stop = true
                } else if stop {
                    cfg.llvm_cov_path = PathBuf::from(arg);
                    break;
                }
            }
        }
        if args.contains(&"-m".to_string()) || // #
            args.contains(&"--multiplier".to_string())
        {
            let mut stop = false;
            for arg in &args {
                if arg == "-m" || arg == "--multiplier" {
                    stop = true
                } else if stop {
                    cfg.multiplier = Some(arg.parse()?);
                    break;
                }
            }
        }
        if args.contains(&"-i".to_string()) || args.contains(&"--iterations".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-i" || arg == "--iterations" {
                    stop = true
                } else if stop {
                    cfg.iterations = arg.parse()?;
                    break;
                }
            }
        }

        if args.contains(&r#"-c"#.to_string()) ||  // #
            args.contains(&"--corpus".to_string())
        {
            let mut stop = false;
            for arg in &args {
                if arg == "-c" || arg == "--corpus" {
                    stop = true
                } else if stop {
                    cfg.corpus_files.push(PathBuf::from(arg));
                    stop = false
                }
            }
        }

        if args.contains(&"-C".to_string()) ||  // #
            args.contains(&"--corpus-dir".to_string())
        {
            let mut stop = false;
            for arg in &args {
                if arg == "-C" || arg == "--corpus-dir" {
                    stop = true
                } else if stop {
                    cfg.corpus_dirs.push(PathBuf::from(arg));
                    stop = false
                }
            }
        }

        if args.contains(&"-o".to_string()) || args.contains(&"--object".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-o" || arg == "--object" {
                    stop = true
                } else if stop {
                    cfg.objects.push(PathBuf::from(arg));
                    stop = false
                }
            }
        }
        if args.contains(&"-O".to_string()) || args.contains(&"--object-files".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-O" || arg == "--object-files" {
                    stop = true;
                } else if stop && arg[..1] != *"-" {
                    cfg.objects.push(PathBuf::from(arg));
                } else {
                    stop = false;
                }
            }
        }

        if cfg.corpus_dirs.is_empty() && cfg.corpus_files.is_empty() {
            cfg.corpus_files.push(PathBuf::from("./input/corpus"));
        }
        Ok(cfg)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct CovReport {
    pub branches: Vec<[u64; 9]>,
    //pub regions: Vec<[u64; 8]>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ReportFile {
    pub files: Vec<CovReport>,
    //pub functions: Vec<CovReport>,
}

impl Exec {
    /// compile and instrument the target.
    pub fn initialize(cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
        // ensure cc is clang 14
        let check_cc_ver = Command::new(&cfg.cc_path).arg("--version").output()?;
        let cc_ver = String::from_utf8_lossy(&check_cc_ver.stdout);
        println!("{}", cc_ver);
        let cc_ver_major = cc_ver.splitn(2, "version ").collect::<Vec<&str>>()[1]
            .splitn(2, '.')
            .collect::<Vec<&str>>()[0];
        if !cc_ver_major.parse::<u64>()? == 14 {
            panic!("Requires CC version 14 or higher. Found {}", cc_ver);
        }

        let cflag_var = std::env::var("CFLAGS").unwrap_or_default();
        println!("CFLAGS={:?}", cflag_var);
        let cflags = cflag_var.split(' ');

        let mut setup_args: Vec<String> = vec![
            (cfg.target_path.as_os_str().to_str().unwrap()),
            "-o",
            "a.out",
            "-fprofile-instr-generate",
            "-fcoverage-mapping",
            // asan - very slow on windows and apple arm64
            #[cfg(not(target_arch = "aarch64"))]
            #[cfg(not(target_os = "windows"))]
            "-fsanitize=address,undefined",
            // msan doesn't work at the same time as usan on windows
            #[cfg(target_os = "windows")]
            "-fsanitize=undefined",
            // msan - not supported on apple arm64
            // #[cfg(not(target_arch = "aarch64"))]
            //"-fsanitize=memory",
            "-fno-optimize-sibling-calls",
            "-fno-omit-frame-pointer",
            #[cfg(target_arch = "aarch64")]
            "-arch",
            #[cfg(target_arch = "aarch64")]
            "arm64",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        for flag in cflags {
            setup_args.push(flag.to_string());
        }

        println!(
            "compiling...\n{} {}\n",
            &cfg.cc_path.as_os_str().to_str().unwrap(),
            setup_args.join(" ")
        );

        let setup_result = Command::new(&cfg.cc_path).args(setup_args).output()?;
        if !setup_result.stderr.is_empty()
            && !byte_index(&b"error: ".to_vec(), &setup_result.stderr.to_vec()).is_empty()
        {
            panic!(
                "compile failed:\n{}\n{}",
                String::from_utf8(setup_result.stdout)?,
                String::from_utf8(setup_result.stderr)?,
            );
        } else if !setup_result.stderr.is_empty() {
            eprintln!(
                "compiled with warnings:\n{}\n{}",
                String::from_utf8(setup_result.stdout)?,
                String::from_utf8(setup_result.stderr)?,
            );
        }
        println!("done compiling");

        Ok(())
    }

    /// execute the target program with a new test input.
    /// record the profiled data to profraw, and index report to profdata
    pub fn trial(
        cfg: &Config,
        profraw: &str,
        profdata: &str,
        test_input: &CorpusInput,
        lifetime: u64,
    ) -> (CorpusInput, ExecResult<Output>) {
        let output = exec_target(cfg, profraw, &test_input.data);
        index_target_report(cfg, profraw, profdata).unwrap();

        // if the program crashes during execution, code coverage checking may
        // yield an empty set. in this case the parent mutation coverage is used
        let new_coverage: HashSet<u64> = match output {
            ExecResult::Ok(_) => check_report_coverage(cfg, profdata).unwrap(),
            ExecResult::Err(_) => {
                let cov = check_report_coverage(cfg, profdata).unwrap();
                if cov.is_empty() {
                    test_input.coverage.clone()
                } else {
                    cov
                }
            }
        };
        //let new_coverage = ;

        let result = CorpusInput {
            data: test_input.data.to_owned(),
            coverage: new_coverage,
            lifetime: lifetime + 1,
        };
        (result, output)
    }
}

pub enum ExecResult<Output> {
    Ok(Output),
    Err(Output),
}

/// execute the target program with a new test input either via an input file,
/// command line arguments, or by sending to the target stdin, as defined in
/// Config
fn exec_target(cfg: &Config, raw_profile_filepath: &str, input: &[u8]) -> ExecResult<Output> {
    if cfg.mutate_file {
        exec_target_filein(raw_profile_filepath, input)
    } else if cfg.mutate_args {
        exec_target_args(raw_profile_filepath, input)
    } else {
        exec_target_stdin(raw_profile_filepath, input)
    }
}

/// execute the target program with test input sent to stdin
fn exec_target_stdin(raw_profile_filepath: &str, input: &[u8]) -> ExecResult<Output> {
    set_var("LLVM_PROFILE_FILE", raw_profile_filepath);
    let mut profile_target = Command::new("./a.out")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let send_input = profile_target.stdin.take().unwrap();
    let mut send_input = BufWriter::new(send_input);

    let mut result = send_input.write_all(input);
    if result.is_ok() {
        result = send_input.flush();
    }

    std::mem::drop(send_input);

    let output = profile_target.wait_with_output().unwrap();

    if result.is_ok() && output.stderr.is_empty() {
        ExecResult::Ok(output)
    } else {
        ExecResult::Err(output)
    }
}

/// execute the target program with test input sent via an input file
fn exec_target_filein(raw_profile_filepath: &str, input: &[u8]) -> ExecResult<Output> {
    let mut f = BufWriter::new(std::fs::File::create("input.mutation").unwrap());
    f.write_all(input).unwrap();

    std::mem::drop(f);

    set_var("LLVM_PROFILE_FILE", raw_profile_filepath);
    let profile_target = Command::new("./a.out")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let result = profile_target.wait_with_output();

    if let Ok(res) = result {
        ExecResult::Ok(res)
    } else {
        ExecResult::Err(result.unwrap())
    }
}

/// execute the target program with test input sent via program arguments
pub fn exec_target_args(
    raw_profile_filepath: &str,
    //cmd_args: &[String; 6],
    input: &[u8],
) -> ExecResult<Output> {
    set_var("LLVM_PROFILE_FILE", raw_profile_filepath);

    //let cmd_args = String::from_utf8_lossy(input.clone());
    #[cfg(not(target_os = "windows"))]
    let mut args: Vec<Vec<u8>> = vec![];
    #[cfg(target_os = "windows")]
    let mut args: Vec<Vec<u16>> = vec![];

    #[cfg(not(target_os = "windows"))]
    let mut cursor: Vec<u8> = Vec::new();
    #[cfg(target_os = "windows")]
    let mut cursor: Vec<u16> = Vec::new();
    for b in input {
        if b == &b'\0' {
            args.push(cursor);
            cursor = Vec::new();
        } else {
            cursor.push(*b);
        }
    }
    if !cursor.is_empty() {
        args.push(cursor);
    }
    #[cfg(not(target_os = "windows"))]
    let os_args: Vec<OsString> = args
        .iter()
        .map(|a| OsStringExt::from_vec(a.to_vec()))
        .collect();
    #[cfg(target_os = "windows")]
    let os_args: Vec<OsString> = args.iter().map(|a| OsStringExt::from_wide(a)).collect();

    let profile_target = Command::new("./a.out")
        .args(os_args)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let output = profile_target.wait_with_output();

    if let Ok(out) = output {
        ExecResult::Ok(out)
    } else {
        ExecResult::Err(output.unwrap())
    }
}

/// convert raw profile data to an indexed file format
pub fn index_target_report(
    cfg: &Config,
    raw_profile_filepath: &str,
    profile_filepath: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let prof_merge_args = &[
        "merge".to_string(),
        "-sparse".to_string(),
        //"--instr".to_string(),
        raw_profile_filepath.to_string(),
        "-o".to_string(),
        profile_filepath.to_string(),
    ];
    let prof_merge_result = Command::new(&cfg.llvm_profdata_path)
        .args(prof_merge_args)
        .output()?;
    if !prof_merge_result.status.success() {
        remove_file(raw_profile_filepath).expect("removing profraw");
        panic!("\n{}", String::from_utf8_lossy(&prof_merge_result.stderr))
    }
    Ok(())
}

/// deserialized indexed report data, and return branch coverage
fn read_report(
    cfg: &Config,
    profile_filepath: &str,
) -> Result<ReportFile, Box<dyn std::error::Error>> {
    let mut prof_report_args: Vec<String> = vec!["export", "--instr-profile", profile_filepath]
        .iter()
        .map(|s| s.to_string())
        .collect();

    #[cfg(debug_assertions)]
    assert!(!cfg.objects.is_empty());

    for obj in &cfg.objects {
        prof_report_args.push("--object".to_string());
        prof_report_args.push(obj.as_os_str().to_string_lossy().to_string());
    }
    let prof_report_result = Command::new(&cfg.llvm_cov_path)
        .args(&prof_report_args)
        .output()
        .unwrap();
    let prof_report_raw = prof_report_result.stdout;
    if prof_report_raw.is_empty() {
        panic!(
            "empty profdata: {}\nargs: {:?}",
            profile_filepath, prof_report_args
        );
    }
    let prof_report_json: jsonValue =
        serde_json::from_slice(&prof_report_raw).expect("reading profdata");
    let prof_report: ReportFile = serde_json::from_value(prof_report_json["data"][0].clone())
        .expect("could not parse JSON profdata!");
    Ok(prof_report)
}

/// read coverage report file and create a HashSet from branches covered in the coverage file
pub fn check_report_coverage(
    cfg: &Config,
    profile_filepath: &str,
) -> Result<HashSet<u64>, Box<dyn std::error::Error>> {
    let report: ReportFile = read_report(cfg, profile_filepath)?;

    let mut coverageset: HashSet<u64> = HashSet::new();

    let mut i = 0;
    for file in report.files {
        //for file in report.functions {
        for branch in file.branches {
            //for branch in file.regions {
            if branch[4] > 0 {
                coverageset.insert(i);
            }
            i += 1
        }
    }

    Ok(coverageset)
}

/// count the number of code branches in the coverage file
pub fn count_branch_total(
    cfg: &Config,
    profile_filepath: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let report: ReportFile = read_report(cfg, profile_filepath)?;

    let mut n: u64 = 0;
    for file in report.files {
        //for file in report.functions {
        for _branch in file.branches {
            //for _branch in file.regions {
            n += 1
        }
    }
    Ok(n)
}
