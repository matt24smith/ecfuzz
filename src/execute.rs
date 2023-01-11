use std::collections::HashSet;
use std::env::set_var;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use serde::Deserialize;
use serde_json::Value as jsonValue;

use crate::corpus::{load_corpus, load_corpus_dir};
use crate::mutator::main as mutate_stdin;

fn help() -> String {
    use crate::mutator::Mutation;
    let t = (SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap())
    .as_secs()
    .to_string();
    let defaults = Config::defaults();
    let mut mutator = Mutation::with_seed(None, t.as_bytes().to_vec());
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

  -, --mutate-stdin             The main event loop wont be run. Read data from
                                stdin, and return mutated bytes to stdout. If
                                used, the options below will be ignored.

  -t, --target <fuzz_target.c>  Clang input file. Defaults to {}

  -x, --compiler                Compiler path. Defaults to {}

  --llvm-profdata-path          Path to llvm-profdata. Defaults to {}

  --llvm-cov-path               Path to llvm-cov. Defaults to {}

  -i, --iterations              Total number of executions. Default {}

  -c, --corpus                  Initial corpus file, entries separated by newlines.
                                Defaults to ./corpus/start. May be repeated

  -C, --corpus-dir              Initialize corpus from a directory of files, one
                                entry per file. May be repeated for multiple directories

  -o, --object                  Object file given to llvm-cov. Defaults to ./a.out.
                                May be repeated for multiple files.

  -O, --object-files            Object files given to llvm-cov. Can be specified
                                as a list of object files or by shell expansion
"#,
        //  -m --mutation-rate            Frequency of mutations to inputs. Default 0.01
        header,
        defaults.target_path.as_os_str().to_str().unwrap(),
        defaults.cc_path.as_os_str().to_str().unwrap(),
        defaults.llvm_profdata_path.as_os_str().to_str().unwrap(),
        defaults.llvm_cov_path.as_os_str().to_str().unwrap(),
        defaults.iterations,
    );
    help
}

pub struct Config {
    pub cc_path: PathBuf,
    pub corpus_dir: PathBuf,
    pub iter_check: usize,
    pub iterations: usize,
    pub llvm_cov_path: PathBuf,
    pub llvm_profdata_path: PathBuf,
    pub target_path: PathBuf,
    pub dict_path: Option<PathBuf>,
    pub seed_corpus: Vec<Vec<u8>>,
    pub seed: Vec<u8>,
    pub objects: Vec<PathBuf>,
}

pub struct Exec {
    pub cfg: Config,
}

impl Config {
    pub fn defaults() -> Self {
        Config {
            corpus_dir: PathBuf::from("./corpus/"),
            iter_check: 100, // frequency of printed status updates
            iterations: 10000,
            target_path: PathBuf::from("./fuzz_target.c"),

            #[cfg(not(target_os = "windows"))]
            cc_path: PathBuf::from("/usr/bin/clang"),
            #[cfg(target_os = "windows")]
            cc_path: PathBuf::from(r"C:\Program Files\LLVM\bin\clang.exe"),

            #[cfg(target_os = "linux")]
            llvm_profdata_path: PathBuf::from("/usr/bin/llvm-profdata"),
            #[cfg(target_os = "linux")]
            llvm_cov_path: PathBuf::from("/usr/bin/llvm-cov"),

            #[cfg(target_os = "macos")]
            llvm_profdata_path: PathBuf::from(
                "/Library/Developer/CommandLineTools/usr/bin/llvm-profdata",
            ),
            #[cfg(target_os = "macos")]
            llvm_cov_path: PathBuf::from("/Library/Developer/CommandLineTools/usr/bin/llvm-cov"),

            #[cfg(target_os = "windows")]
            llvm_profdata_path: PathBuf::from(r"C:\Program Files\LLVM\bin\llvm-profdata.exe"),
            #[cfg(target_os = "windows")]
            llvm_cov_path: PathBuf::from(r"C:\Program Files\LLVM\bin\llvm-cov.exe"),

            dict_path: None,
            //seed: "000".as_bytes().to_vec(),
            seed: vec![],
            seed_corpus: vec![],
            objects: vec![PathBuf::from("a.out")],
        }
    }

    /// parse command line options
    pub fn parse_args() -> Result<Self, Box<dyn std::error::Error>> {
        if std::env::args().any(|x| x == *"--mutate-stdin" || x == *"-") {
            mutate_stdin()?;
            std::process::exit(0);
        }

        let mut cfg: Config = Config::defaults();

        let mut args: Vec<String> = vec![];
        for arg in std::env::args() {
            for a in arg.splitn(2, '=') {
                args.push(a.to_string());
            }
        }

        if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
            println!("{}", help());
            std::process::exit(0);
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

        if args.contains(&"-c".to_string()) || args.contains(&"--corpus".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-c" || arg == "--corpus" {
                    stop = true
                } else if stop {
                    cfg.seed_corpus
                        .append(&mut load_corpus(&PathBuf::from(arg)));
                    cfg.corpus_dir = PathBuf::from(Path::new(&arg).parent().unwrap());
                    stop = false
                }
            }
        }

        if args.contains(&"-C".to_string()) || args.contains(&"--corpus-dir".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-C" || arg == "--corpus-dir" {
                    stop = true
                } else if stop {
                    cfg.seed_corpus
                        .append(&mut load_corpus_dir(&PathBuf::from(arg))?);
                    cfg.corpus_dir = PathBuf::from(Path::new(&arg).parent().unwrap());
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

        /*
        if cfg.objects.is_empty() {
            cfg.objects.push(std::path::PathBuf::from("./a.out"));
        }
        */

        if cfg.seed_corpus.is_empty() {
            cfg.seed_corpus = load_corpus(&PathBuf::from("./corpus/start"));
            cfg.corpus_dir = PathBuf::from("./corpus");
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

        let setup_args: &[String] = &[
            (cfg.target_path.as_os_str().to_str().unwrap()),
            //"-std=c17",
            //"-pipe",
            "-o",
            "a.out",
            "-O1",
            "-fprofile-instr-generate",
            "-fcoverage-mapping",
            // asan - very slow on windows and apple arm64
            #[cfg(not(target_arch = "aarch64"))]
            #[cfg(not(target_os = "windows"))]
            "-fsanitize=address",
            // usan
            "-fsanitize=undefined",
            // msan - not supported on apple arm64
            // #[cfg(not(target_arch = "aarch64"))]
            //"-fsanitize=memory",
            // stack trace
            "-fno-optimize-sibling-calls",
            "-fno-omit-frame-pointer",
            #[cfg(target_arch = "aarch64")]
            "-arch",
            #[cfg(target_arch = "aarch64")]
            "arm64",
        ]
        .map(|s| s.to_string());

        println!(
            "compiling...\n{} {}\n",
            &cfg.cc_path.as_os_str().to_str().unwrap(),
            setup_args.join(" ")
        );

        let setup_result = Command::new(&cfg.cc_path).args(setup_args).output()?;
        if !setup_result.stderr.is_empty() {
            eprintln!(
                "compile failed:\n{}\n{}",
                String::from_utf8(setup_result.stdout)?,
                String::from_utf8(setup_result.stderr)?,
            );
            panic!();
        }
        assert!(setup_result.stderr == b"");
        println!("done compiling");

        Ok(())
    }
}

/// execute the target process with given inputs sent to stdin.
/// returns true if the process stderr contains "Sanitizer"
pub fn exec_target(raw_profile_filepath: &str, input: &[u8]) -> Result<bool, std::io::Error> {
    set_var("LLVM_PROFILE_FILE", raw_profile_filepath);
    let mut profile_target = Command::new("./a.out")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let _send_input = profile_target.stdin.take().unwrap();
    let mut send_input = BufWriter::new(_send_input);
    send_input.write_all(input)?;
    send_input.write_all(b"\n")?;
    send_input.flush()?;
    let result = profile_target.wait_with_output()?;

    if !result.stderr.is_empty() {
        eprintln!(
            "{}\ncrashing input: {}",
            String::from_utf8_lossy(&result.stderr),
            String::from_utf8_lossy(input)
        );
        return Ok(true);
    }
    Ok(false)
}

pub fn exec_target_args(
    raw_profile_filepath: &str,
    cmd_args: &[String; 6],
) -> Result<bool, std::io::Error> {
    set_var("LLVM_PROFILE_FILE", raw_profile_filepath);

    let profile_target = Command::new("./a.out")
        .args(cmd_args)
        .stderr(Stdio::piped())
        .spawn()?;
    let result = profile_target.wait_with_output()?;

    if !result.stderr.is_empty() {
        eprintln!(
            "{}\ncrashing input: {:?}",
            String::from_utf8_lossy(&result.stderr),
            //String::from_utf8_lossy(input),
            cmd_args
        );
        return Ok(true);
    }
    Ok(false)
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
        raw_profile_filepath.to_string(),
        "-o".to_string(),
        profile_filepath.to_string(),
    ];
    let prof_merge_result = Command::new(&cfg.llvm_profdata_path)
        .args(prof_merge_args)
        .output()?;
    if !prof_merge_result.status.success() {
        panic!("\n{}", String::from_utf8_lossy(&prof_merge_result.stderr))
    }
    Ok(())
}

/// deserialized indexed report data, and return branch coverage
fn read_report(
    cfg: &Config,
    profile_filepath: &str,
) -> Result<ReportFile, Box<dyn std::error::Error>> {
    let mut prof_report_args: Vec<String> = vec![
        "export",
        "--instr-profile",
        profile_filepath,
        //"--object",
        //"./a.out",
    ]
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
            assert!(branch[4] <= 1);
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
