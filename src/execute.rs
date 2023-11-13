//! Compiles the target executable with LLVM instrumentation embedded.
//!
//! Available sanitizers:
//!  - linux: `address`, `cfi`, `leak`, `memory`, `safe-stack`, `thread`, `undefined`
//!  - macos: `address`, `thread`, `undefined`
//!  - win10: `address`, `undefined`
//!
//! Enable sanitizers by setting `CFLAGS` in the environment, e.g.
//! ```bash
//! export CFLAGS="-fsanitize=memory,undefined"
//! ```
//!
//! Examples of options that can be passed to the compiler
//! ```bash
//! export CFLAGS="-O3 -mshstk -mllvm -polly -std=c17 -g -fcolor-diagnostics -fuse-ld=lld -L/opt/lib -D_FORTIFY_SOURCE=3 -fstack-protector-all -fcf-protection=full -flto -fvisibility=hidden"
//! ```
//!
//! Further reading:
//! <https://clang.llvm.org/docs/ClangCommandLineReference.html>
//! <https://developers.redhat.com/articles/2022/06/02/use-compiler-flags-stack-protection-gcc-and-clang>

const CFLAGS_DEFAULTS: &str = "-O0 -g -fcolor-diagnostics -fuse-ld=lld";
// also see:
// <https://lldb.llvm.org/use/tutorial.html#starting-or-attaching-to-your-program>

use std::cmp::max;
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs::remove_file;
use std::io::{stdout, BufRead, BufReader, BufWriter, Read, Write};
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
//#[cfg(target_os = "linux")]
//use std::os::unix::process::ExitStatusExt;
#[cfg(target_os = "windows")]
use std::os::windows::{ffi::OsStringExt, process::ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread::{available_parallelism, current, Builder, JoinHandle};
use std::time::Instant;

use futures::future::FutureExt;
use futures::pin_mut;
use futures::select;

use rayon::ThreadPoolBuilder;

use crate::config::Config;
use crate::corpus::{BytesInput, CorpusOps, CorpusType, GraphInput, InputType};
use crate::grammar_tree::GraphTree;
use crate::mutator::{byte_index, Mutation};

/// number of mutations that will be queued for fuzzing before checking results
const FUZZING_QUEUE_SIZE: usize = 256;

#[cfg(not(debug_assertions))]
#[cfg(target_os = "linux")]
pub const SANITIZERS: &[&str] = &[
    "address",
    "cfi",
    "memory",
    "safe-stack",
    "thread",
    "undefined",
];
#[cfg(not(debug_assertions))]
#[cfg(target_os = "macos")]
//pub const SANITIZERS: &[&str] = &["address", "thread", "undefined"];
pub const SANITIZERS: &[&str] = &["cfi", "undefined"];
#[cfg(not(debug_assertions))]
#[cfg(target_os = "windows")]
pub const SANITIZERS: &[&str] = &["address", "undefined"];

#[cfg(debug_assertions)]
pub const SANITIZERS: &[&str] = &[""];

#[derive(Clone)]
pub struct Exec {
    pub cfg: Arc<Config>,
    _private: (),
}

#[derive(Debug)]
pub enum ExecResult<Output> {
    Ok(Output),
    Err(Output),
    NonTerminatingErr(u32), // u32 val is the PID of the unterminated process
    CoverageError(),
}

pub enum CoverageResult {
    Ok(BTreeSet<u128>),
    Err(),
}

/// create a unique number from two numbers.
/// this is used to assign a unique deterministic branch number when given a
/// line number and a block number.
/// https://en.wikipedia.org/wiki/Pairing_function
fn cantor_pair(a: u64, b: u64) -> u64 {
    ((a + b) >> 1) * (a + b + 1) + b
}
fn cantor_pair_u128(a: u128, b: u128) -> u128 {
    ((a + b) >> 1) * (a + b + 1) + b
}

fn compiled_executable_path(cfg: &Config, sanitizer: &str) -> PathBuf {
    let signature = &cfg
        .target_path
        .iter()
        .map(|t| t.file_stem().unwrap().to_str().unwrap())
        .collect::<Vec<&str>>()
        .join("-");

    let exe_name: String = if sanitizer.is_empty() {
        format!("ecfuzz_target.{}.out", signature)
    } else {
        format!("ecfuzz_target.{}-sanitized.{}.out", sanitizer, signature)
    };
    cfg.output_dir.as_path().join(exe_name)
}

/// convert raw profile data to an indexed file format
fn index_target_report(
    cfg: &Arc<Config>,
    raw_profile_filepath: &Path,
    profile_filepath: &Path,
) -> Result<(), ()> {
    let prof_merge_args = &[
        "merge".to_string(),
        "-sparse".to_string(),
        //"--instr".to_string(),
        raw_profile_filepath.display().to_string(),
        "--output".to_string(),
        profile_filepath.display().to_string(),
    ];
    let prof_merge_result = Command::new(&cfg.llvm_profdata_path)
        .args(prof_merge_args)
        .output()
        .expect("executing llvm-profdata");
    if !prof_merge_result.status.success() {
        eprintln!(
            "Could not merge profile data. {} Args:\n{} {}\n",
            String::from_utf8_lossy(&prof_merge_result.stderr),
            &cfg.llvm_profdata_path.display(),
            &prof_merge_args.join(" ")
        );
        return Err(());
    }
    Ok(())
}

/// count the number of code branches in the coverage file
pub fn count_branch_total(
    cfg: &Arc<Config>,
    sanitizer_idx: usize,
    base_input: &[u8],
    base_args: &[u8],
) -> Result<u64, Box<dyn std::error::Error>> {
    let profraw = cfg.output_dir.join(format!(
        "{}.profraw",
        current().name().expect("getting thread name")
    ));
    let profdata = cfg.output_dir.join(format!(
        "{}.profdata",
        current().name().expect("getting thread name")
    ));

    let output = exec_target(cfg, 0, &profraw, base_input, base_args.to_owned());
    if let ExecResult::Err(o) = output {
        if o.status.code().is_none() {
            panic!(
                "could not get status code from target!\nINPUT {}\nARGS {}\nstderr: {:#?}",
                String::from_utf8_lossy(base_input),
                String::from_utf8_lossy(base_args),
                String::from_utf8_lossy(&o.stderr),
            );
        }
    }

    index_target_report(cfg, &profraw, &profdata).unwrap();

    remove_file(profraw).expect("removing raw profile data");

    let prof_report = Command::new(&cfg.llvm_cov_path)
        .args([
            "export",
            "--ignore-filename-regex=libfuzz-driver.cpp|fuzz.cpp|StandaloneFuzzTargetMain.c",
            "--check-binary-ids",
            "--num-threads=1",
            "--skip-expansions",
            "--skip-functions",
            "--format=lcov",
            "--instr-profile",
            &profdata.display().to_string(),
            "--object",
            &compiled_executable_path(cfg, SANITIZERS[sanitizer_idx])
                .display()
                .to_string(),
        ])
        .stdout(Stdio::piped())
        .output()
        .expect("executing llvm-cov");

    if prof_report.stdout.is_empty() {
        panic!(
            "empty profdata: {:#?}\n{}",
            profdata,
            String::from_utf8_lossy(&prof_report.stderr)
        );
    }

    remove_file(profdata).expect("removing coverage profile data");

    let mut branches: BTreeSet<u128> = BTreeSet::new();
    let mut file_index = 0;
    let lines = prof_report.stdout.split(|byte| byte == &b'\n');
    for line in lines {
        if line.len() >= 2 && &line[0..2] == b"SF" {
            file_index += 1;
            continue;
        }
        if !(line.len() >= 4 && &line[0..4] == b"BRDA") {
            continue;
        }
        let linenumber_block_expr_count = &line
            .splitn(2, |l| l == &b':')
            .last()
            .unwrap()
            .split(|l| l == &b',')
            .collect::<Vec<_>>();

        #[cfg(debug_assertions)]
        assert!(linenumber_block_expr_count.len() == 4);

        let line_num: u64 = String::from_utf8(linenumber_block_expr_count[0].to_vec())
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let block: u64 = String::from_utf8(linenumber_block_expr_count[1].to_vec())
            .unwrap()
            .parse::<u64>()
            .unwrap();

        let branch0 = cantor_pair(line_num, block);
        let branch = cantor_pair_u128(branch0.into(), file_index);

        branches.insert(branch);
    }

    assert!(!branches.is_empty());
    Ok(branches.len() as u64)
}

/// read coverage report file and create a BTreeSet from branches covered in the coverage file
pub fn check_report_coverage(
    cfg: &Arc<Config>,
    profile_filepath: &Path,
    sanitizer_idx: usize,
) -> CoverageResult {
    let mut prof_report = Command::new(&cfg.llvm_cov_path)
        .args([
            "export",
            "--ignore-filename-regex=libfuzz-driver.cpp|fuzz.cpp",
            "--check-binary-ids",
            "--num-threads=1",
            "--skip-expansions",
            "--skip-functions",
            "--format=lcov",
            "--instr-profile",
            &profile_filepath.display().to_string(),
            "--object",
            &compiled_executable_path(cfg, SANITIZERS[sanitizer_idx])
                .display()
                .to_string(),
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("executing llvm-cov");

    let mut cov: BTreeSet<u128> = BTreeSet::new();
    let mut file_index = 0;

    let linereader = BufReader::new(prof_report.stdout.as_mut().unwrap());

    for line_result in linereader.split(b'\n') {
        let line = line_result.unwrap();
        if line.len() >= 2 && &line[0..2] == b"SF" {
            //println!("SOURCE FILE {}", String::from_utf8(line.to_vec()).unwrap());
            file_index += 1;
            continue;
        }
        if !(line.len() >= 4
            && &line[0..4] == b"BRDA"
            && match line.split(|l| l == &b',').last().unwrap() {
                b"-" => false,
                b"0" => false,
                _count => true,
            })
        {
            continue;
        }
        let linenumber_block_expr_count = &line
            .splitn(2, |l| l == &b':')
            .last()
            .unwrap()
            .split(|l| l == &b',')
            .collect::<Vec<_>>();

        #[cfg(debug_assertions)]
        assert!(linenumber_block_expr_count.len() == 4);

        let line_num: u64 = String::from_utf8(linenumber_block_expr_count[0].to_vec())
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let block: u64 = String::from_utf8(linenumber_block_expr_count[1].to_vec())
            .unwrap()
            .parse::<u64>()
            .unwrap();

        let branch0 = cantor_pair(line_num, block);
        let branch = cantor_pair_u128(branch0.into(), file_index);

        cov.insert(branch);
    }
    prof_report.wait().unwrap();

    #[cfg(debug_assertions)]
    assert!(prof_report
        .stdout
        .unwrap()
        .bytes()
        .collect::<Vec<Result<u8, std::io::Error>>>()
        .is_empty());

    if cov.is_empty() {
        return CoverageResult::Err();
    }
    CoverageResult::Ok(cov)
}

// move trial to Exec context ??
/// execute the target program with a new test input.
/// records profile data to the output directory.
pub fn trial(
    cfg: &Arc<Config>,
    args: &[u8],
    stdin: &[u8],
    hash_num: usize,
) -> (ExecResult<Output>, BTreeSet<u128>) {
    let profraw = cfg.output_dir.join(format!(
        "{}.profraw",
        current().name().expect("getting thread name")
    ));
    let profdata = cfg.output_dir.join(format!(
        "{}.profdata",
        current().name().expect("getting thread name")
    ));

    let sanitizer_idx: usize = hash_num % SANITIZERS.len();
    let output = exec_target(cfg, sanitizer_idx, &profraw, stdin, args.to_vec());

    #[cfg(debug_assertions)]
    assert!(profraw.exists()); // ensure profile data was generated

    if index_target_report(cfg, &profraw, &profdata).is_err() {
        eprintln!("Corrupted report file!");
        return (ExecResult::CoverageError(), BTreeSet::new());
    };

    remove_file(&profraw).expect("removing raw profile data");

    let cov = match check_report_coverage(cfg, &profdata, sanitizer_idx) {
        CoverageResult::Ok(cov) => cov,
        CoverageResult::Err() => BTreeSet::new(),
    };

    remove_file(&profdata).expect("removing coverage profile data");

    (output, cov)
}

/// If the fuzz execution result for a given mutation yielded new coverage,
/// add it to the cov_corpus.
/// If the mutation yielded a crash with new coverage, add it to the crash_corpus.
/// Results will be logged to the output directory.
fn handle_trial_result(
    cfg: &Arc<Config>,
    result: &ExecResult<Output>,
    corpus_entry: InputType,
    cov_corpus: &mut CorpusType,
    crash_corpus: &mut CorpusType,
    i: &usize,
) {
    let total_coverage = match cov_corpus {
        CorpusType::Bytes(c) => c.total_coverage.clone(),
        CorpusType::Graph(c) => c.total_coverage.clone(),
    };
    let crash_coverage = match crash_corpus {
        CorpusType::Bytes(c) => c.total_coverage.clone(),
        CorpusType::Graph(c) => c.total_coverage.clone(),
    };
    let input_coverage = match corpus_entry {
        InputType::Bytes(ref c) => c.coverage.clone(),
        InputType::Graph(ref c) => c.coverage.clone(),
    };
    match result {
        // if the report contains new coverage, add to corpus as BytesInput
        ExecResult::Ok(_output) | ExecResult::Err(_output)
            if !total_coverage.is_superset(&input_coverage) =>
        {
            log_new_coverage(&corpus_entry, i, cfg.plaintext);
            match cov_corpus {
                CorpusType::Bytes(cov_corpus) => {
                    cov_corpus.add_and_distill_corpus(corpus_entry);
                    cov_corpus
                        .save(&cfg.output_dir.join(Path::new("corpus")))
                        .expect("saving corpus to output directory");
                }
                CorpusType::Graph(cov_corpus) => {
                    cov_corpus.add_and_distill_corpus(corpus_entry);
                    //cov_corpus .save(&cfg.output_dir.join(Path::new("corpus")), stdin_graph.graph) .expect("saving corpus to output directory");
                    eprintln!("TODO: Implement graph corpus saving");
                }
            }
        }

        // if the input resulted in a crash covering new code branches,
        // add it to the crash log
        ExecResult::Err(output) if !crash_coverage.is_superset(&input_coverage) => {
            log_crash_new(&corpus_entry, i, &output.stderr, cfg.plaintext);

            match crash_corpus {
                CorpusType::Bytes(crash_corpus) => {
                    crash_corpus.add_and_distill_corpus(corpus_entry);
                    crash_corpus
                        .save(&cfg.output_dir.join(Path::new("crashes")))
                        .expect("saving crash corpus");
                }
                CorpusType::Graph(crash_corpus) => {
                    crash_corpus.add_and_distill_corpus(corpus_entry);
                    //crash_corpus .save(&cfg.output_dir.join(Path::new("crashes"))) .expect("saving crash corpus");
                    eprintln!("TODO: Implement graph corpus saving");
                }
            }
        }

        // warn if exited before logging coverage
        ExecResult::Ok(_o) | ExecResult::Err(_o) if input_coverage.is_empty() => {
            eprintln!(
                "\nError: could not read coverage from input!\nResult type: {:?}",
                result
            );
        }

        ExecResult::NonTerminatingErr(pid) => {
            panic!("\nRECEIVED KILL SIGNAL FROM WORKER (PID={})...", pid);

            //remove_file(fname).expect("removing input mutation file after abort");
            //profile_target.wait().unwrap();
            /*
            let pkill_result = Command::new("kill")
            .arg(pid.to_string())
            .output()
            .unwrap()
            .status
            .code()
            .unwrap();
            */
            //eprintln!("PKILL RESULT {}", pkill.unwrap());
            //eprintln!("DONE KILL PID={}...", pid);
            //assert!(pkill_result == 0);
            //eprintln!("\nNonTerminatingError: hopefully child process was killed already");
        }

        ExecResult::CoverageError() => {
            eprintln!("unhandled CoverageError");
        }

        ExecResult::Ok(_o) => {
            let cov = match corpus_entry {
                InputType::Bytes(ref i) => &i.coverage,
                InputType::Graph(ref i) => &i.coverage,
            };
            let check_duplicates = match cov_corpus {
                CorpusType::Bytes(c) => c
                    .inputs
                    .iter()
                    .enumerate()
                    .filter_map(|(i, input)| {
                        if &input.coverage == cov {
                            Some(i)
                        } else {
                            None
                        }
                    })
                    .rev()
                    .collect::<Vec<usize>>(),

                CorpusType::Graph(c) => c
                    .inputs
                    .iter()
                    .enumerate()
                    .filter_map(|(i, input)| {
                        if &input.coverage == cov {
                            Some(i)
                        } else {
                            None
                        }
                    })
                    .rev()
                    .collect::<Vec<usize>>(),
            };

            if !check_duplicates.is_empty() {
                let mut duplicates: Vec<InputType> = vec![corpus_entry.clone()];
                for i in check_duplicates {
                    match cov_corpus {
                        CorpusType::Bytes(ref mut c) => {
                            duplicates.push(InputType::Bytes(c.inputs.remove(i)));
                        }
                        CorpusType::Graph(ref mut c) => {
                            duplicates.push(InputType::Graph(c.inputs.remove(i)));
                        }
                    };
                }

                duplicates.sort();
                let keep = duplicates.remove(0);
                match cov_corpus {
                    CorpusType::Bytes(ref mut c) => match keep {
                        InputType::Bytes(i) => {
                            c.inputs.push(i);
                        }
                        _ => panic!(),
                    },
                    CorpusType::Graph(ref mut c) => match keep {
                        InputType::Graph(i) => {
                            c.inputs.push(i);
                        }
                        _ => panic!(),
                    },
                };
            }
        }

        ExecResult::Err(_o) => {
            let cov = match corpus_entry {
                InputType::Bytes(ref i) => &i.coverage,
                InputType::Graph(ref i) => &i.coverage,
            };
            let check_duplicates = match crash_corpus {
                CorpusType::Bytes(c) => c
                    .inputs
                    .iter()
                    .enumerate()
                    .filter_map(|(i, input)| {
                        if &input.coverage == cov {
                            Some(i)
                        } else {
                            None
                        }
                    })
                    .rev()
                    .collect::<Vec<usize>>(),

                CorpusType::Graph(c) => c
                    .inputs
                    .iter()
                    .enumerate()
                    .filter_map(|(i, input)| {
                        if &input.coverage == cov {
                            Some(i)
                        } else {
                            None
                        }
                    })
                    .rev()
                    .collect::<Vec<usize>>(),
            };
            if !check_duplicates.is_empty() {
                let mut duplicates: Vec<InputType> = vec![corpus_entry.clone()];
                for i in check_duplicates {
                    match crash_corpus {
                        CorpusType::Bytes(ref mut c) => {
                            duplicates.push(InputType::Bytes(c.inputs.remove(i)));
                        }
                        CorpusType::Graph(ref mut c) => {
                            duplicates.push(InputType::Graph(c.inputs.remove(i)));
                        }
                    };
                }

                duplicates.sort();
                let keep = duplicates.remove(0);
                match crash_corpus {
                    CorpusType::Bytes(ref mut c) => match keep {
                        InputType::Bytes(i) => {
                            c.inputs.push(i);
                        }
                        _ => panic!(),
                    },
                    CorpusType::Graph(ref mut c) => match keep {
                        InputType::Graph(i) => {
                            c.inputs.push(i);
                        }
                        _ => panic!(),
                    },
                };
            }
        }
    }
}

pub fn prepare_mutation_bytes(cov_corpus: &CorpusType, engine: &mut Mutation) -> InputType {
    match cov_corpus {
        CorpusType::Bytes(c) => {
            let idx = engine.hashfunc() % c.inputs.len();
            engine.data = c.inputs[idx].data.clone();
            engine.mutate();
            InputType::Bytes(BytesInput {
                data: engine.data.clone(),
                args: Vec::new(), /* args will be populated by exec_target from cfg.run_args */
                //coverage: BTreeSet::new(),
                coverage: c.inputs[idx].coverage.clone(),
            })
        }
        _ => panic!(),
    }
}

pub fn prepare_mutation_graph(
    cov_corpus: &mut CorpusType,
    engine: &mut Mutation,
    arg_grammar: &GraphTree,
    grammar: &GraphTree,
) -> InputType {
    let arg_permutation = arg_grammar.grammar_permutation(engine);
    let stdin_permutation = grammar.grammar_permutation(engine);

    match cov_corpus {
        CorpusType::Graph(c) => {
            if !c.inputs.is_empty() {
                let idx = engine.hashfunc() % c.inputs.len();
                let (p1, p2) =
                    grammar.swap_nodes(stdin_permutation, c.inputs[idx].encoding.clone(), engine);
                InputType::Graph(GraphInput {
                    encoding: p1,
                    args: arg_permutation.clone(),
                    coverage: BTreeSet::new(),
                    //coverage: c.inputs[idx].coverage.clone(),
                })
            } else {
                InputType::Graph(GraphInput {
                    encoding: stdin_permutation.clone(),
                    args: arg_permutation.clone(),
                    coverage: BTreeSet::new(),
                })
            }
        }
        _ => panic!(),
    }
}

impl Exec {
    /// compile and instrument the target
    pub fn new(cfg: &Config) -> Self {
        let exec = Exec {
            cfg: cfg.clone().into(),
            _private: (),
        };
        Exec::setup(&exec.cfg);

        exec
    }

    /// compile and instrument target binaries (one for each sanitizer)
    fn setup(cfg: &Config) {
        // ensure cc is clang >= v14.0.0
        let check_cc_ver = Command::new(&cfg.cc_path)
            .arg("--version")
            .output()
            .expect("checking clang install");
        let cc_ver = String::from_utf8_lossy(&check_cc_ver.stdout);
        println!("{}", cc_ver);
        let cc_ver_major = cc_ver.splitn(2, "version ").collect::<Vec<&str>>()[1]
            .splitn(2, '.')
            .collect::<Vec<&str>>()[0];
        if !cc_ver_major.parse::<u64>().expect("parsing clang version") == 14 {
            panic!("Requires CC version 14 or higher. Found {}", cc_ver);
        }

        let cflag_var = std::env::var("CFLAGS").unwrap_or(CFLAGS_DEFAULTS.to_string());
        println!("CFLAGS={:?}", cflag_var);
        let cflags: Vec<String> = cflag_var.split(' ').map(|s| s.to_string()).collect();

        let ldflag_var = std::env::var("LDFLAGS").unwrap_or("".to_string());
        println!("LDFLAGS={:?}", ldflag_var);
        let ldflags: Vec<String> = ldflag_var.split(' ').map(|s| s.to_string()).collect();

        std::fs::create_dir_all(&cfg.output_dir).expect("creating output dir");

        println!("compiling...");

        // check if target binary needs to be recompiled:
        // get most recent modification timestamp from target source
        let latest_modified: &std::time::SystemTime = &cfg
            .target_path
            .iter()
            .map(|f| {
                std::fs::metadata(f)
                    .expect("getting target source file metadata")
                    .modified()
                    .expect("reading modification time for target source file")
            })
            .reduce(max)
            .expect("getting latest binary timestamp");

        let mut handles: Vec<JoinHandle<_>> = Vec::new();

        // use a variety of available sanitizers when possible
        for sanitizer in SANITIZERS {
            let cflags = cflags.clone();
            let ldflags = ldflags.clone();
            let cfg = cfg.clone();
            let latest_modified = *latest_modified;
            let compile_thread = Builder::new()
                .name(format!(
                    "ecfuzz-compile-{}-",
                    if sanitizer == &"" {
                        "unsanitized"
                    } else {
                        sanitizer
                    }
                ))
                .spawn(move || {
                    let sanitizer_arg = format!("-fsanitize={}", sanitizer);
                    let compiled_path = compiled_executable_path(&cfg, sanitizer);

                    if compiled_path.is_file()
                        && std::fs::metadata(&compiled_path)
                            .unwrap()
                            .modified()
                            .unwrap()
                            > latest_modified
                    {
                        println!(
                            "target binary {} newer than target source, skipping compilation...",
                            compiled_path.display()
                        );
                        return;
                    }

                    let mut setup_args: Vec<String> = [
                        "-o",
                        &compiled_path.display().to_string(),
                        &sanitizer_arg,
                        "-g",
                        "-fsanitize-recover=all",
                        //"-D_FORTIFY_SOURCE=1",
                        "-fprofile-instr-generate",
                        "-fcoverage-mapping",
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

                    if setup_args.contains(&"-fsanitize=cfi".to_string()) {
                        setup_args.push("-flto=full".to_string());
                        setup_args.push("-fvisibility=hidden".to_string());
                    }

                    if cfg.plaintext {
                        setup_args.push("-fno-color-diagnostics".to_string());
                    } else {
                        setup_args.push("-fcolor-diagnostics".to_string());
                        setup_args.push("-fdiagnostics-color=always".to_string());
                    }
                    for flag in &cflags {
                        setup_args.push(flag.to_string());
                    }
                    for target in &cfg.target_path {
                        setup_args.push(target.display().to_string());
                    }
                    for flag in &ldflags {
                        setup_args.push(flag.to_string());
                    }
                    for link in &cfg.link_args {
                        setup_args.push(link.to_string());
                    }

                    if !cfg.include.is_empty() {
                        #[cfg(not(target_os = "macos"))]
                        setup_args.push("-Wl,--whole-archive".to_string());
                        #[cfg(target_os = "macos")]
                        setup_args.push("-all_load".to_string());
                    }

                    for inc in &cfg.include {
                        let mut include_string = inc.display().to_string();
                        include_string.insert_str(0, "-I");
                        setup_args.push(include_string);
                    }

                    if !cfg.include.is_empty() {
                        #[cfg(not(target_os = "macos"))]
                        setup_args.push("-Wl,--no-whole-archive".to_string());
                    }

                    println!(
                        "{} {}",
                        &cfg.cc_path.display().to_string(),
                        setup_args.join(" ")
                    );

                    let setup_result = Command::new(&cfg.cc_path)
                        .args(setup_args)
                        .output()
                        .expect("compiling instrumented target");
                    if !setup_result.stderr.is_empty()
                        && !byte_index(b"error: ".as_ref(), &setup_result.stderr).is_empty()
                    {
                        panic!(
                            "compile failed:\n{}\n{}",
                            String::from_utf8(setup_result.stdout).unwrap(),
                            String::from_utf8(setup_result.stderr).unwrap(),
                        );
                    } else if !setup_result.stderr.is_empty() {
                        eprintln!(
                            "compiled with warnings:\n{}\n{}",
                            String::from_utf8(setup_result.stdout).unwrap(),
                            String::from_utf8(setup_result.stderr).unwrap(),
                        );
                    }
                })
                .expect("compiling target thread worker");
            handles.push(compile_thread);
        }
        for handle in handles {
            handle.join().expect("compiling target");
        }
        println!("done compiling");
    }

    /// main loop:
    /// send input to target, read the coverage resulting from the input, and
    /// update the corpus with inputs yielding new coverage
    pub fn exec_loop(
        &self,
        //cfg: Arc<Config>,
        cov_corpus: &mut CorpusType,
        crash_corpus: &mut CorpusType,
        engine: &mut Mutation,
        args_graph: Option<Box<GraphTree>>,
        stdin_graph: Option<Box<GraphTree>>,
    ) {
        // worker thread pool
        let (sender, receiver) = channel::<(usize, InputType, ExecResult<Output>)>();
        let num_cpus: usize = available_parallelism().expect("checking CPU count").into();
        let pool = ThreadPoolBuilder::new()
            .thread_name(|f| format!("ecfuzz-worker-{}", f))
            .num_threads(num_cpus)
            .build()
            .unwrap();

        let base_args: Vec<u8> = self
            .cfg
            .run_args
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .map(|mut v| {
                v.push(b' ');
                v
            })
            .collect::<Vec<Vec<u8>>>()
            .concat();

        let branch_count = count_branch_total(&self.cfg, 0, &[], &base_args)
            .expect("checking number of code branches in target executable");

        assert!(num_cpus <= FUZZING_QUEUE_SIZE / 4);
        assert!(self.cfg.iterations >= FUZZING_QUEUE_SIZE);

        // store finished fuzzing jobs here in the order they finish
        // this allows retrieval of jobs in a deterministic order
        let mut finished_map: HashMap<usize, (InputType, ExecResult<Output>)> =
            HashMap::with_capacity(FUZZING_QUEUE_SIZE);

        //let mut input_history: Vec<Vec<u8>> = Vec::with_capacity(FUZZING_QUEUE_SIZE);
        //let mut input_arg_history: Vec<Vec<u8>> = Vec::with_capacity(FUZZING_QUEUE_SIZE);
        let mut input_history: Vec<InputType> = Vec::with_capacity(FUZZING_QUEUE_SIZE);

        let timer_start = Instant::now();
        let mut checkpoint = Instant::now();
        let iter_count = self.cfg.iterations;

        // set some color codes in the output
        let colorcode_red = if !self.cfg.plaintext { "\x1b[31m" } else { "" };
        let colorcode_normal = if !self.cfg.plaintext { "\x1b[0m" } else { "" };

        for i in 0..iter_count + FUZZING_QUEUE_SIZE {
            if i < iter_count - (FUZZING_QUEUE_SIZE) {
                let cfg_clone = self.cfg.clone();
                let mutation_trial = match cov_corpus {
                    CorpusType::Bytes(..) => prepare_mutation_bytes(cov_corpus, engine),
                    CorpusType::Graph(..) => prepare_mutation_graph(
                        cov_corpus,
                        engine,
                        args_graph.as_ref().unwrap(),
                        stdin_graph.as_ref().unwrap(),
                    ),
                };

                input_history.push(mutation_trial.clone());

                let (args, stdin) = match mutation_trial {
                    InputType::Bytes(ref m) => (m.args.clone(), m.data.clone()),
                    InputType::Graph(ref m) => (
                        args_graph.as_ref().unwrap().decode(&m.args),
                        stdin_graph.as_ref().unwrap().decode(&m.encoding),
                    ),
                };

                let prev_cov = match mutation_trial {
                    InputType::Bytes(ref i) => i.coverage.clone(),
                    InputType::Graph(ref i) => i.coverage.clone(),
                };

                let hash_num = engine.hashfunc();
                let sender = sender.clone();

                pool.spawn_fifo(move || {
                    let (result, result_cov) = trial(&cfg_clone, &args, &stdin, hash_num);
                    let mut mutation = mutation_trial.clone();
                    if !result_cov.is_empty() {
                        match mutation {
                            InputType::Graph(ref mut i) => {
                                i.coverage = result_cov;
                            }
                            InputType::Bytes(ref mut i) => {
                                i.coverage = result_cov;
                            }
                        };
                    } else {
                        match mutation {
                            InputType::Graph(ref mut i) => {
                                i.coverage = prev_cov;
                            }
                            InputType::Bytes(ref mut i) => {
                                i.coverage = prev_cov;
                            }
                        };
                    }

                    sender
                        .send((i, mutation, result))
                        .expect("sending results from worker");
                });
            }

            // start some jobs in the queue before retrieving any results
            if i <= FUZZING_QUEUE_SIZE {
                continue;
            }

            // fuzz jobs may be completed by parallel workers out of order
            // add finished results to a HashMap, and retrieve the latest
            // result from the map at an offset greater than the number of workers
            if i <= self.cfg.iterations {
                let (n, corpus_entry_unordered, result_unordered) = receiver
                    .recv()
                    .expect("receiving results from parallel worker");
                finished_map.insert(n, (corpus_entry_unordered, result_unordered));
            }

            #[cfg(debug_assertions)]
            assert!(finished_map.len() <= FUZZING_QUEUE_SIZE);

            // allow some completed fuzz jobs to gather in the finished queue
            if i < FUZZING_QUEUE_SIZE * 2 {
                continue;
            }

            // get completed fuzz jobs starting at the earliest index
            //.expect("retrieving execution result from finished map");
            let (corpus_entry, result): (InputType, ExecResult<Output>) = finished_map
                .remove(&(i - FUZZING_QUEUE_SIZE * 2))
                .unwrap_or_else(|| {
                    let failed_input = input_history.remove(0);

                    let outpath1 = self.cfg.output_dir.join(PathBuf::from("FATAL.crash"));
                    let mut out1 = std::fs::File::create(&outpath1).unwrap();
                    let outpath2 = self.cfg.output_dir.join(PathBuf::from("FATAL.args"));
                    let mut out2 = std::fs::File::create(outpath2).unwrap();

                    match failed_input {
                        InputType::Bytes(ref i) => {
                            out1.write_all(&i.data).unwrap();
                            out2.write_all(&i.args).unwrap();
                        }
                        InputType::Graph(ref i) => {
                            out1.write_all(&stdin_graph.as_ref().unwrap().decode(&i.encoding))
                                .unwrap();
                            out2.write_all(&args_graph.as_ref().unwrap().decode(&i.args))
                                .unwrap();
                        }
                    }

                    let wait_timer = Instant::now();
                    while wait_timer.elapsed().as_millis() <= 2000 {
                        let retry_get_result = finished_map.remove(&(i - FUZZING_QUEUE_SIZE * 2));
                        if let Some((corpus_entry, result)) = retry_get_result {
                            return (corpus_entry, result);
                        }
                    }

                    eprintln!(
                    "\n{}Warning: killed non-terminating process! {} exec: {}\ndumping stdin to {}",
                    colorcode_red,
                    colorcode_normal,
                    i,
                    outpath1.display(),
                );

                    /*
                    if std::env::var("ECFUZZ_ATTACH_DEBUGGER").is_ok() {
                    eprintln!("ATTACHING LLDB TO PID {}", pid.trim());

                    let mut attach_debug = Command::new ("/opt/bin/lldb")
                    .arg("-p")
                    .arg(pid.trim())
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap();
                    attach_debug.wait().unwrap();
                    } else {
                    eprintln!("Killing nonterminating process {}!\nTo attach a debugger instead, set ECFUZZ_ATTACH_DEBUGGER=1", pid.trim());
                    let pkill = Command::new("kill").arg(pid.trim()).output().unwrap().status.code();
                    pkill.unwrap();
                    }
                    */
                    (failed_input.clone(), ExecResult::NonTerminatingErr(0))
                });

            // if the expected data isn't at the front of the queue, consider it
            // to be abandoned by unresponsive process
            let output_matches_expected = match (&corpus_entry, &input_history[0]) {
                (InputType::Bytes(i), InputType::Bytes(h)) => i.data == h.data && i.args == h.args,
                (InputType::Graph(i), InputType::Graph(h)) => {
                    i.encoding == h.encoding && i.args == h.args
                }
                _ => panic!(),
            };
            if !output_matches_expected {
                if !(matches!(result, ExecResult::NonTerminatingErr(..))) {
                    match result {
                        ExecResult::Err(e) => {
                            panic!("Err(e) {}", String::from_utf8_lossy(&e.stderr))
                        }
                        ExecResult::Ok(e) => panic!("Ok(output) {}", e.status),
                        ExecResult::CoverageError() => panic!("coverage error",),
                        ExecResult::NonTerminatingErr(..) => panic!("impossible match case"),
                    }
                };
            } else {
                input_history.remove(0);
            };

            // remove tracking for abandoned items
            let abandoned_keys: Vec<usize> = finished_map
                .keys()
                .filter(|k| *k < &(i - (FUZZING_QUEUE_SIZE * 2)))
                .copied()
                .collect();
            for k in abandoned_keys {
                finished_map.remove(&k);
            }

            handle_trial_result(
                &self.cfg,
                &result,
                corpus_entry,
                cov_corpus,
                crash_corpus,
                &i,
            );

            // print some status info
            if !self.cfg.plaintext && checkpoint.elapsed() > std::time::Duration::from_millis(125) {
                log_status_msg(
                    &self.cfg,
                    cov_corpus,
                    crash_corpus,
                    branch_count,
                    i,
                    &timer_start,
                );
                checkpoint = Instant::now();
            }
        }
        log_status_msg(
            &self.cfg,
            cov_corpus,
            crash_corpus,
            branch_count,
            self.cfg.iterations,
            &timer_start,
        );

        assert!(finished_map.is_empty());
        assert!(receiver.try_recv().is_err());
    }
}

/// log coverage increases to stdout
fn log_new_coverage(new: &InputType, i: &usize, plaintext: bool) {
    let line_replacement = if !plaintext { "\r" } else { "" };
    let colorcode_green = if !plaintext { "\x1b[32m" } else { "" };
    let colorcode_normal = if !plaintext { "\x1b[0m" } else { "" };
    println!(
        "{}{}New coverage!{:>6}exec: {:<6}{:>57}{:?}\n",
        line_replacement, colorcode_green, colorcode_normal, i, "", new
    );
}

/// log new crashes to stderr
fn log_crash_new(new: &InputType, i: &usize, stderr: &[u8], plaintext: bool) {
    let line_replacement = if !plaintext { "\r" } else { "\n" };
    let colorcode_red = if !plaintext { "\x1b[31m" } else { "" };
    let colorcode_normal = if !plaintext { "\x1b[0m" } else { "" };
    eprintln!(
        "{}{}New crash!{:>6}exec: {:<6}{:<60}{:?}\n{}",
        line_replacement,
        colorcode_red,
        colorcode_normal,
        i,
        "",
        &new,
        String::from_utf8_lossy(stderr)
    );
}

fn log_status_msg(
    cfg: &Arc<Config>,
    cov_corpus: &CorpusType,
    crash_corpus: &CorpusType,
    branch_count: u64,
    i: usize,
    timer_start: &std::time::Instant,
) {
    let total_coverage = match cov_corpus {
        CorpusType::Bytes(c) => &c.total_coverage,
        CorpusType::Graph(c) => &c.total_coverage,
    };
    let cov_inputs_len = match cov_corpus {
        CorpusType::Bytes(c) => c.inputs.len(),
        CorpusType::Graph(c) => c.inputs.len(),
    };
    let crash_inputs_len = match crash_corpus {
        CorpusType::Bytes(c) => c.inputs.len(),
        CorpusType::Graph(c) => c.inputs.len(),
    };
    print!( "{}coverage: {:>5}/{:<5}  exec/s: {:<4.0}  corpus size: {:<4} unique crashes: {:<4} i: {:<8}{}",
            if cfg.plaintext {""} else {"\r"},
            total_coverage.len(),
            branch_count,
            i as f64 / (timer_start.elapsed().as_millis() as f64 / 1000.0),
            cov_inputs_len,
            crash_inputs_len,
            i,
            if cfg.plaintext {"\n"} else {""},
            );
    stdout().flush().unwrap();
}

/// execute the target program with a new test input either via an input file,
/// command line arguments, or by sending to the target stdin, as defined in
/// Config
fn exec_target(
    cfg: &Config,
    sanitizer_idx: usize,
    raw_profile_filepath: &Path,
    input: &[u8],
    mut grammar_args: Vec<u8>,
) -> ExecResult<Output> {
    let executable = compiled_executable_path(cfg, SANITIZERS[sanitizer_idx])
        .display()
        .to_string();

    // target input args
    // if --mutate-file is used, the first argument will be the mutated filepath
    let mut args: Vec<String> = Vec::new();

    // environment variables
    #[allow(unused_mut)]
    let mut env_vars: Vec<(&str, &str)> =
        Vec::from([("LLVM_PROFILE_FILE", raw_profile_filepath.to_str().unwrap())]);
    // malloc nano zone needs to be disabled for ASAN on mac
    #[cfg(target_os = "macos")]
    env_vars.push(("MallocNanoZone", "0"));

    // mutation input file (only used for --mutate-file)
    let fname = format!("{}.mutation", current().name().unwrap());

    // move this to mutate or trial() ????
    if !grammar_args.is_empty() && cfg.mutate_file {
        let placeholder_txt = b"ECFUZZ_MUTATED_FILE".to_vec();
        let placeholder = byte_index(&grammar_args, &placeholder_txt);
        if !placeholder.is_empty() {
            grammar_args.splice(
                placeholder[0]..placeholder[0] + placeholder_txt.len(),
                fname.as_bytes().to_vec(),
            );
        } else {
            grammar_args.insert(0, b' ');
            grammar_args.splice(0..placeholder_txt.len(), fname.as_bytes().to_vec());
        }
    }

    if cfg.mutate_file {
        // execute the target program with test input sent via an input file
        let mut f = BufWriter::new(std::fs::File::create(&fname).unwrap());
        f.write_all(input).unwrap();
        std::mem::drop(f);
        args.push(fname.clone());
    }

    for arg in &cfg.run_args {
        args.push(arg.to_string())
    }
    if !grammar_args.is_empty() {
        for arg in grammar_args.split(|b| b == &b' ') {
            args.push(String::from_utf8(arg.to_vec()).unwrap())
        }
    }

    if cfg.mutate_args {
        let mut fuzzy_args: Vec<Vec<_>> = Vec::new();
        let mut cursor: Vec<_> = Vec::new();

        for b in input {
            if b == &b'\0' {
                fuzzy_args.push(cursor);
                cursor = Vec::new();
            } else {
                cursor.push(*b);
            }
        }
        if !cursor.is_empty() {
            fuzzy_args.push(cursor);
        }

        #[cfg(not(target_os = "windows"))]
        let os_args: Vec<OsString> = fuzzy_args
            .iter()
            .map(|a| OsStringExt::from_vec(a.to_vec()))
            .collect();

        // windows OsString arguments are utf-16, so need to use from_wide()
        #[cfg(target_os = "windows")]
        let os_args: Vec<OsString> = fuzzy_args
            .iter()
            .map(|a| OsStringExt::from_wide(a))
            .collect();

        let _ = os_args
            .iter()
            .map(|a| args.push(a.to_str().unwrap().to_string()));
    }

    let mut profile_target = Command::new(PathBuf::from(".").join(&executable))
        .envs(env_vars)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("Running target executable {}\n{}", executable, e));

    // execute the target program with test input sent to stdin
    let send_input = profile_target.stdin.take().unwrap();
    let mut send_input = BufWriter::new(send_input);
    let recv_output = profile_target.stdout.take().unwrap();
    let recv_outerr = profile_target.stderr.take().unwrap();
    let mut recv_output = BufReader::new(recv_output);
    let mut recv_outerr = BufReader::new(recv_outerr);

    let mut out_buf: Vec<u8> = Vec::new();
    let mut err_buf: Vec<u8> = Vec::new();

    let runner_killer = async {
        async_std::task::sleep(std::time::Duration::from_millis(1000)).await;

        eprintln!(
            "ERR sanitizer {}\tFAILED INPUT {}",
            SANITIZERS[sanitizer_idx],
            String::from_utf8_lossy(input)
        );
    };

    let mut still_running = None;
    let runner = async {
        if cfg.mutate_stdin {
            send_input
                .write_all(input)
                .expect("sending input to target stdin");
            send_input.flush().expect("flushing input to target stdin");
        }
        std::mem::drop(send_input);
        still_running = Some(profile_target.wait().unwrap());

        // caution: read call blocks if the process becomes unresponsive
        recv_output.read_to_end(&mut out_buf).unwrap();
        recv_outerr.read_to_end(&mut err_buf).unwrap();
        //println!("OK sanitizer {:?}", SANITIZERS[sanitizer_idx]);

        //std::mem::drop(recv_output);
        //std::mem::drop(recv_outerr);
    };

    let race = async {
        let r = runner.fuse();
        let k = runner_killer.fuse();
        pin_mut!(r, k);
        //let mut r = Box::pin(r.fuse());
        //let mut k = Box::pin(k.fuse());
        select! {
            () = r => Ok(()),
            () = k => Err(()),
        }
    };
    let race_result: Result<(), ()> = futures::executor::block_on(race);

    if race_result.is_err() {
        eprintln!("\nKILLING PID={}...", profile_target.id(),);
        std::mem::drop(recv_output);
        std::mem::drop(recv_outerr);
        profile_target
            .kill()
            .expect("killing nonterminating process");
        profile_target
            .wait()
            .expect("waiting for killed process to return");
        return ExecResult::NonTerminatingErr(profile_target.id());
    }

    let output = std::process::Output {
        status: still_running.unwrap(),
        stdout: out_buf,
        stderr: err_buf,
    };

    if cfg.mutate_file {
        remove_file(fname).expect("removing input mutation file");
    }

    if output.status.code() == Some(0) {
        ExecResult::Ok(output)
    } else {
        ExecResult::Err(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::BytesCorpus;

    #[test]
    fn test_cli_demo() {
        let mut cfg: Config = Config::defaults();
        cfg.load_env();
        cfg.target_path = [PathBuf::from("./examples/cli/fuzz_target.c")].to_vec();
        cfg.corpus_files = [PathBuf::from("./examples/cli/input/corpus")].to_vec();
        cfg.output_dir = PathBuf::from("./output/testdata/");
        cfg.dict_path = Some(PathBuf::from("examples/cli/input/sample.dict"));
        cfg.iterations = 512;
        cfg.seed = b"117".to_vec();

        let mut engine =
            Mutation::with_seed(cfg.dict_path.clone(), cfg.seed.clone(), cfg.multiplier);

        let mut corpus = BytesCorpus::new();
        for filepath in &cfg.corpus_files {
            corpus.append(&mut BytesCorpus::load(filepath).expect("reading corpus file"))
        }
        for filepath in &cfg.corpus_dirs {
            corpus.append(&mut BytesCorpus::load(filepath).expect("reading corpus dir"))
        }

        let executor = Exec::new(&cfg);
        executor.exec_loop(
            &mut CorpusType::Bytes(corpus),
            &mut CorpusType::Bytes(BytesCorpus::new()),
            &mut engine,
            None,
            None,
        );
    }
}
