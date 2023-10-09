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
use std::error::Error;
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
use crate::corpus::{Corpus, CorpusInput};
use crate::grammar_tree::GrammarTree;
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

pub struct Exec {
    pub cfg: Arc<Config>,
}

pub enum ExecResult<Output> {
    Ok(Output),
    Err(Output),
    NonTerminatingErr(u32),
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

impl Exec {
    /// compile and instrument the target//.
    pub fn new(cfg: Config) -> Result<Exec, Box<dyn std::error::Error>> {
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
                        && !byte_index(&b"error: ".to_vec(), &setup_result.stderr.to_vec())
                            .is_empty()
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

        Ok(Exec {
            cfg: cfg.into(),
            //_private: (),
        })
    }

    pub fn prepare_mutation(
        &self,
        args_bytes: &[u8],
        cov_corpus: &Corpus,
        engine: &mut Mutation,
        grammar: &Option<Box<GrammarTree>>,
    ) -> CorpusInput {
        if self.cfg.grammar.is_some() {
            let tree = grammar.as_ref().unwrap();
            let generated_bytes: Vec<u8> = tree.grammar_permutation(engine);
            if cov_corpus.inputs.is_empty() {
                CorpusInput {
                    data: generated_bytes,
                    args: args_bytes.to_vec(),
                    coverage: BTreeSet::new(),
                    lifetime: 0,
                }
            } else {
                let idx = engine.hashfunc() % cov_corpus.inputs.len();
                let (c1, c2) =
                    tree.crossover(&generated_bytes, &cov_corpus.inputs[idx].data, engine);
                /*
                println!(
                "{}\t\t{}",
                String::from_utf8_lossy(&c1),
                String::from_utf8_lossy(&c2),
                );
                */
                CorpusInput {
                    data: if engine.hashfunc() % 2 == 0 { c1 } else { c2 },
                    args: args_bytes.to_vec(),
                    coverage: BTreeSet::new(),
                    lifetime: 0,
                }
            }
        } else if self.cfg.mutate_stdin {
            let idx = engine.hashfunc() % cov_corpus.inputs.len();
            engine.data = cov_corpus.inputs[idx].data.clone();
            //if i >= initial_corpus_size {
            engine.mutate();
            //}
            let payload = engine.data.clone();
            CorpusInput {
                data: payload,
                args: args_bytes.to_vec(),
                coverage: cov_corpus.inputs[idx].coverage.clone(),
                lifetime: cov_corpus.inputs[idx].lifetime,
            }
        } else {
            CorpusInput {
                data: Vec::new(),
                args: args_bytes.to_vec(),
                coverage: BTreeSet::new(),
                lifetime: 0,
            }
        }
    }

    /// execute the target program with a new test input.
    /// records profile data to the output directory.
    pub fn trial<'main_loop>(
        &'main_loop mut self,
        test_input: &'main_loop mut CorpusInput,
        hash_num: usize,
    ) -> ExecResult<Output> {
        let profraw = self.cfg.output_dir.join(format!(
            "{}.profraw",
            current().name().expect("getting thread name")
        ));
        let profdata = self.cfg.output_dir.join(format!(
            "{}.profdata",
            current().name().expect("getting thread name")
        ));

        let sanitizer_idx: usize = hash_num % SANITIZERS.len();
        let output = exec_target(
            &self.cfg,
            sanitizer_idx,
            &profraw,
            &test_input.data,
            test_input.args.clone(),
        );

        #[cfg(debug_assertions)]
        assert!(profraw.exists()); // ensure profile data was generated

        if self.index_target_report(&profraw, &profdata).is_err() {
            eprintln!("Corrupted report file!");
            return ExecResult::CoverageError();
        };
        remove_file(&profraw).expect("removing raw profile data");

        let cov = match self.check_report_coverage(&profdata, sanitizer_idx) {
            CoverageResult::Ok(cov) => cov,
            CoverageResult::Err() => {
                #[cfg(debug_assertions)]
                assert!(match &output {
                    ExecResult::Err(_)
                    | ExecResult::NonTerminatingErr(..)
                    | ExecResult::CoverageError() => true,
                    ExecResult::Ok(_o) => {
                        eprintln!(
                            "\ncrashing input: {}\nresult: {}\noutput status: {}",
                            test_input,
                            String::from_utf8_lossy(&_o.stderr),
                            _o.status.code().unwrap()
                        );
                        _o.status.code().unwrap() == 1
                    }
                });
                test_input.coverage.clone()
            }
        };
        remove_file(&profdata).expect("removing coverage profile data");

        // if the program crashes during execution, code coverage checking may
        // yield an empty set. in this case the parent mutation coverage is used
        let new_coverage: BTreeSet<u128> = match output {
            ExecResult::Ok(_) => cov,
            ExecResult::Err(_) => {
                if cov.is_empty() {
                    test_input.coverage.clone()
                } else {
                    cov
                }
            }
            ExecResult::NonTerminatingErr(..) => test_input.coverage.clone(),
            ExecResult::CoverageError(..) => test_input.coverage.clone(),
        };
        //test_input.lifetime += 1;
        test_input.coverage = new_coverage;

        output
    }

    /// If the fuzz execution result for a given mutation yielded new coverage,
    /// add it to the cov_corpus.
    /// If the mutation yielded a crash with new coverage, add it to the crash_corpus.
    /// Results will be logged to the output directory.
    pub fn handle_trial_result(
        &self,
        result: &ExecResult<Output>,
        mut corpus_entry: CorpusInput,
        cov_corpus: &mut Corpus,
        crash_corpus: &mut Corpus,
    ) {
        match result {
            // if the report contains new coverage, add to corpus as CorpusInput
            ExecResult::Ok(_output) | ExecResult::Err(_output)
                if !cov_corpus
                    .total_coverage
                    .is_superset(&corpus_entry.coverage) =>
            {
                corpus_entry.lifetime += 1;
                log_new_coverage(&corpus_entry, self.cfg.plaintext);
                cov_corpus.add_and_distill_corpus(corpus_entry);
                cov_corpus
                    .save(&self.cfg.output_dir.join(Path::new("corpus")))
                    .expect("saving corpus to output directory");
            }

            // if the input resulted in a crash covering new code branches,
            // add it to the crash log
            ExecResult::Err(output)
                if !crash_corpus
                    .total_coverage
                    .is_superset(&corpus_entry.coverage) =>
            {
                log_crash_new(&corpus_entry, &output.stderr, self.cfg.plaintext);
                crash_corpus.add_and_distill_corpus(corpus_entry);
                crash_corpus
                    .save(&self.cfg.output_dir.join(Path::new("crashes")))
                    .expect("saving crash corpus");
            }

            // warn if exited before logging coverage
            ExecResult::Ok(_o) | ExecResult::Err(_o) if corpus_entry.coverage.is_empty() => {
                eprintln!("\nError: could not read coverage from crash!",);
                /*
                panic!(
                "{:?}\n{}\n{}",
                _o,
                String::from_utf8_lossy(&args),
                String::from_utf8_lossy(&corpus_entry.data)
                );
                */
            }

            ExecResult::NonTerminatingErr(pid) => {
                //assert!(pid != 0);
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
                let check_duplicates = cov_corpus
                    .inputs
                    .iter()
                    .enumerate()
                    .filter_map(|(i, input)| {
                        if input.coverage == corpus_entry.coverage {
                            Some(i)
                        } else {
                            None
                        }
                    })
                    .rev()
                    .collect::<Vec<usize>>();
                if !check_duplicates.is_empty() {
                    let mut duplicates: Vec<CorpusInput> = vec![corpus_entry.clone()];
                    for i in check_duplicates {
                        duplicates.push(cov_corpus.inputs.remove(i));
                    }

                    duplicates.sort_by(|a, b| {
                        if a.data.len() != b.data.len() {
                            a.data.len().partial_cmp(&b.data.len()).unwrap()
                        } else {
                            a.data.partial_cmp(&b.data).unwrap()
                        }
                    });
                    cov_corpus.inputs.push(duplicates.remove(0));
                }
            }

            ExecResult::Err(_o) => {
                let check_duplicates = crash_corpus
                    .inputs
                    .iter()
                    .enumerate()
                    .filter_map(|(i, input)| {
                        if input.coverage == corpus_entry.coverage {
                            Some(i)
                        } else {
                            None
                        }
                    })
                    .rev()
                    .collect::<Vec<usize>>();
                if !check_duplicates.is_empty() {
                    let mut duplicates: Vec<CorpusInput> = vec![corpus_entry.clone()];
                    for i in check_duplicates {
                        duplicates.push(crash_corpus.inputs.remove(i));
                    }

                    duplicates.sort_by(|a, b| {
                        if a.data.len() != b.data.len() {
                            a.data.len().partial_cmp(&b.data.len()).unwrap()
                        } else {
                            a.data.partial_cmp(&b.data).unwrap()
                        }
                    });
                    crash_corpus.inputs.push(duplicates.remove(0));
                }
            }
        }
    }

    /// main loop:
    /// send input to target, read the coverage resulting from the input, and
    /// update the corpus with inputs yielding new coverage
    pub fn _main_loop(
        &mut self,
        cov_corpus: &mut Corpus,
        mutation: &mut Mutation,
    ) -> Result<(), Box<dyn Error>> {
        let mut crash_corpus = Corpus::new();

        // worker thread pool
        let (sender, receiver) = channel::<(usize, CorpusInput, ExecResult<Output>)>();
        let num_cpus: usize = available_parallelism()?.into();
        let pool = ThreadPoolBuilder::new()
            .thread_name(|f| format!("ecfuzz-worker-{}", f))
            .num_threads(num_cpus)
            .build()
            .unwrap();

        let mut base_args: Vec<u8> = self
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

        let grammar = if self.cfg.grammar.is_none() {
            None
        } else {
            let grammar_path = self.cfg.grammar.as_ref().unwrap();
            //base_args.push(b' ');
            let tree = Box::new(GrammarTree::from_file(grammar_path));

            Some(tree)
        };

        let args_grammar = if self.cfg.run_arg_grammar.is_none() {
            None
        } else {
            let grammar_path = self.cfg.run_arg_grammar.as_ref().unwrap();
            let tree = Box::new(GrammarTree::from_file(grammar_path));
            base_args.splice(base_args.len().., tree.grammar_permutation(mutation));
            Some(tree)
        };

        let base_stdinput = match self.cfg.mutate_stdin {
            true => {
                if self.cfg.grammar.is_some() {
                    grammar.as_ref().unwrap().grammar_permutation(mutation)
                } else {
                    cov_corpus.inputs[0].data.clone()
                }
            }
            false => [].to_vec(),
        };

        let branch_count = self.count_branch_total(0, &base_stdinput, &base_args)?;

        assert!(num_cpus <= FUZZING_QUEUE_SIZE / 4);
        assert!(self.cfg.iterations >= FUZZING_QUEUE_SIZE);

        // store finished fuzzing jobs here in the order they finish
        // this allows retrieval of jobs in a deterministic order
        let mut finished_map: HashMap<usize, (CorpusInput, ExecResult<Output>)> =
            HashMap::with_capacity(FUZZING_QUEUE_SIZE);

        let mut input_history: Vec<Vec<u8>> = Vec::with_capacity(FUZZING_QUEUE_SIZE);
        let mut input_arg_history: Vec<Vec<u8>> = Vec::with_capacity(FUZZING_QUEUE_SIZE);

        let timer_start = Instant::now();
        let mut checkpoint = Instant::now();
        let iter_count = self.cfg.iterations;

        // set some color codes in the output
        let colorcode_red = if !self.cfg.plaintext { "\x1b[31m" } else { "" };
        let colorcode_normal = if !self.cfg.plaintext { "\x1b[0m" } else { "" };

        for i in 0..iter_count + FUZZING_QUEUE_SIZE {
            if i < iter_count - (FUZZING_QUEUE_SIZE) {
                // mutate the input
                let args_grammar = args_grammar.clone();
                let args_bytes = if let Some(g) = args_grammar {
                    g.grammar_permutation(mutation)
                } else {
                    [].to_vec()
                };

                let mut mutation_trial =
                    self.prepare_mutation(&args_bytes, cov_corpus, mutation, &grammar);

                let sender = sender.clone();
                let mut exec_clone = Exec {
                    cfg: self.cfg.clone(),
                };
                let hash_num = mutation.hashfunc();

                // record history of input
                input_history.push(mutation_trial.data.clone());
                input_arg_history.push(mutation_trial.args.clone());

                pool.spawn_fifo(move || {
                    let result = exec_clone.trial(&mut mutation_trial, hash_num);
                    sender
                        .send((i, mutation_trial, result))
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
                let (n, corpus_entry_unordered, result_unordered) = receiver.recv()?;
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
            let (corpus_entry, result) = finished_map
                .remove(&(i - FUZZING_QUEUE_SIZE * 2))
                .unwrap_or_else(|| {
                    let failed_args = input_arg_history.remove(0);
                    let failed_input = input_history.remove(0);

                    let outpath1 = self.cfg.output_dir.join(PathBuf::from("FATAL.crash"));
                    let mut out1 = std::fs::File::create(&outpath1).unwrap();
                    out1.write_all(&failed_input).unwrap();

                    let outpath2 = self.cfg.output_dir.join(PathBuf::from("FATAL.args"));
                    let mut out2 = std::fs::File::create(outpath2).unwrap();
                    out2.write_all(&failed_args).unwrap();


                    let wait_timer = Instant::now();
                    while wait_timer.elapsed().as_millis() <= 2000 {
                        let retry_get_result = finished_map
                            .remove(&(i - FUZZING_QUEUE_SIZE * 2));
                        if let Some((corpus_entry, result))  = retry_get_result {
                            return (corpus_entry, result);
                        }
                    }

                    eprintln!(
                        "\n{}Warning: killed non-terminating process! {} i: {}\nARGS: {}\nINPUT:\n{}\ndumping stdin to {}",
                        colorcode_red,
                        colorcode_normal,
                        i,
                        String::from_utf8_lossy(&failed_args),
                        String::from_utf8_lossy(&failed_input),
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
                    (
                        CorpusInput {
                            coverage: BTreeSet::new(),
                            args: Vec::new(),
                            data: Vec::new(),
                            lifetime: 0,
                        },
                        ExecResult::NonTerminatingErr(0),
                        )
                });

            // if the expected data isn't at the front of the queue, consider it
            // to be abandoned by unresponsive process
            if corpus_entry.data != input_history[0].clone() {
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
                input_arg_history.remove(0);
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

            self.handle_trial_result(&result, corpus_entry, cov_corpus, &mut crash_corpus);

            // print some status info
            if !self.cfg.plaintext && checkpoint.elapsed() > std::time::Duration::from_millis(125) {
                log_status_msg(
                    &self.cfg,
                    cov_corpus,
                    &crash_corpus,
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
            &crash_corpus,
            branch_count,
            self.cfg.iterations,
            &timer_start,
        );

        assert!(finished_map.is_empty());
        assert!(receiver.try_recv().is_err());

        Ok(())
    }

    /// convert raw profile data to an indexed file format
    fn index_target_report(
        &self,
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
        let prof_merge_result = Command::new(&self.cfg.llvm_profdata_path)
            .args(prof_merge_args)
            .output()
            .expect("executing llvm-profdata");
        if !prof_merge_result.status.success() {
            eprintln!(
                "Could not merge profile data. {} Args:\n{} {}\n",
                String::from_utf8_lossy(&prof_merge_result.stderr),
                &self.cfg.llvm_profdata_path.display(),
                &prof_merge_args.join(" ")
            );
            return Err(());
        }
        Ok(())
    }

    /// count the number of code branches in the coverage file
    pub fn count_branch_total(
        &mut self,
        sanitizer_idx: usize,
        base_input: &[u8],
        base_args: &[u8],
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let profraw = self.cfg.output_dir.join(format!(
            "{}.profraw",
            current().name().expect("getting thread name")
        ));
        let profdata = self.cfg.output_dir.join(format!(
            "{}.profdata",
            current().name().expect("getting thread name")
        ));

        let output = exec_target(&self.cfg, 0, &profraw, base_input, base_args.to_owned());
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

        self.index_target_report(&profraw, &profdata).unwrap();

        remove_file(profraw).expect("removing raw profile data");

        let prof_report = Command::new(&self.cfg.llvm_cov_path)
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
                &compiled_executable_path(&self.cfg, SANITIZERS[sanitizer_idx])
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
        &self,
        profile_filepath: &Path,
        sanitizer_idx: usize,
    ) -> CoverageResult {
        let mut prof_report = Command::new(&self.cfg.llvm_cov_path)
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
                &compiled_executable_path(&self.cfg, SANITIZERS[sanitizer_idx])
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
}

/// log coverage increases to stdout
fn log_new_coverage(new: &CorpusInput, plaintext: bool) {
    let line_replacement = if !plaintext { "\r" } else { "" };
    let colorcode_green = if !plaintext { "\x1b[32m" } else { "" };
    let colorcode_normal = if !plaintext { "\x1b[0m" } else { "" };
    println!(
        "{}{}New coverage!{}{:>73}{:?}\n",
        line_replacement, colorcode_green, colorcode_normal, "", new
    );
}

/// log new crashes to stderr
fn log_crash_new(new: &CorpusInput, stderr: &[u8], plaintext: bool) {
    let line_replacement = if !plaintext { "\r" } else { "\n" };
    let colorcode_red = if !plaintext { "\x1b[31m" } else { "" };
    let colorcode_normal = if !plaintext { "\x1b[0m" } else { "" };
    eprintln!(
        "{}{}New crash!{}{:<76}{:?}\n{}",
        line_replacement,
        colorcode_red,
        colorcode_normal,
        "",
        &new,
        String::from_utf8_lossy(stderr)
    );
}

fn log_status_msg(
    cfg: &Arc<Config>,
    cov_corpus: &Corpus,
    crash_corpus: &Corpus,
    branch_count: u64,
    i: usize,
    timer_start: &std::time::Instant,
) {
    print!("{}",format!(
            "{}coverage: {:>5}/{:<5}  exec/s: {:<4.0}  corpus size: {:<4} unique crashes: {:<4} i: {:<8}{}",
            if cfg.plaintext {""} else {"\r"},
            cov_corpus.total_coverage.len(),
            branch_count,
            i as f64 / (timer_start.elapsed().as_millis() as f64 / 1000.0),
            cov_corpus.inputs.len(),
            crash_corpus.inputs.len(),
            i,
            if cfg.plaintext {"\n"} else {""},
            ));
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
