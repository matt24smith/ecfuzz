//! Compiles the target executable with LLVM instrumentation embedded.
//!
//! Available sanitizers12:
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

#[cfg(not(debug_assertions))]
const CFLAGS_DEFAULTS: &str = "-O3 -g -fcolor-diagnostics -fuse-ld=lld -fstack-protector-all";
#[cfg(debug_assertions)]
const CFLAGS_DEFAULTS: &str = "-O0 -g -fcolor-diagnostics -fuse-ld=lld";
// also see:
// <https://lldb.llvm.org/use/tutorial.html#starting-or-attaching-to-your-program>

use std::cmp::max;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::OsString;
use std::fs::remove_file;
#[cfg(debug_assertions)]
use std::io::Read;
use std::io::{stdout, BufRead, BufReader, BufWriter, Write};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread::{available_parallelism, current};
use std::time::Instant;

use rayon::ThreadPoolBuilder;

use crate::config::Config;
use crate::corpus::{Corpus, CorpusInput};
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
pub const SANITIZERS: &[&str] = &["", "address", "thread", "undefined"];
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
}

pub enum CoverageResult {
    Ok(HashSet<u128>),
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
    /// compile and instrument the target.
    pub fn initialize(cfg: Config) -> Result<Exec, Box<dyn std::error::Error>> {
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
            //.filter(|m| m.is_ok())
            //.map(|m| m.expect("reading modification for target source file"))
            .reduce(max)
            .unwrap();

        // use a variety of available sanitizers when possible
        for sanitizer in SANITIZERS {
            let sanitizer_arg = format!("-fsanitize={}", sanitizer);
            let compiled_path = compiled_executable_path(&cfg, sanitizer);

            //if PathBuf::from(compiled_path).is_file() && std::fs::metadata
            if compiled_path.is_file()
                && &std::fs::metadata(&compiled_path)
                    .unwrap()
                    .modified()
                    .unwrap()
                    > latest_modified
            {
                println!(
                    "target binary {} newer than target source, skipping compilation...",
                    compiled_path.display()
                );
                continue;
            }

            let mut setup_args: Vec<String> = [
                "-o",
                &compiled_path.display().to_string(),
                &sanitizer_arg,
                "-flto=thin",
                "-fvisibility=hidden",
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

            for flag in &cflags {
                setup_args.push(flag.to_string());
            }
            for target in &cfg.target_path {
                setup_args.push(target.display().to_string());
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
                "compiling...\n{} {}\n",
                &cfg.cc_path.display().to_string(),
                setup_args.join(" ")
            );

            let setup_result = Command::new(&cfg.cc_path)
                .args(setup_args)
                .output()
                .expect("compiling instrumented target");
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
        }
        println!("done compiling");

        Ok(Exec { cfg: cfg.into() })
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
            &test_input.data.borrow(),
        );

        #[cfg(debug_assertions)]
        assert!(profraw.exists()); // ensure profile data was generated

        self.index_target_report(&profraw, &profdata).unwrap();
        remove_file(&profraw).expect("removing raw profile data");

        let cov = match self.check_report_coverage(&profdata, sanitizer_idx) {
            CoverageResult::Ok(cov) => cov,
            CoverageResult::Err() => {
                assert!(matches!(output, ExecResult::Err(_)));
                test_input.coverage.clone()
            }
        };
        //.unwrap_or_else(|_e| {
        //assert!(match output { ExecResult::Err(_) => true, _ => false, });
        //});
        remove_file(&profdata).expect("removing coverage profile data");

        // if the program crashes during execution, code coverage checking may
        // yield an empty set. in this case the parent mutation coverage is used
        let new_coverage: HashSet<u128> = match output {
            ExecResult::Ok(_) => cov,
            ExecResult::Err(_) => {
                if cov.is_empty() {
                    test_input.coverage.clone()
                } else {
                    cov
                }
            }
        };
        test_input.lifetime += 1;
        test_input.coverage = new_coverage;

        output
    }

    /// main loop:
    /// send input to target, read the coverage resulting from the input, and
    /// update the corpus with inputs yielding new coverage
    pub fn _main_loop(
        &mut self,
        cov_corpus: &mut Corpus,
        mutation: &mut Mutation,
    ) -> Result<(), Box<dyn Error>> {
        // crashlog
        let mut crash_corpus = Corpus::new();
        let branch_count = self.count_branch_total(0)?;
        let save_corpus_dir = self.cfg.output_dir.join(Path::new("corpus"));
        let save_crashes_dir = self.cfg.output_dir.join(Path::new("crashes"));

        // truncate old results
        cov_corpus
            .save(&save_corpus_dir)
            .expect("emptying corpus output directory");
        crash_corpus
            .save(&save_corpus_dir)
            .expect("emptying crashes output directory");

        // worker thread pool
        let (sender, receiver) = channel::<(usize, CorpusInput, ExecResult<Output>)>();
        let num_cpus: usize = available_parallelism()?.into();
        let pool = ThreadPoolBuilder::new()
            .thread_name(|f| format!("ecfuzz-worker-{}", f))
            .num_threads(num_cpus)
            .build()
            .unwrap();

        assert!(num_cpus <= FUZZING_QUEUE_SIZE / 4);
        assert!(self.cfg.iterations >= FUZZING_QUEUE_SIZE);

        // store finished fuzzing jobs here in the order they finish
        // this allows retrieval of jobs in a deterministic order
        let mut finished_map: HashMap<usize, (CorpusInput, ExecResult<Output>)> =
            HashMap::with_capacity(FUZZING_QUEUE_SIZE);

        let mut timer_start = Instant::now();
        let mut status: String = String::default();
        let mut refresh_rate: usize = 0;

        for i in 0..self.cfg.iterations + FUZZING_QUEUE_SIZE {
            // mutate the input
            if i < self.cfg.iterations - FUZZING_QUEUE_SIZE {
                let idx = mutation.hashfunc() % cov_corpus.inputs.len();
                mutation.data = cov_corpus.inputs[idx].data.clone();
                mutation.mutate();

                let mut mutation_trial = CorpusInput {
                    data: mutation.data.clone(),
                    coverage: cov_corpus.inputs[idx].coverage.clone(),
                    lifetime: cov_corpus.inputs[idx].lifetime,
                };

                let sender = sender.clone();
                let mut exec_clone = Exec {
                    cfg: self.cfg.clone(),
                };
                let hash_num = mutation.hashfunc();
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
            let (corpus_entry, result) = finished_map
                .remove(&(i - FUZZING_QUEUE_SIZE * 2))
                .expect("retrieving fuzz job results");

            // If the fuzz execution result for a given mutation yielded new coverage,
            // add it to the cov_corpus.
            // If the mutation yielded a crash with new coverage, add it to the crash_corpus.
            // Corpus will be saved to outdir, crashes are logged to crashdir.
            match result {
                // if the report contains new coverage, add to corpus as CorpusInput
                ExecResult::Ok(_output) => {
                    if !cov_corpus
                        .total_coverage
                        .is_superset(&corpus_entry.coverage)
                    {
                        // update corpus
                        let before = cov_corpus.inputs.len() + 1;
                        cov_corpus.add_and_distill_corpus(corpus_entry);
                        let after = cov_corpus.inputs.len();
                        let pruned = before - after;
                        log_new_coverage(
                            &i,
                            cov_corpus.inputs.last().unwrap(),
                            pruned,
                            cov_corpus.inputs.len(),
                        );
                        cov_corpus
                            .save(&save_corpus_dir)
                            .expect("saving corpus to output directory");

                        // print updated corpus
                        print!("{}", status);
                        stdout().flush().unwrap();
                    }
                }
                // if the report crashed, try to check the coverage or fallback to
                // parent coverage
                ExecResult::Err(output) => {
                    if !crash_corpus
                        .total_coverage
                        .is_superset(&corpus_entry.coverage)
                    {
                        log_crash_new(&output.stderr, &i, &corpus_entry);
                        // update corpus
                        crash_corpus.add_and_distill_corpus(corpus_entry);
                        crash_corpus
                            .save(&save_crashes_dir)
                            .expect("saving crash corpus");

                        // print updated corpus
                        print!("{}", status);
                        stdout().flush().unwrap();
                    } else {
                        //log_crash_known(&output.stderr, &i, &crash_corpus);
                        print!("{}", status);
                        stdout().flush().unwrap();
                        if corpus_entry.coverage.is_empty() {
                            eprintln!(
                                        "\nError: could not read coverage from crash! See output from sanitizer\n{}",
                                        String::from_utf8_lossy(&output.stderr)
                                        );
                        }
                    }
                }
            }
            // print some status info
            if i == FUZZING_QUEUE_SIZE {
                timer_start = Instant::now();
            } else if i == FUZZING_QUEUE_SIZE * 2 {
                let exec_rate =
                    FUZZING_QUEUE_SIZE as f64 / (timer_start.elapsed().as_micros() as f64 / 1e6); // seconds
                refresh_rate = max(10, (exec_rate / 4.0) as usize); // frames per second
                timer_start = Instant::now();
            } else if i % refresh_rate == 0 && refresh_rate > 0 && i <= self.cfg.iterations {
                let exec_rate =
                    refresh_rate as f64 / (timer_start.elapsed().as_micros() as f64 / 1e6);
                status = format!(
                    "\rcoverage: {:>5}/{:<5}  exec/s: {:<4.0}  corpus size: {:<4} unique crashes: {:<4} i: {:<8}",
                    cov_corpus.total_coverage.len(),
                    branch_count,
                    exec_rate,
                    cov_corpus.inputs.len(),
                    crash_corpus.inputs.len(),
                    i,
                    );
                print!("{}", status);
                stdout().flush().unwrap();
                timer_start = Instant::now();
            }
        }
        println!("{}", status);

        cov_corpus.save(&save_corpus_dir).unwrap();
        crash_corpus.save(&save_crashes_dir).unwrap();

        assert!(finished_map.is_empty());

        Ok(())
    }

    /// convert raw profile data to an indexed file format
    fn index_target_report(
        &self,
        raw_profile_filepath: &Path,
        profile_filepath: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
            panic!(
                "Could not merge profile data. {} Args:\n{} {}\n",
                String::from_utf8_lossy(&prof_merge_result.stderr),
                &self.cfg.llvm_profdata_path.display(),
                &prof_merge_args.join(" ")
            )
        }
        Ok(())
    }

    /// count the number of code branches in the coverage file
    pub fn count_branch_total(
        &mut self,
        sanitizer_idx: usize,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let profraw = self.cfg.output_dir.join(format!(
            "{}.profraw",
            current().name().expect("getting thread name")
        ));
        let profdata = self.cfg.output_dir.join(format!(
            "{}.profdata",
            current().name().expect("getting thread name")
        ));

        let output = exec_target(&self.cfg, 0, &profraw, b"");
        if let ExecResult::Err(o) = output {
            panic!("{:#?}", o);
        }

        self.index_target_report(&profraw, &profdata).unwrap();

        remove_file(profraw).expect("removing raw profile data");

        let prof_report = Command::new(&self.cfg.llvm_cov_path)
            .args([
                "export",
                "--ignore-filename-regex=libfuzz-driver.cpp|fuzz.cpp",
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

        //let branch_count = parse_report_cov(&prof_report.stdout).unwrap();
        //Ok(branch_count.len() as u64)
        //let report: Report = serde_json::from_slice(&prof_report.stdout).unwrap();
        //Ok(report.data[0].totals.branches.count.into())
        let mut branches: HashSet<u128> = HashSet::new();
        let mut file_index = 0;
        let lines = prof_report.stdout.split(|byte| byte == &b'\n');
        for line in lines {
            if line.len() >= 2 && &line[0..2] == b"SF" {
                file_index += 1;
                continue;
            }
            if !(
                line.len() >= 4 && &line[0..4] == b"BRDA"
                //&& match &line.split(|l| l == &b',').last().unwrap() { &b"-" => false, &b"0" => false, _count => true, }
            ) {
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

    /// read coverage report file and create a HashSet from branches covered in the coverage file
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

        let mut cov: HashSet<u128> = HashSet::new();
        let mut file_index = 0;
        //let lines = prof_report.stdout.split(|byte| byte == &b'\n');
        let linereader = BufReader::new(prof_report.stdout.as_mut().unwrap());
        for line_result in linereader.lines() {
            let line = line_result.unwrap();
            if line.len() >= 2 && &line[0..2] == "SF" {
                //println!("SOURCE FILE {}", String::from_utf8(line.to_vec()).unwrap());
                file_index += 1;
                continue;
            }
            if !(line.len() >= 4
                && &line[0..4] == "BRDA"
                && match &line.split(|l| l == ',').last().unwrap() {
                    &"-" => false,
                    &"0" => false,
                    _count => true,
                })
            {
                continue;
            }
            let linenumber_block_expr_count = &line
                .splitn(2, |l| l == ':')
                .last()
                .unwrap()
                .split(|l| l == ',')
                .collect::<Vec<_>>();

            #[cfg(debug_assertions)]
            assert!(linenumber_block_expr_count.len() == 4);

            let line_num: u64 = linenumber_block_expr_count[0].parse::<u64>().unwrap();
            let block: u64 = linenumber_block_expr_count[1].parse::<u64>().unwrap();

            let branch0 = cantor_pair(line_num, block);
            //let branch1 = cantor_pair(block, expr);
            let branch = cantor_pair_u128(branch0.into(), file_index);

            //println!("LINE {}", line);
            //#[cfg(debug_assertions)]
            //assert!(!cov.contains(&branch.try_into().unwrap()));

            cov.insert(branch);
        }
        //assert!(prof_report.try_wait().unwrap().unwrap().code().unwrap() == 0);
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
        //Ok(cov)
        CoverageResult::Ok(cov)
    }
}

/// log coverage increases to stdout
fn log_new_coverage(i: &usize, new: &CorpusInput, pruned: usize, corpus_size: usize) {
    println!(
        "\r\x1b[32mNew coverage!\x1b[0m execs: {:<6} pruned: {:<2} corpus size: {:<4} updating inputs...{:>12}{:?}\n",
        i, pruned, corpus_size, "", new
        );
}

/// log new crashes to stderr
fn log_crash_new(stderr: &[u8], i: &usize, new: &CorpusInput) {
    eprintln!(
        "\r\x1b[31mNew crash!\x1b[0m execs: {}  updating crash log...{:<50}{:?}\n{}",
        i,
        "",
        //&crash_corpus,
        &new,
        String::from_utf8_lossy(stderr)
    );
}

/*
/// log known crashes to stderr
fn log_crash_known(_stderr: &[u8], i: &usize, _crash_corpus: &Corpus) {
eprintln!(
//"\r\x1b[91mKnown crash!\x1b[0m execs: {:<80}\n{}",
"\r\x1b[91mKnown crash!\x1b[0m execs: {:<80}",
i,
//String::from_utf8_lossy(stderr),
);
}
*/

/// execute the target program with a new test input either via an input file,
/// command line arguments, or by sending to the target stdin, as defined in
/// Config
fn exec_target(
    cfg: &Config,
    sanitizer_idx: usize,
    raw_profile_filepath: &Path,
    input: &[u8],
) -> ExecResult<Output> {
    let executable = compiled_executable_path(cfg, SANITIZERS[sanitizer_idx])
        .display()
        .to_string();
    if cfg.mutate_file {
        exec_target_filein(&executable, raw_profile_filepath, input)
    } else if cfg.mutate_args {
        exec_target_args(&executable, raw_profile_filepath, input)
    } else {
        exec_target_stdin(&executable, raw_profile_filepath, input)
    }
}

/// execute the target program with test input sent to stdin
fn exec_target_stdin(
    executable: &str,
    raw_profile_filepath: &Path,
    input: &[u8],
) -> ExecResult<Output> {
    let mut env_vars: Vec<(&str, &str)> =
        Vec::from([("LLVM_PROFILE_FILE", raw_profile_filepath.to_str().unwrap())]);
    #[cfg(target_os = "macos")]
    env_vars.push(("MallocNanoZone", "0"));
    let mut profile_target = Command::new(PathBuf::from(".").join(executable))
        .envs(env_vars)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("Running target executable {}\n{}", executable, e));

    let send_input = profile_target.stdin.take().unwrap();
    let mut send_input = BufWriter::new(send_input);

    send_input
        .write_all(input)
        .expect("sending input to instrumented target");
    let result = send_input.flush();

    std::mem::drop(send_input);

    let output = profile_target.wait_with_output().unwrap();

    if result.is_ok() && output.status.code().is_some() {
        ExecResult::Ok(output)
    } else {
        ExecResult::Err(output)
    }
}

/// execute the target program with test input sent via an input file
fn exec_target_filein(
    executable: &str,
    raw_profile_filepath: &Path,
    input: &[u8],
) -> ExecResult<Output> {
    let fname = format!("{}.mutation", current().name().unwrap());
    let mut f = BufWriter::new(std::fs::File::create(&fname).unwrap());
    f.write_all(input).unwrap();

    std::mem::drop(f);

    let mut env_vars: Vec<(&str, &str)> =
        Vec::from([("LLVM_PROFILE_FILE", raw_profile_filepath.to_str().unwrap())]);

    #[cfg(target_os = "macos")]
    env_vars.push(("MallocNanoZone", "0"));

    let profile_target = Command::new(executable)
        .envs(env_vars)
        .arg(&fname)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let result = profile_target.wait_with_output().unwrap();

    remove_file(fname).expect("removing input mutation file");

    if result.status.code().is_some() {
        ExecResult::Ok(result)
    } else {
        ExecResult::Err(result)
    }
}

/// execute the target program with test input sent via program arguments
pub fn exec_target_args(
    executable: &str,
    raw_profile_filepath: &Path,
    input: &[u8],
) -> ExecResult<Output> {
    let mut args: Vec<Vec<_>> = vec![];
    let mut cursor: Vec<_> = Vec::new();

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

    // windows OsString arguments are utf-16, so need to use from_wide()
    #[cfg(target_os = "windows")]
    let os_args: Vec<OsString> = args.iter().map(|a| OsStringExt::from_wide(a)).collect();

    let mut env_vars: Vec<(&str, &str)> =
        Vec::from([("LLVM_PROFILE_FILE", raw_profile_filepath.to_str().unwrap())]);
    #[cfg(target_os = "macos")]
    env_vars.push(("MallocNanoZone", "0"));

    let profile_target = Command::new(executable)
        .envs(env_vars)
        .args(os_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let output = profile_target.wait_with_output().unwrap();

    //if let Ok(out) = output {
    if output.status.code().is_some() {
        ExecResult::Ok(output)
    } else {
        ExecResult::Err(output)
    }
}
