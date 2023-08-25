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
//! Examples of options that can be passed to the compiler (with clang+tools installed in `/opt/bin`):
//! ```bash
//! export CFLAGS="-O3 -mshstk -mllvm -polly -std=c17 -g -fcolor-diagnostics -fuse-ld=lld -L/opt/lib -D_FORTIFY_SOURCE=3 -fstack-protector-all -fcf-protection=full -fsanitize=memory,undefined,cfi -flto -fvisibility=hidden"
//! ```
//!
//! Further reading:
//! <https://clang.llvm.org/docs/ClangCommandLineReference.html>
//! <https://developers.redhat.com/articles/2022/06/02/use-compiler-flags-stack-protection-gcc-and-clang>

const CFLAGS_DEFAULTS: &str =
    "-O3 -mshstk -std=c17 -g -fcolor-diagnostics -fuse-ld=lld -fstack-protector-all";
// also see:
// <https://lldb.llvm.org/use/tutorial.html#starting-or-attaching-to-your-program>

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::OsString;
use std::fs::remove_file;
use std::io::{stdout, BufWriter, Write};
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
use serde::Deserialize;
use serde_json::Value as jsonValue;

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
    "leak",
    //"memory",
    "safe-stack",
    //"thread",
    "undefined",
];
#[cfg(not(debug_assertions))]
#[cfg(target_os = "macos")]
pub const SANITIZERS: &[&str] = &["address", "thread", "undefined"];
#[cfg(not(debug_assertions))]
#[cfg(target_os = "windows")]
pub const SANITIZERS: &[&str] = &["address", "undefined"];

#[cfg(debug_assertions)]
pub const SANITIZERS: &[&str] = &["undefined"];

pub struct Exec {
    pub cfg: Arc<Config>,
    //pub engine: Mutation,
}

pub enum ExecResult<Output> {
    Ok(Output),
    Err(Output),
}

#[derive(Deserialize, Debug)]
pub struct CovReport {
    pub branches: Vec<[u64; 9]>,
    //pub regions: Vec<[u64; 8]>,
}

#[derive(Deserialize, Debug)]
pub struct ReportFile {
    pub files: Vec<CovReport>,
    //pub functions: Vec<CovReport>,
}

fn compiled_executable_path(cfg: &Config, sanitizer: &str) -> String {
    cfg.output_dir
        .as_path()
        .join(format!("ecfuzz.{}-sanitized.out", sanitizer))
        .display()
        .to_string()
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

        // use a variety of available sanitizers when possible
        for sanitizer in SANITIZERS {
            let sanitizer_arg = format!("-fsanitize={}", sanitizer);

            let mut setup_args: Vec<String> = [
                "-o",
                &compiled_executable_path(&cfg, sanitizer),
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
            setup_args.push("-Wl,--whole-archive".to_string());
            for inc in &cfg.include {
                let mut include_string = inc.display().to_string();
                include_string.insert_str(0, "-I");
                setup_args.push(include_string);
            }
            setup_args.push("-Wl,--no-whole-archive".to_string());

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
        let profraw = PathBuf::from(format!(
            "output/{}.profraw",
            current().name().expect("getting thread name"),
        ));
        let profdata = PathBuf::from(format!(
            "output/{}.profdata",
            current().name().expect("getting thread name"),
        ));

        //let sanitizer_idx: usize = self.engine.hashfunc() % SANITIZERS.len();
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

        let cov = self
            .check_report_coverage(&profdata, sanitizer_idx)
            .unwrap();
        remove_file(&profdata).expect("removing coverage profile data");

        // if the program crashes during execution, code coverage checking may
        // yield an empty set. in this case the parent mutation coverage is used
        let new_coverage: HashSet<u64> = match output {
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
        /*
        let result = CorpusInput {
        data: test_input.data.to_owned(),
        coverage: new_coverage,
        lifetime: test_input.lifetime + 1,
        };
        (result, output)
        (test_input, output)
        */
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
        let save_corpus_dir = self.cfg.output_dir.join(Path::new("corpus")).to_path_buf();
        let save_crashes_dir = self.cfg.output_dir.join(Path::new("crashes")).to_path_buf();

        // worker thread pool
        let (sender, receiver) = channel::<(usize, CorpusInput, ExecResult<Output>)>();
        let num_cpus: usize = available_parallelism()?.into();
        let pool = ThreadPoolBuilder::new()
            .thread_name(|f| format!("ecfuzz-worker-{}", f))
            .num_threads(num_cpus)
            .build()
            .unwrap();
        assert!(num_cpus <= FUZZING_QUEUE_SIZE / 4);

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
                        log_new_coverage(&i, &corpus_entry);
                        // update corpus
                        cov_corpus.add_and_distill_corpus(corpus_entry);
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
                refresh_rate = (exec_rate / 24.0) as usize; // frames per second
                timer_start = Instant::now();
            } else if i % refresh_rate == 0 && refresh_rate > 0 && i <= self.cfg.iterations {
                let exec_rate =
                    refresh_rate as f64 / (timer_start.elapsed().as_micros() as f64 / 1e6);
                status = format!(
                    //"\rcoverage: {:>2}/{}  exec/s: {:<4.0}  corpus size: {:<4} unique crashes: {:<4} i: {:<8} {:<32}",
                    "\rcoverage: {:>5}/{:<5}  exec/s: {:<4.0}  corpus size: {:<4} unique crashes: {:<4} i: {:<8}",
                    cov_corpus.total_coverage.len(),
                    branch_count,
                    exec_rate,
                    cov_corpus.inputs.len(),
                    crash_corpus.inputs.len(),
                    i,
                    //String::from_utf8_lossy(&mutation.data.borrow()[0..min(32, mutation.data.borrow().len())]).replace("\n",""),
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

    /// count the number of code branches in the coverage file
    pub fn count_branch_total(
        &mut self,
        sanitizer_idx: usize,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let profraw = PathBuf::from(format!(
            "output/{}.profraw",
            current().name().expect("getting thread name"),
        ));
        let profdata = PathBuf::from(format!(
            "output/{}.profdata",
            current().name().expect("getting thread name"),
        ));
        let _output = exec_target(&self.cfg, 0, &profraw, b"");

        self.index_target_report(&profraw, &profdata).unwrap();
        remove_file(profraw).expect("removing raw profile data");

        let report: ReportFile = self.read_report(&profdata, sanitizer_idx)?;
        remove_file(profdata).expect("removing coverage profile data");

        let mut n: u64 = 0;
        for file in report.files {
            //for file in report.functions {
            for _branch in file.branches {
                //for _branch in file.regions {
                n += 1
            }
        }
        #[cfg(debug_assertions)]
        println!("total branches hit: {}", n);
        Ok(n)
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
            "-o".to_string(),
            profile_filepath.display().to_string(),
        ];
        let prof_merge_result = Command::new(&self.cfg.llvm_profdata_path)
            .args(prof_merge_args)
            .output()
            .expect("merge profile command");
        if !prof_merge_result.status.success() {
            panic!(
                "Could not merge profile data. {}",
                String::from_utf8_lossy(&prof_merge_result.stderr)
            )
        }
        Ok(())
    }

    /// deserialized indexed report data, and return branch coverage
    fn read_report(
        &self,
        profile_filepath: &PathBuf,
        sanitizer_idx: usize,
    ) -> Result<ReportFile, Box<dyn std::error::Error>> {
        let mut prof_report_args: Vec<String> = [
            "export",
            "--instr-profile",
            &profile_filepath.display().to_string(),
            "--ignore-filename-regex=libfuzz-driver.cpp|fuzz.cpp", //"-check-binary-ids",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        prof_report_args.push("--object".to_string());
        prof_report_args.push(compiled_executable_path(
            &self.cfg,
            SANITIZERS[sanitizer_idx],
        ));
        let prof_report_result = Command::new(&self.cfg.llvm_cov_path)
            .args(&prof_report_args)
            .output()
            .unwrap();
        let prof_report_raw = prof_report_result.stdout;
        if prof_report_raw.is_empty() {
            panic!(
                "empty profdata: {:#?}\nargs: {:?}\n\n{}",
                profile_filepath,
                prof_report_args,
                String::from_utf8_lossy(&prof_report_result.stderr)
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
        &self,
        profile_filepath: &PathBuf,
        sanitizer_idx: usize,
    ) -> Result<HashSet<u64>, Box<dyn std::error::Error>> {
        let report: ReportFile = self.read_report(profile_filepath, sanitizer_idx)?;

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
}

/// log coverage increases to stdout
fn log_new_coverage(i: &usize, new: &CorpusInput) {
    println!(
        "\r\x1b[32mNew coverage!\x1b[0m execs: {}  updating inputs... {:<50}{:?}\n",
        i, "", new
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

/// log known crashes to stderr
fn log_crash_known(_stderr: &[u8], i: &usize, _crash_corpus: &Corpus) {
    eprintln!(
        //"\r\x1b[91mKnown crash!\x1b[0m execs: {:<80}\n{}",
        "\r\x1b[91mKnown crash!\x1b[0m execs: {:<80}",
        i,
        //String::from_utf8_lossy(stderr),
    );
}

/// execute the target program with a new test input either via an input file,
/// command line arguments, or by sending to the target stdin, as defined in
/// Config
fn exec_target(
    cfg: &Config,
    sanitizer_idx: usize,
    raw_profile_filepath: &PathBuf,
    input: &[u8],
) -> ExecResult<Output> {
    let executable = compiled_executable_path(cfg, SANITIZERS[sanitizer_idx]);
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
    raw_profile_filepath: &PathBuf,
    input: &[u8],
) -> ExecResult<Output> {
    let mut profile_target = Command::new(PathBuf::from(".").join(executable))
        .env("LLVM_PROFILE_FILE", raw_profile_filepath)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| panic!("Running target executable {}", executable));

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
fn exec_target_filein(
    executable: &str,
    raw_profile_filepath: &PathBuf,
    input: &[u8],
) -> ExecResult<Output> {
    let fname = format!("{}.mutation", current().name().unwrap());
    let mut f = BufWriter::new(std::fs::File::create(&fname).unwrap());
    f.write_all(input).unwrap();

    std::mem::drop(f);

    let profile_target = Command::new(executable)
        .env("LLVM_PROFILE_FILE", raw_profile_filepath)
        //.args(["--mutation-file", &fname])
        .arg(&fname)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let result = profile_target.wait_with_output();

    remove_file(fname).expect("removing input mutation file");

    if let Ok(res) = result {
        ExecResult::Ok(res)
    } else {
        ExecResult::Err(result.unwrap())
    }
}

/// execute the target program with test input sent via program arguments
pub fn exec_target_args(
    executable: &str,
    raw_profile_filepath: &PathBuf,
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

    let profile_target = Command::new(executable)
        .env("LLVM_PROFILE_FILE", raw_profile_filepath)
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
