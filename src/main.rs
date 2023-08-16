use std::cmp::min;
use std::collections::HashMap;
use std::error::Error;
use std::fs::create_dir;
use std::io::{stdout, Write};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::mpsc::channel;
use std::thread::available_parallelism;
use std::time::Instant;

use rayon::ThreadPoolBuilder;

use ecfuzz::config::Config;
use ecfuzz::corpus::{Corpus, CorpusInput};
use ecfuzz::execute::{Exec, ExecResult};
use ecfuzz::mutator::Mutation;

/// number of mutations that will be queued for fuzzing before checking results
const FUZZING_QUEUE_SIZE: usize = 256;

/// log coverage increases to stdout
fn log_new_coverage(i: &usize, cov_corpus: &Corpus) {
    println!(
        "\r\x1b[32mNew coverage!\x1b[0m execs: {}  updating inputs... {:<50}{}\n",
        i, "", cov_corpus
    );
}

/// log new crashes to stderr
fn log_crash_new(stderr: &[u8], i: &usize, crash_corpus: &Corpus) {
    eprintln!(
        "\r\x1b[31mNew crash!\x1b[0m execs: {}  updating crash log...{:<50}{}\n{}",
        i,
        "",
        &crash_corpus,
        String::from_utf8_lossy(stderr)
    );
}

/// log known crashes to stderr
fn log_crash_known(stderr: &[u8], i: &usize, _crash_corpus: &Corpus) {
    eprintln!(
        "\r\x1b[91mKnown crash!\x1b[0m execs: {:<80}\n{}",
        i,
        String::from_utf8_lossy(stderr),
    );
}

/// If the fuzz execution result for a given mutation yielded new coverage,
/// add it to the cov_corpus.
/// If the mutation yielded a crash with new coverage, add it to the crash_corpus.
/// Corpus will be saved to outdir, crashes are logged to crashdir.
fn handle_fuzzed_result(
    corpus_entry: CorpusInput,
    cov_corpus: &mut Corpus,
    crash_corpus: &mut Corpus,
    result: ExecResult<Output>,
    outdir: &Path,
    crashdir: &Path,
    i: &usize,
) {
    match result {
        // if the report contains new coverage, add to corpus as CorpusInput
        ExecResult::Ok(_output) => {
            if !cov_corpus
                .total_coverage
                .is_superset(&corpus_entry.coverage)
            {
                // update corpus
                cov_corpus.add_and_distill_corpus(corpus_entry.clone());
                cov_corpus
                    .save(outdir.to_path_buf())
                    .expect("saving corpus to output directory");

                // print updated corpus
                log_new_coverage(i, cov_corpus);
            }
        }
        // if the report crashed, try to check the coverage or fallback to
        // parent coverage
        ExecResult::Err(output) => {
            if !crash_corpus
                .total_coverage
                .is_superset(&corpus_entry.coverage)
            {
                // update corpus
                crash_corpus.add_and_distill_corpus(corpus_entry);
                crash_corpus
                    .save(crashdir.to_path_buf())
                    .expect("saving crash corpus");

                // print updated corpus
                log_crash_new(&output.stderr, i, crash_corpus);
            } else {
                log_crash_known(&output.stderr, i, crash_corpus);
                if corpus_entry.coverage.is_empty() {
                    eprintln!(
                        "Error: could not read coverage from crash! See output from sanitizer"
                    );
                }
            }
        }
    }
}

/// main loop:
/// send input to target, read the coverage resulting from the input, and
/// update the corpus with inputs yielding new coverage
pub fn _main_loop(
    exec: Exec,
    cov_corpus: &mut Corpus,
    mutation: &mut Mutation,
) -> Result<(), Box<dyn Error>> {
    // crashlog
    let mut crash_corpus = Corpus::new();
    let branch_count = exec.count_branch_total()?;
    let outdir = PathBuf::from("output/mutations");
    let crashdir = PathBuf::from("output/crashes");
    create_dir(&outdir).unwrap_or_default();

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

    for i in 0..exec.cfg.iterations + FUZZING_QUEUE_SIZE {
        // mutate the input
        if i < exec.cfg.iterations - FUZZING_QUEUE_SIZE {
            let idx = mutation.hashfunc() % cov_corpus.inputs.len();
            mutation.data = cov_corpus.inputs[idx].data.clone();
            mutation.mutate();

            let mutation_trial = CorpusInput {
                data: mutation.data.clone(),
                coverage: cov_corpus.inputs[idx].coverage.clone(),
                lifetime: cov_corpus.inputs[idx].lifetime,
            };

            let lifetime = cov_corpus.inputs[idx].lifetime;
            let sender = sender.clone();
            let exec2 = exec.clone();
            pool.spawn_fifo(move || {
                let (corpus_entry, result) = exec2.trial(&mutation_trial, lifetime);
                sender
                    .send((i, corpus_entry, result))
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
        if i <= exec.cfg.iterations {
            let (n, corpus_entry_unordered, result_unordered) = receiver.recv()?;
            finished_map.insert(n, (corpus_entry_unordered, result_unordered));
        }

        // allow some completed fuzz jobs to gather in the finished queue
        if i < FUZZING_QUEUE_SIZE * 2 {
            continue;
        }

        // get completed fuzz jobs starting at the earliest index
        let (corpus_entry, result) = finished_map
            .remove(&(i - FUZZING_QUEUE_SIZE * 2))
            .expect("retrieving fuzz job results");

        handle_fuzzed_result(
            corpus_entry,
            cov_corpus,
            &mut crash_corpus,
            result,
            &outdir,
            &crashdir,
            &i,
        );

        // print some status info
        if i % exec.cfg.iter_check == 0 && 0 < i && i <= exec.cfg.iterations {
            assert!(timer_start.elapsed().as_millis() > 0);
            let exec_rate =
                exec.cfg.iter_check as f64 / (timer_start.elapsed().as_micros() as f64 / 1e6);
            status = format!(
                "\rcoverage: {:>2}/{}  exec/s: {:<4.0}  corpus size: {:<4} unique crashes: {:<4} i: {:<8}  {}",
                cov_corpus.total_coverage.len(),
                branch_count,
                exec_rate,
                cov_corpus.inputs.len(),
                crash_corpus.inputs.len(),
                i,
                String::from_utf8_lossy(&mutation.data[0..min(32, mutation.data.len())]),
                );
            print!("{}", status);
            stdout().flush().unwrap();
            timer_start = Instant::now();
        }
    }
    println!("{}", status);

    cov_corpus.save(outdir).unwrap();
    crash_corpus.save(crashdir).unwrap();

    assert!(finished_map.is_empty());

    Ok(())
}

/// initialize fuzzing engine and run the main loop
pub fn main() -> Result<(), Box<dyn Error>> {
    // configure paths and initial state
    let mut cfg: Config = Config::parse_args()?;
    cfg.load_env();
    let mut engine = Mutation::with_seed(cfg.dict_path.clone(), cfg.seed.clone(), cfg.multiplier);
    let mut cov_corpus = Corpus::new();

    // compile target
    let executor = Exec::initialize(cfg).expect("preparing execution context");

    // coverage profile paths
    println!("seeding...");

    // load corpus into memory
    for filepath in &executor.cfg.corpus_files {
        cov_corpus.append(Corpus::load(filepath).expect("reading corpus file"))
    }
    for filepath in &executor.cfg.corpus_dirs {
        cov_corpus.append(Corpus::load(filepath).expect("reading corpus dir"))
    }

    // check initial corpus coverage
    cov_corpus.initialize(&executor);

    println!(
        "branches hit by initial corpus: {}/{}\n{}",
        cov_corpus.total_coverage.len(),
        executor.count_branch_total()?,
        cov_corpus
    );

    _main_loop(executor, &mut cov_corpus, &mut engine)?;

    Ok(())
}
