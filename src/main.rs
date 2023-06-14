use std::collections::HashSet;
use std::fs::{create_dir, remove_file};
use std::path::PathBuf;
use std::process::id;
//use std::time::{Duration, Instant};
use std::time::Instant;

use ecfuzz::corpus::Corpus;
use ecfuzz::execute::{count_branch_total, Config, Exec, ExecResult};
use ecfuzz::mutator::Mutation;

/// main loop:
/// send input to target, read the coverage resulting from the input, and
/// update the corpus with inputs yielding new coverage
pub fn _main_loop(
    cfg: &Config,
    cov_corpus: &mut Corpus,
    mutation: &mut Mutation,
    profdata: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // crashlog
    let mut crash_corpus = Corpus::new();
    let branch_count = count_branch_total(cfg, profdata)?;
    let outdir = PathBuf::from("output/mutations");
    let crashdir = PathBuf::from("output/crashes");
    let profraw = format!("output/{}.profraw", id());
    let profdata = format!("output/{}.profdata", id());
    create_dir(&outdir).unwrap_or_default();

    let mut timer_start = Instant::now();

    for i in 0..cfg.iterations + 1 {
        // mutate the input
        let idx = mutation.hashfunc() % cov_corpus.inputs.len();
        mutation.data = cov_corpus.inputs[idx].data.clone();
        mutation.mutate();

        let (corpus_entry, result) = Exec::trial(
            cfg,
            &profraw,
            &profdata,
            &mutation.data,
            cov_corpus.inputs[idx].file_stem.clone(),
            cov_corpus.inputs[idx].file_ext.clone(),
            cov_corpus.inputs[idx].lifetime,
        );

        // if the report contains new coverage, add to corpus as CorpusInput
        match result {
            ExecResult::Ok(_output) => {
                if !cov_corpus
                    .total_coverage
                    .is_superset(&corpus_entry.coverage)
                {
                    corpus_entry.serialize(&outdir).unwrap();
                    cov_corpus.add_and_distill_corpus(corpus_entry.clone());
                    println!(
                        "\n\x1b[32mNew coverage hit!\x1b[0m execs: {}\tupdating inputs... {}\n",
                        i, cov_corpus
                    );
                } else {
                    // file cleanup
                    remove_file(&profraw).expect("removing raw profile data");
                    remove_file(&profdata).expect("removing coverage profile data");
                }
            }
            ExecResult::Err(output) => {
                if !crash_corpus.total_coverage.is_superset(
                    &corpus_entry
                        .coverage
                        .union(&cov_corpus.inputs[idx].coverage)
                        .map(|i| i.to_owned())
                        .collect::<HashSet<u64>>(),
                ) {
                    crash_corpus.add_and_distill_corpus(corpus_entry);
                    eprintln!(
                        "\n{}\x1b[31mNew crash!\x1b[0m execs: {}\t updating crash log... {}\n",
                        String::from_utf8_lossy(&output.stderr),
                        i,
                        &crash_corpus
                    );
                } else {
                    // file cleanup
                    remove_file(&profraw).expect("removing raw profile data");
                    remove_file(&profdata).expect("removing coverage profile data");
                    eprintln!(
                        "\n{}\x1b[91mKnown crash!\x1b[0m execs: {}{}\n",
                        String::from_utf8_lossy(&output.stderr),
                        i,
                        crash_corpus
                    );
                    if corpus_entry.coverage.is_empty() {
                        eprintln!(
                            "Error: could not read coverage from crash! See output from sanitizer"
                        );
                    }
                }
            }
        }

        // print some status info
        if i % cfg.iter_check == 0 && i > 0 {
            let mut max = 32;
            if mutation.data.len() < max {
                max = mutation.data.len();
            }
            println!(
                "coverage: {:>2}/{}  exec/s: {:.2}  inputs: {}  new crashes: {}  i: {:<4}  {}",
                cov_corpus.total_coverage.len(),
                branch_count,
                cfg.iter_check as f32 / (timer_start.elapsed().as_millis() as f32 / 1000.0),
                cov_corpus.inputs.len(),
                crash_corpus.inputs.len(),
                i,
                String::from_utf8_lossy(&mutation.data[0..max]),
            );
            timer_start = Instant::now();
        }
    }
    cov_corpus.save(outdir).unwrap();
    crash_corpus.save(crashdir).unwrap();

    Ok(())
}

/// initialize fuzzing engine and run the main loop
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    // configure paths and initial state
    let cfg = Config::parse_args()?;
    let mut engine = Mutation::with_seed(cfg.dict_path.clone(), cfg.seed.clone(), cfg.multiplier);
    let mut cov_corpus = Corpus::new();

    // compile target
    Exec::initialize(&cfg)?;

    // coverage profile paths
    println!("seeding...");
    //let profraw = &format!("output/{}.profraw", id());
    let profdata = &format!("output/{}.profdata", id());

    // check code coverage for initial corpus inputs
    for filepath in &cfg.corpus_files {
        cov_corpus
            .load(&cfg, filepath, false)
            .expect("loading corpus from file");
    }
    for filepath in &cfg.corpus_dirs {
        cov_corpus
            .load(&cfg, filepath, true)
            .expect("loading corpus from directory");
    }

    let branch_count = count_branch_total(&cfg, profdata)?;

    println!(
        "branches hit by seed corpus: {:?}  total branches: {}",
        cov_corpus.total_coverage, branch_count
    );

    _main_loop(&cfg, &mut cov_corpus, &mut engine, profdata)?;

    Ok(())
}
