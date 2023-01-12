use std::fs::remove_file;
use std::time::{Duration, Instant};

use ecfuzz::corpus::{Corpus, CorpusInput};
use ecfuzz::execute::{
    check_report_coverage, count_branch_total, exec_target, index_target_report, Config, Exec,
};
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

    // start some timers
    let mut cmd_timer: Instant;
    let mut exec_time = Duration::new(0, 0);
    let mut profile_time = Duration::new(0, 0);
    let mut cov_time = Duration::new(0, 0);
    let mut timer_start = Instant::now();

    let branch_count = count_branch_total(cfg, profdata)?;

    for i in 0..cfg.iterations + 1 {
        // create a string name for this iteration
        let i_padded = format!("{:0>8}", i);
        let profraw = format!("output/{}_id{:?}.profraw", i_padded, std::process::id(),);
        let profdata = format!("output/{}_id{:?}.profdata", i_padded, std::process::id(),);

        // mutate the input
        let idx = mutation.hashfunc() % cov_corpus.inputs.len();
        mutation.data = cov_corpus.inputs[idx].data.clone();
        mutation.mutate();

        cmd_timer = Instant::now();
        let caused_crash = exec_target(cfg, &profraw, &mutation.data)?;
        exec_time += cmd_timer.elapsed();

        if caused_crash {
            crash_corpus.add(CorpusInput {
                data: mutation.data.clone(),
                coverage: cov_corpus.inputs[i % cov_corpus.inputs.len()]
                    .coverage
                    .clone(),
            });
            //remove_file(&profraw)?;
            //continue;
        } else {
            // index the raw profile data
            cmd_timer = Instant::now();
            index_target_report(cfg, &profraw, &profdata).unwrap();
            profile_time += cmd_timer.elapsed();

            // generate JSON report from profile data
            cmd_timer = Instant::now();
            let coverage = check_report_coverage(cfg, &profdata).expect("getting report coverage");
            cov_time += cmd_timer.elapsed();

            // file cleanup
            remove_file(&profraw).expect("removing raw profile data");
            remove_file(&profdata).expect("removing coverage profile data");

            // if the report contains new coverate,
            // add both to the corpus as CorpusInput
            if !cov_corpus.total_coverage.is_superset(&coverage) {
                let corpus_entry = CorpusInput {
                    data: mutation.data.clone(),
                    coverage,
                };
                cov_corpus.add_and_distill_corpus(corpus_entry);
            }
        }

        // print some status info
        if i % cfg.iter_check == 0 && i > 0 {
            let mut max = 32;
            if mutation.data.len() < max {
                max = mutation.data.len();
            }
            println!(
                //"branch hits: {:>2}/{}  exec/s: {:.2}  ratio: {:.2}/{:.2}/{:.2}  inputs: {}  i: {:<4}  {}",
                "hits: {:>2}/{}  exec/s: {:.2}  inputs: {}  i: {:<4}  {}",
                cov_corpus.total_coverage.len(),
                branch_count,
                cfg.iter_check as f32 / (timer_start.elapsed().as_millis() as f32 / 1000.0),
                //exec_time.as_millis() as f32 / 1000.0,
                //profile_time.as_millis() as f32 / 1000.0,
                //cov_time.as_millis() as f32 / 1000.0,
                cov_corpus.inputs.len(),
                i,
                String::from_utf8_lossy(&mutation.data[0..max]),
            );
            exec_time = Duration::new(0, 0);
            profile_time = Duration::new(0, 0);
            cov_time = Duration::new(0, 0);
            timer_start = Instant::now();
        }
    }

    cov_corpus.save(&cfg.corpus_dir, "mutations", false)?;
    crash_corpus.save(&cfg.corpus_dir, "crashes", false)?;

    Ok(())
}

/// initialize fuzzing engine and run the main loop
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    // configure paths and initial state
    let cfg = Config::parse_args()?;
    let mut engine = Mutation::with_seed(cfg.dict_path.clone(), cfg.seed.clone());
    let mut cov_corpus = Corpus::new();

    // compile target
    Exec::initialize(&cfg)?;

    // initial profile paths
    let rawprof = "init.profraw";
    let profdata = "init.profdata";

    // check code coverage for seeded inputs
    println!("seeding...");
    for input in &cfg.seed_corpus {
        assert!(!input.is_empty());
        let _caused_crash = exec_target(&cfg, rawprof, input)?;
        index_target_report(&cfg, rawprof, profdata)?;

        let corpus_entry = CorpusInput {
            data: input.to_vec(),
            coverage: check_report_coverage(&cfg, profdata)?,
        };
        cov_corpus.add(corpus_entry);
    }
    let branch_count = count_branch_total(&cfg, profdata)?;

    println!(
        "branches hit by seed corpus: {:?}  total branches: {}",
        cov_corpus.total_coverage, branch_count
    );

    _main_loop(&cfg, &mut cov_corpus, &mut engine, profdata)?;

    Ok(())
}
