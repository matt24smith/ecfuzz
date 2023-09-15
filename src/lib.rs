#![doc = include_str!("../readme.md")]

pub mod config;

pub mod corpus;

pub mod execute;

pub mod mutator;

use std::error::Error;

use crate::config::Config;
use crate::corpus::Corpus;
use crate::execute::Exec;
use crate::mutator::Mutation;

pub fn begin() -> Result<(), Box<dyn Error>> {
    // configure paths and initial state
    let mut cfg: Config = Config::parse_args().expect("parsing config");
    cfg.load_env();
    let mut cov_corpus = Corpus::new();

    let ch_dir = &cfg.output_dir.clone();

    println!("setting execution directory: {}\n", ch_dir.display());
    std::env::set_current_dir(ch_dir)?;

    // compile target
    let mut engine = Mutation::with_seed(cfg.dict_path.clone(), cfg.seed.clone(), cfg.multiplier);
    let mut executor = Exec::initialize(cfg).expect("preparing execution context");

    // load corpus into memory
    for filepath in &executor.cfg.corpus_files {
        cov_corpus.append(Corpus::load(filepath).expect("reading corpus file"))
    }
    for filepath in &executor.cfg.corpus_dirs {
        cov_corpus.append(Corpus::load(filepath).expect("reading corpus dir"))
    }

    // coverage profile paths
    println!("seeding {} inputs...", cov_corpus.inputs.len());

    // check initial corpus coverage
    cov_corpus.initialize(&mut executor);

    println!(
        "branches hit by initial corpus: {}/{}\n{:?}",
        cov_corpus.total_coverage.len(),
        executor
            .count_branch_total(0)
            .expect("checking branch count"),
        cov_corpus
    );

    executor
        ._main_loop(&mut cov_corpus, &mut engine)
        .expect("executing main loop");

    Ok(())
}
