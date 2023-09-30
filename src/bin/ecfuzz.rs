use ecfuzz::config::Config;
use ecfuzz::corpus::Corpus;
use ecfuzz::execute::Exec;
use ecfuzz::mutator::Mutation;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // read configuration from command line arguments,
    // such as fuzz target filepath, compiler path, input files, etc.
    // see 'ecfuzz --help' for more info
    let mut cfg: Config = Config::parse_args().expect("parsing config");

    // The following environment options may be used to set paths to llvm tools,
    // overriding configured settings
    //  - ECFUZZ_CC_PATH
    //  - ECFUZZ_LLVM_COV_PATH
    //  - ECFUZZ_LLVM_PROFDATA_PATH
    cfg.load_env();

    // change directory to output_dir
    std::env::set_current_dir(&cfg.output_dir)?;

    // mutation engine
    let mut engine = Mutation::with_seed(cfg.dict_path.clone(), cfg.seed.clone(), cfg.multiplier);

    // execution context: compile instrumented target from source,
    // and prepare threadpool for fuzzing
    let mut executor = Exec::new(cfg).expect("preparing execution context");

    // load corpus into memory
    // note: GrammarNode may instead be used here for grammar tree generative
    // fuzzing instead of genetic fuzzing
    let mut corpus = Corpus::new();
    for filepath in &executor.cfg.corpus_files {
        corpus.append(&mut Corpus::load(filepath).expect("reading corpus file"))
    }
    for filepath in &executor.cfg.corpus_dirs {
        corpus.append(&mut Corpus::load(filepath).expect("reading corpus dir"))
    }

    // run the fuzzer in a loop
    executor
        ._main_loop(&mut corpus, &mut engine)
        .expect("executing main loop");

    Ok(())
}
