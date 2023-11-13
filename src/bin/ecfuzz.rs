use ecfuzz::config::Config;
use ecfuzz::corpus::{BytesCorpus, CorpusType};
use ecfuzz::execute::Exec;
use ecfuzz::grammar_tree::GraphTree;
use ecfuzz::mutator::Mutation;

fn main() {
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
    std::env::set_current_dir(&cfg.output_dir).expect("setting current directory to output_dir");

    // load initial corpus into memory
    let mut corpus = BytesCorpus::new();
    for filepath in cfg.corpus_files.iter().chain(cfg.corpus_dirs.iter()) {
        corpus.append(&mut BytesCorpus::load(filepath).expect("reading corpus"))
    }
    let mut cov_corpus = CorpusType::Bytes(corpus);
    let mut crash_corpus = CorpusType::Bytes(BytesCorpus::new());

    // mutation engine
    let mut engine = Mutation::with_seed(cfg.dict_path.clone(), cfg.seed.clone(), cfg.multiplier);

    // note: GraphTree may instead be used instead for graph-based
    // mutations instead of binary mutations
    let graph_stdin: Option<Box<GraphTree>> = if cfg.run_arg_grammar.is_some() {
        Some(Box::new(GraphTree::from_file(
            cfg.run_arg_grammar.as_ref().unwrap(),
        )))
    } else {
        None
    };
    let graph_args: Option<Box<GraphTree>> = if cfg.grammar.is_some() {
        Some(Box::new(GraphTree::from_file(
            cfg.grammar.as_ref().unwrap(),
        )))
    } else {
        None
    };

    // compile and instrument target
    let executor = Exec::new(&cfg);
    executor.exec_loop(
        &mut cov_corpus,
        &mut crash_corpus,
        &mut engine,
        graph_args,
        graph_stdin,
    );
}
