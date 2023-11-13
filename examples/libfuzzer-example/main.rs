use std::fs::read_to_string;
use std::path::PathBuf;

use ecfuzz::config::Config;
use ecfuzz::corpus::{CorpusType, GraphCorpus};
use ecfuzz::execute::Exec;
use ecfuzz::grammar_tree::GraphTree;
use ecfuzz::mutator::Mutation;

/// Example grammar definition for a phone number and name sequence:
/// ```text
/// <args>=<digit><digit><digit> <digit><digit><digit> <digit><digit><digit><digit> <firstname> <lastname> <lastname>
/// ```
/// names will be read from a dictionary file stored in `./examples/libfuzzer-example/input/`
fn create_grammar_bytemap() -> Vec<u8> {
    let mut grammar_def = b"<args>=<digit><digit><digit> <digit><digit><digit> <digit><digit><digit><digit> <firstname> <lastname> <lastname>".to_vec();
    grammar_def.push(b'\n');
    for digit in 0..10 {
        grammar_def.append(&mut b"<digit>=".to_vec());
        grammar_def.append(&mut digit.to_string().as_bytes().to_vec());
        grammar_def.push(b'\n');
    }
    for line in read_to_string(PathBuf::from(
        "./examples/libfuzzer-example/input/firstname.dict",
    ))
    .expect("reading firstnames")
    .lines()
    {
        grammar_def.splice(grammar_def.len().., b"<firstname>=".to_vec());
        grammar_def.append(&mut line.as_bytes().to_vec());
        grammar_def.push(b'\n');
    }
    for line in read_to_string(PathBuf::from(
        "./examples/libfuzzer-example/input/lastname.dict",
    ))
    .expect("reading lastnames")
    .lines()
    {
        grammar_def.append(&mut b"<lastname>=".to_vec());
        grammar_def.append(&mut line.as_bytes().to_vec());
        grammar_def.push(b'\n');
    }

    grammar_def
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // config
    let mut cfg = Config::defaults();
    cfg.target_path = Vec::from([
        PathBuf::from("./examples/libfuzzer-example/example.c"),
        PathBuf::from("./libfuzzer-driver.cpp"),
    ]);
    cfg.iterations = 2_500;
    cfg.output_dir = PathBuf::from("./output/libfuzzer-example");
    cfg.load_env();
    cfg.seed = b"0".to_vec();

    // number generator and fuzzing engine
    let mut engine = Mutation::with_seed(cfg.dict_path.clone(), cfg.seed.clone(), cfg.multiplier);

    // load grammar bytemap into memory and construct graph
    let grammar_rawdata = create_grammar_bytemap();
    let arg_grammar_rawdata = Vec::new();
    let args_graph: Box<GraphTree> = Box::new(GraphTree::from(&arg_grammar_rawdata));
    let stdin_graph: Box<GraphTree> = Box::new(GraphTree::from(&grammar_rawdata));

    // current mutations and new crashes will be stored here
    let mut cov_corpus = CorpusType::Graph(GraphCorpus::new());
    let mut crash_corpus = CorpusType::Graph(GraphCorpus::new());

    // execution context: compile instrumented target from source,
    // and prepare threadpool for fuzzing
    let executor = Exec::new(&cfg);
    executor.exec_loop(
        &mut cov_corpus,
        &mut crash_corpus,
        &mut engine,
        Some(args_graph),
        Some(stdin_graph),
    );

    Ok(())
}
