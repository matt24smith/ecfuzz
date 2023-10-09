use std::env::temp_dir;
use std::fs::read_to_string;
use std::io::Write;
use std::path::{Path, PathBuf};

use ecfuzz::config::Config;
use ecfuzz::corpus::Corpus;
use ecfuzz::execute::Exec;
use ecfuzz::grammar_tree::GrammarNode;
use ecfuzz::mutator::Mutation;

fn create_grammar_file(p: &Path) -> Result<(), ()> {
    let mut grammar_def = b"<args>=<digit><digit><digit> <digit><digit><digit> <digit><digit><digit> <firstname> <lastname> <lastname>".to_vec();
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
        //grammar_def.append(&mut b"<firstname>=".to_vec());
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

    let mut grammar_file = std::fs::File::create(p).expect("creating grammar file");
    grammar_file
        .write_all(&grammar_def)
        .expect("writing to grammar file");

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // sets clang compiler and llvm tools paths to default settings
    let mut cfg = Config::defaults();
    cfg.target_path = Vec::from([
        PathBuf::from("./examples/libfuzzer-example/example.c"),
        PathBuf::from("./libfuzzer-driver.cpp"),
    ]);
    cfg.iterations = 50_000;
    cfg.output_dir = PathBuf::from("./output/libfuzzer-example");
    cfg.load_env();

    let grammar_path = temp_dir().join("tmp.grammar");
    //cfg.run_arg_grammar = Some(grammar_path.clone());
    create_grammar_file(&grammar_path).unwrap();
    let print_tree = GrammarNode::from_file(&grammar_path);
    cfg.grammar = Some(grammar_path);

    println!("{}", print_tree.display(None));

    // mutation engine
    let mut engine = Mutation::with_seed(cfg.dict_path.clone(), cfg.seed.clone(), cfg.multiplier);

    // execution context: compile instrumented target from source,
    // and prepare threadpool for fuzzing
    let mut executor = Exec::new(cfg).expect("preparing execution context");

    // load corpus into memory
    // note: GrammarNode may instead be used here for grammar tree generative
    // fuzzing instead of genetic fuzzing
    let mut corpus = Corpus::new();
    /*
    for filepath in &executor.cfg.corpus_files {
    corpus.append(&mut Corpus::load(filepath).expect("reading corpus file"))
    }
    for filepath in &executor.cfg.corpus_dirs {
    corpus.append(&mut Corpus::load(filepath).expect("reading corpus dir"))
    }
    */
    // run the fuzzer in a loop
    executor
        ._main_loop(&mut corpus, &mut engine)
        .expect("executing main loop");

    Ok(())
}
