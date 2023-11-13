//! Maintain corpus inputs as they evolve with each generation of mutations

use std::cmp::{max, min};
use std::collections::BTreeSet;
use std::fs::{create_dir_all, metadata, read, read_dir, remove_file, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;

use crate::config::Config;
use crate::execute::{trial, Exec, ExecResult, SANITIZERS};
use crate::grammar_tree::{GraphMutation, GraphTree};

/// each test input sent to the target program contains the byte vector
/// to be tested, as well as the resulting branch coverage set and some metadata
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct BytesInput {
    pub data: Vec<u8>,
    pub args: Vec<u8>,
    pub coverage: BTreeSet<u128>,
}

#[derive(Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct GraphInput {
    pub args: GraphMutation,
    pub encoding: GraphMutation,
    pub coverage: BTreeSet<u128>,
}

#[derive(Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum InputType {
    Bytes(BytesInput),
    Graph(GraphInput),
}

/// corpus contains a vector of corpus inputs, and the total branch coverage set
pub struct BytesCorpus {
    pub inputs: Vec<BytesInput>,
    pub total_coverage: BTreeSet<u128>,
}

/// corpus contains a vector of corpus inputs, and the total branch coverage set
pub struct GraphCorpus {
    pub inputs: Vec<GraphInput>,
    pub total_coverage: BTreeSet<u128>,
}

pub enum CorpusType {
    Bytes(BytesCorpus),
    Graph(GraphCorpus),
}

pub trait CorpusOps {
    fn add(&mut self, new_input: InputType);

    /// add a new entry into the corpus.
    /// Each time an entry is added, the corpus will be distilled:
    /// all corpus entries with branch coverage that is a
    /// subset of the newest coverage will be pruned
    fn add_and_distill_corpus(&mut self, new: InputType);

    // append corpus entries to the corpus file.
    // a .coverage file will also be created with branch coverage info
    //fn save(&self, output_dir: &Path) -> std::io::Result<()>;

    /// get indices of inputs with matching coverage to the new input
    fn check_matching_coverage_idx(&self, new: &InputType) -> Vec<usize>;

    fn check_matching_and_sort(&mut self, new: InputType);
}

impl BytesInput {
    /// Initialize a new BytesInput with empty values
    pub fn empty() -> Self {
        BytesInput {
            data: Vec::new(),
            args: Vec::new(),
            coverage: BTreeSet::new(),
        }
    }

    /// Check the coverage of this input with all sanitizers and test for regression
    pub fn check_sanitizers_coverages(
        &self,
        cfg: &Arc<Config>,
    ) -> Vec<(ExecResult<Output>, BTreeSet<u128>)> {
        let mut results_coverages: Vec<(ExecResult<Output>, BTreeSet<u128>)> = Vec::new();
        for san_idx in 0..SANITIZERS.len() {
            let (result, new_cov) = trial(cfg, &self.args, &self.data, san_idx);
            results_coverages.push((result, new_cov))
        }
        results_coverages
    }

    /// Recursively remove bytes from a test input while coverage, stdout,
    /// and stderr remain unchanged.
    /// Very slow for large inputs.
    /// Assumes coverage data is already up to date.
    pub fn minimize_input(&mut self, exec: &Exec) {
        let start_bytesize = self.data.len();
        let chunk_size = 2_usize.pow(max(1, (start_bytesize as i64 / 64) - 2).ilog2());

        // compute hash of output stdout, stderr, and exit code for each sanitizer
        let unmodified_hashes: Vec<(ExecResult<Output>, BTreeSet<u128>)> =
            self.check_sanitizers_coverages(&exec.cfg);

        for byte_idx in (1..self.data.len() - chunk_size + 1)
            .step_by(chunk_size)
            .rev()
        {
            // remove bytes from test input
            let mut minified_input = self.clone();
            for _ in 0..chunk_size {
                minified_input.data.remove(byte_idx);
            }

            let test_hashes = minified_input.check_sanitizers_coverages(&exec.cfg);
            let hashes_match = unmodified_hashes
                .iter()
                .zip(test_hashes.iter())
                .filter(|&(a, b)| {
                    a.1 == b.1
                        && match (&a.0, &b.0) {
                            (ExecResult::Ok(..), ExecResult::Ok(..)) => true,
                            (ExecResult::Err(..), ExecResult::Err(..)) => true,
                            (
                                ExecResult::NonTerminatingErr(..),
                                ExecResult::NonTerminatingErr(..),
                            ) => true,
                            (ExecResult::CoverageError(..), ExecResult::CoverageError(..)) => true,
                            _ => false,
                        }
                })
                .count()
                == unmodified_hashes.len();

            // if output remains unchanged, mutate the corpus entry
            if hashes_match {
                for _ in 0..chunk_size {
                    self.data.remove(byte_idx);
                }
            }
        }
        let bytes_removed = start_bytesize - self.data.len();
        println!(
            "  removed {:4} bytes from input:\n{}",
            bytes_removed,
            String::from_utf8_lossy(&self.data[0..min(64, self.data.len())]),
        );
    }

    /// Serialize the test input to an output directory for logging.
    /// Two files will be created: a .mutation file containing the mutated
    /// input, and a .coverage file containing the set of code branches hit
    pub fn serialize(
        &self,
        mutation_dir: &Path,
        coverage_dir: &Path,
        output_name: &str,
    ) -> Result<(), std::io::Error> {
        let hit_str = self
            .coverage
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<String>>()
            .join("\n");

        #[cfg(debug_assertions)]
        assert!(mutation_dir.is_dir());
        #[cfg(debug_assertions)]
        assert!(coverage_dir.is_dir());

        create_dir_all(mutation_dir).unwrap();
        create_dir_all(coverage_dir).unwrap();

        let mut fpath = mutation_dir.join(output_name);
        fpath.set_extension("mutation");

        let mut cov_path = coverage_dir.join(output_name);
        cov_path.set_extension("coverage");

        File::create(&fpath)
            .unwrap_or_else(|e| panic!("{}: {}", e, fpath.display()))
            .write_all(&self.data)
            .expect("writing mutation to file");
        File::create(cov_path.clone())
            .unwrap_or_else(|_| panic!("creating cov_path: {}", cov_path.to_str().unwrap()))
            .write_all(hit_str.as_bytes())
            .expect("writing mutation coverage to file");

        Ok(())
    }
}

impl GraphInput {
    /// Serialize the test input to an output directory for logging.
    /// Two files will be created: a .mutation file containing the mutated
    /// input, and a .coverage file containing the set of code branches hit
    pub fn serialize(
        &self,
        mutation_dir: &Path,
        coverage_dir: &Path,
        output_name: &str,
        tree: &GraphTree,
    ) -> Result<(), std::io::Error> {
        let hit_str = self
            .coverage
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<String>>()
            .join("\n");

        #[cfg(debug_assertions)]
        assert!(mutation_dir.is_dir());
        #[cfg(debug_assertions)]
        assert!(coverage_dir.is_dir());

        create_dir_all(mutation_dir).unwrap();
        create_dir_all(coverage_dir).unwrap();

        let mut fpath = mutation_dir.join(output_name);
        fpath.set_extension("mutation");

        let mut cov_path = coverage_dir.join(output_name);
        cov_path.set_extension("coverage");

        File::create(&fpath)
            .unwrap_or_else(|e| panic!("{}: {}", e, fpath.display()))
            .write_all(&tree.decode(&self.encoding))
            .expect("writing mutation to file");
        File::create(cov_path.clone())
            .unwrap_or_else(|_| panic!("creating cov_path: {}", cov_path.to_str().unwrap()))
            .write_all(hit_str.as_bytes())
            .expect("writing mutation coverage to file");

        Ok(())
    }
}

impl InputType {
    pub fn serialize(
        &self,
        mutation_dir: &Path,
        coverage_dir: &Path,
        output_name: &str,
        tree: Option<&GraphTree>,
    ) -> Result<(), std::io::Error> {
        match self {
            InputType::Bytes(i) => i.serialize(mutation_dir, coverage_dir, output_name),
            InputType::Graph(i) => i.serialize(
                mutation_dir,
                coverage_dir,
                output_name,
                tree.expect("serializing graph mutation requires GraphTree argument"),
            ),
        }
    }
}

impl BytesCorpus {
    /// append the inputs of another corpus into this corpus, consuming it
    pub fn append(&mut self, corpus: &mut BytesCorpus) {
        for input in corpus.inputs.drain(..) {
            self.inputs.push(input);
        }
        self.total_coverage.extend(&corpus.total_coverage);
    }

    /// Load corpus inputs from lines in a file
    pub fn load_corpus_lines(corpus_path: &PathBuf) -> std::io::Result<BytesCorpus> {
        assert!(!corpus_path.is_dir());

        let f: Vec<u8> = read(corpus_path).expect("couldn't find corpus path!");
        let inputs = f
            .split(|x| x == &b'\n')
            .map(|x| x.to_vec())
            .filter(|x| !x.is_empty())
            .map(|x| BytesInput {
                data: x,
                args: Vec::new(),
                coverage: BTreeSet::new(),
            })
            .collect::<Vec<BytesInput>>();

        Ok(BytesCorpus {
            inputs,
            total_coverage: BTreeSet::new(),
        })
    }

    /// Load a single corpus input from a file
    pub fn load_corpus_file(corpus_path: &PathBuf) -> std::io::Result<BytesCorpus> {
        assert!(!corpus_path.is_dir());

        let f: Vec<u8> = read(corpus_path).expect("couldn't find corpus path!");
        let c = BytesInput {
            data: f,
            args: Vec::new(),
            coverage: BTreeSet::new(),
        };

        Ok(BytesCorpus {
            inputs: vec![c],
            total_coverage: BTreeSet::new(),
        })
    }

    /// load a corpus of input files from a directory path
    pub fn load_corpus_dir(corpus_dir: &PathBuf) -> std::io::Result<BytesCorpus> {
        let filepaths: Vec<PathBuf> = read_dir(corpus_dir)
            .unwrap()
            .map(|f| f.unwrap().path())
            .collect();

        let inputs = filepaths
            .iter()
            .map(|e| read(e).expect("reading corpus dir"))
            .map(|x| BytesInput {
                data: x,
                args: Vec::new(),
                coverage: BTreeSet::new(),
            })
            .collect::<Vec<BytesInput>>();

        Ok(BytesCorpus {
            inputs,
            total_coverage: BTreeSet::new(),
        })
    }

    /// Load the corpus from a newline-separated file, or directory of files.
    /// No coverage will be measured at this step, see corpus::initialize for
    /// measuring initial coverage
    pub fn load(corpus_path: &PathBuf) -> std::io::Result<BytesCorpus> {
        if metadata(corpus_path)
            .expect("getting corpus path metadata")
            .is_dir()
        {
            BytesCorpus::load_corpus_dir(corpus_path)
        } else {
            BytesCorpus::load_corpus_file(corpus_path)
        }
    }
}

impl BytesCorpus {
    /// create a new Corpus object with empty inputs and coverage
    pub fn new() -> Self {
        BytesCorpus {
            inputs: vec![],
            total_coverage: BTreeSet::new(),
        }
    }

    /// append corpus entries to the corpus file.
    /// a .coverage file will also be created with branch coverage info
    pub fn save(&self, output_dir: &Path) -> std::io::Result<()> {
        let mutations: PathBuf = output_dir.join("mutation");
        let coverages: PathBuf = output_dir.join("coverage");

        for dir in [&mutations, &coverages] {
            if !dir.exists() {
                create_dir_all(dir).expect("creating dir");
            } else {
                for entry in read_dir(dir).unwrap() {
                    remove_file(entry.unwrap().path()).unwrap();
                }
            }
        }

        let mut outputs: Vec<&BytesInput> = self.inputs.iter().collect();
        outputs.sort_by(|a, b| b.coverage.len().cmp(&a.coverage.len()));

        for (i, output) in outputs.iter().enumerate() {
            let output_name = format!("{:05}-cov{:04}", i, &output.coverage.len(),);
            output
                .serialize(&mutations, &coverages, &output_name)
                .expect("saving corpus to directory");
        }

        Ok(())
    }
}

impl CorpusOps for BytesCorpus {
    /// add a new entry into the corpus
    fn add(&mut self, new_input: InputType) {
        match new_input {
            InputType::Bytes(new_input) => {
                self.total_coverage.extend(&new_input.coverage);
                self.inputs.push(new_input);
            }
            _ => panic!(),
        }
    }

    /// add a new entry into the corpus.
    /// Each time an entry is added, the corpus will be distilled:
    /// all corpus entries with branch coverage that is a
    /// subset of the newest coverage will be pruned
    fn add_and_distill_corpus(&mut self, new: InputType) {
        // TODO: sort any matching coverage sets by shortest/alpahnumerically
        // to allow algorithm to converge on smallest input
        match new {
            InputType::Bytes(new) => {
                self.total_coverage.extend(&new.coverage);
                self.inputs
                    .retain(|i| !new.coverage.is_superset(&i.coverage));
                self.inputs.push(new);
            }
            _ => panic!(),
        }
    }

    fn check_matching_coverage_idx(&self, new: &InputType) -> Vec<usize> {
        let cov = match new {
            InputType::Bytes(ref n) => &n.coverage,
            InputType::Graph(ref n) => &n.coverage,
        };
        self.inputs
            .iter()
            .enumerate()
            .filter_map(|(i, input)| {
                if &input.coverage == cov {
                    Some(i)
                } else {
                    None
                }
            })
            .rev()
            .collect::<Vec<usize>>()
    }

    fn check_matching_and_sort(&mut self, new: InputType) {
        let check_duplicates = self.check_matching_coverage_idx(&new);
        if !check_duplicates.is_empty() {
            let mut duplicates: Vec<InputType> = vec![new.clone()];
            for i in check_duplicates {
                duplicates.push(InputType::Bytes(self.inputs.remove(i)));
            }
            duplicates.sort();
            let keep = duplicates.remove(0);
            match keep {
                InputType::Bytes(k) => {
                    self.inputs.push(k);
                }
                _ => panic!(),
            };
        }
    }
}

impl GraphCorpus {
    /// create a new Corpus object with empty inputs and coverage
    pub fn new() -> Self {
        GraphCorpus {
            inputs: vec![],
            total_coverage: BTreeSet::new(),
        }
    }

    /// append corpus entries to the corpus file.
    /// a .coverage file will also be created with branch coverage info
    pub fn save(&self, output_dir: &Path, tree: &GraphTree) -> std::io::Result<()> {
        let mutations: PathBuf = output_dir.join("mutation");
        let coverages: PathBuf = output_dir.join("coverage");

        for dir in [&mutations, &coverages] {
            if !dir.exists() {
                create_dir_all(dir).expect("creating dir");
            } else {
                for entry in read_dir(dir).unwrap() {
                    remove_file(entry.unwrap().path()).unwrap();
                }
            }
        }

        let mut outputs: Vec<&GraphInput> = self.inputs.iter().collect();
        outputs.sort_by(|a, b| b.coverage.len().cmp(&a.coverage.len()));

        eprintln!("TODO: fix slow graph clone");
        for (i, output) in outputs.iter().enumerate() {
            let output_name = format!("{:05}-cov{:04}", i, &output.coverage.len(),);
            output
                .serialize(&mutations, &coverages, &output_name, tree)
                .expect("saving corpus to directory");
        }

        Ok(())
    }
}

impl CorpusOps for GraphCorpus {
    /// add a new entry into the corpus
    fn add(&mut self, new: InputType) {
        match new {
            InputType::Graph(new) => {
                self.total_coverage.extend(&new.coverage);
                self.inputs.push(new);
            }
            _ => panic!(),
        }
    }

    /// add a new entry into the corpus.
    /// Each time an entry is added, the corpus will be distilled:
    /// all corpus entries with branch coverage that is a
    /// subset of the newest coverage will be pruned
    fn add_and_distill_corpus(&mut self, new: InputType) {
        // TODO: sort any matching coverage sets by shortest/alpahnumerically
        // to allow algorithm to converge on smallest input
        match new {
            InputType::Graph(new) => {
                self.total_coverage.extend(&new.coverage);
                self.inputs
                    .retain(|i| !new.coverage.is_superset(&i.coverage));
                self.inputs.push(new);
            }
            _ => panic!(),
        }
    }

    fn check_matching_coverage_idx(&self, new: &InputType) -> Vec<usize> {
        let cov = match new {
            InputType::Bytes(ref n) => &n.coverage,
            InputType::Graph(ref n) => &n.coverage,
        };
        self.inputs
            .iter()
            .enumerate()
            .filter_map(|(i, input)| {
                if &input.coverage == cov {
                    Some(i)
                } else {
                    None
                }
            })
            .rev()
            .collect::<Vec<usize>>()
    }

    fn check_matching_and_sort(&mut self, new: InputType) {
        let check_duplicates = self.check_matching_coverage_idx(&new);
        if !check_duplicates.is_empty() {
            let mut duplicates: Vec<InputType> = vec![new.clone()];
            for i in check_duplicates {
                duplicates.push(InputType::Graph(self.inputs.remove(i)));
            }
            duplicates.sort();
            let keep = duplicates.remove(0);
            match keep {
                InputType::Graph(k) => {
                    self.inputs.push(k);
                }
                _ => panic!(),
            };
        }
    }
}

impl CorpusType {
    pub fn save(
        &self,
        output_dir: &std::path::Path,
        tree: Option<&GraphTree>,
    ) -> Result<(), std::io::Error> {
        match self {
            CorpusType::Bytes(c) => c.save(output_dir),
            CorpusType::Graph(c) => c.save(
                output_dir,
                tree.expect("tree argument required to export Graph corpus"),
            ),
        }
    }
}

impl CorpusOps for CorpusType {
    fn add(&mut self, new: InputType) {
        match self {
            CorpusType::Bytes(c) => c.add(new),
            CorpusType::Graph(c) => c.add(new),
        }
    }

    fn add_and_distill_corpus(&mut self, new: InputType) {
        match self {
            CorpusType::Bytes(c) => c.add_and_distill_corpus(new),
            CorpusType::Graph(c) => c.add_and_distill_corpus(new),
        }
    }

    fn check_matching_coverage_idx(&self, new: &InputType) -> Vec<usize> {
        match self {
            CorpusType::Bytes(c) => c.check_matching_coverage_idx(new),
            CorpusType::Graph(c) => c.check_matching_coverage_idx(new),
        }
    }

    fn check_matching_and_sort(&mut self, new: InputType) {
        match self {
            CorpusType::Bytes(c) => c.check_matching_and_sort(new),
            CorpusType::Graph(c) => c.check_matching_and_sort(new),
        }
    }
}

impl std::fmt::Debug for InputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut print_name = "\n    ".to_string();
        let mut print_buf: Vec<u8> = Vec::new();
        let coverage = match self {
            InputType::Bytes(s) => {
                print_name += "InputType::Bytes ";
                let max_len = min(s.data.len(), 32);
                print_buf.extend_from_slice(&s.data[..max_len]);
                &s.coverage
            }
            InputType::Graph(s) => {
                print_name += "InputType::Graph ";
                for edge in &s.encoding.encoding {
                    print_buf.extend(format!("{}>{} ", edge.0.index(), edge.1.index()).as_bytes());
                }
                &s.coverage
            }
        };
        f.debug_struct(&print_name)
            .field("coverage", &coverage.len())
            .field(
                "preview",
                &String::from_utf8_lossy(&print_buf).replace('\n', "\\n"),
            )
            /*
            .field(
            "args",
            &String::from_utf8_lossy(&self.args[0..min(self.args.len(), 32)])
            .replace('\n', "\\n"),
            )
            */
            .finish()
    }
}

/*
impl std::fmt::Debug for CorpusType<'_, '_> {
fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
let &inputs = match self {
CorpusType::Bytes(c) => &c.inputs,
CorpusType::Graph(c) => &c.inputs,
};
f.debug_struct("\n  BytesCorpus")
.field("inputs", &self.inputs)
.field("\n  Total coverage", &self.total_coverage.len())
.finish()
}
}
impl std::fmt::Display for BytesCorpus {
fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
f.debug_struct("\n  BytesCorpus")
.field("inputs", &self.inputs)
.field("\n  Total coverage", &self.total_coverage.len())
.finish()
}
}
*/

/*
impl Default for BytesCorpus {
fn default() -> Self {
Self::new()
}
}
*/

#[cfg(test)]
mod tests {
    use super::BytesCorpus;
    use super::BytesInput;
    use crate::config::Config;
    use crate::corpus::CorpusOps;
    use crate::corpus::InputType;
    use crate::execute::trial;
    use crate::execute::Exec;
    use crate::execute::ExecResult;
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[test]
    fn load_corpus() {
        let corpus = BytesCorpus::load(&PathBuf::from("./examples/cli/input/corpus")).unwrap();
        assert!(!corpus.inputs.is_empty());
    }

    #[test]
    fn load_corpus_dir() {
        let corpus = BytesCorpus::load(&PathBuf::from("./tests/")).unwrap();
        assert!(!corpus.inputs.is_empty());
    }

    #[test]
    fn initialize_corpus_coverage() {
        let mut corpus = BytesCorpus::load(&PathBuf::from("./examples/cli/input/corpus")).unwrap();
        assert!(!corpus.inputs.is_empty());

        let mut cfg = Config::defaults();
        cfg.load_env();
        cfg.target_path = Vec::from([PathBuf::from("./examples/cli/fuzz_target.c")]);
        let cfg = Arc::new(cfg);

        // compile target
        let _exec = Exec::new(&cfg);

        // check coverage of initial inputs
        for input in &corpus.inputs {
            let _result = trial(&cfg, &input.args, &input.data, 0);
            if input.coverage.is_subset(&corpus.total_coverage) {
                continue;
            }
            corpus.total_coverage.extend(&input.coverage);
        }
        corpus.save(&PathBuf::from("./output/cli/")).unwrap();
        let mut corpus2 = BytesCorpus::new();
        for i in &corpus.inputs {
            corpus2.add_and_distill_corpus(InputType::Bytes(i.clone()));
        }
        corpus.append(&mut corpus2);
    }

    #[test]
    fn chunksizes() {
        let sizes: [i32; 11] = [0, 1, 2, 128, 255, 256, 257, 512, 1024, 2048, 4096];
        for i in sizes {
            let chunk_size = 2_usize.pow(std::cmp::max(1, (i / 64) - 2).ilog2());
            eprintln!("{}={}", i, chunk_size)
        }
    }

    #[test]
    fn test_minimize_input() {
        let mut test_input = BytesInput {
            coverage: BTreeSet::new(),
            args: Vec::new(),
            data: b"ABC0000000".to_vec(),
        };
        let mut cfg = Config::defaults();
        cfg.load_env();
        cfg.target_path = Vec::from([PathBuf::from("./examples/cli/fuzz_target.c")]);
        cfg.output_dir = PathBuf::from("./output/testdata");
        std::fs::create_dir_all(&cfg.output_dir).unwrap();
        let exec = Exec::new(&cfg);

        let (result, _result_cov) = trial(&Arc::new(cfg), &test_input.args, &test_input.data, 0);
        if let ExecResult::Ok(_r) = result {
        } else {
            panic!("this input should pass");
        }
        test_input.minimize_input(&exec);

        assert_eq!(String::from_utf8_lossy(&test_input.data), "ABC");
        assert_ne!(test_input.data, BytesInput::empty().data);
    }
}
