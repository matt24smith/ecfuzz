//! Maintain corpus inputs as they evolve with each generation of mutations

use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::{metadata, read, read_dir, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::execute::{Exec, ExecResult};

/// each test input sent to the target program contains the byte vector
/// to be tested, as well as the resulting branch coverage set and some metadata
pub struct CorpusInput {
    pub data: RefCell<Vec<u8>>,
    pub coverage: HashSet<u64>,
    pub lifetime: u64,
}

/// corpus contains a vector of corpus inputs, and the total branch coverage set
pub struct Corpus {
    pub inputs: Vec<CorpusInput>,
    pub total_coverage: HashSet<u64>,
}

impl CorpusInput {
    /// Initialize a new CorpusInput with empty values
    pub fn empty() -> Self {
        CorpusInput {
            data: b"".to_vec().into(),
            coverage: HashSet::new(),
            lifetime: 0,
        }
    }

    /// Serialize the test input to an output directory for logging.
    /// Two files will be created: a .mutation file containing the mutated
    /// input, and a .coverage file containing the set of code branches hit
    fn serialize(
        &self,
        mutation_dir: &Path,
        coverage_dir: &Path,
        output_name: &str,
    ) -> Result<(), std::io::Error> {
        let mut hits = self.coverage.clone().drain().collect::<Vec<u64>>();
        hits.sort();
        let hit_str = hits
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<String>>()
            .join("\n");

        #[cfg(debug_assertions)]
        assert!(mutation_dir.is_dir());
        #[cfg(debug_assertions)]
        assert!(coverage_dir.is_dir());

        let mut fpath = mutation_dir.join(output_name);
        fpath.set_extension("mutation");

        let mut cov_path = coverage_dir.join(output_name);
        cov_path.set_extension("coverage");

        File::create(fpath)
            .expect("creating fpath")
            .write_all(&self.data.borrow())
            .expect("writing mutation to file");
        File::create(cov_path.clone())
            .unwrap_or_else(|_| panic!("creating cov_path: {}", cov_path.to_str().unwrap()))
            .write_all(hit_str.as_bytes())
            .expect("writing mutation coverage to file");

        Ok(())
    }
}

impl Corpus {
    /// create a new Corpus object with empty inputs and coverage
    pub fn new() -> Self {
        Corpus {
            inputs: vec![],
            total_coverage: HashSet::new(),
        }
    }

    /// add a new entry into the corpus
    pub fn add(&mut self, input: CorpusInput) {
        for branch in &input.coverage {
            self.total_coverage.insert(*branch);
        }
        self.inputs.push(input);
    }

    /// add a new entry into the corpus.
    /// Each time an entry is added, the corpus will be distilled:
    /// all corpus entries with branch coverage that is a
    /// subset of the newest coverage will be pruned
    pub fn add_and_distill_corpus(&mut self, new_input: CorpusInput) {
        let diff: Vec<u64> = new_input
            .coverage
            .difference(&self.total_coverage)
            .copied()
            .collect();
        for branch in diff {
            self.total_coverage.insert(branch);
        }

        self.inputs
            .retain(|i| !new_input.coverage.is_superset(&i.coverage));
        self.inputs.push(new_input);
    }

    /// Load a corpus of inputs from a single file, separated by newlines.
    /// No coverage will be measured at this step, see corpus::initialize for
    /// measuring initial coverage
    fn load_corpus_file(corpus_path: &PathBuf) -> std::io::Result<Corpus> {
        assert!(!corpus_path.is_dir());

        let f: Vec<u8> = read(corpus_path).expect("couldn't find corpus path!");
        let inputs = f
            .split(|x| x == &b'\n')
            .map(|x| x.to_vec())
            .filter(|x| !x.is_empty())
            .map(|x| CorpusInput {
                data: x.into(),
                coverage: HashSet::new(),
                lifetime: 0,
            })
            .collect::<Vec<CorpusInput>>();

        Ok(Corpus {
            inputs,
            total_coverage: HashSet::new(),
        })
    }

    /// load a corpus of input files from a directory path
    fn load_corpus_dir(corpus_dir: &PathBuf) -> std::io::Result<Corpus> {
        let filepaths: Vec<PathBuf> = read_dir(corpus_dir)
            .unwrap()
            .map(|f| f.unwrap().path())
            .collect();

        let inputs = filepaths
            .iter()
            .map(|e| read(e).expect("reading corpus dir"))
            .map(|x| CorpusInput {
                data: x.into(),
                coverage: HashSet::new(),
                lifetime: 0,
            })
            .collect::<Vec<CorpusInput>>();

        Ok(Corpus {
            inputs,
            total_coverage: HashSet::new(),
        })
    }

    /// Load the corpus from a newline-separated file, or directory of files.
    /// No coverage will be measured at this step, see corpus::initialize for
    /// measuring initial coverage
    pub fn load(corpus_path: &PathBuf) -> std::io::Result<Corpus> {
        if metadata(corpus_path)
            .expect("getting corpus path metadata")
            .is_dir()
        {
            Corpus::load_corpus_dir(corpus_path)
        } else {
            Corpus::load_corpus_file(corpus_path)
        }
    }

    /// append the inputs of another corpus into this corpus
    pub fn append(&mut self, corpus: Corpus) {
        for input in corpus.inputs {
            self.inputs.push(input);
        }
        self.total_coverage.extend(&corpus.total_coverage);
    }

    /// append corpus entries to the corpus file.
    /// a .coverage file will also be created with branch coverage info
    pub fn save(&self, output_dir: &PathBuf) -> std::io::Result<()> {
        let mutations: PathBuf = output_dir.join("mutation");
        let coverages: PathBuf = output_dir.join("coverage");

        let _ = std::fs::remove_dir_all(&mutations);
        let _ = std::fs::remove_dir_all(&coverages);

        for dir in [&output_dir, &mutations, &coverages] {
            if !dir.exists() {
                std::fs::create_dir_all(dir).expect("creating dir");
            }
        }

        println!("\rsaving to {:#?} ... {:<70}", output_dir, "");

        for (i, input) in self.inputs.iter().enumerate() {
            input
                .serialize(&mutations, &coverages, format!("{:05}", i).as_str())
                .expect("saving corpus to directory");
        }

        Ok(())
    }

    /// update code coverage metrics for corpus inputs without mutating
    pub fn initialize(&mut self, executor: &mut Exec) {
        for input in &mut self.inputs {
            let _result: ExecResult<std::process::Output> = executor.trial(input, 0);
            //input.coverage = input_updated.coverage.clone();
            self.total_coverage.extend(&input.coverage);
        }
    }
}

impl std::fmt::Debug for CorpusInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut maxlen = 32;
        if self.data.borrow().len() < maxlen {
            maxlen = self.data.borrow().len();
        }
        f.debug_struct("\n    CorpusInput: ")
            .field("coverage", &self.coverage.len())
            .field("lifetime", &self.lifetime)
            .field(
                "preview",
                &String::from_utf8_lossy(&self.data.borrow()[0..maxlen]).replace("\n", ""),
            )
            .finish()
    }
}
impl std::fmt::Display for CorpusInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut maxlen = 32;
        if self.data.borrow().len() < maxlen {
            maxlen = self.data.borrow().len();
        }
        f.debug_struct("\n    CorpusInput: ")
            .field("coverage", &self.coverage.len())
            .field("lifetime", &self.lifetime)
            .field(
                "preview",
                &String::from_utf8_lossy(&self.data.borrow()[0..maxlen]).replace("\n", ""),
            )
            .finish()
    }
}

impl std::fmt::Debug for Corpus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("\n  Corpus")
            .field("inputs", &self.inputs)
            .field("\n  Total coverage", &self.total_coverage.len())
            .finish()
    }
}
impl std::fmt::Display for Corpus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("\n  Corpus")
            .field("inputs", &self.inputs)
            .field("\n  Total coverage", &self.total_coverage.len())
            .finish()
    }
}

impl Default for Corpus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Corpus;
    use crate::config::Config;
    use crate::execute::Exec;
    use std::path::PathBuf;

    #[test]
    fn test_load_corpus() {
        let corpus = Corpus::load(&PathBuf::from("./examples/cli/input/corpus")).unwrap();
        assert!(!corpus.inputs.is_empty());
    }

    #[test]
    fn test_load_corpus_dir() {
        let corpus = Corpus::load(&PathBuf::from("./tests/")).unwrap();
        assert!(!corpus.inputs.is_empty());
    }

    #[test]
    fn test_initialize_corpus_coverage() {
        let mut corpus = Corpus::load(&PathBuf::from("./examples/cli/input/corpus")).unwrap();
        assert!(!corpus.inputs.is_empty());

        let mut cfg = Config::defaults();
        cfg.target_path = Vec::from([PathBuf::from("./examples/cli/fuzz_target.c")]);

        // compile target with instrumentation
        let mut exec = Exec::initialize(cfg).unwrap();

        // check coverage of initial inputs
        corpus.initialize(&mut exec);
    }
}
