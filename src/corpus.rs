use std::collections::HashSet;
use std::fs::{create_dir, metadata, read, read_dir, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::execute::{Config, Exec};

/// each test input sent to the target program contains the byte vector
/// to be tested, as well as the resulting branch coverage set and some metadata
#[derive(Clone)]
pub struct CorpusInput {
    pub data: Vec<u8>,
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
            data: b"".to_vec(),
            coverage: HashSet::new(),
            lifetime: 0,
        }
    }
    /// Serialize the test input to an output directory for logging.
    /// Two files will be created: a .mutation file containing the mutated
    /// input, and a .coverage file containing the set of code branches hit
    fn serialize(&self, output_dir: &Path, output_name: &str) -> Result<(), std::io::Error> {
        let mut hits = self.coverage.clone().drain().collect::<Vec<u64>>();
        hits.sort();
        let hit_str = hits
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<String>>()
            .join("\n");

        assert!(output_dir.is_dir());

        let mut fpath = output_dir.to_path_buf();
        fpath = fpath.join(output_name);
        fpath.set_extension("mutation");

        let mut cov_path = fpath.clone();
        cov_path.set_extension("coverage");

        #[cfg(debug_assertions)]
        println!("writing to {}", fpath.to_str().unwrap(),);

        File::create(fpath)
            .expect("creating fpath")
            .write_all(&self.data)
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
                data: x,
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
                data: x,
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
        for input in &corpus.inputs {
            self.inputs.push(input.clone());
        }
        self.total_coverage.extend(&corpus.total_coverage);
    }

    /// append corpus entries to the corpus file.
    /// a .coverage file will also be created with branch coverage info
    pub fn save(&self, output_dir: PathBuf) -> std::io::Result<()> {
        if !output_dir.exists() {
            std::fs::create_dir_all(&output_dir).unwrap();
        }

        for (i, input) in self.inputs.iter().enumerate() {
            input
                .serialize(&output_dir, format!("{}", i).as_str())
                .unwrap_or_else(|_| {
                    panic!(
                        "serializing {} as file in directory {}",
                        i,
                        output_dir.as_path().to_str().unwrap()
                    )
                });
        }

        Ok(())
    }

    /// update code coverage metrics for corpus inputs without mutating
    pub fn initialize(&mut self, cfg: &Config) {
        let output_dir = PathBuf::from("output");
        if !output_dir.is_dir() {
            create_dir(output_dir).expect("creating output directory");
        };
        for input in &self.inputs {
            let (input_updated, _crashed) = Exec::trial(cfg, input, input.lifetime + 1);
            self.total_coverage.extend(&input_updated.coverage);
        }
    }
}

impl std::fmt::Debug for CorpusInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut maxlen = 32;
        if self.data.len() < maxlen {
            maxlen = self.data.len();
        }
        f.debug_struct("\n    CorpusInput: ")
            .field("coverage", &self.coverage)
            .field("lifetime", &self.lifetime)
            .field("preview", &String::from_utf8_lossy(&self.data[0..maxlen]))
            .finish()
    }
}
impl std::fmt::Display for CorpusInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut maxlen = 32;
        if self.data.len() < maxlen {
            maxlen = self.data.len();
        }
        f.debug_struct("\n    CorpusInput: ")
            .field("coverage", &self.coverage)
            .field("lifetime", &self.lifetime)
            .field("data", &String::from_utf8_lossy(&self.data[0..maxlen]))
            .finish()
    }
}

impl std::fmt::Debug for Corpus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("\n  Corpus")
            .field("inputs", &self.inputs)
            .field("\n  Total coverage", &self.total_coverage)
            .finish()
    }
}
impl std::fmt::Display for Corpus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("\n  Corpus")
            .field("inputs", &self.inputs)
            .field("\n  Total coverage", &self.total_coverage)
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
    use crate::execute::{Config, Exec};
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
        cfg.target_path = PathBuf::from("./examples/cli/fuzz_target.c");

        // compile target with instrumentation
        Exec::initialize(&cfg).unwrap();

        // check coverage of initial inputs
        corpus.initialize(&cfg);
    }
}
