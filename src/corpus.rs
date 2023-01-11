use std::collections::HashSet;
use std::fs::{read, read_dir, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct CorpusInput {
    pub data: Vec<u8>,
    pub coverage: HashSet<u64>,
}

impl std::fmt::Debug for CorpusInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut maxlen = 64;
        if &self.data.len() < &64 {
            maxlen = self.data.len();
        }
        f.debug_struct("\n    CorpusInput: ")
            .field("data", &String::from_utf8_lossy(&self.data[0..maxlen]))
            .field("coverage", &self.coverage)
            .finish()
    }
}

pub struct Corpus {
    pub inputs: Vec<CorpusInput>,
    pub total_coverage: HashSet<u64>,
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
        println!("new code coverage hit! updating inputs... {}", self);
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

    /// append corpus entries to the corpus file.
    /// a {corpus_path}.coverage file will be appended with branch coverage info
    pub fn save(&self, corpus_dir: &PathBuf, name: &str, append: bool) -> std::io::Result<()> {
        assert!(corpus_dir.is_dir());
        // corpus file
        let fpath = Path::new(corpus_dir).join(Path::new(format!("{}.corpus", name).as_str()));
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .open(&fpath)?;
        if !append {
            f.set_len(0)?;
        }

        // coverage file
        let fcov_path =
            Path::new(corpus_dir).join(Path::new(format!("{}.coverage", name).as_str()));
        let mut fcov = OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .open(fcov_path)?;
        if !append {
            fcov.set_len(0)?;
        }

        // write to files
        for input in &self.inputs {
            f.write_all(&input.data)?;
            f.write_all(&[b'\n'])?;
            fcov.write_all(format!("{:?}\n", &input.coverage).as_bytes())?;
        }

        Ok(())
    }
}

/// load a corpus of inputs from a single file, separated by newlines
pub fn load_corpus(corpus_path: &PathBuf) -> Vec<Vec<u8>> {
    let f: Vec<u8> = read(corpus_path).expect("couldn't find corpus path!");
    let s = f
        .split(|x| x == &b'\n')
        .map(|x| x.to_vec())
        .filter(|x| !x.is_empty())
        .collect::<Vec<Vec<u8>>>();

    s
}

/// load a corpus of input files from a directory path
pub fn load_corpus_dir(corpus_dir: &PathBuf) -> Result<Vec<Vec<u8>>, std::io::Error> {
    let d = read_dir(corpus_dir)
        .unwrap()
        .map(|e| read(e.expect("reading corpus file").path()).expect("reading corpus dir"))
        .collect::<Vec<Vec<u8>>>();
    Ok(d)
}
