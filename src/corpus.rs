use std::collections::HashSet;
use std::fs::{read, read_dir, File};
use std::io::Write;
use std::iter::zip;
use std::path::{Path, PathBuf};

use crate::execute::{check_report_coverage, index_target_report, Config, Exec};

#[derive(Clone)]
pub struct CorpusInput {
    pub data: Vec<u8>,
    pub coverage: HashSet<u64>,
    pub file_stem: PathBuf,
    pub file_ext: PathBuf,
    pub lifetime: u64,
}

pub struct Corpus {
    pub inputs: Vec<CorpusInput>,
    pub total_coverage: HashSet<u64>,
}

impl CorpusInput {
    pub fn get_filename(&self) -> PathBuf {
        let mut p = PathBuf::from(self.file_stem.to_str().unwrap());
        p.set_extension(self.file_ext.clone());
        p
    }
    pub fn serialize(&self, output_dir: &Path) -> Result<(), std::io::Error> {
        let mut hits = self.coverage.clone().drain().collect::<Vec<u64>>();
        hits.sort();
        let hit_str = hits
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<String>>()
            .join("_");

        assert!(output_dir.is_dir());
        let mut fpath = output_dir.to_path_buf();
        let fname = self.get_filename();
        fpath = fpath.join(fname.to_str().unwrap().to_owned() + "_" + hit_str.as_str());
        fpath.set_extension(fname.extension().unwrap_or_default());

        #[cfg(debug_assertions)]
        println!("writing to {}", fpath.to_str().unwrap(),);
        File::create(fpath)?.write_all(&self.data)?;

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

    /// load a corpus of inputs from a single file, separated by newlines
    pub fn load_corpus_file(corpus_path: &PathBuf) -> (Vec<Vec<u8>>, Vec<PathBuf>) {
        assert!(!corpus_path.is_dir());

        fn new_fpath(corpus_path: &Path) -> PathBuf {
            let output_dir = PathBuf::from("output");
            assert!(output_dir.is_dir());
            let basename = corpus_path.file_stem().unwrap().to_str().unwrap();
            output_dir.join(Path::new(&basename))
        }

        let f: Vec<u8> = read(corpus_path).expect("couldn't find corpus path!");
        let inputs = f
            .split(|x| x == &b'\n')
            .map(|x| x.to_vec())
            .filter(|x| !x.is_empty())
            .collect::<Vec<Vec<u8>>>();

        let names: Vec<PathBuf> = (0..inputs.len()).map(|_i| new_fpath(corpus_path)).collect();
        (inputs, names)
    }
    /// load a corpus of input files from a directory path
    pub fn load_corpus_dir(corpus_dir: &PathBuf) -> (Vec<Vec<u8>>, Vec<PathBuf>) {
        let filepaths: Vec<PathBuf> = read_dir(corpus_dir)
            .unwrap()
            .map(|f| f.unwrap().path())
            .collect();

        let files = filepaths
            .iter()
            .map(|e| read(e).expect("reading corpus dir"))
            .collect::<Vec<Vec<u8>>>();

        let output_dir = PathBuf::from("output");
        assert!(output_dir.is_dir());

        let outfile_prefixes: Vec<PathBuf> = filepaths
            .iter()
            .map(|p| output_dir.clone().join(p.file_stem().unwrap()))
            .collect();

        let extensions: Vec<String> = filepaths
            .iter()
            .map(|f| {
                f.extension()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect();

        let outfiles: Vec<PathBuf> = zip(outfile_prefixes, extensions)
            .map(|(o, e)| o.with_extension(e))
            .collect();

        for (mut o, f) in zip(outfiles.clone(), filepaths) {
            o.set_extension(f.extension().unwrap_or_default());
        }

        (files, outfiles)
    }

    /// load the corpus from a newline-separated file, or directory of files
    pub fn load(&mut self, cfg: &Config, corpus_path: &PathBuf, is_dir: bool) {
        let profraw = &format!("output/{}.profraw", std::process::id());
        let profdata = &format!("output/{}.profdata", std::process::id());
        let (inputs, filenames) = if is_dir {
            Corpus::load_corpus_dir(corpus_path)
        } else {
            Corpus::load_corpus_file(corpus_path)
        };
        for (input, filename) in zip(inputs, filenames) {
            let (input, _crashed) = Exec::trial(
                cfg,
                profraw,
                profdata,
                &input,
                PathBuf::from(filename.file_stem().unwrap()),
                PathBuf::from(filename.extension().unwrap_or_default()),
                0,
            );
            index_target_report(cfg, profraw, profdata).unwrap();
            let coverage = check_report_coverage(cfg, profdata).unwrap();

            self.total_coverage.extend(&coverage);
            self.add_and_distill_corpus(CorpusInput {
                data: input.data,
                file_stem: input.file_stem,
                file_ext: input.file_ext,
                coverage,
                lifetime: 0,
            });
        }
    }

    /// append corpus entries to the corpus file.
    /// a {corpus_path}.coverage file will be appended with branch coverage info
    pub fn save(&self, output_dir: PathBuf) -> std::io::Result<()> {
        if !output_dir.exists() {
            std::fs::create_dir_all(&output_dir).unwrap();
        }
        for input in &self.inputs {
            input.serialize(&output_dir).unwrap();
        }

        Ok(())
    }
}

impl std::fmt::Debug for CorpusInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut maxlen = 32;
        if self.data.len() < maxlen {
            maxlen = self.data.len();
        }
        f.debug_struct("\n    CorpusInput: ")
            .field("stem", &self.file_stem)
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
            .field("stem", &self.file_stem)
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
    use crate::execute::Config;
    use std::path::PathBuf;

    #[test]
    fn test_load_corpus() {
        let cfg = Config::defaults();
        let mut corpus = Corpus::new();
        corpus.load(&cfg, &PathBuf::from("input/corpus"), false);
        corpus.load(&cfg, &PathBuf::from("input/sample.dict"), false);
        assert!(!corpus.inputs.is_empty());
    }

    #[test]
    fn test_load_corpus_dir() {
        let cfg = Config::defaults();
        let mut corpus = Corpus::new();
        corpus.load(&cfg, &PathBuf::from("./tests/"), true);
        //corpus.load(&cfg, &PathBuf::from("./input/testing/"), true);
        assert!(!corpus.inputs.is_empty());
    }
}
