//! Maintain corpus inputs as they evolve with each generation of mutations

use std::cmp::{max, min};
use std::collections::BTreeSet;
use std::fs::{create_dir_all, metadata, read, read_dir, remove_file, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::execute::Exec;
use crate::execute::SANITIZERS;

/// each test input sent to the target program contains the byte vector
/// to be tested, as well as the resulting branch coverage set and some metadata
#[derive(Clone)]
pub struct CorpusInput {
    pub data: Vec<u8>,
    pub args: Vec<u8>,
    pub coverage: BTreeSet<u128>,
    pub lifetime: u64,
}

/// corpus contains a vector of corpus inputs, and the total branch coverage set
pub struct Corpus {
    pub inputs: Vec<CorpusInput>,
    pub total_coverage: BTreeSet<u128>,
}

impl CorpusInput {
    /// Initialize a new CorpusInput with empty values
    pub fn empty() -> Self {
        CorpusInput {
            data: Vec::new(),
            args: Vec::new(),
            coverage: BTreeSet::new(),
            lifetime: 0,
        }
    }

    /// Compute hashes of stdout, stderr by executing input with each sanitizer.
    /// Hashes will only be computed for outputs with matching coverage sets
    fn exec_output_hashes(&self, exec: &mut Exec) -> Vec<u64> {
        //eprintln!("CHECK HASH FOR {}", String::from_utf8_lossy(&self.data),);
        let mut hashes: Vec<u64> = Vec::new();

        for san_idx in 0..SANITIZERS.len() {
            let mut test_input = self.clone();
            let _result = exec.trial(&mut test_input, san_idx);
            let mut concat = Vec::new();
            for cov in test_input.coverage.iter() {
                concat.append(&mut cov.to_le_bytes().to_vec());
            }
            /*
                   match exec_res {
                   ExecResult::Ok(o) | ExecResult::Err(o) => {
                   concat.append(&mut o.stdout.to_vec());
                   concat.append(&mut o.stderr.to_vec());
                   for word in &mut o
                   .stdout
                   .split(|b| b == &b'\n' || b == &b' ')
                   .chain(o.stderr.split(|b| b == &b'\n' || b == &b' '))
                   {
                /*
                // skip memory addresses when hashing
                if !byte_index(b"0x".to_vec().as_ref(), &word.to_vec()).is_empty()
                || !byte_index(b"==WARNING".to_vec().as_ref(), &word.to_vec())
                .is_empty()
                || !byte_index(b"==ERROR".to_vec().as_ref(), &word.to_vec())
                .is_empty()
                || !byte_index(b"ecfuzz_target".to_vec().as_ref(), &word.to_vec())
                .is_empty()
                {
                //eprintln!("SKIPPED {:?}", String::from_utf8_lossy(&word));
                continue;
                }
                */
                //eprintln!("NOT SKIPPED {}", String::from_utf8_lossy(&word));
                concat.append(&mut word.to_vec());
            }
            }
            ExecResult::NonTerminatingErr() => {}
            };
            */

            hashes.push(xxhash_rust::xxh3::xxh3_64(concat.as_slice()));
        }
        hashes
    }

    /// Recursively remove bytes from a test input while coverage, stdout,
    /// and stderr remain unchanged.
    /// Very slow for large inputs.
    /// Assumes coverage data is already up to date.
    pub fn minimize_input(&mut self, exec: &mut Exec) {
        let start_bytesize = self.data.len();
        let chunk_size = 2_usize.pow(max(1, (start_bytesize as i64 / 64) - 2).ilog2());

        // compute hash of output stdout, stderr, and exit code for each sanitizer
        let unmodified_hashes: Vec<u64> = self.exec_output_hashes(exec);

        for byte_idx in (1..self.data.len() - chunk_size + 1)
            .step_by(chunk_size)
            .rev()
        {
            // remove bytes from test input
            let mut minified_input = self.clone();
            for _ in 0..chunk_size {
                minified_input.data.remove(byte_idx);
            }

            let test_hashes = minified_input.exec_output_hashes(exec);
            let hashes_match = unmodified_hashes
                .iter()
                .zip(test_hashes.iter())
                .filter(|&(a, b)| a == b)
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
        //let mut hits = self.coverage.clone().iter().collect::<Vec<u128>>();
        //hits.sort();
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

impl Corpus {
    /// create a new Corpus object with empty inputs and coverage
    pub fn new() -> Self {
        Corpus {
            inputs: vec![],
            total_coverage: BTreeSet::new(),
        }
    }

    /// add a new entry into the corpus
    pub fn add(&mut self, new_input: CorpusInput) {
        self.total_coverage.extend(&new_input.coverage);
        self.inputs.push(new_input);
    }

    /// add a new entry into the corpus.
    /// Each time an entry is added, the corpus will be distilled:
    /// all corpus entries with branch coverage that is a
    /// subset of the newest coverage will be pruned
    pub fn add_and_distill_corpus(&mut self, new: CorpusInput) {
        // TODO: sort any matching coverage sets by shortest/alpahnumerically
        // to allow algorithm to converge on smallest input

        self.total_coverage.extend(&new.coverage);
        self.inputs
            .retain(|i| !new.coverage.is_superset(&i.coverage));
        self.inputs.push(new);
    }

    /*

        let sender = sender.clone();
        let mut exec_clone = Exec {
            cfg: exec.cfg.clone(),
        };
        let mut minimized = input.clone();
        let arg_bytes_2 = arg_bytes.to_owned();
        pool.spawn_fifo(move || {
            minimized.minimize_input(&mut exec_clone, &arg_bytes_2);
            sender.send(minimized).expect("sending results from worker");
        });

    //let _ = skip_minimization.drain(..).map(|c| self.add(c.clone()));

    for _counted in 0..fetch_count {
        let minimized = receiver.recv().unwrap();
        self.add_and_distill_corpus(minimized.clone());
        print!("\rminimized {}/{}", _counted, fetch_count);
        stdout().flush().unwrap();
    }
    println!("minimized {}/{}", fetch_count, fetch_count);
    //println!("begin spawn {}", self.inputs.len());
    self.inputs
    .sort_by(|a, b| a.data.partial_cmp(&b.data).unwrap());
    }
    */

    /// Load corpus inputs from lines in a file
    pub fn load_corpus_lines(corpus_path: &PathBuf) -> std::io::Result<Corpus> {
        assert!(!corpus_path.is_dir());

        let f: Vec<u8> = read(corpus_path).expect("couldn't find corpus path!");
        let inputs = f
            .split(|x| x == &b'\n')
            .map(|x| x.to_vec())
            .filter(|x| !x.is_empty())
            .map(|x| CorpusInput {
                data: x,
                args: Vec::new(),
                coverage: BTreeSet::new(),
                lifetime: 0,
            })
            .collect::<Vec<CorpusInput>>();

        Ok(Corpus {
            inputs,
            total_coverage: BTreeSet::new(),
        })
    }

    /// Load a single corpus input from a file
    pub fn load_corpus_file(corpus_path: &PathBuf) -> std::io::Result<Corpus> {
        assert!(!corpus_path.is_dir());

        let f: Vec<u8> = read(corpus_path).expect("couldn't find corpus path!");
        let c = CorpusInput {
            data: f,
            args: Vec::new(),
            coverage: BTreeSet::new(),
            lifetime: 0,
        };

        Ok(Corpus {
            inputs: vec![c],
            total_coverage: BTreeSet::new(),
        })
    }

    /// load a corpus of input files from a directory path
    pub fn load_corpus_dir(corpus_dir: &PathBuf) -> std::io::Result<Corpus> {
        let filepaths: Vec<PathBuf> = read_dir(corpus_dir)
            .unwrap()
            .map(|f| f.unwrap().path())
            .collect();

        let inputs = filepaths
            .iter()
            .map(|e| read(e).expect("reading corpus dir"))
            .map(|x| CorpusInput {
                data: x,
                args: Vec::new(),
                coverage: BTreeSet::new(),
                lifetime: 0,
            })
            .collect::<Vec<CorpusInput>>();

        Ok(Corpus {
            inputs,
            total_coverage: BTreeSet::new(),
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

    /// append the inputs of another corpus into this corpus, consuming it
    pub fn append(&mut self, corpus: &mut Corpus) {
        for input in corpus.inputs.drain(..) {
            self.inputs.push(input);
        }
        self.total_coverage.extend(&corpus.total_coverage);
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

        let mut outputs: Vec<&CorpusInput> = self.inputs.iter().collect();
        outputs.sort_by(|a, b| b.coverage.len().cmp(&a.coverage.len()));

        for (i, output) in outputs.iter().enumerate() {
            let output_name = format!(
                "{:05}-cov{:04}-gen{:03}",
                i,
                &output.coverage.len(),
                &output.lifetime
            );
            output
                .serialize(&mutations, &coverages, &output_name)
                .expect("saving corpus to directory");
        }

        Ok(())
    }
}

impl std::fmt::Debug for CorpusInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("\n    CorpusInput: ")
            .field("coverage", &self.coverage.len())
            .field("lifetime", &self.lifetime)
            .field(
                "preview",
                &String::from_utf8_lossy(&self.data[0..min(self.data.len(), 32)])
                    .replace('\n', "\\n"),
            )
            .field(
                "args",
                &String::from_utf8_lossy(&self.args[0..min(self.args.len(), 32)])
                    .replace('\n', "\\n"),
            )
            .finish()
    }
}
impl std::fmt::Display for CorpusInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("\n    CorpusInput: ")
            .field("coverage", &self.coverage.len())
            .field("lifetime", &self.lifetime)
            .field(
                "preview",
                &String::from_utf8_lossy(&self.data[0..min(self.data.len(), 32)])
                    .replace('\n', "\\n"),
            )
            .field(
                "args",
                &String::from_utf8_lossy(&self.args[0..min(self.args.len(), 32)])
                    .replace('\n', "\\n"),
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
    use super::CorpusInput;
    use crate::config::Config;
    use crate::execute::Exec;
    use crate::execute::ExecResult;
    use std::collections::BTreeSet;
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
        cfg.load_env();
        cfg.target_path = Vec::from([PathBuf::from("./examples/cli/fuzz_target.c")]);

        // compile target with instrumentation
        let mut exec = Exec::new(cfg).unwrap();

        // check coverage of initial inputs
        //corpus.initialize(&mut exec, &vec![]);
        for input in &mut corpus.inputs {
            let _result = exec.trial(input, 0);
            if input.coverage.is_subset(&corpus.total_coverage) {
                continue;
            }
            corpus.total_coverage.extend(&input.coverage);
            input.minimize_input(&mut exec);
        }
        corpus.save(&PathBuf::from("./output/cli/")).unwrap();
        let mut corpus2 = Corpus::new();
        for i in &corpus.inputs {
            corpus2.add(i.clone());
            corpus2.add_and_distill_corpus(i.clone());
        }
        corpus.append(&mut corpus2);
        println!("{} {:?}", corpus, corpus);
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
        let mut test_input = CorpusInput {
            coverage: BTreeSet::new(),
            args: Vec::new(),
            data: b"ABC0000000".to_vec(),
            lifetime: 0,
        };

        // executor config
        let mut cfg = Config::defaults();
        cfg.load_env();
        cfg.target_path = Vec::from([PathBuf::from("./examples/cli/fuzz_target.c")]);
        cfg.output_dir = PathBuf::from("./output/testdata");
        std::fs::create_dir_all(&cfg.output_dir).unwrap();
        let mut exec = Exec::new(cfg).unwrap();

        let result = exec.trial(&mut test_input, 0);
        if let ExecResult::Ok(_r) = result {
        } else {
            panic!("this input should pass");
        }
        test_input.minimize_input(&mut exec);

        println!("{} {:?}", test_input, test_input);

        assert_eq!(String::from_utf8_lossy(&test_input.data), "ABC");
        assert_ne!(test_input.data, CorpusInput::empty().data);
    }
}
