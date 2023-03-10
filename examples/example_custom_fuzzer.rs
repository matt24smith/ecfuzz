use std::collections::HashSet;
use std::ffi::{c_uint, CString};
use std::io::{stdout, Write};
use std::path::PathBuf;
use std::time::Instant;

use ecfuzz::corpus::{Corpus, CorpusInput};
use ecfuzz::execute::{count_branch_total, Config, Exec, ExecResult};
use ecfuzz::mutator::Mutation;

#[repr(C)]
#[derive(Clone, Debug)]
struct MyTargetInput {
    num1: c_uint,
    num2: c_uint,
    num3: c_uint,
    str1: CString,
    str2: CString,
    str3: CString,
}

struct MyFuzzEngine {
    mutation_engine: Mutation,
    firstname_seeds: Vec<Vec<u8>>,
    lastname_seeds: Vec<Vec<u8>>,
    pub data: MyTargetInput,
}

/// arbitrary types can be used for input, as long as they can serialize to Vec<u8>
impl MyTargetInput {
    /// serialize the test input to byte vector
    pub fn serialize(self, coverage: HashSet<u64>) -> CorpusInput {
        // create byte vector to store input data
        let mut bytes: Vec<u8> = Vec::new();

        // append numbers as bytes
        for num in [self.num1, self.num2, self.num3] {
            let n = num.to_string().as_bytes().to_vec();
            for byte in n {
                bytes.push(byte);
            }
            bytes.push(b'\0');
        }

        // append test as bytes
        for text in [self.str1, self.str2, self.str3] {
            let s = text.as_bytes().iter();
            for byte in s {
                bytes.push(*byte);
            }
            bytes.push(b'\0');
        }

        // serialized input format
        CorpusInput {
            data: bytes,
            coverage,
            lifetime: 0,
            file_stem: PathBuf::from("MyCustomInput"),
            file_ext: PathBuf::from("mutation"),
        }
    }

    /// deserialize the test input from CorpusInput.data: Vec<u8>
    pub fn deserialize(serialized: &CorpusInput) -> Self {
        let mut bytesplit: Vec<Vec<u8>> = vec![];
        let mut cstring: Vec<u8> = vec![];
        for b in &serialized.data {
            if b != &b'\0' {
                cstring.push(*b);
            } else {
                bytesplit.push(cstring);
                cstring = Vec::new();
            }
        }

        bytesplit[3].push(b'\0');
        bytesplit[4].push(b'\0');
        bytesplit[5].push(b'\0');

        MyTargetInput {
            num1: String::from_utf8(bytesplit[0].to_vec())
                .unwrap()
                .parse::<c_uint>()
                .unwrap_or(0),
            num2: String::from_utf8(bytesplit[1].to_vec())
                .unwrap()
                .parse::<c_uint>()
                .unwrap_or(0),
            num3: String::from_utf8(bytesplit[2].to_vec())
                .unwrap()
                .parse::<c_uint>()
                .unwrap_or(0),
            str1: CString::from_vec_with_nul(bytesplit[3].to_vec()).unwrap(),
            str2: CString::from_vec_with_nul(bytesplit[4].to_vec()).unwrap(),
            str3: CString::from_vec_with_nul(bytesplit[5].to_vec()).unwrap(),
        }
    }
}

impl MyFuzzEngine {
    pub fn new() -> Self {
        let multiplier = Some(0.01);
        let dict_path: Option<PathBuf> = None;

        let firstnames = Corpus::load_corpus_file(&PathBuf::from("examples/firstname.dict")).0;
        let lastnames = Corpus::load_corpus_file(&PathBuf::from("examples/lastname.dict")).0;

        MyFuzzEngine {
            mutation_engine: Mutation::new(dict_path, multiplier),
            firstname_seeds: firstnames,
            lastname_seeds: lastnames,
            data: MyTargetInput {
                num1: 0,
                num2: 0,
                num3: 0,
                str1: CString::new([].to_vec()).unwrap(),
                str2: CString::new([].to_vec()).unwrap(),
                str3: CString::new([].to_vec()).unwrap(),
            },
        }
    }

    fn mutate_number_1(mut self) -> Self {
        self.data.num1 = (self.mutation_engine.hashfunc() % 1000usize)
            .try_into()
            .unwrap();
        self
    }
    fn mutate_number_2(mut self) -> Self {
        self.data.num2 = (self.mutation_engine.hashfunc() % 1000usize)
            .try_into()
            .unwrap();
        self
    }
    fn mutate_number_3(mut self) -> Self {
        self.data.num3 = (self.mutation_engine.hashfunc() % 10000usize)
            .try_into()
            .unwrap();
        self
    }
    fn mutate_string_1(mut self) -> Self {
        self.mutation_engine.data = self.firstname_seeds
            [self.mutation_engine.hashfunc() % self.firstname_seeds.len()]
        .clone();
        if self.mutation_engine.hashfunc() % 2 == 0 {
            self.mutation_engine.mutate();
            while self.mutation_engine.data.contains(&b'\0') {
                self.mutation_engine.mutate();
            }
        };
        self.data.str1 = CString::new(self.mutation_engine.data.clone()).unwrap();
        self
    }
    fn mutate_string_2(mut self) -> Self {
        self.mutation_engine.data = self.lastname_seeds
            [self.mutation_engine.hashfunc() % self.lastname_seeds.len()]
        .clone();
        if self.mutation_engine.hashfunc() % 2 == 0 {
            self.mutation_engine.mutate();
            while self.mutation_engine.data.contains(&b'\0') {
                self.mutation_engine.mutate();
            }
        };
        self.data.str2 = CString::new(self.mutation_engine.data.clone()).unwrap();
        self
    }
    fn mutate_string_3(mut self) -> Self {
        self.mutation_engine.data = self.lastname_seeds
            [self.mutation_engine.hashfunc() % self.lastname_seeds.len()]
        .clone();
        if self.mutation_engine.hashfunc() % 2 == 0 {
            while self.mutation_engine.data.contains(&b'\0') {
                self.mutation_engine.mutate();
            }
        };
        self.data.str3 = CString::new(self.mutation_engine.data.clone()).unwrap();
        self
    }

    pub fn mutate(mut self, total_coverage_count: usize) -> Self {
        let idx;
        if total_coverage_count < 6 {
            // "drill mode" column indexing
            // works best when program execution order is known
            idx = total_coverage_count;
        } else {
            // default: select by hash
            idx = self.mutation_engine.hashfunc() % 6;
        }
        [
            MyFuzzEngine::mutate_number_1,
            MyFuzzEngine::mutate_number_2,
            MyFuzzEngine::mutate_number_3,
            MyFuzzEngine::mutate_string_1,
            MyFuzzEngine::mutate_string_2,
            MyFuzzEngine::mutate_string_3,
        ][idx](self)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // sets clang compiler and llvm tools paths to default settings
    // caution: default paths not yet defined for windows
    let mut cfg = Config::defaults();
    cfg.iter_check = 8;
    cfg.target_path = PathBuf::from("./examples/example.c");
    cfg.iterations = 10_000;
    cfg.objects = vec![PathBuf::from("./a.out")];
    cfg.mutate_args = true;

    // compile target with instrumentation
    Exec::initialize(&cfg)?;

    // create new mutation engine and corpus, seed the corpus with zeros
    let mut engine = MyFuzzEngine::new();

    println!("done initialize");
    let mut cov_corpus = Corpus::new();
    let mut crash_corpus = Corpus::new();

    let seed = MyTargetInput {
        num1: 0,
        num2: 0,
        num3: 0,
        str1: CString::from_vec_with_nul(b"\0".to_vec()).unwrap(),
        str2: CString::from_vec_with_nul(b"\0".to_vec()).unwrap(),
        str3: CString::from_vec_with_nul(b"\0".to_vec()).unwrap(),
    };

    println!("seeding: {:?}", &seed);
    cov_corpus.add_and_distill_corpus(seed.serialize(HashSet::new()));

    // coverage profile paths
    let profraw = "output/custom1.profraw";
    let profdata = "output/custom1.profdata";

    let mut out = stdout().lock();

    let mut timer_start = Instant::now();
    for i in 0..cfg.iterations {
        // deserialize mutation inputs stored in the corpus
        let input_raw: CorpusInput = cov_corpus.inputs[i % cov_corpus.inputs.len()].clone();
        engine.data = MyTargetInput::deserialize(&input_raw);

        // apply a mutation
        engine = engine.mutate(cov_corpus.total_coverage.len());
        let mutated = engine.data.clone();

        // run the program with mutated inputs, log crashes to crash corpus
        let (entry, output) = Exec::trial(
            &cfg,
            profraw,
            profdata,
            &mutated.clone().serialize(HashSet::default()).data,
            PathBuf::new(),
            PathBuf::new(),
            0,
        );

        let output = match output {
            ExecResult::Ok(o) => o,
            ExecResult::Err(o) => o,
        };

        // add inputs yielding new coverage to the corpus
        //if !cov_corpus.total_coverage.is_superset(&coverage) {
        if output.stderr.is_empty() && !cov_corpus.total_coverage.is_superset(&entry.coverage) {
            let corpus_entry = engine.data.serialize(entry.coverage);
            out.write_all(&[b'\r'])?;
            cov_corpus.add_and_distill_corpus(corpus_entry);
            println!("\nnew entry! {}", cov_corpus);
        } else if !output.stderr.is_empty() {
            let corpus_entry = engine.data.serialize(entry.coverage);
            out.write_all(&[b'\r'])?;
            crash_corpus.add_and_distill_corpus(corpus_entry);
            eprintln!("\ncrashed! {}", crash_corpus);
        }

        // log some status messages every 100 execs
        if i % cfg.iter_check == 0 && i > 0 {
            let branch_count = count_branch_total(&cfg, profdata)?;
            let status_msg = format!(
                "\r{:0>3} {:0>3} {:0>4}  {: >10}  {: >10}\t{: >10}  branches: {}/{}  exec/s {:.2}  i: {}",
                &mutated.num1,
                &mutated.num2,
                &mutated.num3,
                String::from_utf8_lossy(&mutated.str1.as_bytes().to_vec()),
                String::from_utf8_lossy(&mutated.str2.as_bytes().to_vec()),
                String::from_utf8_lossy(&mutated.str3.as_bytes().to_vec()),
                cov_corpus.total_coverage.len(),
                branch_count,
                cfg.iter_check as f32 / (timer_start.elapsed().as_millis() as f32 / 1000.0),
                i
                );
            timer_start = Instant::now();
            out.write_all(&status_msg.as_bytes().to_vec())?;
            out.flush()?;
        }
    }

    // save the results
    cov_corpus.save(PathBuf::from("output/example1/"))?;
    crash_corpus.save(PathBuf::from("output/example1_crash/"))?;

    Ok(())
}
