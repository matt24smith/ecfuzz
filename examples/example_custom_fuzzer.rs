use std::collections::HashSet;
use std::ffi::{c_uint, CString};
use std::io::{stdout, Write};
use std::path::PathBuf;
use std::time::Instant;

use ecfuzz::corpus::{load_corpus, Corpus, CorpusInput};
use ecfuzz::execute::{
    check_report_coverage, count_branch_total, exec_target_args, index_target_report, Config, Exec,
};
use ecfuzz::mutator::Mutation;

#[repr(C)]
#[derive(Clone)]
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
        MyFuzzEngine {
            mutation_engine: Mutation::new(None),
            firstname_seeds: load_corpus(&PathBuf::from("examples/firstname.dict")),
            lastname_seeds: load_corpus(&PathBuf::from("examples/lastname.dict")),
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

    /// return mutated string arguments that will be sent to target argv
    /// caution: data sent to the target program may contain invalid strings
    pub fn get_target_args(&self) -> [String; 6] {
        unsafe {
            [
                format!("{}", &self.data.num1).to_string(),
                format!("{}", &self.data.num2).to_string(),
                format!("{}", &self.data.num3).to_string(),
                String::from_utf8_unchecked(self.data.str1.as_bytes().to_vec()),
                String::from_utf8_unchecked(self.data.str2.as_bytes().to_vec()),
                String::from_utf8_unchecked(self.data.str3.as_bytes().to_vec()),
            ]
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

    // compile target with instrumentation
    Exec::initialize(&cfg)?;

    // create new mutation engine and corpus, seed the corpus with zeros
    let mut engine = MyFuzzEngine::new();
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
    cov_corpus.add(seed.serialize(HashSet::new()));

    // initial profile paths
    let rawprof = "init.profraw";
    let profdata = "init.profdata";

    let mut out = stdout().lock();

    let mut timer_start = Instant::now();
    for i in 0..cfg.iterations {
        // deserialize mutation inputs stored in the corpus
        let input_raw: CorpusInput = cov_corpus.inputs[i % cov_corpus.inputs.len()].clone();
        engine.data = MyTargetInput::deserialize(&input_raw);

        // apply a mutation
        engine = engine.mutate(cov_corpus.total_coverage.len());

        // run the program with mutated inputs, log crashes to crash corpus
        let args = engine.get_target_args();
        let crashed = exec_target_args(rawprof, &args).unwrap();
        if crashed {
            crash_corpus
                .inputs
                .push(engine.data.serialize(input_raw.coverage));
            continue;
        }

        // check the program coverage
        index_target_report(&cfg, &rawprof, &profdata)?;
        let coverage = check_report_coverage(&cfg, &profdata)?;

        // add inputs yielding new coverage to the corpus
        if !cov_corpus.total_coverage.is_superset(&coverage) {
            let corpus_entry = engine.data.serialize(coverage);
            out.write_all(&[b'\r'])?;
            cov_corpus.add_and_distill_corpus(corpus_entry);
        }

        // log some status messages every 100 execs
        if i % cfg.iter_check == 0 && i > 0 {
            let branch_count = count_branch_total(&cfg, profdata)?;
            let status_msg = format!(
                "\r{:>3} {:>3} {:>4}{}{:?}{}{:?}{}{:?}\t\tbranches: {:?}/{}\texec/s {:.2}\ti: {}",
                &args[0],
                &args[1],
                &args[2],
                vec![' '; 12 - args[3].len()].iter().collect::<String>(),
                String::from_utf8_lossy(&args[3].as_bytes().to_vec()),
                vec![' '; 12 - args[4].len()].iter().collect::<String>(),
                String::from_utf8_lossy(&args[4].as_bytes().to_vec()),
                vec![' '; 12 - args[5].len()].iter().collect::<String>(),
                String::from_utf8_lossy(&args[5].as_bytes().to_vec()),
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
    cov_corpus.save(&PathBuf::from("output/"), "example_output", false)?;
    crash_corpus.save(&PathBuf::from("output/"), "example_crashes", false)?;

    Ok(())
}
