use std::env::vars;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::mutator::main as mutate_stdin;
use crate::mutator::Mutation;

const HELPTXT: &str = r#"
Mutate {}

Options:

  -d, --dictionary-path <file>  Optionally supply a dictionary to enable random
                                dictionary value insertion, and tokenized
                                dictionary replacement

  -s, --seed <seed>             Optionally seed the mutation engine with a given value

  -m, --multiplier <N>          Mutations per byte. Default 0.01

   -, --mutate-stdin            The main loop won't be run. Instead, read data from
                                stdin, and return mutated bytes to stdout. If
                                used, the options below will be ignored.

  -f, --mutate-file             If this flag is set, mutations will be written
                                to './ecfuzz-worker-N.mutation' instead of the
                                target stdin

  -t, --target <fuzz_target.c>  Clang input file. Defaults to '{}'

  -x, --compiler <path>         Compiler path. Defaults to '{}'

  --llvm-profdata-path <path>   Path to llvm-profdata. Defaults to '{}'

  --llvm-cov-path <path>        Path to llvm-cov. Defaults to '{}'

  -i, --iterations <N>          Total number of executions. Default {}

  -c, --corpus <file>           Initial corpus file, entries separated by newlines.
                                Defaults to ./input/corpus. May be repeated

  -C, --corpus-dir <directory>  Initialize corpus from a directory of files, one
                                entry per file. May be repeated for multiple directories

  -o, --object <path>           Object file given to llvm-cov. Defaults to '{}'.
                                May be repeated for multiple files.

  -O, --object-files <path1...> Object files given to llvm-cov. Can be specified
                                as a list of object files or by shell expansion

Pass additional args to the compiler by setting $CFLAGS
"#;

#[derive(Clone)]
pub struct Config {
    pub cc_path: PathBuf,
    pub iter_check: usize,
    pub iterations: usize,
    pub llvm_cov_path: PathBuf,
    pub llvm_profdata_path: PathBuf,
    pub target_path: PathBuf,
    pub dict_path: Option<PathBuf>,
    pub corpus_files: Vec<PathBuf>,
    pub corpus_dirs: Vec<PathBuf>,
    pub seed: Vec<u8>,
    pub objects: Vec<PathBuf>,
    pub mutate_file: bool,
    pub mutate_args: bool,
    pub multiplier: Option<f64>,
}

/// target executor configurations: clang executable path, set CFLAGS variable,
/// max number of executions, etc.
impl Config {
    /// returns CLI help text including platform-specific defaults
    pub fn help(mut mutator: Mutation) -> String {
        let defaults = Config::defaults();
        mutator.data = defaults
            .target_path
            .as_os_str()
            .to_str()
            .unwrap()
            .as_bytes()
            .to_vec();
        mutator.mutate();
        let header: String = String::from_utf8_lossy(&mutator.data).to_string();
        let mut help = HELPTXT.to_owned();
        for arg in [
            &header,
            defaults.target_path.as_os_str().to_str().unwrap(),
            defaults.cc_path.as_os_str().to_str().unwrap(),
            defaults.llvm_profdata_path.as_os_str().to_str().unwrap(),
            defaults.llvm_cov_path.as_os_str().to_str().unwrap(),
            format!("{}", defaults.iterations).as_ref(),
            defaults.objects[0].as_os_str().to_str().unwrap(),
        ] {
            help = help.replacen("{}", arg, 1);
        }
        help
    }

    /// initialize target execution config with default values
    pub fn defaults() -> Self {
        Config {
            iter_check: 100, // frequency of printed status updates
            iterations: 10000,
            target_path: PathBuf::from("./fuzz_target.c"),

            // default paths for Linux
            #[cfg(target_os = "linux")]
            cc_path: PathBuf::from("/usr/bin/clang"),
            #[cfg(target_os = "linux")]
            llvm_profdata_path: PathBuf::from("/usr/bin/llvm-profdata"),
            #[cfg(target_os = "linux")]
            llvm_cov_path: PathBuf::from("/usr/bin/llvm-cov"),

            // default paths for MacOS
            #[cfg(target_os = "macos")]
            //cc_path: PathBuf::from("/Library/Developer/CommandLineTools/usr/bin/clang"),
            cc_path: PathBuf::from("/usr/bin/clang"),
            #[cfg(target_os = "macos")]
            llvm_profdata_path: PathBuf::from(
                "/Library/Developer/CommandLineTools/usr/bin/llvm-profdata",
                ),
                #[cfg(target_os = "macos")]
            llvm_cov_path: PathBuf::from("/Library/Developer/CommandLineTools/usr/bin/llvm-cov"),

            // default paths for Windows
            #[cfg(target_os = "windows")]
            cc_path: PathBuf::from(r"C:\Program Files\LLVM\bin\clang.exe"),
            #[cfg(target_os = "windows")]
            llvm_profdata_path: PathBuf::from(r"C:\Program Files\LLVM\bin\llvm-profdata.exe"),
            #[cfg(target_os = "windows")]
            llvm_cov_path: PathBuf::from(r"C:\Program Files\LLVM\bin\llvm-cov.exe"),

            dict_path: None,
            seed: Vec::new(),
            corpus_files: Vec::new(),
            corpus_dirs: Vec::new(),
            objects: vec![PathBuf::from("a.out")],
            mutate_file: false,
            mutate_args: false,
            multiplier: Some(0.01),
        }
    }

    /// Update Config settings as set by environment variables
    pub fn load_env(&mut self) {
        for (k, v) in vars()
            .filter(|kv| kv.0.contains("ECFUZZ_"))
            .collect::<Vec<(String, String)>>()
        {
            println!("{}={}", k, v);
            match k.as_ref() {
                "ECFUZZ_CC_PATH" => self.cc_path = PathBuf::from(v),
                "ECFUZZ_CORPUS_DIRS" => {
                    self.corpus_dirs = v.split_whitespace().map(PathBuf::from).collect()
                }
                "ECFUZZ_CORPUS_FILES" => {
                    self.corpus_files = v.split_whitespace().map(PathBuf::from).collect()
                }
                "ECFUZZ_DICT_PATH" => self.dict_path = Some(PathBuf::from(v)),
                "ECFUZZ_ITERATIONS" => {
                    self.iterations = v.parse().expect("parsing $ECFUZZ_ITERATIONS as usize")
                }
                "ECFUZZ_ITER_CHECK" => {
                    self.iter_check = v.parse().expect("parsing $ECFUZZ_ITER_CHECK as usize")
                }
                "ECFUZZ_LLVM_COV_PATH" => self.llvm_cov_path = PathBuf::from(v),
                "ECFUZZ_LLVM_PROFDATA_PATH" => self.llvm_profdata_path = PathBuf::from(v),
                "ECFUZZ_MULTIPLIER" => {
                    self.multiplier = Some(v.parse().expect("parsing $ECFUZZ_MULTIPLIER as f64"))
                }
                "ECFUZZ_MUTATE_ARGS" => self.mutate_args = true,
                "ECFUZZ_MUTATE_FILE" => self.mutate_file = true,
                "ECFUZZ_OBJECTS" => {
                    self.objects = v.split_whitespace().map(PathBuf::from).collect()
                }
                "ECFUZZ_SEED" => self.seed = v.into_bytes(),
                _ => {
                    panic!("unknown env option {}", k)
                }
            }
        }
    }

    /// Parse command line arguments as a Config struct.
    /// If "-h" or "--help" is given as an argument, the help text
    /// will be printed and the program will exit.
    pub fn parse_args() -> Result<Config, Box<dyn std::error::Error>>
    where
        Self: Sized,
    {
        let mut cfg: Config = Config::defaults();

        let mut args: Vec<String> = vec![];
        for arg in std::env::args() {
            for a in arg.splitn(2, '=') {
                args.push(a.to_string());
            }
        }

        // print help text
        if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
            let t = (SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap())
            .as_secs()
            .to_string();
            let mutator = Mutation::with_seed(None, t.as_bytes().to_vec(), None);
            println!("{}", Config::help(mutator));
            std::process::exit(0);
        }

        // warn about extra arguments
        let argstring = HELPTXT.replace(',', " ");
        let known_args: Vec<&str> = argstring
            .split(' ')
            .filter(|a| !a.is_empty() && a.starts_with('-'))
            .collect();
        for arg in args.iter().filter(|a| a.starts_with('-')) {
            if !known_args.iter().any(|a| a.contains(arg)) {
                eprintln!("\x1b[91mWarning\x1b[0m: unknown argument {}", arg);
            }
        }

        // mutator mode
        if std::env::args().any(|x| x == *"--mutate-stdin" || x == *"-") {
            mutate_stdin()?;
            std::process::exit(0);
        }

        if args.contains(&"-f".to_string()) || args.contains(&"--mutate-file".to_string()) {
            cfg.mutate_file = true;
        }

        if args.contains(&"-d".to_string()) || args.contains(&"--dictionary-path".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-d" || arg == "--dictionary-path" {
                    stop = true;
                } else if stop {
                    cfg.dict_path = Some(PathBuf::from(arg));
                    break;
                }
            }
        }

        if args.contains(&"-s".to_string()) || args.contains(&"--seed".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-s" || arg == "--seed" {
                    stop = true
                } else if stop {
                    cfg.seed = arg.as_bytes().to_vec();
                    break;
                }
            }
        }

        if args.contains(&"-t".to_string()) || args.contains(&"--target".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-t" || arg == "--target" {
                    stop = true
                } else if stop {
                    cfg.target_path = PathBuf::from(arg);
                    break;
                }
            }
        }

        if args.contains(&"-x".to_string()) || args.contains(&"--compiler".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-x" || arg == "--compiler" {
                    stop = true
                } else if stop {
                    cfg.cc_path = PathBuf::from(arg);
                    break;
                }
            }
        }

        if args.contains(&"--llvm-profdata-path".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "--llvm-profdata-path" {
                    stop = true
                } else if stop {
                    cfg.llvm_profdata_path = PathBuf::from(arg);
                    break;
                }
            }
        }
        if args.contains(&"--llvm-cov-path".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "--llvm-cov-path" {
                    stop = true
                } else if stop {
                    cfg.llvm_cov_path = PathBuf::from(arg);
                    break;
                }
            }
        }
        if args.contains(&"-m".to_string()) || // #
                args.contains(&"--multiplier".to_string())
        {
            let mut stop = false;
            for arg in &args {
                if arg == "-m" || arg == "--multiplier" {
                    stop = true
                } else if stop {
                    cfg.multiplier = Some(arg.parse()?);
                    break;
                }
            }
        }
        if args.contains(&"-i".to_string()) || args.contains(&"--iterations".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-i" || arg == "--iterations" {
                    stop = true
                } else if stop {
                    cfg.iterations = arg.parse()?;
                    break;
                }
            }
        }

        if args.contains(&r#"-c"#.to_string()) ||  // #
                args.contains(&"--corpus".to_string())
        {
            let mut stop = false;
            for arg in &args {
                if arg == "-c" || arg == "--corpus" {
                    stop = true
                } else if stop {
                    cfg.corpus_files.push(PathBuf::from(arg));
                    stop = false
                }
            }
        }

        if args.contains(&"-C".to_string()) ||  // #
                args.contains(&"--corpus-dir".to_string())
        {
            let mut stop = false;
            for arg in &args {
                if arg == "-C" || arg == "--corpus-dir" {
                    stop = true
                } else if stop {
                    cfg.corpus_dirs.push(PathBuf::from(arg));
                    stop = false
                }
            }
        }

        if args.contains(&"-o".to_string()) || args.contains(&"--object".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-o" || arg == "--object" {
                    stop = true
                } else if stop {
                    cfg.objects.push(PathBuf::from(arg));
                    stop = false
                }
            }
        }
        if args.contains(&"-O".to_string()) || args.contains(&"--object-files".to_string()) {
            let mut stop = false;
            for arg in &args {
                if arg == "-O" || arg == "--object-files" {
                    stop = true;
                } else if stop && arg[..1] != *"-" {
                    cfg.objects.push(PathBuf::from(arg));
                } else {
                    stop = false;
                }
            }
        }

        if cfg.corpus_dirs.is_empty() && cfg.corpus_files.is_empty() {
            cfg.corpus_files.push(PathBuf::from("./input/corpus"));
        }
        Ok(cfg)
    }
}
