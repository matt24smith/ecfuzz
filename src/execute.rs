use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::remove_file;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;

use serde::Deserialize;
use serde_json::Value as jsonValue;

use crate::config::Config;
use crate::corpus::CorpusInput;
use crate::mutator::byte_index;

pub struct Exec {
    pub cfg: Config,
}

pub enum ExecResult<Output> {
    Ok(Output),
    Err(Output),
}

#[derive(Deserialize, Debug, Clone)]
pub struct CovReport {
    pub branches: Vec<[u64; 9]>,
    //pub regions: Vec<[u64; 8]>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ReportFile {
    pub files: Vec<CovReport>,
    //pub functions: Vec<CovReport>,
}

impl Exec {
    /// compile and instrument the target.
    pub fn initialize(cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
        // ensure cc is clang 14
        let check_cc_ver = Command::new(&cfg.cc_path).arg("--version").output()?;
        let cc_ver = String::from_utf8_lossy(&check_cc_ver.stdout);
        println!("{}", cc_ver);
        let cc_ver_major = cc_ver.splitn(2, "version ").collect::<Vec<&str>>()[1]
            .splitn(2, '.')
            .collect::<Vec<&str>>()[0];
        if !cc_ver_major.parse::<u64>()? == 14 {
            panic!("Requires CC version 14 or higher. Found {}", cc_ver);
        }

        let cflag_var = std::env::var("CFLAGS").unwrap_or_default();
        println!("CFLAGS={:?}", cflag_var);
        let cflags = cflag_var.split(' ');

        let mut setup_args: Vec<String> = [
            (cfg.target_path.as_os_str().to_str().unwrap()),
            "-o",
            "a.out",
            "-fprofile-instr-generate",
            "-fcoverage-mapping",
            // asan - very slow on windows and apple arm64
            #[cfg(not(any(target_os = "windows", target_arch = "aarch64")))]
            "-fsanitize=address,undefined",
            // msan doesn't work at the same time as usan on windows
            #[cfg(target_os = "windows")]
            "-fsanitize=undefined",
            // msan - not supported on apple arm64
            // #[cfg(not(target_arch = "aarch64"))]
            //"-fsanitize=memory",
            "-fno-optimize-sibling-calls",
            "-fno-omit-frame-pointer",
            #[cfg(target_arch = "aarch64")]
            "-arch",
            #[cfg(target_arch = "aarch64")]
            "arm64",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        for flag in cflags {
            setup_args.push(flag.to_string());
        }

        println!(
            "compiling...\n{} {}\n",
            &cfg.cc_path.as_os_str().to_str().unwrap(),
            setup_args.join(" ")
        );

        let setup_result = Command::new(&cfg.cc_path).args(setup_args).output()?;
        if !setup_result.stderr.is_empty()
            && !byte_index(&b"error: ".to_vec(), &setup_result.stderr.to_vec()).is_empty()
        {
            panic!(
                "compile failed:\n{}\n{}",
                String::from_utf8(setup_result.stdout)?,
                String::from_utf8(setup_result.stderr)?,
            );
        } else if !setup_result.stderr.is_empty() {
            eprintln!(
                "compiled with warnings:\n{}\n{}",
                String::from_utf8(setup_result.stdout)?,
                String::from_utf8(setup_result.stderr)?,
            );
        }
        println!("done compiling");

        Ok(())
    }

    /// execute the target program with a new test input.
    /// records profile data to the output directory.
    pub fn trial(
        cfg: &Config,
        test_input: &CorpusInput,
        lifetime: u64,
    ) -> (CorpusInput, ExecResult<Output>) {
        let profraw = PathBuf::from(format!(
            "output/{}.profraw",
            std::thread::current().name().expect("getting thread name"),
        ));
        let profdata = PathBuf::from(format!(
            "output/{}.profdata",
            std::thread::current().name().expect("getting thread name"),
        ));

        #[cfg(debug_assertions)]
        assert!(!profraw.exists()); // ensure profile data was cleaned up last time

        let output = exec_target(cfg, &profraw, &test_input.data);

        #[cfg(debug_assertions)]
        assert!(profraw.exists()); // ensure profile data was generated

        index_target_report(cfg, &profraw, &profdata).unwrap();
        remove_file(&profraw).expect("removing raw profile data");

        let cov = check_report_coverage(cfg, &profdata).unwrap();
        remove_file(&profdata).expect("removing coverage profile data");

        // if the program crashes during execution, code coverage checking may
        // yield an empty set. in this case the parent mutation coverage is used
        let new_coverage: HashSet<u64> = match output {
            ExecResult::Ok(_) => cov,
            ExecResult::Err(_) => {
                if cov.is_empty() {
                    test_input.coverage.clone()
                } else {
                    cov
                }
            }
        };
        let result = CorpusInput {
            data: test_input.data.to_owned(),
            coverage: new_coverage,
            lifetime: lifetime + 1,
        };
        (result, output)
    }

    /// count the number of code branches in the coverage file
    pub fn count_branch_total(cfg: &Config) -> Result<u64, Box<dyn std::error::Error>> {
        let profraw = PathBuf::from(format!(
            "output/{}.profraw",
            std::thread::current().name().expect("getting thread name"),
        ));
        let profdata = PathBuf::from(format!(
            "output/{}.profdata",
            std::thread::current().name().expect("getting thread name"),
        ));

        let _output = exec_target(cfg, &profraw, b"");

        index_target_report(cfg, &profraw, &profdata).unwrap();
        remove_file(profraw).expect("removing raw profile data");

        let report: ReportFile = read_report(cfg, &profdata)?;
        remove_file(profdata).expect("removing coverage profile data");

        let mut n: u64 = 0;
        for file in report.files {
            //for file in report.functions {
            for _branch in file.branches {
                //for _branch in file.regions {
                n += 1
            }
        }
        Ok(n)
    }
}

/// execute the target program with a new test input either via an input file,
/// command line arguments, or by sending to the target stdin, as defined in
/// Config
fn exec_target(cfg: &Config, raw_profile_filepath: &PathBuf, input: &[u8]) -> ExecResult<Output> {
    if cfg.mutate_file {
        exec_target_filein(raw_profile_filepath, input)
    } else if cfg.mutate_args {
        exec_target_args(raw_profile_filepath, input)
    } else {
        exec_target_stdin(raw_profile_filepath, input)
    }
}

/// execute the target program with test input sent to stdin
fn exec_target_stdin(raw_profile_filepath: &PathBuf, input: &[u8]) -> ExecResult<Output> {
    #[cfg(debug_assertions)]
    assert!(!std::path::Path::new(&raw_profile_filepath).exists()); // ensure profile data was cleaned up last time
    let mut profile_target = Command::new("./a.out")
        .env("LLVM_PROFILE_FILE", raw_profile_filepath)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let send_input = profile_target.stdin.take().unwrap();
    let mut send_input = BufWriter::new(send_input);

    let mut result = send_input.write_all(input);
    if result.is_ok() {
        result = send_input.flush();
    }

    std::mem::drop(send_input);

    let output = profile_target.wait_with_output().unwrap();

    if result.is_ok() && output.stderr.is_empty() {
        ExecResult::Ok(output)
    } else {
        ExecResult::Err(output)
    }
}

/// execute the target program with test input sent via an input file
fn exec_target_filein(raw_profile_filepath: &PathBuf, input: &[u8]) -> ExecResult<Output> {
    let fname = format!("{}.mutation", std::thread::current().name().unwrap());
    let mut f = BufWriter::new(std::fs::File::create(&fname).unwrap());
    f.write_all(input).unwrap();

    std::mem::drop(f);

    let profile_target = Command::new("./a.out")
        .env("LLVM_PROFILE_FILE", raw_profile_filepath)
        .args(["--mutation-file", &fname])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let result = profile_target.wait_with_output();

    remove_file(fname).expect("removing input mutation file");

    if let Ok(res) = result {
        ExecResult::Ok(res)
    } else {
        ExecResult::Err(result.unwrap())
    }
}

/// execute the target program with test input sent via program arguments
pub fn exec_target_args(raw_profile_filepath: &PathBuf, input: &[u8]) -> ExecResult<Output> {
    let mut args: Vec<Vec<_>> = vec![];
    let mut cursor: Vec<_> = Vec::new();

    for b in input {
        if b == &b'\0' {
            args.push(cursor);
            cursor = Vec::new();
        } else {
            cursor.push(*b);
        }
    }
    if !cursor.is_empty() {
        args.push(cursor);
    }
    #[cfg(not(target_os = "windows"))]
    let os_args: Vec<OsString> = args
        .iter()
        .map(|a| OsStringExt::from_vec(a.to_vec()))
        .collect();
    #[cfg(target_os = "windows")]
    let os_args: Vec<OsString> = args.iter().map(|a| OsStringExt::from_wide(a)).collect();

    let profile_target = Command::new("./a.out")
        .env("LLVM_PROFILE_FILE", raw_profile_filepath)
        .args(os_args)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let output = profile_target.wait_with_output();

    if let Ok(out) = output {
        ExecResult::Ok(out)
    } else {
        ExecResult::Err(output.unwrap())
    }
}

/// convert raw profile data to an indexed file format
fn index_target_report(
    cfg: &Config,
    raw_profile_filepath: &Path,
    profile_filepath: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let prof_merge_args = &[
        "merge".to_string(),
        "-sparse".to_string(),
        //"--instr".to_string(),
        raw_profile_filepath
            .as_os_str()
            .to_str()
            .unwrap()
            .to_string(),
        "-o".to_string(),
        profile_filepath.as_os_str().to_str().unwrap().to_string(),
    ];
    let prof_merge_result = Command::new(&cfg.llvm_profdata_path)
        .args(prof_merge_args)
        .output()
        .expect("merge profile command");
    if !prof_merge_result.status.success() {
        panic!(
            "Could not merge profile data. {}",
            String::from_utf8_lossy(&prof_merge_result.stderr)
        )
    }
    Ok(())
}

/// deserialized indexed report data, and return branch coverage
fn read_report(
    cfg: &Config,
    profile_filepath: &PathBuf,
) -> Result<ReportFile, Box<dyn std::error::Error>> {
    let mut prof_report_args: Vec<String> = [
        "export",
        "--instr-profile",
        profile_filepath.as_os_str().to_str().unwrap(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    #[cfg(debug_assertions)]
    assert!(!cfg.objects.is_empty());

    for obj in &cfg.objects {
        prof_report_args.push("--object".to_string());
        prof_report_args.push(obj.as_os_str().to_string_lossy().to_string());
    }
    let prof_report_result = Command::new(&cfg.llvm_cov_path)
        .args(&prof_report_args)
        .output()
        .unwrap();
    let prof_report_raw = prof_report_result.stdout;
    if prof_report_raw.is_empty() {
        panic!(
            "empty profdata: {:#?}\nargs: {:?}",
            profile_filepath, prof_report_args
        );
    }
    let prof_report_json: jsonValue =
        serde_json::from_slice(&prof_report_raw).expect("reading profdata");
    let prof_report: ReportFile = serde_json::from_value(prof_report_json["data"][0].clone())
        .expect("could not parse JSON profdata!");
    Ok(prof_report)
}

/// read coverage report file and create a HashSet from branches covered in the coverage file
pub fn check_report_coverage(
    cfg: &Config,
    profile_filepath: &PathBuf,
) -> Result<HashSet<u64>, Box<dyn std::error::Error>> {
    let report: ReportFile = read_report(cfg, profile_filepath)?;

    let mut coverageset: HashSet<u64> = HashSet::new();

    let mut i = 0;
    for file in report.files {
        //for file in report.functions {
        for branch in file.branches {
            //for branch in file.regions {
            if branch[4] > 0 {
                coverageset.insert(i);
            }
            i += 1
        }
    }

    Ok(coverageset)
}
