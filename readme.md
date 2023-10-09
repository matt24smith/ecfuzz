<img style="display: block; margin-left: auto; margin-right: auto;" src="https://raw.githubusercontent.com/matt24smith/ecfuzz/master/examples/animate_logo/output/ecfuzz.gif" alt="ECFuzz"></img>

# ECFuzz
Evolutionary Coverage-guided Fuzzing engine. 
Lightweight, multithreaded, deterministic. 
Supports mutational and tree-based generative fuzzing.
Mutations are managed by a genetic algorithm selecting for maximized code coverage, filtering redundant inputs.
A library interface is also provided in addition to the command-line utility. 
Requires clang 14 (or newer) and llvm tools.


## Quick Start
Clang and llvm tools can be installed with your preferred package manager.
For the best fuzzing performance, refer to the section below on [Installing clang and LLVM from Source](#install-clang-and-llvm-from-source)

Install ``ecfuzz`` with cargo, and run it using the command line interface. 
Setting the ``--mutate-stdin`` flag generates a single mutation from standard input without measuring code coverage. 
Mutated results are output to stdout.


```bash
cargo install ecfuzz
ecfuzz --help
echo 'Hello world!' | ecfuzz --mutate-stdin --seed 0
```

See examples below for a demonstration of how source code coverage is measured for a preset number of mutations.

## How it works

### Interfaces
 - CLI (see `ecfuzz --help`)
 - Rust lib (docs: <https://docs.rs/ecfuzz/latest/ecfuzz/>)
 - [LibFuzzer fuzz targets](<https://www.llvm.org/docs/LibFuzzer.html#fuzz-target>)
    - `libfuzzer-driver.cpp` can be included as a target from the project repo as a drop-in replacement for `StandaloneFuzzTargetMain.c`

### Corpus Distillation
A genetic algorithm is used to maximize code coverage while minimizing corpus size:
1. Compile target with code coverage mapping and sanitizers
2. Mutate one of the seeded inputs, and send it to the target via stdin, input file, or command args
3. Measure code coverage as a set of code branches executed
4. If a new branch is discovered by a mutation, add it to the corpus
    - Compare the new branch coverage to existing corpus entries, and prune entries with a coverage subset of the newest coverage
    - If two coverage sets are equal, the shortest input will be chosen as a tie breaker. If input lengths are equal, choose the first input when sorted by byte order

### Test Case Minimization
In addition to maintaining a minimal set of inputs in the corpus, each input in the corpus can be minimized. Bytes will be removed from the input until no further bytes can be removed without changing the code coverage, stdout, and stderr returned from the target executable.


### Number Generation

The xxhash algorithm is used for number generation, resulting in fully deterministic fuzzer output

### Byte Mutations
- XOR bit flip + byteshift
- byte insert
- byte delete
- byte replace
- magic character replacement
- dictionary insertion
- tokenized dictionary replacement

#### Dictionary mutations
To enable dictionary mutations, a dictionary filepath must be included.
Lines in the dictionary file containing `key` items will be spliced into the input.
Dictionary lines containing `key=value` will be inserted using tokenized replacement , e.g. mutate a `key` item in the seed input by replacing it with a `value`. 
Keys are split on the first `=` symbol, and keys may be repeated on a new line for multiple values.


### Grammar Fuzzing
In addition to mutational fuzzing, a byte map can be supplied to specify a grammar syntax tree. 
Each line (seperated by '\n') defines a tree node, with `key=value` separated by the first `=` symbol.
Parent nodes must be defined before child nodes, and parents may have multiple children.
Mutations will be generated from a depth-first walk through the resulting tree, with node navigations selected by hash.

Grammar-generated inputs will be sent to stdin from the grammar file given to `--grammar <path>`, and inputs generated from grammar file `--arg-grammar <path>` will be passed as arguments to the target executable.
Input substrings surrounded by `ECFUZZ_START_MUTATION`,`ECFUZZ_END_MUTATION` will be mutated with byte and dictionary mutations.
If `--mutate-file` is set, input substrings matching `ECFUZZ_MUTATED_FILE` wil be replaced with a path to the mutated file.

`--print-grammar-file <path>` can be used to display a string representation of the resulting tree, e.g. `ecfuzz --print-grammar-file ./tests/phone_number.grammar`

## Examples

### CLI
There are 2 errors in [fuzz_target.c](https://github.com/matt24smith/ecfuzz/blob/master/examples/cli/fuzz_target.c), occurring after some 'if' statements depending on user input.
The program will compile and run the target file with embedded instrumentation, and send mutated inputs based on the samples in ``./examples/cli/input/corpus`` to the executable.
The code coverage of each new input is monitored, and any inputs yielding new code coverage will be added to the corpus.

```bash
git clone https://github.com/matt24smith/ecfuzz.git && cd ecfuzz

# set additional flags for the clang compiler 
export CFLAGS="-std=c17 -g -fcolor-diagnostics -O3"

# see 'ecfuzz --help' for a complete description of arguments
ecfuzz \
  --target ./examples/cli/fuzz_target.c \
  --corpus ./examples/cli/input/corpus \
  --output-dir ./output/cli_demo/ \
  --dictionary-path ./examples/cli/input/sample.dict \
  --iterations 10000 \
  --seed 117 --plaintext 2>&1 | tee fuzz.log

```

Sanitizer output and other target error messages will be written to stderr.

Example output:
<details>
<summary>
Fuzz.log
</summary>

```text
CFLAGS="-std=c17 -g -fcolor-diagnostics -O3 -fuse-ld=lld"
LDFLAGS="-fuse-ld=lld"
compiling...
target binary /home/matt/ecfuzz/output/cli_demo/ecfuzz_target.address-sanitized.fuzz_target.out newer than target source, skipping compilation...
target binary /home/matt/ecfuzz/output/cli_demo/ecfuzz_target.cfi-sanitized.fuzz_target.out newer than target source, skipping compilation...
target binary /home/matt/ecfuzz/output/cli_demo/ecfuzz_target.safe-stack-sanitized.fuzz_target.out newer than target source, skipping compilation...
target binary /home/matt/ecfuzz/output/cli_demo/ecfuzz_target.thread-sanitized.fuzz_target.out newer than target source, skipping compilation...
target binary /home/matt/ecfuzz/output/cli_demo/ecfuzz_target.memory-sanitized.fuzz_target.out newer than target source, skipping compilation...
target binary /home/matt/ecfuzz/output/cli_demo/ecfuzz_target.undefined-sanitized.fuzz_target.out newer than target source, skipping compilation...
done compiling
New coverage! execs: 512    pruned: 1  corpus size: 1    updating inputs...            
    CorpusInput:  { coverage: 2, lifetime: 1, preview: "000000000000000" }

coverage:     2/12     exec/s: 2626  corpus size: 1    unique crashes: 0    i: 512     
New coverage! execs: 535    pruned: 0  corpus size: 2    updating inputs...            
    CorpusInput:  { coverage: 3, lifetime: 1, preview: "AB0000000000000" }

coverage:     4/12     exec/s: 2548  corpus size: 2    unique crashes: 0    i: 535     
New coverage! execs: 773    pruned: 1  corpus size: 2    updating inputs...            
    CorpusInput:  { coverage: 4, lifetime: 1, preview: "GH0000000000000" }

coverage:     6/12     exec/s: 2159  corpus size: 2    unique crashes: 0    i: 773     
New coverage! execs: 1938   pruned: 1  corpus size: 2    updating inputs...            
    CorpusInput:  { coverage: 4, lifetime: 1, preview: "ABC000000000000" }

coverage:     7/12     exec/s: 1778  corpus size: 2    unique crashes: 0    i: 1938    
New coverage! execs: 1940   pruned: 1  corpus size: 2    updating inputs...            
    CorpusInput:  { coverage: 5, lifetime: 2, preview: "GHI000000000000" }

coverage:     8/12     exec/s: 1777  corpus size: 2    unique crashes: 0    i: 1940    
New coverage! execs: 2909   pruned: 1  corpus size: 2    updating inputs...            
    CorpusInput:  { coverage: 6, lifetime: 3, preview: "GHIJ000000000000" }

coverage:     9/12     exec/s: 1709  corpus size: 2    unique crashes: 0    i: 2909    
New coverage! execs: 3397   pruned: 1  corpus size: 2    updating inputs...            
    CorpusInput:  { coverage: 5, lifetime: 1, preview: "ABCD0000000000" }

coverage:    10/12     exec/s: 1693  corpus size: 2    unique crashes: 0    i: 3397    
New coverage! execs: 4218   pruned: 1  corpus size: 2    updating inputs...            
    CorpusInput:  { coverage: 6, lifetime: 2, preview: "ABCDE0000000000" }

coverage:    11/12     exec/s: 1670  corpus size: 2    unique crashes: 0    i: 4218    
New coverage! execs: 5142   pruned: 1  corpus size: 2    updating inputs...            
    CorpusInput:  { coverage: 7, lifetime: 4, preview: "GHIJK000000000" }

coverage:    12/12     exec/s: 1646  corpus size: 2    unique crashes: 0    i: 5142    

New crash! execs: 6165   pruned: 1   unique crashes: 1    updating crash log...                              
    CorpusInput:  { coverage: 6, lifetime: 2, preview: "ABCDE00000000" }
==3339243==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x55c542fd86b0 in do_comparison /home/matt/ecfuzz/examples/cli/fuzz_target.c:4:7
    #1 0x55c542fd86b0 in main /home/matt/ecfuzz/examples/cli/fuzz_target.c:40:3
    #2 0x7f908554accf  (/usr/lib/libc.so.6+0x27ccf) (BuildId: 023ea16fd6c04ef9cf094507024e6ecdb35e02ca)
    #3 0x7f908554ad89 in __libc_start_main (/usr/lib/libc.so.6+0x27d89) (BuildId: 023ea16fd6c04ef9cf094507024e6ecdb35e02ca)
    #4 0x55c542f422c4 in _start (/home/matt/ecfuzz/output/cli_demo/ecfuzz_target.memory-sanitized.fuzz_target.out+0x672c4)

SUMMARY: MemorySanitizer: use-of-uninitialized-value /home/matt/ecfuzz/examples/cli/fuzz_target.c:4:7 in do_comparison
Exiting

coverage:    12/12     exec/s: 1631  corpus size: 2    unique crashes: 1    i: 6165    

New crash! execs: 6400   pruned: 1   unique crashes: 2    updating crash log...                              
    CorpusInput:  { coverage: 7, lifetime: 4, preview: "GHIJKL00000000" }
crashing path B...
==3340218==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x561478b4671b in do_comparison /home/matt/ecfuzz/examples/cli/fuzz_target.c:10:15
    #1 0x561478b4671b in main /home/matt/ecfuzz/examples/cli/fuzz_target.c:40:3
    #2 0x7f13677afccf  (/usr/lib/libc.so.6+0x27ccf) (BuildId: 023ea16fd6c04ef9cf094507024e6ecdb35e02ca)
    #3 0x7f13677afd89 in __libc_start_main (/usr/lib/libc.so.6+0x27d89) (BuildId: 023ea16fd6c04ef9cf094507024e6ecdb35e02ca)
    #4 0x561478ab02c4 in _start (/home/matt/ecfuzz/output/cli_demo/ecfuzz_target.memory-sanitized.fuzz_target.out+0x672c4)

SUMMARY: MemorySanitizer: use-of-uninitialized-value /home/matt/ecfuzz/examples/cli/fuzz_target.c:10:15 in do_comparison
Exiting

coverage:    12/12     exec/s: 1630  corpus size: 2    unique crashes: 2    i: 6400    
coverage:    12/12     exec/s: 1607  corpus size: 2    unique crashes: 2    i: 10000   
```

</details>

### LibFuzzer example

ECFuzz is compatible with LibFuzzer test harnesses.
To run LibFuzzer tests, include [`libfuzzer-driver.cpp`](https://github.com/matt24smith/ecfuzz/blob/master/libfuzzer-driver.cpp) from the project repository as a target, and set the compiler to `clang++`. 
This source file is drop-in replacement for [`StandaloneFuzzTargetMain.c`](https://github.com/llvm-mirror/compiler-rt/blob/master/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c), sending input to the target stdin.
Example: [Running LibFuzzer targets under ECFuzz](https://github.com/matt24smith/ecfuzz/blob/master/examples/libfuzzer-example/)

## Install Clang and LLVM from source

Building the clang compiler from the latest source code instead of installing with a package manager may improve fuzzing performance significantly.
The recommended configuration to build and install clang and LLVM tools to `/opt/bin/` using the [Ninja build system](https://ninja-build.org/) is as follows:

```bash
# tested with clang v18.0.0
git clone https://github.com/llvm/llvm-project.git
cd llvm-project

# configure the build
cmake -S llvm -B build -G Ninja \
  -DCMAKE_BUILD_TYPE="Release" \
  -DCMAKE_INSTALL_PREFIX=/opt \
  -DLLVM_ENABLE_RUNTIMES=all \
  -DLLVM_PARALLEL_LINK_JOBS=1 \
  -DLLVM_USE_LINKER="lld" \
  -DLLDB_ENABLE_LIBEDIT=1 \
  -DLLDB_ENABLE_PYTHON=1 \
  -DLLVM_ENABLE_PROJECTS='clang;clang-tools-extra;lld;lldb;polly;compiler-rt'


# build and install
ninja -C build check-llvm
sudo -E ninja -C build install
```

Then update the environment:
```bash
# install paths
export ECFUZZ_CC_PATH="/opt/bin/clang"
export ECFUZZ_LLVM_COV_PATH="/opt/bin/llvm-cov"
export ECFUZZ_LLVM_PROFDATA_PATH="/opt/bin/llvm-profdata"

# build options
export CFLAGS="-O3 -mllvm -polly -std=c17 -g -fcolor-diagnostics -fuse-ld=lld -fsanitize=undefined,address"
```

For more info on building clang and LLVM from source, see:
<https://llvm.org/docs/GettingStarted.html#getting-the-source-code-and-building-llvm>

For more info on ensuring determistic output from the clang compiler, see: 
<https://blog.llvm.org/2019/11/deterministic-builds-with-clang-and-lld.html>,
