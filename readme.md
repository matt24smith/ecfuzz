<img style="display: block; margin-left: auto; margin-right: auto;" src="https://raw.githubusercontent.com/matt24smith/ecfuzz/master/examples/animate_logo/output/ecfuzz.gif" alt="ECFuzz"></img>

# ECFuzz
Evolutionary Coverage-guided Fuzzing engine. 
Lightweight, multithreaded, fully deterministic. 
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
ecfuzz --help | tail -n+4 | ecfuzz --mutate-stdin --seed 1
```

See examples below for a demonstration of how source code coverage is measured for a preset number of mutations.

## How it works

### Corpus Distillation
1. compile target with code coverage mapping and sanitizers
2. mutate one of the seeded inputs, and send it to the target via stdin, input file, or command args
3. measure code coverage as a set of code branches executed
4. if a new branch is discovered by a mutation, add it to the corpus
    - compare the new branch coverage to existing corpus entries, and prune entries with a coverage subset of the newest coverage


### Number Generation

The xxhash algorithm is used for number generation, which means that fuzzing results will be fully deterministic as long as the input remains unchanged, even across different platforms.


### Mutations
- XOR bit flip + byteshift
- byte replacement
- magic character replacement
- dictionary insertion
- tokenized dictionary replacement

#### Dictionary mutations
To enable dictionary mutations, a dictionary filepath must be included.
Lines in the dictionary file containing `key` items will be spliced into the input.
Dictionary lines containing `key=value` will be inserted using tokenized replacement , e.g. mutate a `key` item in the seed input by replacing it with a `value`. 
Keys are split on the first `=` symbol, and keys may be repeated on a new line for multiple values.


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
    --dictionary-path ./examples/cli/input/sample.dict \
    --seed 0 \
    --iterations 10000
```

Results will be deterministic as long as the inputs (and ecfuzz version) remain unchanged.
Sanitizer output and other target error messages will be written to stderr.

Example output (sanitizers disabled):
```text
...

branches hit by initial corpus: 0/12
New coverage! execs: 554  updating inputs...                                                 
  Corpus { inputs: [
    CorpusInput:  { coverage: {7, 6}, lifetime: 1, preview: "GH0000000000000" }], 
  Total coverage: {6, 7} }

...

New coverage! execs: 4161  updating inputs...                                                 
  Corpus { inputs: [
    CorpusInput:  { coverage: {4, 1, 0, 3, 2}, lifetime: 4, preview: "ABCDE0000000000" }, 
    CorpusInput:  { coverage: {8, 7, 6}, lifetime: 2, preview: "GHI000000000000" }], 
  Total coverage: {4, 3, 6, 8, 7, 0, 1, 2} }

New crash! execs: 5416  updating crash log...                                                 
  Corpus { inputs: [
    CorpusInput:  { coverage: {1, 6, 4, 2, 0, 5, 3}, lifetime: 5, preview: "ABCDEF000000000" }], 
  Total coverage: {5, 3, 4, 1, 6, 2, 0} }
crashing path A...

Known crash! execs: 5793                                                                        
crashing path A...

...

coverage: 10/12  exec/s: 2222  corpus size: 2  unique crashes: 2  i: 10000  GH�JK0000000000
```

### Custom Fuzzer using ECFuzz Library

Another example shows implementation of a custom fuzzer for ``./examples/lib_custom_fuzzer/example_lib.c`` and ``examples/lib_custom_fuzzer/example.c``, sending inputs as arguments to the target executable
```bash
cargo run --example=custom_fuzzer
```

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
  -DCMAKE_INSTALL_PREFIX="/opt" \
  -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lld;lldb;polly;compiler-rt" \ 
  -DLLVM_ENABLE_RUNTIMES=all \
  -DLLVM_PARALLEL_LINK_JOBS=1 \
  -DLLVM_USE_LINKER="lld"

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
