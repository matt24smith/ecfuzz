<img style="display: block; margin-left: auto; margin-right: auto;" src="/examples/animate_logo/output/ecfuzz.gif" alt="ECFuzz"></img>

## ECFuzz
Evolutionary Coverage-guided Fuzzing engine. Requires clang 14 and llvm tools.

### Quick Start
There are 2 errors in ``fuzz_target.c``, occurring after some 'if' statements depending on user input.
The program will compile and run the target file with embedded instrumentation, and send mutated inputs based on the samples in ``./input/corpus`` to the executable's standard input.
The code coverage of each new input is monitored, and any inputs yielding new code coverage will be added to the corpus.

```bash
cargo install ecfuzz
git clone https://github.com/matt24smith/ecfuzz.git && cd ecfuzz
export CFLAGS="-std=c17 -g -fcolor-diagnostics -O3"
ecfuzz --target fuzz_target.c --corpus ./input/corpus --dictionary-path input/sample.dict --seed 000 --iterations 5000
```

Initializing the fuzzing engine with seed ``000`` finds both bugs in ``fuzz_target.c`` after 4628 attempts.
Results will be deterministic as long as the corpus, dictionary, and seed remain unchanged.
Mutations will be logged to the same directory as the ``corpus`` file.

```text
...
branch hits: 10/12  exec/s: 63.21  inputs: 2  i: 4600  ABCDE0001000000
fuzz_target.c:12:15: runtime error: applying zero offset to null pointer       
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior fuzz_target.c:12:15 in 
fuzz_target.c:12:15: runtime error: store to null pointer of type 'char'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior fuzz_target.c:12:15 in

  This frame has 1 object(s):
    [32, 288) 'str1' <== Memory access at offset 32 is inside this variable

SUMMARY: AddressSanitizer: unknown-crash (/home/matt/ecfuzz/a.out+0x11a322) (BuildId: d47f3011239226931362fe3a8999c8bc129a9a52) in do_comparison
Shadow bytes around the buggy address:
  0x10005a40c570: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10005a40c580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x10005a40c590: f1 f1 f1 f1[00]00 00 00 00 00 00 00 00 00 00 00
  0x10005a40c5a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10005a40c5b0: 00 00 00 00 f3 f3 f3 f3 f3 f3 f3 f3 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:             00 
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
...
crashing path A...
New crash! execs: 4628  crash log:
  Corpus { inputs: [
    CorpusInput:  { stem: "corpus", coverage: {}, lifetime: 7, preview: "ABCDEF\r00000000\r" }],
  Total coverage: {} }
```


See the full list of options with the ``--help`` flag

```bash
ecfuzz --help
```


Another example shows implementation of a custom fuzzer for ``examples/example_lib.c`` and ``examples/example.c``, sending inputs as arguments to the target executable
```bash
cargo run --example=example_custom_fuzzer
```

Windows users can download clang+LLVM here: 
https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/LLVM-14.0.6-win64.exe


### Distillation Strategy
1. compile target with code coverage mapping, asan, and usan
2. mutate one of the seeded inputs, and send it to the target via stdin
3. measure code coverage as a set of code branches executed
4. if a new branch is discovered by a mutation, add it to the corpus.
  - 4b. compare the new branch coverage to existing corpus entries,
    and prune entries with a coverage subset of the newest coverage


### Mutations
- XOR bit flip + byteshift
- byte replacement
- magic character replacement
- dictionary insertion
- tokenized dictionary replacement

Try it out!
```bash
ecfuzz --help | tail -n+4 | ecfuzz --mutate-stdin --seed 1
```


#### Dictionary mutations
To enable dictionary mutations, a dictionary filepath must be included.
Lines in the dictionary file containing `key` items will be spliced into the input.
Dictionary lines containing `key=value` will be inserted using tokenized replacement , e.g. mutate a `key` item in the seed input by replacing it with a `value`. 
Keys are split on the first `=` symbol, and keys may be repeated on a new line for multiple values.

