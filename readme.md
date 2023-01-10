## ECFuzz
Evolutionary Coverage-guided Fuzzing engine. Requires clang 14 and llvm tools.


### Quick Start
There are 2 errors in ``fuzz_target.c``, occurring after some 'if' statements depending on user input.
The program will compile and run the target file with embedded instrumentation, and send mutated inputs based on the samples in ``./corpus/start`` to the executable's standard input.
The code coverage of each new input is monitored, and any inputs yielding new code coverage will be added to the corpus.

```bash
cargo install ecfuzz
git clone https://github.com/matt24smith/ecfuzz.git && cd ecfuzz
ecfuzz --target fuzz_target.c --corpus ./corpus/start --dictionary-path input/sample.dict --seed 000 --iterations 5000
```

Initializing the fuzzing engine with seed 000 finds both bugs in this example after ~4700 attempts.
The resulting mutations will be logged to the same directory as the ``start`` file.

```text
...
branch hits: 10/12  exec/s: 63.21  inputs: 2  i: 4600  ABCDE0001000000
crashing path A...
fuzz_target.c:12:15: runtime error: applying zero offset to null pointer       
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior fuzz_target.c:12:15 in 
fuzz_target.c:12:15: runtime error: store to null pointer of type 'char'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior fuzz_target.c:12:15 in
AddressSanitizer:DEADLYSIGNAL
...

SUMMARY: AddressSanitizer: SEGV (/usr/lib/libc.so.6+0x73ba2) (BuildId: 1e94beb079e278ac4f2c8bce1f53091548ea1584) in fwrite
crashing input: ABCDEF000000000
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
    and prune entries that are a subset of the newest coverage


### Mutations
- XOR bit flip + byteshift
- byte replacement
- magic character replacement
- dictionary insertion
- tokenized dictionary replacement


#### Dictionary mutations
To enable dictionary mutations, a dictionary filepath must be included.
Lines in the dictionary file containing `key` items will be inserted at random.
Dictionary entries containing `key=value` will be inserted using tokenized replacement , e.g. mutate a `key` item in the seed input by replacing it with a `value`. 
Keys are split on the first `=` symbol, and keys may be repeated on a new line for multiple values.
