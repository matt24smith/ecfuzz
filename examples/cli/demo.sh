#!/bin/sh
export CFLAGS="-std=c17 -g -fcolor-diagnostics -O3 -fuse-ld=lld"

# see 'ecfuzz --help' for a complete description of input arguments
cargo run --release --quiet -- \
  --target ./examples/cli/fuzz_target.c \
  --corpus ./examples/cli/input/corpus \
  --dictionary-path ./examples/cli/input/sample.dict \
  --iterations 2300 \
  --seed 295 

  #--plaintext |& > log.txt

