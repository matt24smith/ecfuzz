#!/bin/sh


export CFLAGS="-std=c17 -g -fcolor-diagnostics -O3"

# see 'ecfuzz --help' for a complete description of input arguments
cargo run -- \
  --target ./examples/cli/fuzz_target.c \
  --corpus ./examples/cli/input/corpus \
  --dictionary-path ./examples/cli/input/sample.dict \
  --iterations 20000 \
  --seed 0

