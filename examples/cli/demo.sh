#!/bin/sh
export CFLAGS="-std=c17 -g -fcolor-diagnostics -O3 -fuse-ld=lld"

# see 'ecfuzz --help' for a complete description of input arguments
cargo run --release -- \
  --target ./examples/cli/fuzz_target.c \
  --corpus ./examples/cli/input/corpus \
  --output-dir ./output/cli_demo/ \
  --dictionary-path ./examples/cli/input/sample.dict \
  --iterations 10000 \
  --seed 62
  #--plaintext |& > log.txt

