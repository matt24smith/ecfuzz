#!/bin/sh


export CFLAGS="-std=c17 -g -fcolor-diagnostics -O3"

# see 'ecfuzz --help' for a complete description of input arguments
ecfuzz \
  --target fuzz_target.c \
  --corpus ./input/corpus \
  --dictionary-path input/sample.dict \
  --iterations 5000 \
  --seed 000
