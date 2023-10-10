#!/bin/bash
set -e

#cargo clean
rm -rf ./target/debug/deps/ecfuzz-*
rm -rf ./target/release/deps/ecfuzz-*
[[ `uname` = 'Darwin' ]] && PREFIX="xcrun"


if [ $# -eq 0 ]; then
  ALLOWED="--ignore-filename-regex=registry|fast_local"
else
  MODULE_NAME=`echo $1 | cut -d'.' -f1 | cut -d'/' -f2`
  IGNORED=`find src | grep -v $MODULE_NAME | tail -n+2 | cut -d'.' -f1 | cut -d'/' -f2 | tr '\n' '|'`
  IGNORED=${IGNORED::-1}
  ALLOWED="--ignore-filename-regex=registry|fast_local|$IGNORED"
fi


export RUSTFLAGS='-C instrument-coverage'
cargo test --lib --no-fail-fast $MODULE_NAME 
TARGET_BIN=`ls --color=none target/debug/deps/ecfuzz-* | head -n1`

$PREFIX llvm-profdata merge \
  -sparse \
  default_*.profraw \
  -o ecfuzz.profdata

rm default_*.profraw

$PREFIX llvm-cov show \
  --summary-only \
  --instr-profile="ecfuzz.profdata" \
  $ALLOWED \
  $TARGET_BIN 

  #--ignore-filename-regex="registry" \
  #--ignore-filename-regex="fast-local" \
$PREFIX llvm-cov report \
  --summary-only \
  --instr-profile ecfuzz.profdata \
  $ALLOWED \
  $TARGET_BIN

echo "$1 $MODULE_NAME ALLOWED=$ALLOWED"
