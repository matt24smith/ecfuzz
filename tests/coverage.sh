set -e
[[ `uname` = 'Darwin' ]] && PREFIX="xcrun"
export RUSTFLAGS='-C instrument-coverage'

cargo test --lib
TARGET_BIN=`ls --color=none target/debug/deps/ecfuzz-* | head -n1`

$PREFIX llvm-profdata merge \
  -sparse \
  default_*.profraw \
  -o ecfuzz.profdata

rm default_*.profraw

$PREFIX llvm-cov show \
  --summary-only \
  --instr-profile="ecfuzz.profdata" \
  --ignore-filename-regex="registry" \
  $TARGET_BIN 

$PREFIX llvm-cov report \
  --instr-profile ecfuzz.profdata \
  --summary-only \
  --ignore-filename-regex="registry" \
  $TARGET_BIN
