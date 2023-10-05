
export CFLAGS="-O3 -mllvm -polly -std=c17 -g -fcolor-diagnostics -fuse-ld=lld -L/opt/lib -D_FORTIFY_SOURCE=3 -fstack-protector-all -flto"

rm output/ecfuzz_target.*.out
rm -rf output/ecfuzz_target.*.dSYM

cargo build && cargo build --release

sudo -E flamegraph -o graph.svg -- ./target/release/ecfuzz \
  --target ./examples/cli/fuzz_target.c \
  --corpus ./examples/cli/input/corpus \
  --output-dir ./output/flamegraph-smalltarget \
  --dictionary-path ./examples/cli/input/sample.dict \
  --iterations 10000 \
  --seed 117
