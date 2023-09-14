cargo build && cargo build --release

sudo -E flamegraph -o graph.svg -- ./target/release/ecfuzz \
    --target ./input/sqlite3_build/sqlite3.c \
    --target ./input/sqlite3_build/shell.c \
    --corpus ./examples/sqlite3/corpus \
    --iterations 1000 \
    --output-dir ./output/sqlite3-flamegraph
