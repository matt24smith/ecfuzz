export CFLAGS="-g -fcolor-diagnostics -fuse-ld=lld -O3"
export CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld"
export LDFLAGS=$CMAKE_EXE_LINKER_FLAGS

ITER=1000000

cargo run --release -- \
    --target ./input/sqlite3_build/sqlite3.c \
    --target ./input/sqlite3_build/shell.c \
    --corpus ./examples/sqlite3/corpus \
    --seed 1 \
    --iterations $ITER \
    --output-dir ./output/sqlite3-$ITER
