export CFLAGS="-g -fcolor-diagnostics -fuse-ld=lld -O3"
export CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld"
export LDFLAGS=$CMAKE_EXE_LINKER_FLAGS

ITER=10000

# run fuzzer with byte mutations
cargo run --release -- \
    --target ./input/sqlite3_build/sqlite3.c \
    --target ./input/sqlite3_build/shell.c \
    --seed 0 \
    --iterations $ITER \
    --corpus ./examples/sqlite3/corpus \
    --output-dir ./output/sqlite3-$ITER


# run fuzzer with grammar syntax specification
cargo run --release -- \
    --target ./input/sqlite3_build/sqlite3.c \
    --target ./input/sqlite3_build/shell.c \
    --seed 0 \
    --iterations $ITER \
    --grammar ./tests/sqlite.grammar \
    --output-dir ./output/sqlite3-$ITER


# examine the resulting inputs
awk 'FNR==1{printf ""}1' ./output/sqlite3-$ITER/corpus/mutation/*.mutation  | sort 
awk 'FNR==1{printf ""}1' ./output/sqlite3-$ITER/crashes/mutation/*.mutation  | sort 

