# Note:
# To use this fuzzer with libfuzzer, add '-fsanitize=fuzzer' to CFLAGS,
# and add '--mutate-file' to ecfuzz arguments. 
# This allows removing the ecfuzz argument '--target ./libfuzz_driver.c'
#
# To further investigate crashes:
: <<COMMENT
wc -l output/jsoncpp/corpus/coverage/* | sort -shr | head -n10
wc -l output/jsoncpp/crashes/coverage/* | sort -shr | head -n10


LLVM_PROFILE_FILE=profraw ./output/jsoncpp/ecfuzz.undefined-sanitized.out < ./output/jsoncpp/corpus/mutation/00107.mutation
$BINPATH/llvm-profdata merge -sparse profraw -o profdata
$BINPATH/llvm-cov show --instr-profile profdata ./output/jsoncpp/ecfuzz.undefined-sanitized.out --ignore-filename-regex=libfuzz-driver.cpp\|fuzz.cpp --summary-only --line-coverage-gt=0
COMMENT

BINPATH=/opt/bin
export CC="$BINPATH/clang"
export CXX="$BINPATH/clang++"
export CFLAGS="-O3 -mllvm -polly -g -fcolor-diagnostics -fuse-ld=lld -mshstk"
#export CFLAGS="$CFLAGS -fsanitize=fuzzer"
export CXXFLAGS=$CFLAGS
export LDFLAGS="-L./input/jsoncpp/build/lib/libjsoncpp.a -Wl,--whole-archive"

LLVM_PROFDATA_PATH=$BINPATH/llvm-profdata
LLVM_COV_PATH=$BINPATH/llvm-cov

cd $0/../..

cargo run --release --\
    --compiler $CXX \
    --target ./libfuzz-driver.cpp \
    --target ./input/jsoncpp/src/test_lib_json/fuzz.cpp \
    --target ./input/jsoncpp/build/lib/libjsoncpp.a \
    --include ./input/jsoncpp/include \
    --corpus-dir ./input/jsoncpp/test/jsonchecker \
    --corpus-dir ./input/jsoncpp/test/data \
    --dictionary-path ./input/jsoncpp/src/test_lib_json/fuzz.dict \
    --seed 0 \
    --iterations 10000 \
    --llvm-profdata-path $LLVM_PROFDATA_PATH \
    --llvm-cov-path $LLVM_COV_PATH \
    --output-dir ./output/jsoncpp/

    #--mutate-file \
