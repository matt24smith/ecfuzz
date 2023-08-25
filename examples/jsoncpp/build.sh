set -e

# move to ecfuzz project root folder
WORK_DIR=`dirname $0/`
WORK_DIR=`dirname $WORK_DIR/`
WORK_DIR=`dirname $WORK_DIR/`
cd $WORK_DIR

# clone jsoncpp repo
mkdir -p input
git -C input/jsoncpp pull || git clone https://github.com/open-source-parsers/jsoncpp input/jsoncpp

# clang build options
export CC="/opt/bin/clang"
export CXX="/opt/bin/clang++"
export CFLAGS="-O3 -mllvm -polly -g -fcolor-diagnostics -fuse-ld=lld -fcoverage-mapping -fprofile-instr-generate"
export CXXFLAGS=$CFLAGS
export LDFLAGS="-L./input/jsoncpp/build/lib/libjsoncpp.a -Wl,--whole-archive"


# build library to link against
mkdir -p ./input/jsoncpp/build
cd ./input/jsoncpp/build
cmake -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF -DJSONCPP_WITH_TESTS=OFF \
      -DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles" ..
make
cd ../../..


# verify target library can be linked to fuzzer
CFLAGS=$CFLAGS LDFLAGS=$LDFLAGS $CXX \
  -fuse-ld=lld \
  ./libfuzz-driver.cpp \
  -I./input/jsoncpp/include \
  ./input/jsoncpp/src/test_lib_json/fuzz.cpp \
  ./input/jsoncpp/build/lib/libjsoncpp.a \
  -o output/jsoncpp_fuzzer

