set -e

WORK_DIR=`dirname $0/`
WORK_DIR=`dirname $WORK_DIR/`
WORK_DIR=`dirname $WORK_DIR/`
cd $WORK_DIR

mkdir -p input/sqlite3_build

wget -O input/sqlite-src.zip https://www.sqlite.org/2023/sqlite-src-3430000.zip

rm -rf input/sqlite-src-* input/sqlite3_build || echo ''
unzip -d input/ input/sqlite-src.zip
mkdir input/sqlite3_build


#export CXX=/Library/Developer/CommandLineTools/usr/bin/clang++
#export CC=/Library/Developer/CommandLineTools/usr/bin/clang
#export CC=/usr/bin/clang
#export CXX=/usr/bin/clang++

export CFLAGS="-O3 -g -fcolor-diagnostics -fcoverage-mapping -fprofile-instr-generate -DSQLITE_THREADSAFE=0 -DSQLITE_ENABLE_LOAD_EXTENSION=0 -DSQLITE_NO_SYNC -DSQLITE_OMIT_RANDOMNESS"

#export CFLAGS="-O3 -g -fcolor-diagnostics -DSQLITE_THREADSAFE=0 -DSQLITE_ENABLE_LOAD_EXTENSION=0 -DSQLITE_NO_SYNC -DSQLITE_OMIT_RANDOMNESS"
export CXXFLAGS=$CFLAGS
export LDFLAGS="-fuse-ld=lld"


mkdir -p input/sqlite3_build
cd input/sqlite3_build

../sqlite-src-*/configure --disable-threadsafe --enable-tempstore
make -j8
make sqlite3.c shell.c

#$CC -O2 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION  -fprofile-instr-generate -fcoverage-mapping -arch arm64 -I. -I./src sqlite3.pc -o sqlite3
make sqlite3.c


