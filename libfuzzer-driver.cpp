/*
ECFuzz driver for libfuzzer harnesses
This file is equivalent of libfuzz StandaloneFuzzTargetMain.c, except it will 
send input via stdin instead of an input file
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);


extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size) {
  assert(false && "LLVMFuzzerMutate should not be called from this driver");
  return 0;
}

//__attribute__((weak)) extern int LLVMFuzzerInitialize(int *argc, char ***argv);

const uint_fast32_t maxsize = 2 * 1024 * 1024;
const uint_fast32_t bufsize = 64;

int main(int argc, char **argv) {
  //if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);

  uint8_t bytes[maxsize] = {0};
  uint32_t count = 0;
  char buf[bufsize] = {0};
  uint32_t nread;

  while ((nread = read(STDIN_FILENO, buf, bufsize)) > 0) {
    memcpy(&bytes[count], buf, nread);
    count += nread;
  }

  return LLVMFuzzerTestOneInput(bytes, sizeof(bytes));
}
