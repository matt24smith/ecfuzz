/*
ECFuzz driver for libfuzz harnesses
This file is equivalent of libfuzz StandaloneFuzzTargetMain.c, except it will 
send input via stdin instead of an input file
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>


extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);
__attribute__((weak)) extern int LLVMFuzzerInitialize(int *argc, char ***argv);

extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size) {
  assert(false && "LLVMFuzzerMutate should not be called from this driver");
  return 0;
}

const uint_fast32_t maxsize = 2 * 1024 * 1024;
const uint_fast32_t bufsize = 128;

int main(int argc, char **argv) {
  if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);

  uint8_t bytes[maxsize] = {};
  uint32_t count = 0;
  char buf[bufsize];
  uint32_t nread;

  while ((nread = read(STDIN_FILENO, buf, bufsize)) > 0) {
    memcpy(&bytes[count], buf, nread);
    count += nread;
  }
  return LLVMFuzzerTestOneInput(bytes, sizeof(bytes));
}
