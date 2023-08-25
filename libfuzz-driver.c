#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <math.h>
#include "input/jsoncpp/src/test_lib_json/fuzz.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
  assert(false && "LLVMFuzzerMutate should not be called from this driver");
  return 0;
}

const uint_fast32_t maxsize = 2 * 1024 * 1024;
const uint_fast32_t bufsize = 1024;

int main(int argc, char **argv) {
  //if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);
  uint8_t bytes[maxsize] = {};
  uint32_t count = 0;
  char buf[bufsize];
  uint32_t nread;

  while ((nread = read(STDIN_FILENO, buf, bufsize)) > 0) {
    memcpy(&bytes[count], buf, nread);
    count += nread;
  }
  //printf("BYTE SIZE: %d\t %s\n", count, bytes);
  return LLVMFuzzerTestOneInput(bytes, sizeof(bytes));
}
