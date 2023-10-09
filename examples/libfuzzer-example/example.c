#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "./example_lib.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  unsigned int n1;
  unsigned int n2 ;
  unsigned int n3 ;
  char str1[32];
  char str2[32];
  char str3[32];
  sscanf((char* )data, "%u %u %u %s %s %s", &n1, &n2, &n3, str1, str2, str3);

  //fprintf(stderr, "testing input args: %u %u %u %s %s %s\n", n1, n2, n3, str1, str2, str3);
  insert_name(n1, n2, n3, str1, str2, str3);

  return 0;
}
