#include <stdio.h>
#include "./example_lib.c"


int main(int argc, char** argv) {
  unsigned int n1 ;
  sscanf(argv[1], "%u", &n1);
  unsigned int n2 ;
  sscanf(argv[2], "%u", &n2);
  unsigned int n3 ;
  sscanf(argv[3], "%u", &n3);

  insert_name(n1, n2, n3, argv[4], argv[5], argv[6]);

  return 0;
}
