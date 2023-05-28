#include <string.h>
#include <stdbool.h>
#include <stdio.h>

int insert_name(unsigned int num1, unsigned int num2, unsigned int num3, char* str1, char* str2, char* str3) {
  if (num1 == 555 && num2 == 555 && num3 == 1234) {
    if (strcmp(str1, "Urist") == 0 && strcmp(str2, "Bogsosh") == 0 && strcmp(str3, "Guthstak") == 0) {
      fprintf(stderr, "crashing...");
      char* crash = 0;
      crash[0] = 'X';
      return true;
    }
  }

  return false;
}
