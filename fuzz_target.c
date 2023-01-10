#include <stdio.h>

void do_comparison(char* data) {
  if (data[0] == 'A') {
    if (data[1] == 'B') {
      if (data[2] == 'C') {
        if (data[3] == 'D') {
          if (data[4] == 'E') {
            if (data[5] == 'F') {
              fprintf(stderr, "crashing path A...\n");
              char* crash = 0;
              crash[0] = 'X';
            }
          }
        }
      }
    }
  }

  else if (data[0] == 'G') {
    if (data[1] == 'H') {
      if (data[2] == 'I') {
        if (data[3] == 'J') {
          if (data[4] == 'K') {
            if (data[5] == 'L') {
              fprintf(stderr, "crashing path B...\n");
              char* crash = 0;
              crash[0] = 'X';
            }
          }
        }
      }
    }
  }
}

int main() {
  char str1[256];
  scanf_s("%255[^\n]s", str1);
  do_comparison(str1);
  return 0;
}
