#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

extern int to_extract(int);

int main(int argc, char *argv[]) {
  int a = atoi(argv[1]);
  printf("f(%d)=%d\n", a, to_extract(a));
}
