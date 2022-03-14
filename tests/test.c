#include <stdio.h>
#include <stdlib.h>

int test = 0xdeadbeef;

static int square(int x) { return x * x; }
static int cube(int x) { return x * x * x; }

static int callFn(int (*fn)(int), int val) { return square(val); }

int to_extract(int x) {
  printf("extract called: %d\n", x);
  switch (x) {
  case 0:
    return x;
  case 1:
    return x + test;
  case 2:
    return square(x);
  case 3:
    return cube(x);
  case 4:
    return callFn(cube, x);
  case 5:
    return callFn(square, x);
  default:
    return x * x - x;
  }
}

int main(int argc, char *argv[]) {
  int a = atoi(argv[1]);
  printf("f(%d)=%d\n", a, to_extract(a));
}
