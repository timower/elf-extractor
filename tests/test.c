#include <stdio.h>
#include <stdlib.h>

int test = 0;

static int square(int x) { return x * x; }
static int cube(int x) { return x * x * x; }

static int callFn(int (*fn)(int), int val) { return square(val); }

int to_extract(int x) {
  printf("extract called: %d\n", x);
  if (x <= 0) {
    return x;
  }

  x += test;

  if (x > 2) {
    return x * x - x;
  }
  return callFn(cube, x);
}

int main(int argc, char *argv[]) {
  int a = atoi(argv[1]);
  printf("f(%d)=%d\n", a, to_extract(a));
}
