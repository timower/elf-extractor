#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

extern int extracted_func(int);

int main(int argc, char *argv[]) {
  void *handle = dlopen("./libxochitl.so", RTLD_NOW);
  if (handle == NULL) {
    puts(dlerror());
  }
  int a = atoi(argv[1]);
  printf("f(%d)=%d\n", a, extracted_func(a));
}
