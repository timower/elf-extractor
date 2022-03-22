#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dirent.h>

#define SCREEN_WIDTH 1404
#define SCREEN_HEIGHT 1872

enum Waveform {
  FAST = 0,
  MEDIUM = 1,
  HQ = 2,
  INIT = HQ,
};

enum UpdateFlags {
  FullRefresh = 1,
  Sync = 2,
  FastDraw = 4, // TODO: what does this do? Used for strokes by xochitl.
};

struct UpdateParams {
  int x1;
  int y1;
  int x2;
  int y2;
  int flags;
  int waveform;
};

void initBss();
extern int create(const char *path, void *bits);
extern int clear();
extern int shutdown();
extern int update(struct UpdateParams *params);

#define REM
#ifndef REM
// opendir/readdir hooks to be able to run under qemu.

DIR *opendir(const char *name) {
  printf("Open: %s\n", name);
  return (DIR *)name;
}

int closedir(DIR *dir) { return 0; }

struct dirent *readdir(DIR *dir) {
  static const char *file_name = "320_R259_AFAB21_ED103TC2M1_TC.wbf";
  static struct dirent dir_p = {
      .d_ino = 0, .d_reclen = sizeof(struct dirent), .d_type = DT_REG};

  const char *name = (const char *)dir;
  printf("Read %s\n", name);

  if (strcmp(name, "/usr/share/remarkable/") == 0 && dir_p.d_ino < 1) {
    printf("Returning file\n");
    strcpy(dir_p.d_name, file_name);
    dir_p.d_ino++;
    return &dir_p;
  }
  return NULL;
}
#endif

int main() {
  initBss();

  const size_t size = SCREEN_HEIGHT * SCREEN_WIDTH;
  void *bits = malloc(size * sizeof(uint16_t));
  memset(bits, 0xFF, SCREEN_WIDTH * SCREEN_HEIGHT * sizeof(uint16_t));
  uint16_t *image = (uint16_t *)bits;

  int res = create("/dev/fb0", bits);
  if (res != 0) {
    return res;
  }

  clear();
  puts("SWTCON inited!");
  for (int y = 0; y < SCREEN_HEIGHT; y++) {
    for (int x = 0; x < SCREEN_WIDTH; x++) {
      uint16_t *ptr = &image[y * SCREEN_WIDTH + x];
      if ((x / 10) % 2 == (y / 10) % 2) {
        *ptr = 0;
      } else {
        *ptr = 0xFFFF;
      }
    }
  }

  struct UpdateParams upd;

  // x and y are swapped??
  upd.x1 = 0;
  upd.x2 = SCREEN_HEIGHT;
  upd.y1 = 0;
  upd.y2 = SCREEN_HEIGHT;

  upd.waveform = HQ; // HQ
  upd.flags = Sync;  // Sync

  printf("update: %d\n", update(&upd));
  sleep(2);
  return shutdown();
}
