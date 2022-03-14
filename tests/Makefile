TRIPLE = arm-remarkable-linux-gnueabi
TOOLCHAIN = /opt/codex/rm11x/3.1.2/sysroots/x86_64-codexsdk-linux/usr/bin/arm-remarkable-linux-gnueabi
SYSROOT = /opt/codex/rm11x/3.1.2/sysroots/cortexa7hf-neon-remarkable-linux-gnueabi

OPT ?= -O0
CC = ${TOOLCHAIN}/${TRIPLE}-gcc
CFLAGS = -mfpu=neon -mfloat-abi=hard -mcpu=cortex-a7 --sysroot=${SYSROOT}

all: test.bin minimal.bin

test.bin: test.c
	$(CC) $(CFLAGS) $^ -o $@ $(OPT) -fPIC

libtest.s: test.bin
	../main.py $^ --symbol to_extract > $@

libtest.so: libtest.s
	$(CC) $(CFLAGS) -shared $^ -o $@

main.bin: main.c libtest.so
	$(CC) $(CFLAGS) $^ -o $@ -Wl,-rpath='$$ORIGIN' -ldl

test_main: main.bin
	qemu-arm -L $(SYSROOT) $^ 12
	qemu-arm -L $(SYSROOT) $^ 2
	qemu-arm -L $(SYSROOT) $^ 0
	qemu-arm -L $(SYSROOT) $^ -100

minimal.bin: minimal.c
	$(CC) $(CFLAGS) $^ -o $@ -nostdlib -nostartfiles -fno-unwind-tables -Wl,--build-id=none -fno-exceptions

createThreads.s:
	../main.py xochitl_2.12.1.527 --address 0x3d9714 > $@

shutdownThreads.s:
	../main.py xochitl_2.12.1.527 --address 0x3d96b8 > $@

update.s:
	../main.py xochitl_2.12.1.527 --address 0x3d8c94 > $@


.PHONY: clean all test_main
clean:
	rm -f *.bin *.so libtest.s createThreads.s shutdownThreads.s update.s
