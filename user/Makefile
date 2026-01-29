ARCH ?= riscv64
ROOT_DIR := $(abspath ..)
SYSROOT ?= $(ROOT_DIR)/build/$(ARCH)/sysroot
TOOLCHAIN_PREFIX ?= $(ARCH)-linux-musl-
ifeq ($(ARCH),riscv64)
TARGET_TRIPLE := riscv64-linux-musl
else ifeq ($(ARCH),x86_64)
TARGET_TRIPLE := x86_64-linux-musl
else ifeq ($(ARCH),aarch64)
TARGET_TRIPLE := aarch64-linux-musl
else
TARGET_TRIPLE := $(ARCH)-linux-musl
endif

ifneq ($(shell command -v $(TOOLCHAIN_PREFIX)gcc 2>/dev/null),)
CC := $(TOOLCHAIN_PREFIX)gcc
else ifneq ($(shell command -v $(TARGET_TRIPLE:-linux-musl=-linux-gnu)-gcc 2>/dev/null),)
CC := $(TARGET_TRIPLE:-linux-musl=-linux-gnu)-gcc
else
CC := clang --target=$(TARGET_TRIPLE) -fuse-ld=lld
endif

OUT_DIR := $(ROOT_DIR)/build/$(ARCH)/user
INIT := $(OUT_DIR)/init

CFLAGS := -Os -static -fno-stack-protector -fno-pie --sysroot=$(SYSROOT)
CFLAGS += -isystem $(SYSROOT)/include
ifeq ($(ARCH),riscv64)
CFLAGS += -march=rv64gc -mabi=lp64
endif
CFLAGS += -Wall -Wextra
LDFLAGS := -no-pie --sysroot=$(SYSROOT)
LDFLAGS += -L$(SYSROOT)/lib
ifeq ($(ARCH),riscv64)
LDFLAGS += -march=rv64gc -mabi=lp64
endif

.PHONY: all clean

all: $(INIT)

$(INIT): init/main.c
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(OUT_DIR)
