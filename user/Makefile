ARCH ?= riscv64
USE_GCC ?= 0
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

ifeq ($(USE_GCC),1)
  ifneq ($(shell command -v $(TOOLCHAIN_PREFIX)gcc 2>/dev/null),)
    CC := $(TOOLCHAIN_PREFIX)gcc
  else ifneq ($(shell command -v $(TARGET_TRIPLE:-linux-musl=-linux-gnu)-gcc 2>/dev/null),)
    CC := $(TARGET_TRIPLE:-linux-musl=-linux-gnu)-gcc
  else
    CC := clang --target=$(TARGET_TRIPLE) -fuse-ld=lld
  endif
else
  CC := clang --target=$(TARGET_TRIPLE) -fuse-ld=lld
endif

OUT_DIR := $(ROOT_DIR)/build/$(ARCH)/user
INIT := $(OUT_DIR)/init
INITRAMFS := $(OUT_DIR)/initramfs/init

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

ifeq ($(USE_GCC),0)
RTLIB_DIR := $(ROOT_DIR)/build/$(ARCH)/compiler-rt/lib
RTLIB_FLAGS := -rtlib=compiler-rt -unwindlib=none
RT_RESOURCE_DIR := $(ROOT_DIR)/build/$(ARCH)/compiler-rt/resource
RT_RESOURCE_FLAGS := -resource-dir=$(RT_RESOURCE_DIR)
CFLAGS += $(RTLIB_FLAGS)
CFLAGS += $(RT_RESOURCE_FLAGS)
LDFLAGS += $(RTLIB_FLAGS) -L$(RTLIB_DIR) $(RT_RESOURCE_FLAGS)
RTLIB_BUILTINS := $(wildcard $(RTLIB_DIR)/libclang_rt.builtins-*.a)
ifeq ($(RTLIB_BUILTINS),)
$(warning compiler-rt builtins not found; run ./scripts/build-compiler-rt.sh $(ARCH))
endif
endif

.PHONY: all clean initramfs

all: $(INIT)

$(INIT): init/main.c
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

initramfs: $(INITRAMFS)

$(INITRAMFS): initramfs/init.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(OUT_DIR)
