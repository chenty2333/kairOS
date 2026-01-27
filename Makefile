# Kairos Kernel Makefile
#
# Usage:
#   make                    # Build for default architecture (riscv64)
#   make ARCH=x86_64        # Build for x86_64
#   make ARCH=aarch64       # Build for AArch64
#   make run                # Run in QEMU
#   make debug              # Run with GDB server
#   make clean              # Clean build artifacts
#   make test               # Run kernel tests

# ============================================================
#                      Configuration
# ============================================================

# Default architecture
ARCH ?= riscv64

# Build directory
BUILD_DIR := build/$(ARCH)

# Output files
KERNEL := $(BUILD_DIR)/kairos.elf
KERNEL_BIN := $(BUILD_DIR)/kairos.bin
ISO := $(BUILD_DIR)/kairos.iso

# Verbose mode (V=1 for verbose)
V ?= 0
ifeq ($(V),0)
  Q := @
  MAKEFLAGS += --no-print-directory
else
  Q :=
endif

# ============================================================
#                    Toolchain Setup
# ============================================================

# Use clang for cross-compilation (set USE_GCC=1 to use GCC)
USE_GCC ?= 0

ifeq ($(ARCH),riscv64)
  CROSS_COMPILE ?= riscv64-unknown-elf-
  CLANG_TARGET := riscv64-unknown-elf
  QEMU := qemu-system-riscv64
  QEMU_MACHINE := virt
  QEMU_CPU := rv64
  KERNEL_LOAD := 0x80200000
else ifeq ($(ARCH),x86_64)
  CROSS_COMPILE ?=
  CLANG_TARGET := x86_64-unknown-elf
  QEMU := qemu-system-x86_64
  QEMU_MACHINE := q35
  KERNEL_LOAD := 0xffffffff80000000
else ifeq ($(ARCH),aarch64)
  CROSS_COMPILE ?= aarch64-none-elf-
  CLANG_TARGET := aarch64-unknown-elf
  QEMU := qemu-system-aarch64
  QEMU_MACHINE := virt
  QEMU_CPU := cortex-a72
  KERNEL_LOAD := 0x40000000
else
  $(error Unsupported architecture: $(ARCH))
endif

ifeq ($(USE_GCC),1)
  CC := $(CROSS_COMPILE)gcc
  LD := $(CROSS_COMPILE)ld
  AS := $(CROSS_COMPILE)as
else
  CC := clang --target=$(CLANG_TARGET)
  LD := ld.lld
  AS := clang --target=$(CLANG_TARGET)
endif
OBJCOPY := llvm-objcopy
OBJDUMP := llvm-objdump

# ============================================================
#                    Compiler Flags
# ============================================================

# Common flags
CFLAGS := -ffreestanding -fno-common -nostdlib -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror=implicit-function-declaration
CFLAGS += -O2 -g
CFLAGS += -I kernel/include
CFLAGS += -I kernel/arch/$(ARCH)/include
CFLAGS += -D__KAIROS__ -DARCH_$(ARCH)

# Architecture-specific flags
ifeq ($(ARCH),riscv64)
  ifeq ($(USE_GCC),1)
    CFLAGS += -march=rv64gc -mabi=lp64d -mcmodel=medany
  else
    CFLAGS += -march=rv64gc -mabi=lp64d -mcmodel=medany
  endif
  LDFLAGS :=
else ifeq ($(ARCH),x86_64)
  CFLAGS += -m64 -mno-red-zone -mno-sse -mno-sse2
  CFLAGS += -mcmodel=kernel
  LDFLAGS :=
else ifeq ($(ARCH),aarch64)
  CFLAGS += -mgeneral-regs-only
  LDFLAGS :=
endif

LDFLAGS += -nostdlib -static

# Linker script
LDSCRIPT := kernel/arch/$(ARCH)/linker.ld

# ============================================================
#                    Source Files
# ============================================================

# Phase 0: Minimal boot sources
# Additional sources will be added as phases are implemented

# Core kernel sources (architecture-independent)
CORE_SRCS := \
    kernel/core/main.c \
    kernel/core/mm/buddy.c \
    kernel/core/mm/kmalloc.c \
    kernel/core/mm/vmm.c \
    kernel/core/proc/process.c \
    kernel/core/proc/user_test.c \
    kernel/core/proc/elf.c \
    kernel/core/proc/fd.c \
    kernel/core/proc/signal.c \
    kernel/core/sched/sched.c \
    kernel/core/sync/sync.c \
    kernel/core/sync/wait.c \
    kernel/core/syscall/syscall.c \
    kernel/lib/printk.c \
    kernel/lib/vsprintf.c \
    kernel/lib/fdt.c \
    kernel/lib/rbtree.c \
    kernel/lib/string.c \
    kernel/fs/bio.c \
    kernel/fs/vfs/vfs.c \
    kernel/fs/vfs/pipe.c \
    kernel/fs/devfs/devfs.c \
    kernel/fs/ext2/ext2.c \
    kernel/core/device.c \
    kernel/drivers/bus/platform.c \
    kernel/drivers/virtio/virtio.c \
    kernel/drivers/virtio/virtio_mmio.c \
    kernel/drivers/virtio/virtio_ring.c \
    kernel/drivers/block/blkdev.c \
    kernel/drivers/block/virtio_blk.c

# Architecture-specific sources
ARCH_SRCS := \
    kernel/arch/$(ARCH)/boot.S \
    kernel/arch/$(ARCH)/entry.c \
    kernel/arch/$(ARCH)/plic.c \
    kernel/arch/$(ARCH)/mmu.c \
    kernel/arch/$(ARCH)/trapasm.S \
    kernel/arch/$(ARCH)/trap.c \
    kernel/arch/$(ARCH)/timer.c \
    kernel/arch/$(ARCH)/switch.S \
    kernel/arch/$(ARCH)/context.c \
    kernel/arch/$(ARCH)/extable.c \
    kernel/arch/$(ARCH)/lib/uaccess.S

# Future phases will add:
# - kernel/core/sched/sched.c, cfs.c
# - kernel/core/mm/pmm.c, vmm.c, kmalloc.c
# - kernel/core/proc/process.c, fork.c, exec.c
# - kernel/core/trap/trap.c, kernel/arch/$(ARCH)/trap.S, trap.c
# - kernel/core/time/time.c, kernel/arch/$(ARCH)/timer.c
# - kernel/ipc/pipe.c, signal.c
# - kernel/fs/*, kernel/drivers/*, kernel/syscall/*

# All sources
SRCS := $(CORE_SRCS) $(ARCH_SRCS)

# Object files
OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(filter %.c,$(SRCS)))
OBJS += $(patsubst %.S,$(BUILD_DIR)/%.o,$(filter %.S,$(SRCS)))

# Embedded user init (riscv64 only)
ifeq ($(ARCH),riscv64)
USER_INIT_BLOB := kernel/core/proc/user_init_blob.h
$(USER_INIT_BLOB): user/init/init.S user/init/linker.ld scripts/gen-user-init.sh
	./scripts/gen-user-init.sh $(ARCH)
$(OBJS): $(USER_INIT_BLOB)
endif

# Dependency files
DEPS := $(OBJS:.o=.d)

# ============================================================
#                    Build Rules
# ============================================================

.PHONY: all clean run debug iso test

all: $(KERNEL)

# Link kernel
$(KERNEL): $(OBJS) $(LDSCRIPT)
	@echo "  LD      $@"
	@mkdir -p $(dir $@)
	$(Q)$(LD) $(LDFLAGS) -T $(LDSCRIPT) -o $@ $(OBJS)
	@echo "  OBJCOPY $(KERNEL_BIN)"
	$(Q)$(OBJCOPY) -O binary $@ $(KERNEL_BIN)

# Compile C files
$(BUILD_DIR)/%.o: %.c
	@echo "  CC      $<"
	@mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Assemble .S files
$(BUILD_DIR)/%.o: %.S
	@echo "  AS      $<"
	@mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Include dependencies
-include $(DEPS)

# ============================================================
#                    QEMU Targets
# ============================================================

# Common QEMU flags
QEMU_FLAGS := -machine $(QEMU_MACHINE) -m 256M -smp 4 -nographic
QEMU_FLAGS += -serial mon:stdio

ifeq ($(ARCH),riscv64)
  QEMU_FLAGS += -bios default -kernel $(KERNEL)
else ifeq ($(ARCH),x86_64)
  # For x86_64 with Limine, we'd use ISO boot
  QEMU_FLAGS += -kernel $(KERNEL)
else ifeq ($(ARCH),aarch64)
  QEMU_FLAGS += -cpu $(QEMU_CPU) -kernel $(KERNEL)
endif

# Add virtio disk
DISK_IMG := disk.img
ifeq ($(ARCH),riscv64)
  # For RISC-V, explicitly create virtio-blk-device
  QEMU_FLAGS += -global virtio-mmio.force-legacy=false
  QEMU_FLAGS += -drive id=hd,file=$(DISK_IMG),format=raw,if=none
  QEMU_FLAGS += -device virtio-blk-device,drive=hd
else
  QEMU_FLAGS += -drive file=$(DISK_IMG),if=virtio,format=raw
endif

# Add network (virtio-net for development)
HOSTFWD_PORT ?=
ifeq ($(HOSTFWD_PORT),)
  QEMU_FLAGS += -netdev user,id=net0
else
  QEMU_FLAGS += -netdev user,id=net0,hostfwd=tcp::$(HOSTFWD_PORT)-:80
endif
QEMU_FLAGS += -device virtio-net-pci,netdev=net0

run: $(KERNEL)
	$(QEMU) $(QEMU_FLAGS)

# Run with e1000 network card (for testing)
run-e1000: $(KERNEL)
	$(QEMU) $(QEMU_FLAGS) -device e1000,netdev=net0

# Create bootable ISO (x86_64 only for now)
iso: $(KERNEL)
	./scripts/make-iso.sh $(ARCH)

# Run from ISO
run-iso: iso
	$(QEMU) -cdrom $(BUILD_DIR)/kairos.iso -m 256M $(QEMU_EXTRA)

# Debug with GDB
debug: $(KERNEL)
	@echo "Starting QEMU with GDB server on localhost:1234"
	@echo "In another terminal: gdb $(KERNEL) -ex 'target remote localhost:1234'"
	$(QEMU) $(QEMU_FLAGS) -s -S

# ============================================================
#                    Utility Targets
# ============================================================

clean:
	rm -rf build/

# Create a disk image with ext2 filesystem
disk:
	@echo "Creating disk image..."
	dd if=/dev/zero of=$(DISK_IMG) bs=1M count=64
	mkfs.ext2 $(DISK_IMG)

# Disassembly
disasm: $(KERNEL)
	$(OBJDUMP) -d $(KERNEL) > $(BUILD_DIR)/kairos.asm

# Symbol table
symbols: $(KERNEL)
	$(OBJDUMP) -t $(KERNEL) | sort > $(BUILD_DIR)/kairos.sym

# Run tests (in QEMU)
test: $(KERNEL)
	$(QEMU) $(QEMU_FLAGS) -append "test"

# Show help
help:
	@echo "Kairos Kernel Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build kernel (default)"
	@echo "  run      - Run in QEMU"
	@echo "  debug    - Run with GDB server"
	@echo "  clean    - Remove build artifacts"
	@echo "  disk     - Create disk image"
	@echo "  test     - Run kernel tests"
	@echo ""
	@echo "Variables:"
	@echo "  ARCH     - Target architecture (riscv64, x86_64, aarch64)"
	@echo "  V        - Verbose mode (V=1)"
	@echo ""
	@echo "Examples:"
	@echo "  make ARCH=x86_64 run"
	@echo "  make V=1"
