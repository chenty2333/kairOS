# Kairos Kernel Makefile
#
# Usage:
#   make                    # Build for default architecture (riscv64)
#   make ARCH=x86_64        # Build for x86_64
#   make ARCH=aarch64       # Build for AArch64
#   make run                # Run in QEMU (riscv64 default: builds busybox/rootfs)
#   make debug              # Run with GDB server
#   make clean              # Clean build artifacts
#   make test               # Run kernel tests
#   make uefi               # Prepare RISC-V UEFI boot image (riscv64 only)
#   make disk               # Build ext2 disk image with busybox + init

# ============================================================
#                      Configuration
# ============================================================

# Default architecture
ARCH ?= riscv64
EMBEDDED_INIT ?= 0
EXTRA_CFLAGS ?=

# Auto-detect parallelism: use all available cores
NPROC := $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
MAKEFLAGS += -j$(NPROC)

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
  QUIET_ENV := QUIET=1
  MAKEFLAGS += --no-print-directory
else
  Q :=
  QUIET_ENV :=
endif

# Shared architecture sources
COMMON_ARCH_SRCS := \
    kernel/arch/common/arch_common.c \
    kernel/arch/common/mmu_common.c

# ============================================================
#                    Toolchain Setup
# ============================================================

# Use clang for cross-compilation (set USE_GCC=1 to use GCC)
USE_GCC ?= 0

# Optional subsystems (set to 0 to disable)
CONFIG_DRM_LITE ?= 1

ifeq ($(ARCH),riscv64)
  CROSS_COMPILE ?= riscv64-unknown-elf-
  CLANG_TARGET := riscv64-unknown-elf
  QEMU := qemu-system-riscv64
  QEMU_MACHINE := virt
  QEMU_CPU := rv64gc
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
  QEMU_MACHINE := virt,gic-version=3
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
CFLAGS += -DCONFIG_EMBEDDED_INIT=$(EMBEDDED_INIT)
CFLAGS += -DCONFIG_DRM_LITE=$(CONFIG_DRM_LITE)
CFLAGS += $(EXTRA_CFLAGS)

# lwIP include paths
LWIP_DIR := third_party/lwip
CFLAGS += -I kernel/net/lwip_port
CFLAGS += -I $(LWIP_DIR)/src/include
# Compat shims for lwIP (provides string.h, stdlib.h, errno.h)
LWIP_COMPAT_CFLAGS := -I kernel/net/lwip_port/compat

# Architecture-specific flags
LDFLAGS := -nostdlib -static

ifeq ($(ARCH),riscv64)
  CFLAGS += -march=rv64gc -mabi=lp64d -mcmodel=medany
else ifeq ($(ARCH),x86_64)
  CFLAGS += -m64 -mno-red-zone -mno-sse -mno-sse2
  CFLAGS += -mcmodel=kernel
else ifeq ($(ARCH),aarch64)
  CFLAGS += -mgeneral-regs-only -fno-omit-frame-pointer
endif

# Linker script
LDSCRIPT := kernel/arch/$(ARCH)/linker.ld

# ============================================================
#                    Source Files
# ============================================================

# Core kernel sources (architecture-independent) — auto-discovered via wildcard.
# ARCH_SRCS and LWIP_SRCS are kept explicit (see below).
CORE_SRCS := $(wildcard kernel/core/*.c kernel/core/*/*.c)
CORE_SRCS += $(wildcard kernel/lib/*.c)
CORE_SRCS += $(wildcard kernel/firmware/*.c)
CORE_SRCS += $(wildcard kernel/fs/*/*.c)
CORE_SRCS += $(wildcard kernel/bus/*.c)
CORE_SRCS += $(wildcard kernel/drivers/*/*.c)
CORE_SRCS += $(wildcard kernel/net/*.c) kernel/net/lwip_port/sys_arch.c
CORE_SRCS += kernel/boot/boot.c kernel/boot/limine.c

ifeq ($(CONFIG_DRM_LITE),0)
CORE_SRCS := $(filter-out kernel/drivers/gpu/drm_lite.c,$(CORE_SRCS))
endif

# Architecture-specific sources
ifeq ($(ARCH),riscv64)
ARCH_SRCS := \
    kernel/arch/riscv64/boot.S \
    kernel/arch/riscv64/entry.c \
    kernel/arch/riscv64/plic.c \
    kernel/arch/riscv64/mmu.c \
    kernel/arch/riscv64/trapasm.S \
    kernel/arch/riscv64/trap.c \
    kernel/arch/riscv64/timer.c \
    kernel/arch/riscv64/switch.S \
    kernel/arch/riscv64/context.c \
    kernel/arch/riscv64/extable.c \
    kernel/arch/riscv64/lib/uaccess.S
else ifeq ($(ARCH),x86_64)
ARCH_SRCS := \
    kernel/arch/x86_64/boot.S \
    kernel/arch/x86_64/entry.c \
    kernel/arch/x86_64/mmu.c \
    kernel/arch/x86_64/trapasm.S \
    kernel/arch/x86_64/trap.c \
    kernel/arch/x86_64/timer.c \
    kernel/arch/x86_64/apic.c \
    kernel/arch/x86_64/ioapic.c \
    kernel/arch/x86_64/firmware.c \
    kernel/arch/x86_64/switch.S \
    kernel/arch/x86_64/context.c \
    kernel/arch/x86_64/extable.c \
    kernel/arch/x86_64/lib/uaccess.S
else ifeq ($(ARCH),aarch64)
ARCH_SRCS := \
    kernel/arch/aarch64/boot.S \
    kernel/arch/aarch64/entry.c \
    kernel/arch/aarch64/mmu.c \
    kernel/arch/aarch64/trapasm.S \
    kernel/arch/aarch64/trap.c \
    kernel/arch/aarch64/timer.c \
    kernel/arch/aarch64/gic.c \
    kernel/arch/aarch64/firmware.c \
    kernel/arch/aarch64/switch.S \
    kernel/arch/aarch64/context.c \
    kernel/arch/aarch64/extable.c \
    kernel/arch/aarch64/lib/uaccess.S
endif

# lwIP sources
LWIP_SRCS := \
    $(LWIP_DIR)/src/core/init.c \
    $(LWIP_DIR)/src/core/def.c \
    $(LWIP_DIR)/src/core/dns.c \
    $(LWIP_DIR)/src/core/inet_chksum.c \
    $(LWIP_DIR)/src/core/ip.c \
    $(LWIP_DIR)/src/core/mem.c \
    $(LWIP_DIR)/src/core/memp.c \
    $(LWIP_DIR)/src/core/netif.c \
    $(LWIP_DIR)/src/core/pbuf.c \
    $(LWIP_DIR)/src/core/raw.c \
    $(LWIP_DIR)/src/core/stats.c \
    $(LWIP_DIR)/src/core/sys.c \
    $(LWIP_DIR)/src/core/tcp.c \
    $(LWIP_DIR)/src/core/tcp_in.c \
    $(LWIP_DIR)/src/core/tcp_out.c \
    $(LWIP_DIR)/src/core/timeouts.c \
    $(LWIP_DIR)/src/core/udp.c \
    $(LWIP_DIR)/src/core/ipv4/acd.c \
    $(LWIP_DIR)/src/core/ipv4/autoip.c \
    $(LWIP_DIR)/src/core/ipv4/dhcp.c \
    $(LWIP_DIR)/src/core/ipv4/etharp.c \
    $(LWIP_DIR)/src/core/ipv4/icmp.c \
    $(LWIP_DIR)/src/core/ipv4/igmp.c \
    $(LWIP_DIR)/src/core/ipv4/ip4.c \
    $(LWIP_DIR)/src/core/ipv4/ip4_addr.c \
    $(LWIP_DIR)/src/core/ipv4/ip4_frag.c \
    $(LWIP_DIR)/src/api/err.c \
    $(LWIP_DIR)/src/api/tcpip.c \
    $(LWIP_DIR)/src/netif/ethernet.c

# lwIP needs relaxed warnings (third-party code)
LWIP_CFLAGS := $(CFLAGS) $(LWIP_COMPAT_CFLAGS) -Wno-unused-parameter \
    -Wno-sign-compare -Wno-address -Wno-type-limits

# All sources
SRCS := $(CORE_SRCS) $(ARCH_SRCS) $(COMMON_ARCH_SRCS) $(LWIP_SRCS)

# Object files
OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(filter %.c,$(SRCS)))
OBJS += $(patsubst %.S,$(BUILD_DIR)/%.o,$(filter %.S,$(SRCS)))

# Embedded user init (riscv64 only, optional)
ifeq ($(ARCH),riscv64)
ifeq ($(EMBEDDED_INIT),1)
USER_INIT_BLOB := kernel/core/proc/user_init_blob.h
$(USER_INIT_BLOB): user/init/init.S user/init/linker.ld scripts/gen-user-init.sh
	./scripts/gen-user-init.sh $(ARCH)
$(OBJS): $(USER_INIT_BLOB)
endif
endif

# Dependency files
DEPS := $(OBJS:.o=.d)

# ============================================================
#                    Build Rules
# ============================================================

STAMP_DIR := $(BUILD_DIR)/stamps
BUSYBOX_STAMP := $(STAMP_DIR)/busybox.stamp
ROOTFS_BASE_STAMP := $(STAMP_DIR)/rootfs-base.stamp
ROOTFS_BUSYBOX_STAMP := $(STAMP_DIR)/rootfs-busybox.stamp
ROOTFS_INIT_STAMP := $(STAMP_DIR)/rootfs-init.stamp
ROOTFS_STAMP := $(STAMP_DIR)/rootfs.stamp
DISK_STAMP := $(STAMP_DIR)/disk.stamp
INITRAMFS_STAMP := $(STAMP_DIR)/initramfs.stamp
COMPILER_RT_STAMP := $(STAMP_DIR)/compiler-rt.stamp
USER_INIT := $(BUILD_DIR)/user/init
USER_INITRAMFS := $(BUILD_DIR)/user/initramfs/init

.PHONY: all clean run debug iso test user initramfs compiler-rt busybox rootfs rootfs-base rootfs-busybox rootfs-init disk check-tools

all: | _reset_count
all: $(KERNEL)

_reset_count:
	@mkdir -p $(BUILD_DIR) && echo 0 > $(OBJ_COUNT_FILE)

user: $(USER_INIT)

ifeq ($(USE_GCC),0)
USER_TOOLCHAIN_DEPS := $(COMPILER_RT_STAMP)
else
USER_TOOLCHAIN_DEPS :=
endif

compiler-rt: $(COMPILER_RT_STAMP)

$(COMPILER_RT_STAMP): scripts/build-compiler-rt.sh
	@mkdir -p $(STAMP_DIR)
	ARCH=$(ARCH) ./scripts/build-compiler-rt.sh $(ARCH)
	@touch $@

$(USER_INIT): $(USER_TOOLCHAIN_DEPS) user/init/main.c user/Makefile scripts/build-musl.sh
	./scripts/build-musl.sh $(ARCH)
	$(MAKE) -C user ARCH=$(ARCH) USE_GCC=$(USE_GCC)

initramfs: $(INITRAMFS_STAMP)

$(USER_INITRAMFS): $(USER_TOOLCHAIN_DEPS) user/initramfs/init.c user/Makefile scripts/build-musl.sh
	./scripts/build-musl.sh $(ARCH)
	$(MAKE) -C user ARCH=$(ARCH) USE_GCC=$(USE_GCC) initramfs

$(INITRAMFS_STAMP): $(USER_INITRAMFS) scripts/make-initramfs.sh
	@mkdir -p $(STAMP_DIR)
	$(QUIET_ENV) ARCH=$(ARCH) ./scripts/make-initramfs.sh $(ARCH)
	@touch $@

busybox: $(BUSYBOX_STAMP)

$(BUSYBOX_STAMP): tools/busybox/kairos_defconfig scripts/build-busybox.sh
	@mkdir -p $(STAMP_DIR)
	./scripts/build-busybox.sh $(ARCH)
	@touch $@

rootfs-base: $(ROOTFS_BASE_STAMP)

$(ROOTFS_BASE_STAMP): scripts/make-disk.sh
	@mkdir -p $(STAMP_DIR)
	$(QUIET_ENV) ROOTFS_ONLY=1 ROOTFS_STAGE=base ARCH=$(ARCH) ./scripts/make-disk.sh $(ARCH)
	@touch $@

rootfs-busybox: $(ROOTFS_BUSYBOX_STAMP)

$(ROOTFS_BUSYBOX_STAMP): $(BUSYBOX_STAMP) scripts/make-disk.sh
	@mkdir -p $(STAMP_DIR)
	$(QUIET_ENV) ROOTFS_ONLY=1 ROOTFS_STAGE=busybox ARCH=$(ARCH) ./scripts/make-disk.sh $(ARCH)
	@touch $@

rootfs-init: $(ROOTFS_INIT_STAMP)

$(ROOTFS_INIT_STAMP): $(USER_INIT) scripts/make-disk.sh
	@mkdir -p $(STAMP_DIR)
	$(QUIET_ENV) ROOTFS_ONLY=1 ROOTFS_STAGE=init ARCH=$(ARCH) ./scripts/make-disk.sh $(ARCH)
	@touch $@

rootfs: $(ROOTFS_STAMP)

$(ROOTFS_STAMP): $(ROOTFS_BASE_STAMP) $(ROOTFS_BUSYBOX_STAMP) $(ROOTFS_INIT_STAMP)
	@mkdir -p $(STAMP_DIR)
	@touch $@

# Track CFLAGS changes so object files rebuild when EXTRA_CFLAGS changes.
CFLAGS_HASH := $(shell printf '%s' "$(CFLAGS)" | sha1sum | awk '{print $$1}')
CFLAGS_STAMP := $(BUILD_DIR)/.cflags.$(CFLAGS_HASH)

$(CFLAGS_STAMP):
	@mkdir -p $(dir $@)
	@touch $@

# Progress counter for build output
OBJ_TOTAL := $(words $(OBJS))
OBJ_COUNT_FILE := $(BUILD_DIR)/.obj_count

define inc_count
$(shell mkdir -p $(BUILD_DIR) && \
  flock $(OBJ_COUNT_FILE).lock sh -c \
    'n=$$(cat $(OBJ_COUNT_FILE) 2>/dev/null || echo 0); n=$$((n+1)); echo $$n > $(OBJ_COUNT_FILE); echo $$n')
endef

# Link kernel
$(KERNEL): $(OBJS) $(LDSCRIPT)
	@echo "  LD      kairos.elf ($(OBJ_TOTAL) objects, $(ARCH))"
	@mkdir -p $(dir $@)
	$(Q)$(LD) $(LDFLAGS) -T $(LDSCRIPT) -o $@ $(OBJS)
	@if [ "$(ARCH)" = "riscv64" ]; then \
		echo "  PATCH   $@"; \
		python3 scripts/patch-elf-phdrs.py $@; \
	fi
	@echo "  OBJCOPY $(KERNEL_BIN)"
	$(Q)$(OBJCOPY) -O binary $@ $(KERNEL_BIN)

# Compile lwIP C files (relaxed warnings for third-party code)
$(BUILD_DIR)/$(LWIP_DIR)/%.o: $(LWIP_DIR)/%.c $(CFLAGS_STAMP)
	@echo "  [$(inc_count)/$(OBJ_TOTAL)] CC $<"
	@mkdir -p $(dir $@)
	$(Q)$(CC) $(LWIP_CFLAGS) -MMD -MP -c -o $@ $<

# Compile C files
$(BUILD_DIR)/%.o: %.c $(CFLAGS_STAMP)
	@echo "  [$(inc_count)/$(OBJ_TOTAL)] CC $<"
	@mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Assemble .S files
$(BUILD_DIR)/%.o: %.S $(CFLAGS_STAMP)
	@echo "  [$(inc_count)/$(OBJ_TOTAL)] AS $<"
	@mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Include dependencies
-include $(DEPS)

# ============================================================
#                    QEMU Targets
# ============================================================

# Common QEMU flags
QEMU_FLAGS := -machine $(QEMU_MACHINE) -m 256M -smp 4
QEMU_FLAGS += -serial stdio -monitor none

# Optional graphical output (QEMU_GUI=1)
ifeq ($(QEMU_GUI),1)
  QEMU_FLAGS += -display gtk
ifeq ($(ARCH),riscv64)
  QEMU_FLAGS += -device ramfb
else
  QEMU_FLAGS += -device virtio-gpu-pci
endif
else
  QEMU_FLAGS += -nographic
endif
QEMU_FLAGS += $(QEMU_EXTRA)

ifeq ($(ARCH),aarch64)
  QEMU_FLAGS += -cpu $(QEMU_CPU)
endif

# Add virtio disk
DISK_IMG := $(BUILD_DIR)/disk.img
QEMU_DISK_FLAGS :=
ifeq ($(ARCH),riscv64)
  # For RISC-V, explicitly create virtio-blk-device
  QEMU_DISK_FLAGS += -global virtio-mmio.force-legacy=false
  QEMU_DISK_FLAGS += -drive id=hd,file=$(DISK_IMG),format=raw,if=none
  QEMU_DISK_FLAGS += -device virtio-blk-device,drive=hd
else
  QEMU_DISK_FLAGS += -drive file=$(DISK_IMG),if=virtio,format=raw
endif

# RISC-V UEFI boot (Limine)
ifeq ($(ARCH),riscv64)
  UEFI_CODE_SRC ?= /usr/share/edk2/riscv/RISCV_VIRT_CODE.fd
  UEFI_VARS_SRC ?= /usr/share/edk2/riscv/RISCV_VIRT_VARS.fd
  UEFI_CODE := $(BUILD_DIR)/uefi-code.fd
  UEFI_VARS := $(BUILD_DIR)/uefi-vars.fd
  UEFI_BOOT := $(BUILD_DIR)/boot.img
  QEMU_UEFI_FLAGS := -drive if=pflash,format=raw,unit=0,file=$(UEFI_CODE),readonly=on
  QEMU_UEFI_FLAGS += -drive if=pflash,format=raw,unit=1,file=$(UEFI_VARS)
  QEMU_BOOT_FLAGS := -drive id=boot,file=$(UEFI_BOOT),format=raw,if=none
  QEMU_BOOT_FLAGS += -device virtio-blk-device,drive=boot,bootindex=0
  QEMU_MEDIA_FLAGS := $(QEMU_UEFI_FLAGS) $(QEMU_BOOT_FLAGS)
else ifeq ($(ARCH),x86_64)
  QEMU_MEDIA_FLAGS := -cdrom $(BUILD_DIR)/kairos.iso
else
  QEMU_MEDIA_FLAGS :=
endif

# Add network (virtio-net for development)
HOSTFWD_PORT ?=
ifeq ($(HOSTFWD_PORT),)
  QEMU_FLAGS += -netdev user,id=net0
else
  QEMU_FLAGS += -netdev user,id=net0,hostfwd=tcp::$(HOSTFWD_PORT)-:80
endif
ifeq ($(ARCH),riscv64)
  QEMU_FLAGS += -device virtio-net-device,netdev=net0
else
  QEMU_FLAGS += -device virtio-net-pci,netdev=net0
endif

QEMU_RUN_FLAGS := $(QEMU_FLAGS) $(QEMU_MEDIA_FLAGS) $(QEMU_DISK_FLAGS)

check-disk:
	@if [ -f "$(DISK_IMG)" ]; then \
		if ! debugfs -R "stat /bin/busybox" "$(DISK_IMG)" >/dev/null 2>&1; then \
			echo "WARN: $(DISK_IMG) missing /bin/busybox (run: make ARCH=$(ARCH) disk)"; \
		fi; \
	else \
		echo "WARN: $(DISK_IMG) not found (run: make ARCH=$(ARCH) disk)"; \
	fi

check-tools:
	@command -v $(QEMU) >/dev/null 2>&1 || { \
		echo "Error: $(QEMU) not found"; exit 1; }
	@command -v mke2fs >/dev/null 2>&1 || { \
		echo "Error: mke2fs not found (install e2fsprogs)"; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { \
		echo "Error: python3 not found"; exit 1; }
ifeq ($(ARCH),x86_64)
	@command -v xorriso >/dev/null 2>&1 || { \
		echo "Error: xorriso not found (needed for ISO)"; exit 1; }
endif
ifeq ($(ARCH),riscv64)
	@command -v mkfs.fat >/dev/null 2>&1 || command -v mkfs.vfat >/dev/null 2>&1 || { \
		echo "Error: mkfs.fat not found (install dosfstools)"; exit 1; }
	@if [ ! -f "$(UEFI_CODE_SRC)" ] || [ ! -f "$(UEFI_VARS_SRC)" ]; then \
		echo "Error: RISC-V UEFI firmware not found:"; \
		echo "  $(UEFI_CODE_SRC)"; \
		echo "  $(UEFI_VARS_SRC)"; \
		exit 1; \
	fi
endif

# Per-arch boot prerequisites (kernel image + boot media + disk)
ifeq ($(ARCH),x86_64)
  RUN_DEPS := check-tools iso disk
else ifeq ($(ARCH),riscv64)
  RUN_DEPS := check-tools $(KERNEL) uefi disk
else
  RUN_DEPS := check-tools $(KERNEL) disk
endif

run: $(RUN_DEPS)
	@$(MAKE) --no-print-directory check-disk
	@echo "  QEMU    $(ARCH) ($(QEMU_MACHINE), 256M, 4 SMP)"
	$(Q)$(QEMU) $(QEMU_RUN_FLAGS)

run-e1000: $(RUN_DEPS)
	@echo "  QEMU    $(ARCH) ($(QEMU_MACHINE), 256M, 4 SMP, e1000)"
	$(Q)$(QEMU) $(QEMU_RUN_FLAGS) -device e1000,netdev=net0

# Create bootable ISO (x86_64 only for now)
iso: $(KERNEL) initramfs
	./scripts/make-iso.sh $(ARCH)

# Run from ISO
run-iso: iso
	@echo "  QEMU    $(ARCH) (ISO boot)"
	$(Q)$(QEMU) -cdrom $(BUILD_DIR)/kairos.iso -m 256M $(QEMU_EXTRA)

debug: $(RUN_DEPS)
	@echo "  QEMU    $(ARCH) ($(QEMU_MACHINE), 256M, 4 SMP, GDB :1234)"
	@echo "  In another terminal: gdb $(KERNEL) -ex 'target remote localhost:1234'"
	$(Q)$(QEMU) $(QEMU_RUN_FLAGS) -s -S

# ============================================================
#                    Utility Targets
# ============================================================

clean:
	rm -rf build/

# Prepare RISC-V UEFI firmware + Limine boot image
uefi: $(KERNEL) initramfs
	$(QUIET_ENV) ARCH=$(ARCH) ./scripts/prepare-uefi.sh $(ARCH)
	$(QUIET_ENV) ARCH=$(ARCH) ./scripts/make-uefi-disk.sh $(ARCH)

# Create a disk image with ext2 filesystem
disk: $(DISK_STAMP)

$(DISK_STAMP): $(ROOTFS_STAMP) scripts/make-disk.sh
	@mkdir -p $(STAMP_DIR)
	$(QUIET_ENV) ARCH=$(ARCH) ./scripts/make-disk.sh $(ARCH)
	@touch $@

# Disassembly
disasm: $(KERNEL)
	$(OBJDUMP) -d $(KERNEL) > $(BUILD_DIR)/kairos.asm

# Symbol table
symbols: $(KERNEL)
	$(OBJDUMP) -t $(KERNEL) | sort > $(BUILD_DIR)/kairos.sym

# Run tests (in QEMU)
TEST_EXTRA_CFLAGS := -DCONFIG_KERNEL_TESTS=1
TEST_TIMEOUT ?= 180
TEST_LOG ?= $(BUILD_DIR)/test.log

test: check-tools scripts/run-qemu-test.sh
	rm -rf $(BUILD_DIR)/kernel $(BUILD_DIR)/third_party $(KERNEL) $(KERNEL_BIN) $(BUILD_DIR)/.cflags.*
	QEMU_CMD="$(MAKE) --no-print-directory ARCH=$(ARCH) EXTRA_CFLAGS='$(TEST_EXTRA_CFLAGS)' run" TEST_TIMEOUT="$(TEST_TIMEOUT)" TEST_LOG="$(TEST_LOG)" ./scripts/run-qemu-test.sh; rc=$$?; \
	rm -rf $(BUILD_DIR)/kernel $(BUILD_DIR)/third_party $(KERNEL) $(KERNEL_BIN) $(BUILD_DIR)/.cflags.*; \
	exit $$rc

# Show help
help:
	@echo "Kairos Kernel Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build kernel (default)"
	@echo "  run      - Run in QEMU"
	@echo "  debug    - Run with GDB server"
	@echo "  clean    - Remove build artifacts"
	@echo "  user     - Build userland init"
	@echo "  initramfs - Build initramfs image"
	@echo "  compiler-rt - Build clang compiler-rt builtins"
	@echo "  busybox  - Build busybox for userland"
	@echo "  rootfs-base    - Stage rootfs base"
	@echo "  rootfs-busybox - Stage busybox + applets"
	@echo "  rootfs-init    - Stage init"
	@echo "  rootfs         - Stage full rootfs"
	@echo "  disk     - Create disk image"
	@echo "  uefi     - Prepare RISC-V UEFI boot image"
	@echo "  check-tools - Verify host toolchain"
	@echo "  test     - Run kernel tests"
	@echo ""
	@echo "Variables:"
	@echo "  ARCH     - Target architecture (riscv64, x86_64, aarch64)"
	@echo "  EMBEDDED_INIT - Build embedded init blob (riscv64 only)"
	@echo "  V        - Verbose mode (V=1)"
	@echo ""
	@echo "Examples:"
	@echo "  make ARCH=x86_64 run"
	@echo "  make V=1"
