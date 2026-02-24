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
#   make uefi               # Prepare UEFI boot image (all architectures)
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
ifeq ($(MAKELEVEL),0)
MAKEFLAGS += -j$(NPROC)
endif

# Build directory
BUILD_ROOT ?= build
BUILD_ROOT_ABS := $(abspath $(BUILD_ROOT))
BUILD_DIR := $(BUILD_ROOT)/$(ARCH)

# Output files
KERNEL := $(BUILD_DIR)/kairos.elf
KERNEL_BIN := $(BUILD_DIR)/kairos.bin
ISO := $(BUILD_DIR)/kairos.iso

# Verbose mode (V=1 for verbose)
V ?= 0
HELP_ADVANCED ?= 0
ifeq ($(V),0)
  Q := @
  QUIET_ENV := QUIET=1
  MAKEFLAGS += --no-print-directory
else
  Q :=
  QUIET_ENV :=
endif

KAIROS_CMD := ./scripts/kairos.sh --arch $(ARCH) --build-root $(BUILD_ROOT) --jobs $(NPROC)
ifeq ($(V),0)
  KAIROS_CMD += --quiet
else
  KAIROS_CMD += --verbose
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
TOOLCHAIN_MODE ?= auto
WITH_TCC ?= 1
INITRAMFS_BUSYBOX ?= 0
QEMU_SMP ?= 4

# Optional subsystems (set to 0 to disable)
CONFIG_DRM_LITE ?= 1

ifeq ($(ARCH),riscv64)
  CROSS_COMPILE ?= riscv64-unknown-elf-
  CLANG_TARGET := riscv64-unknown-elf
  QEMU := qemu-system-riscv64
  QEMU_MACHINE := virt
  QEMU_VIRTIO_BLK_DEV := virtio-blk-device
  KERNEL_LOAD := 0x80200000
else ifeq ($(ARCH),x86_64)
  CROSS_COMPILE ?=
  CLANG_TARGET := x86_64-unknown-elf
  QEMU := qemu-system-x86_64
  QEMU_MACHINE := q35
  QEMU_VIRTIO_BLK_DEV := virtio-blk-pci
  KERNEL_LOAD := 0xffffffff80000000
else ifeq ($(ARCH),aarch64)
  CROSS_COMPILE ?= aarch64-none-elf-
  CLANG_TARGET := aarch64-unknown-elf
  QEMU := qemu-system-aarch64
  QEMU_MACHINE := virt,gic-version=3
  QEMU_CPU := cortex-a72
  QEMU_VIRTIO_BLK_DEV := virtio-blk-pci
  INITRAMFS_BUSYBOX := 1
  # AArch64 SMP path is still unstable; default to single CPU for run/debug.
  QEMU_SMP := 1
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
# LWIP_SRCS is kept explicit (see below).
CORE_SRCS := $(wildcard kernel/core/*.c kernel/core/*/*.c)
CORE_SRCS += $(wildcard kernel/lib/*.c)
CORE_SRCS += $(wildcard kernel/firmware/*.c)
CORE_SRCS += $(wildcard kernel/fs/*/*.c)
CORE_SRCS += $(wildcard kernel/bus/*.c)
CORE_SRCS += $(wildcard kernel/drivers/*/*.c)
CORE_SRCS += $(wildcard kernel/net/*.c) kernel/net/lwip_port/sys_arch.c
CORE_SRCS += $(wildcard kernel/platform/*.c)
CORE_SRCS += kernel/boot/boot.c kernel/boot/limine.c

ifeq ($(CONFIG_DRM_LITE),0)
CORE_SRCS := $(filter-out kernel/drivers/gpu/drm_lite.c,$(CORE_SRCS))
endif

# Architecture-specific sources (auto-discovered)
ARCH_SRCS := $(wildcard kernel/arch/$(ARCH)/*.c kernel/arch/$(ARCH)/*.S)
ARCH_SRCS += $(wildcard kernel/arch/$(ARCH)/lib/*.c kernel/arch/$(ARCH)/lib/*.S)

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
TCC_STAMP := $(STAMP_DIR)/tcc.stamp
ROOTFS_BASE_STAMP := $(STAMP_DIR)/rootfs-base.stamp
ROOTFS_BUSYBOX_STAMP := $(STAMP_DIR)/rootfs-busybox.stamp
ROOTFS_INIT_STAMP := $(STAMP_DIR)/rootfs-init.stamp
ROOTFS_TCC_STAMP := $(STAMP_DIR)/rootfs-tcc.stamp
ROOTFS_STAMP := $(STAMP_DIR)/rootfs.stamp
DISK_STAMP := $(STAMP_DIR)/disk.stamp
INITRAMFS_STAMP := $(STAMP_DIR)/initramfs.stamp
COMPILER_RT_STAMP := $(STAMP_DIR)/compiler-rt.stamp
MUSL_STAMP := $(STAMP_DIR)/musl.stamp
USER_INIT := $(BUILD_DIR)/user/init
USER_INITRAMFS := $(BUILD_DIR)/user/initramfs/init
KAIROS_DEPS := scripts/kairos.sh $(wildcard scripts/modules/*.sh scripts/lib/*.sh scripts/impl/*.sh scripts/patches/*/*)

ifeq ($(WITH_TCC),1)
ROOTFS_OPTIONAL_STAMPS := $(ROOTFS_TCC_STAMP)
else
ROOTFS_OPTIONAL_STAMPS :=
endif

.PHONY: all clean clean-all distclean run run-direct run-e1000 run-e1000-direct debug iso test test-ci-default test-exec-elf-smoke test-tcc-smoke test-busybox-applets-smoke test-errno-smoke test-isolated test-driver test-mm test-sync test-vfork test-sched test-crash test-syscall-trap test-syscall test-vfs-ipc test-socket test-device-virtio test-devmodel test-tty test-soak-pr test-concurrent-smoke test-concurrent-vfs-ipc gc-runs lock-status lock-clean-stale print-config user initramfs compiler-rt busybox tcc rootfs rootfs-base rootfs-busybox rootfs-init rootfs-tcc disk uefi check-tools doctor

all: | _reset_count
all: $(KERNEL)

_reset_count:
	@mkdir -p $(BUILD_DIR) && echo 0 > $(OBJ_COUNT_FILE)

user: $(USER_INIT)

ifeq ($(TOOLCHAIN_MODE),clang)
USER_TOOLCHAIN_DEPS := $(COMPILER_RT_STAMP)
else
USER_TOOLCHAIN_DEPS :=
endif

compiler-rt: $(COMPILER_RT_STAMP)

$(COMPILER_RT_STAMP): $(KAIROS_DEPS)
	@mkdir -p $(STAMP_DIR)
	$(Q)USE_GCC=$(USE_GCC) TOOLCHAIN_MODE=$(TOOLCHAIN_MODE) TOOLCHAIN_LOCK_WAIT=$(TOOLCHAIN_LOCK_WAIT) $(KAIROS_CMD) toolchain compiler-rt
	@touch $@

$(MUSL_STAMP): $(USER_TOOLCHAIN_DEPS) $(KAIROS_DEPS)
	@mkdir -p $(STAMP_DIR)
	$(Q)USE_GCC=$(USE_GCC) TOOLCHAIN_MODE=$(TOOLCHAIN_MODE) TOOLCHAIN_LOCK_WAIT=$(TOOLCHAIN_LOCK_WAIT) $(KAIROS_CMD) toolchain musl
	@touch $@

$(USER_INIT): $(MUSL_STAMP) user/init/main.c user/Makefile
	$(Q)$(MAKE) -C user ARCH=$(ARCH) BUILD_ROOT=$(BUILD_ROOT_ABS) USE_GCC=$(USE_GCC) V=$(V)

initramfs: $(INITRAMFS_STAMP)

$(USER_INITRAMFS): $(MUSL_STAMP) user/initramfs/init.c user/Makefile
	$(Q)$(MAKE) -C user ARCH=$(ARCH) BUILD_ROOT=$(BUILD_ROOT_ABS) USE_GCC=$(USE_GCC) V=$(V) initramfs

$(INITRAMFS_STAMP): $(USER_INITRAMFS) $(BUSYBOX_STAMP) $(KAIROS_DEPS) scripts/busybox-applets.txt
	@mkdir -p $(STAMP_DIR)
	$(Q)INITRAMFS_BUSYBOX=$(INITRAMFS_BUSYBOX) $(KAIROS_CMD) image initramfs
	@touch $@

busybox: $(BUSYBOX_STAMP)

$(BUSYBOX_STAMP): $(MUSL_STAMP) $(KAIROS_DEPS) tools/busybox/kairos_defconfig
	@mkdir -p $(STAMP_DIR)
	$(Q)USE_GCC=$(USE_GCC) TOOLCHAIN_MODE=$(TOOLCHAIN_MODE) TOOLCHAIN_LOCK_WAIT=$(TOOLCHAIN_LOCK_WAIT) $(KAIROS_CMD) toolchain busybox
	@touch $@

tcc: $(TCC_STAMP)

$(TCC_STAMP): $(MUSL_STAMP) $(KAIROS_DEPS)
	@mkdir -p $(STAMP_DIR)
	$(Q)USE_GCC=$(USE_GCC) TOOLCHAIN_MODE=$(TOOLCHAIN_MODE) TOOLCHAIN_LOCK_WAIT=$(TOOLCHAIN_LOCK_WAIT) $(KAIROS_CMD) toolchain tcc
	@touch $@

rootfs-base: $(ROOTFS_BASE_STAMP)

$(ROOTFS_BASE_STAMP): $(KAIROS_DEPS)
	@mkdir -p $(STAMP_DIR)
	$(Q)$(KAIROS_CMD) image rootfs-base
	@touch $@

rootfs-busybox: $(ROOTFS_BUSYBOX_STAMP)

$(ROOTFS_BUSYBOX_STAMP): $(BUSYBOX_STAMP) $(KAIROS_DEPS) scripts/busybox-applets.txt
	@mkdir -p $(STAMP_DIR)
	$(Q)$(KAIROS_CMD) image rootfs-busybox
	@touch $@

rootfs-init: $(ROOTFS_INIT_STAMP)

$(ROOTFS_INIT_STAMP): $(USER_INIT) $(KAIROS_DEPS)
	@mkdir -p $(STAMP_DIR)
	$(Q)$(KAIROS_CMD) image rootfs-init
	@touch $@

rootfs-tcc: $(ROOTFS_TCC_STAMP)

$(ROOTFS_TCC_STAMP): $(TCC_STAMP) $(KAIROS_DEPS)
	@mkdir -p $(STAMP_DIR)
	$(Q)$(KAIROS_CMD) image rootfs-tcc
	@touch $@

rootfs: $(ROOTFS_STAMP)

$(ROOTFS_STAMP): $(ROOTFS_BASE_STAMP) $(ROOTFS_BUSYBOX_STAMP) $(ROOTFS_INIT_STAMP) $(ROOTFS_OPTIONAL_STAMPS)
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

# Link kernel
$(KERNEL): $(OBJS) $(LDSCRIPT)
	@echo "  LD      kairos.elf ($(OBJ_TOTAL) objects, $(ARCH))"
	@mkdir -p $(dir $@)
	$(Q)$(LD) $(LDFLAGS) -T $(LDSCRIPT) -o $@ $(OBJS)
	@if [ "$(ARCH)" = "riscv64" ] || [ "$(ARCH)" = "aarch64" ]; then \
		echo "  PATCH   $@"; \
		python3 scripts/patch-elf-phdrs.py $@; \
	fi
	@echo "  OBJCOPY $(KERNEL_BIN)"
	$(Q)$(OBJCOPY) -O binary $@ $(KERNEL_BIN)

# Compile lwIP C files (relaxed warnings for third-party code)
$(BUILD_DIR)/$(LWIP_DIR)/%.o: $(LWIP_DIR)/%.c $(CFLAGS_STAMP) | _reset_count
	@mkdir -p $(dir $@)
	@flock $(OBJ_COUNT_FILE).lock sh -c \
	  'n=$$(cat $(OBJ_COUNT_FILE) 2>/dev/null || echo 0); n=$$((n+1)); echo $$n > $(OBJ_COUNT_FILE); printf "  [%s/$(OBJ_TOTAL)] CC %s\n" "$$n" "$<"'
	$(Q)$(CC) $(LWIP_CFLAGS) -MMD -MP -c -o $@ $<

# Compile C files
$(BUILD_DIR)/%.o: %.c $(CFLAGS_STAMP) | _reset_count
	@mkdir -p $(dir $@)
	@flock $(OBJ_COUNT_FILE).lock sh -c \
	  'n=$$(cat $(OBJ_COUNT_FILE) 2>/dev/null || echo 0); n=$$((n+1)); echo $$n > $(OBJ_COUNT_FILE); printf "  [%s/$(OBJ_TOTAL)] CC %s\n" "$$n" "$<"'
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Assemble .S files
$(BUILD_DIR)/%.o: %.S $(CFLAGS_STAMP) | _reset_count
	@mkdir -p $(dir $@)
	@flock $(OBJ_COUNT_FILE).lock sh -c \
	  'n=$$(cat $(OBJ_COUNT_FILE) 2>/dev/null || echo 0); n=$$((n+1)); echo $$n > $(OBJ_COUNT_FILE); printf "  [%s/$(OBJ_TOTAL)] AS %s\n" "$$n" "$<"'
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Include dependencies
-include $(DEPS)

# ============================================================
#                    QEMU Targets
# ============================================================

# Common QEMU flags
QEMU_FLAGS := -machine $(QEMU_MACHINE) -m 256M -smp $(QEMU_SMP)
# Use QEMU stdio multiplexer for robust interactive input in -nographic mode.
QEMU_FLAGS += -serial mon:stdio
QEMU_UEFI_NOISE_FILTER := ./scripts/impl/filter-uefi-noise.sh

ifeq ($(ARCH),aarch64)
  # Avoid loading mismatched PCI option ROMs in AArch64 UEFI boot.
  QEMU_VIRTIO_PCI_ROM_OPT := ,romfile=
  # Filter known non-fatal EDK2 noise by default on AArch64.
  QEMU_FILTER_UEFI_NOISE ?= 1
else
  QEMU_VIRTIO_PCI_ROM_OPT :=
  QEMU_FILTER_UEFI_NOISE ?= 0
endif

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
# Silence OVMF debug spew (Image Section Alignment warnings etc.)
ifeq ($(ARCH),x86_64)
QEMU_FLAGS += -global isa-debugcon.iobase=0x402 -debugcon file:/dev/null
endif
QEMU_FLAGS += $(QEMU_EXTRA)

# Pass -cpu when defined (riscv64 and aarch64)
ifneq ($(QEMU_CPU),)
  QEMU_FLAGS += -cpu $(QEMU_CPU)
endif

# Add virtio disk
DISK_IMG := $(BUILD_DIR)/disk.img
QEMU_DISK_FLAGS :=
ifeq ($(ARCH),riscv64)
  # Use modern virtio-mmio mode on RISC-V.
  QEMU_DISK_FLAGS += -global virtio-mmio.force-legacy=false
endif
QEMU_DISK_FLAGS += -drive id=hd,file=$(DISK_IMG),format=raw,if=none
QEMU_DISK_FLAGS += -device $(QEMU_VIRTIO_BLK_DEV),drive=hd$(QEMU_VIRTIO_PCI_ROM_OPT)

# UEFI firmware paths (per architecture)
ifeq ($(ARCH),riscv64)
  UEFI_CODE_SRC ?= /usr/share/edk2/riscv/RISCV_VIRT_CODE.fd
  UEFI_VARS_SRC ?= /usr/share/edk2/riscv/RISCV_VIRT_VARS.fd
else ifeq ($(ARCH),x86_64)
  UEFI_CODE_SRC ?= /usr/share/edk2/ovmf/OVMF_CODE.fd
  UEFI_VARS_SRC ?= /usr/share/edk2/ovmf/OVMF_VARS.fd
else ifeq ($(ARCH),aarch64)
  ifneq ($(wildcard /usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw),)
    UEFI_CODE_SRC ?= /usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw
  else
    UEFI_CODE_SRC ?= /usr/share/edk2/aarch64/QEMU_EFI-pflash.raw
  endif
  UEFI_VARS_SRC ?= /usr/share/edk2/aarch64/vars-template-pflash.raw
endif

UEFI_CODE := $(BUILD_DIR)/uefi-code.fd
UEFI_VARS := $(BUILD_DIR)/uefi-vars.fd
UEFI_BOOT := $(BUILD_DIR)/boot.img
UEFI_BOOT_DIR := $(BUILD_DIR)/bootfs
UEFI_BOOT_MODE ?=
QEMU_UEFI_BOOT_MODE ?=

VALID_UEFI_BOOT_MODES := dir img both
VALID_QEMU_UEFI_BOOT_MODES := dir img

ifeq ($(strip $(UEFI_BOOT_MODE)),)
ifeq ($(strip $(QEMU_UEFI_BOOT_MODE)),)
UEFI_BOOT_MODE := dir
else
UEFI_BOOT_MODE := $(QEMU_UEFI_BOOT_MODE)
endif
endif

ifneq ($(filter $(UEFI_BOOT_MODE),$(VALID_UEFI_BOOT_MODES)),$(UEFI_BOOT_MODE))
$(error invalid UEFI_BOOT_MODE='$(UEFI_BOOT_MODE)' (expected dir|img|both))
endif

ifeq ($(strip $(QEMU_UEFI_BOOT_MODE)),)
ifeq ($(UEFI_BOOT_MODE),both)
QEMU_UEFI_BOOT_MODE := dir
else
QEMU_UEFI_BOOT_MODE := $(UEFI_BOOT_MODE)
endif
endif

ifneq ($(filter $(QEMU_UEFI_BOOT_MODE),$(VALID_QEMU_UEFI_BOOT_MODES)),$(QEMU_UEFI_BOOT_MODE))
$(error invalid QEMU_UEFI_BOOT_MODE='$(QEMU_UEFI_BOOT_MODE)' (expected dir|img))
endif

ifneq ($(UEFI_BOOT_MODE),both)
ifneq ($(QEMU_UEFI_BOOT_MODE),$(UEFI_BOOT_MODE))
$(error UEFI_BOOT_MODE='$(UEFI_BOOT_MODE)' mismatches QEMU_UEFI_BOOT_MODE='$(QEMU_UEFI_BOOT_MODE)'; set one mode or use UEFI_BOOT_MODE=both)
endif
endif

# UEFI pflash + Limine boot image (all architectures)
QEMU_UEFI_FLAGS := -drive if=pflash,format=raw,unit=0,file=$(UEFI_CODE),readonly=on
QEMU_UEFI_FLAGS += -drive if=pflash,format=raw,unit=1,file=$(UEFI_VARS)

ifeq ($(QEMU_UEFI_BOOT_MODE),img)
QEMU_BOOT_FLAGS := -drive id=boot,file=$(UEFI_BOOT),format=raw,if=none
else
QEMU_BOOT_FLAGS := -drive id=boot,file=fat:rw:$(UEFI_BOOT_DIR),format=raw,if=none
endif
QEMU_BOOT_FLAGS += -device $(QEMU_VIRTIO_BLK_DEV),drive=boot,bootindex=0$(QEMU_VIRTIO_PCI_ROM_OPT)

QEMU_MEDIA_FLAGS := $(QEMU_UEFI_FLAGS) $(QEMU_BOOT_FLAGS)

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
  QEMU_FLAGS += -device virtio-net-pci,netdev=net0$(QEMU_VIRTIO_PCI_ROM_OPT)
endif

QEMU_RUN_FLAGS := $(QEMU_FLAGS) $(QEMU_MEDIA_FLAGS) $(QEMU_DISK_FLAGS)
ifeq ($(shell tty -s && test -r /dev/tty && echo yes),yes)
QEMU_STDIN := </dev/tty
else
QEMU_STDIN :=
endif

check-disk:
	@if [ -f "$(DISK_IMG)" ]; then \
		if ! debugfs -R "stat /bin/busybox" "$(DISK_IMG)" >/dev/null 2>&1; then \
			echo "WARN: $(DISK_IMG) missing /bin/busybox (run: make ARCH=$(ARCH) disk)"; \
		fi; \
	else \
		echo "WARN: $(DISK_IMG) not found (run: make ARCH=$(ARCH) disk)"; \
	fi

check-tools:
	$(Q)UEFI_CODE_SRC=$(UEFI_CODE_SRC) UEFI_VARS_SRC=$(UEFI_VARS_SRC) $(KAIROS_CMD) doctor

doctor: check-tools

# Boot prerequisites: UEFI firmware + Limine boot image + disk (all architectures)
RUN_DEPS := check-tools $(KERNEL) uefi disk

# Avoid self-contention on image locks when make runs with global -j.
.NOTPARALLEL: $(ROOTFS_STAMP) run-direct run-e1000-direct debug

run:
	$(Q)if [ "$(RUN_ISOLATED)" = "1" ]; then \
		if [ "$(RUN_GC_AUTO)" = "1" ]; then \
			$(MAKE) --no-print-directory gc-runs RUNS_KEEP="$(RUNS_KEEP_RUN)" TEST_RUNS_ROOT="$(RUN_RUNS_ROOT)"; \
		fi; \
		$(MAKE) --no-print-directory ARCH="$(ARCH)" BUILD_ROOT="$(RUN_BUILD_ROOT)" \
			RUN_ISOLATED=0 RUN_ID="$(RUN_ID)" run-direct; \
	else \
		$(MAKE) --no-print-directory ARCH="$(ARCH)" BUILD_ROOT="$(BUILD_ROOT)" RUN_ID="$(RUN_ID)" run-direct; \
	fi

run-direct: $(RUN_DEPS) scripts/run-qemu-session.sh
	@$(MAKE) --no-print-directory check-disk
	@echo "  QEMU    $(ARCH) ($(QEMU_MACHINE), 256M, $(QEMU_SMP) SMP)"
ifeq ($(QEMU_FILTER_UEFI_NOISE),1)
ifneq ($(strip $(QEMU_STDIN)),)
	$(Q)RUN_ID="$(RUN_ID)" SESSION_KIND=run SESSION_TIMEOUT="$(RUN_TIMEOUT)" \
		SESSION_LOG="$(RUN_LOG)" SESSION_BUILD_ROOT="$(BUILD_ROOT)" SESSION_BUILD_DIR="$(BUILD_DIR)" \
		SESSION_ARCH="$(ARCH)" SESSION_RUN_ID="$(RUN_ID)" SESSION_REQUIRE_BOOT="$(RUN_REQUIRE_BOOT)" \
		SESSION_LOCK_WAIT="$(RUN_LOCK_WAIT)" \
		SESSION_MANIFEST="$(RUN_MANIFEST)" SESSION_RESULT="$(RUN_RESULT)" \
		UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
		QEMU_CMD='$(QEMU) $(QEMU_RUN_FLAGS) $(QEMU_STDIN)' ./scripts/run-qemu-session.sh
else
	$(Q)RUN_ID="$(RUN_ID)" SESSION_KIND=run SESSION_TIMEOUT="$(RUN_TIMEOUT)" \
		SESSION_LOG="$(RUN_LOG)" SESSION_BUILD_ROOT="$(BUILD_ROOT)" SESSION_BUILD_DIR="$(BUILD_DIR)" \
		SESSION_ARCH="$(ARCH)" SESSION_RUN_ID="$(RUN_ID)" SESSION_REQUIRE_BOOT="$(RUN_REQUIRE_BOOT)" \
		SESSION_LOCK_WAIT="$(RUN_LOCK_WAIT)" \
		SESSION_MANIFEST="$(RUN_MANIFEST)" SESSION_RESULT="$(RUN_RESULT)" \
		SESSION_FILTER_CMD="$(QEMU_UEFI_NOISE_FILTER)" \
		UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
		QEMU_CMD='$(QEMU) $(QEMU_RUN_FLAGS) $(QEMU_STDIN)' ./scripts/run-qemu-session.sh
endif
else
	$(Q)RUN_ID="$(RUN_ID)" SESSION_KIND=run SESSION_TIMEOUT="$(RUN_TIMEOUT)" \
		SESSION_LOG="$(RUN_LOG)" SESSION_BUILD_ROOT="$(BUILD_ROOT)" SESSION_BUILD_DIR="$(BUILD_DIR)" \
		SESSION_ARCH="$(ARCH)" SESSION_RUN_ID="$(RUN_ID)" SESSION_REQUIRE_BOOT="$(RUN_REQUIRE_BOOT)" \
		SESSION_LOCK_WAIT="$(RUN_LOCK_WAIT)" \
		SESSION_MANIFEST="$(RUN_MANIFEST)" SESSION_RESULT="$(RUN_RESULT)" \
		UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
		QEMU_CMD='$(QEMU) $(QEMU_RUN_FLAGS) $(QEMU_STDIN)' ./scripts/run-qemu-session.sh
endif

run-e1000:
	$(Q)if [ "$(RUN_ISOLATED)" = "1" ]; then \
		if [ "$(RUN_GC_AUTO)" = "1" ]; then \
			$(MAKE) --no-print-directory gc-runs RUNS_KEEP="$(RUNS_KEEP_RUN)" TEST_RUNS_ROOT="$(RUN_RUNS_ROOT)"; \
		fi; \
		$(MAKE) --no-print-directory ARCH="$(ARCH)" BUILD_ROOT="$(RUN_BUILD_ROOT)" \
			RUN_ISOLATED=0 RUN_ID="$(RUN_ID)" run-e1000-direct; \
	else \
		$(MAKE) --no-print-directory ARCH="$(ARCH)" BUILD_ROOT="$(BUILD_ROOT)" RUN_ID="$(RUN_ID)" run-e1000-direct; \
	fi

run-e1000-direct: $(RUN_DEPS) scripts/run-qemu-session.sh
	@$(MAKE) --no-print-directory check-disk
	@echo "  QEMU    $(ARCH) ($(QEMU_MACHINE), 256M, $(QEMU_SMP) SMP, e1000)"
ifeq ($(QEMU_FILTER_UEFI_NOISE),1)
ifneq ($(strip $(QEMU_STDIN)),)
	$(Q)RUN_ID="$(RUN_ID)" SESSION_KIND=run SESSION_TIMEOUT="$(RUN_TIMEOUT)" \
		SESSION_LOG="$(RUN_LOG)" SESSION_BUILD_ROOT="$(BUILD_ROOT)" SESSION_BUILD_DIR="$(BUILD_DIR)" \
		SESSION_ARCH="$(ARCH)" SESSION_RUN_ID="$(RUN_ID)" SESSION_REQUIRE_BOOT="$(RUN_REQUIRE_BOOT)" \
		SESSION_LOCK_WAIT="$(RUN_LOCK_WAIT)" \
		SESSION_MANIFEST="$(RUN_MANIFEST)" SESSION_RESULT="$(RUN_RESULT)" \
		UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
		QEMU_CMD='$(QEMU) $(QEMU_RUN_FLAGS) -device e1000,netdev=net0 $(QEMU_STDIN)' ./scripts/run-qemu-session.sh
else
	$(Q)RUN_ID="$(RUN_ID)" SESSION_KIND=run SESSION_TIMEOUT="$(RUN_TIMEOUT)" \
		SESSION_LOG="$(RUN_LOG)" SESSION_BUILD_ROOT="$(BUILD_ROOT)" SESSION_BUILD_DIR="$(BUILD_DIR)" \
		SESSION_ARCH="$(ARCH)" SESSION_RUN_ID="$(RUN_ID)" SESSION_REQUIRE_BOOT="$(RUN_REQUIRE_BOOT)" \
		SESSION_LOCK_WAIT="$(RUN_LOCK_WAIT)" \
		SESSION_MANIFEST="$(RUN_MANIFEST)" SESSION_RESULT="$(RUN_RESULT)" \
		SESSION_FILTER_CMD="$(QEMU_UEFI_NOISE_FILTER)" \
		UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
		QEMU_CMD='$(QEMU) $(QEMU_RUN_FLAGS) -device e1000,netdev=net0 $(QEMU_STDIN)' ./scripts/run-qemu-session.sh
endif
else
	$(Q)RUN_ID="$(RUN_ID)" SESSION_KIND=run SESSION_TIMEOUT="$(RUN_TIMEOUT)" \
		SESSION_LOG="$(RUN_LOG)" SESSION_BUILD_ROOT="$(BUILD_ROOT)" SESSION_BUILD_DIR="$(BUILD_DIR)" \
		SESSION_ARCH="$(ARCH)" SESSION_RUN_ID="$(RUN_ID)" SESSION_REQUIRE_BOOT="$(RUN_REQUIRE_BOOT)" \
		SESSION_LOCK_WAIT="$(RUN_LOCK_WAIT)" \
		SESSION_MANIFEST="$(RUN_MANIFEST)" SESSION_RESULT="$(RUN_RESULT)" \
		UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
		QEMU_CMD='$(QEMU) $(QEMU_RUN_FLAGS) -device e1000,netdev=net0 $(QEMU_STDIN)' ./scripts/run-qemu-session.sh
endif

# Create bootable ISO (x86_64 only for now)
iso: $(KERNEL) initramfs
	$(Q)$(KAIROS_CMD) image iso

# Run from ISO
run-iso: iso
	@echo "  QEMU    $(ARCH) (ISO boot)"
	$(Q)$(QEMU) -cdrom $(ISO) -m 256M $(QEMU_EXTRA)

debug: $(RUN_DEPS)
	@echo "  QEMU    $(ARCH) ($(QEMU_MACHINE), 256M, $(QEMU_SMP) SMP, GDB :1234)"
	@echo "  In another terminal: gdb $(KERNEL) -ex 'target remote localhost:1234'"
	$(Q)$(QEMU) $(QEMU_RUN_FLAGS) -s -S $(QEMU_STDIN)

# ============================================================
#                    Utility Targets
# ============================================================

clean:
	rm -rf $(BUILD_DIR)

clean-all:
	rm -rf build/

# Deep clean: also purge build artifacts from third_party source trees
distclean: clean-all
	@for d in third_party/musl third_party/busybox; do \
		if [ -d "$$d" ]; then \
			echo "  CLEAN   $$d"; \
			$(MAKE) -C "$$d" distclean >/dev/null 2>&1 || true; \
		fi; \
	done

# Prepare UEFI firmware + Limine boot image
uefi: $(KERNEL) initramfs
	$(Q)UEFI_CODE_SRC=$(UEFI_CODE_SRC) UEFI_VARS_SRC=$(UEFI_VARS_SRC) QEMU_SMP=$(QEMU_SMP) UEFI_BOOT_MODE=$(UEFI_BOOT_MODE) \
		QEMU_UEFI_BOOT_MODE=$(QEMU_UEFI_BOOT_MODE) $(KAIROS_CMD) image uefi

# Create a disk image with ext2 filesystem
disk: $(DISK_STAMP)

$(DISK_STAMP): $(ROOTFS_STAMP) $(KAIROS_DEPS)
	@mkdir -p $(STAMP_DIR)
	$(Q)$(KAIROS_CMD) image disk
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
TCC_SMOKE_TIMEOUT ?= 240
TCC_SMOKE_LOG ?= $(BUILD_DIR)/tcc-smoke.log
TCC_SMOKE_EXTRA_CFLAGS ?=
EXEC_ELF_SMOKE_TIMEOUT ?= $(TCC_SMOKE_TIMEOUT)
EXEC_ELF_SMOKE_LOG ?= $(BUILD_DIR)/exec-elf-smoke.log
EXEC_ELF_SMOKE_EXTRA_CFLAGS ?= $(TCC_SMOKE_EXTRA_CFLAGS)
BUSYBOX_APPLET_SMOKE_TIMEOUT ?= 240
BUSYBOX_APPLET_SMOKE_LOG ?= $(BUILD_DIR)/busybox-applets-smoke.log
BUSYBOX_APPLET_SMOKE_EXTRA_CFLAGS ?=
ERRNO_SMOKE_TIMEOUT ?= 240
ERRNO_SMOKE_LOG ?= $(BUILD_DIR)/errno-smoke.log
ERRNO_SMOKE_EXTRA_CFLAGS ?=
SOAK_TIMEOUT ?= 600
SOAK_LOG ?= $(BUILD_DIR)/soak.log
SOAK_EXTRA_CFLAGS ?= -DCONFIG_PMM_PCP_MODE=2
SOAK_PR_TIMEOUT ?= 1800
SOAK_PR_EXTRA_CFLAGS ?= -DCONFIG_KERNEL_FAULT_INJECT=1 -DCONFIG_KERNEL_SOAK_PR_DURATION_SEC=900 -DCONFIG_KERNEL_SOAK_PR_FAULT_PERMILLE=3
TEST_RUNS_ROOT ?= build/runs
RUNS_KEEP ?= 20
GC_RUNS_AUTO ?= 1
TEST_ISOLATED ?= 1
TCC_SMOKE_ISOLATED ?= 0
EXEC_ELF_SMOKE_ISOLATED ?= $(TCC_SMOKE_ISOLATED)
BUSYBOX_APPLET_SMOKE_ISOLATED ?= 0
ERRNO_SMOKE_ISOLATED ?= 0
TEST_CONCURRENCY ?= 3
TEST_ROUNDS ?= 3
TEST_CONCURRENT_TARGET ?= test-vfs-ipc
TEST_CONCURRENT_TIMEOUT ?= $(TEST_TIMEOUT)
RUN_RUNS_ROOT ?= build/runs/run
RUNS_KEEP_RUN ?= 5
RUN_GC_AUTO ?= 1
RUN_ISOLATED ?= 1
RUN_TIMEOUT ?= 0
RUN_REQUIRE_BOOT ?= 1
LOCK_WAIT ?= 0
RUN_LOCK_WAIT ?= $(LOCK_WAIT)
TEST_LOCK_WAIT ?= $(LOCK_WAIT)
TOOLCHAIN_LOCK_WAIT ?= 900
TEST_LOG_FWD :=
TCC_SMOKE_LOG_FWD :=
EXEC_ELF_SMOKE_LOG_FWD :=
BUSYBOX_APPLET_SMOKE_LOG_FWD :=
ERRNO_SMOKE_LOG_FWD :=
ifneq ($(origin TEST_LOG),file)
TEST_LOG_FWD := TEST_LOG="$(TEST_LOG)"
endif
ifneq ($(origin TCC_SMOKE_LOG),file)
TCC_SMOKE_LOG_FWD := TCC_SMOKE_LOG="$(TCC_SMOKE_LOG)"
endif
ifneq ($(origin EXEC_ELF_SMOKE_LOG),file)
EXEC_ELF_SMOKE_LOG_FWD := EXEC_ELF_SMOKE_LOG="$(EXEC_ELF_SMOKE_LOG)"
endif
ifneq ($(origin BUSYBOX_APPLET_SMOKE_LOG),file)
BUSYBOX_APPLET_SMOKE_LOG_FWD := BUSYBOX_APPLET_SMOKE_LOG="$(BUSYBOX_APPLET_SMOKE_LOG)"
endif
ifneq ($(origin ERRNO_SMOKE_LOG),file)
ERRNO_SMOKE_LOG_FWD := ERRNO_SMOKE_LOG="$(ERRNO_SMOKE_LOG)"
endif
ifndef RUN_ID
RUN_ID := $(shell sh -c 'ts="$$(date +%y%m%d-%H%M)"; rnd="$$(od -An -N2 -tx1 /dev/urandom 2>/dev/null | tr -d "[[:space:]]")"; if [ -z "$$rnd" ]; then rnd="$$(printf "%04x" "$$$$")"; fi; printf "%s-%s" "$$ts" "$$rnd"')
endif
TEST_BUILD_ROOT ?= $(TEST_RUNS_ROOT)/$(RUN_ID)
RUN_BUILD_ROOT ?= $(RUN_RUNS_ROOT)/$(RUN_ID)
ifeq ($(TEST_ISOLATED),1)
SOAK_PR_LOG_DEFAULT = $(TEST_BUILD_ROOT)/$(ARCH)/test.log
else
SOAK_PR_LOG_DEFAULT = $(BUILD_DIR)/soak-pr.log
endif
SOAK_PR_LOG ?= $(SOAK_PR_LOG_DEFAULT)
RUN_LOG ?= $(BUILD_DIR)/run.log
RUN_MANIFEST ?= $(BUILD_ROOT)/manifest.json
RUN_RESULT ?= $(BUILD_ROOT)/result.json

test: check-tools $(KAIROS_DEPS) scripts/run-qemu-test.sh
		$(Q)if [ "$(TEST_ISOLATED)" = "1" ]; then \
			if [ "$(GC_RUNS_AUTO)" = "1" ]; then \
				$(MAKE) --no-print-directory gc-runs RUNS_KEEP="$(RUNS_KEEP)" TEST_RUNS_ROOT="$(TEST_RUNS_ROOT)"; \
			fi; \
			$(MAKE) --no-print-directory ARCH="$(ARCH)" BUILD_ROOT="$(TEST_BUILD_ROOT)" \
				TEST_ISOLATED=0 RUN_ID="$(RUN_ID)" TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS)" \
				TEST_TIMEOUT="$(TEST_TIMEOUT)" $(TEST_LOG_FWD) TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" test; \
		else \
			RUN_ID="$(RUN_ID)" TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
				$(KAIROS_CMD) run test --extra-cflags "$(TEST_EXTRA_CFLAGS)" --timeout "$(TEST_TIMEOUT)" --log "$(TEST_LOG)"; \
		fi

test-ci-default:
		$(Q)set -eu; \
		run_and_assert() { \
			label="$$1"; \
			target="$$2"; \
			$(MAKE) --no-print-directory ARCH="$(ARCH)" "$$target"; \
			latest="$$(ls -1dt "$(TEST_RUNS_ROOT)"/* 2>/dev/null | head -n 1 || true)"; \
			if [ -z "$$latest" ]; then \
				echo "No isolated run found after $$label" >&2; \
				exit 2; \
			fi; \
			python3 scripts/impl/assert-result-pass.py "$$latest/result.json" --require-structured; \
		}; \
		run_and_assert "quick regression" test; \
		run_and_assert "exec/ELF smoke regression" test-exec-elf-smoke; \
		run_and_assert "errno smoke regression" test-errno-smoke; \
		run_and_assert "BusyBox applet smoke regression" test-busybox-applets-smoke

test-exec-elf-smoke: check-tools $(KAIROS_DEPS) scripts/run-qemu-test.sh
		$(Q)if [ "$(EXEC_ELF_SMOKE_ISOLATED)" = "1" ]; then \
			if [ "$(GC_RUNS_AUTO)" = "1" ]; then \
				$(MAKE) --no-print-directory gc-runs RUNS_KEEP="$(RUNS_KEEP)" TEST_RUNS_ROOT="$(TEST_RUNS_ROOT)"; \
			fi; \
			$(MAKE) --no-print-directory ARCH="$(ARCH)" BUILD_ROOT="$(TEST_BUILD_ROOT)" \
				EXEC_ELF_SMOKE_ISOLATED=0 RUN_ID="$(RUN_ID)" EXEC_ELF_SMOKE_EXTRA_CFLAGS="$(EXEC_ELF_SMOKE_EXTRA_CFLAGS)" \
				EXEC_ELF_SMOKE_TIMEOUT="$(EXEC_ELF_SMOKE_TIMEOUT)" $(EXEC_ELF_SMOKE_LOG_FWD) \
				TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" test-exec-elf-smoke; \
		else \
			RUN_ID="$(RUN_ID)" TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
				EXEC_ELF_SMOKE_BOOT_DELAY_SEC="$(EXEC_ELF_SMOKE_BOOT_DELAY_SEC)" \
				EXEC_ELF_SMOKE_STEP_DELAY_SEC="$(EXEC_ELF_SMOKE_STEP_DELAY_SEC)" \
				EXEC_ELF_SMOKE_EXPECTED_INTERP="$(EXEC_ELF_SMOKE_EXPECTED_INTERP)" \
				$(KAIROS_CMD) run test-exec-elf-smoke --extra-cflags "$(EXEC_ELF_SMOKE_EXTRA_CFLAGS)" \
				--timeout "$(EXEC_ELF_SMOKE_TIMEOUT)" --log "$(EXEC_ELF_SMOKE_LOG)"; \
		fi

test-tcc-smoke: check-tools $(KAIROS_DEPS) scripts/run-qemu-test.sh
		$(Q)if [ "$(TCC_SMOKE_ISOLATED)" = "1" ]; then \
			if [ "$(GC_RUNS_AUTO)" = "1" ]; then \
				$(MAKE) --no-print-directory gc-runs RUNS_KEEP="$(RUNS_KEEP)" TEST_RUNS_ROOT="$(TEST_RUNS_ROOT)"; \
			fi; \
			$(MAKE) --no-print-directory ARCH="$(ARCH)" BUILD_ROOT="$(TEST_BUILD_ROOT)" \
				TCC_SMOKE_ISOLATED=0 RUN_ID="$(RUN_ID)" TCC_SMOKE_EXTRA_CFLAGS="$(TCC_SMOKE_EXTRA_CFLAGS)" \
				TCC_SMOKE_TIMEOUT="$(TCC_SMOKE_TIMEOUT)" $(TCC_SMOKE_LOG_FWD) \
				TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" test-tcc-smoke; \
		else \
			RUN_ID="$(RUN_ID)" TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
				TCC_SMOKE_BOOT_DELAY_SEC="$(TCC_SMOKE_BOOT_DELAY_SEC)" \
				TCC_SMOKE_STEP_DELAY_SEC="$(TCC_SMOKE_STEP_DELAY_SEC)" \
				$(KAIROS_CMD) run test-tcc-smoke --extra-cflags "$(TCC_SMOKE_EXTRA_CFLAGS)" \
				--timeout "$(TCC_SMOKE_TIMEOUT)" --log "$(TCC_SMOKE_LOG)"; \
		fi

test-busybox-applets-smoke: check-tools $(KAIROS_DEPS) scripts/run-qemu-test.sh
		$(Q)if [ "$(BUSYBOX_APPLET_SMOKE_ISOLATED)" = "1" ]; then \
			if [ "$(GC_RUNS_AUTO)" = "1" ]; then \
				$(MAKE) --no-print-directory gc-runs RUNS_KEEP="$(RUNS_KEEP)" TEST_RUNS_ROOT="$(TEST_RUNS_ROOT)"; \
			fi; \
			$(MAKE) --no-print-directory ARCH="$(ARCH)" BUILD_ROOT="$(TEST_BUILD_ROOT)" \
				BUSYBOX_APPLET_SMOKE_ISOLATED=0 RUN_ID="$(RUN_ID)" \
				BUSYBOX_APPLET_SMOKE_EXTRA_CFLAGS="$(BUSYBOX_APPLET_SMOKE_EXTRA_CFLAGS)" \
				BUSYBOX_APPLET_SMOKE_TIMEOUT="$(BUSYBOX_APPLET_SMOKE_TIMEOUT)" \
				$(BUSYBOX_APPLET_SMOKE_LOG_FWD) TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" test-busybox-applets-smoke; \
		else \
			RUN_ID="$(RUN_ID)" TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
				BUSYBOX_APPLET_SMOKE_BOOT_DELAY_SEC="$(BUSYBOX_APPLET_SMOKE_BOOT_DELAY_SEC)" \
				BUSYBOX_APPLET_SMOKE_STEP_DELAY_SEC="$(BUSYBOX_APPLET_SMOKE_STEP_DELAY_SEC)" \
				$(KAIROS_CMD) run test-busybox-applets-smoke --extra-cflags "$(BUSYBOX_APPLET_SMOKE_EXTRA_CFLAGS)" \
				--timeout "$(BUSYBOX_APPLET_SMOKE_TIMEOUT)" --log "$(BUSYBOX_APPLET_SMOKE_LOG)"; \
		fi

test-errno-smoke: check-tools $(KAIROS_DEPS) scripts/run-qemu-test.sh
		$(Q)if [ "$(ERRNO_SMOKE_ISOLATED)" = "1" ]; then \
			if [ "$(GC_RUNS_AUTO)" = "1" ]; then \
				$(MAKE) --no-print-directory gc-runs RUNS_KEEP="$(RUNS_KEEP)" TEST_RUNS_ROOT="$(TEST_RUNS_ROOT)"; \
			fi; \
			$(MAKE) --no-print-directory ARCH="$(ARCH)" BUILD_ROOT="$(TEST_BUILD_ROOT)" \
				ERRNO_SMOKE_ISOLATED=0 RUN_ID="$(RUN_ID)" \
				ERRNO_SMOKE_EXTRA_CFLAGS="$(ERRNO_SMOKE_EXTRA_CFLAGS)" \
				ERRNO_SMOKE_TIMEOUT="$(ERRNO_SMOKE_TIMEOUT)" \
				$(ERRNO_SMOKE_LOG_FWD) TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" test-errno-smoke; \
		else \
			RUN_ID="$(RUN_ID)" TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
				ERRNO_SMOKE_BOOT_DELAY_SEC="$(ERRNO_SMOKE_BOOT_DELAY_SEC)" \
				ERRNO_SMOKE_READY_WAIT_SEC="$(ERRNO_SMOKE_READY_WAIT_SEC)" \
				$(KAIROS_CMD) run test-errno-smoke --extra-cflags "$(ERRNO_SMOKE_EXTRA_CFLAGS)" \
				--timeout "$(ERRNO_SMOKE_TIMEOUT)" --log "$(ERRNO_SMOKE_LOG)"; \
		fi

test-isolated:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_ISOLATED=1 RUN_ID="$(RUN_ID)" TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS)" TEST_TIMEOUT="$(TEST_TIMEOUT)" test

test-driver:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_TIMEOUT="$(TEST_TIMEOUT)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x01" test

test-mm:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_TIMEOUT="$(TEST_TIMEOUT)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x02" test

test-sync:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_TIMEOUT="$(TEST_TIMEOUT)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x04" test

test-vfork:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_TIMEOUT="$(TEST_TIMEOUT)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x08" test

test-sched:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_TIMEOUT="$(TEST_TIMEOUT)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x10" test

test-crash:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_TIMEOUT="$(TEST_TIMEOUT)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x20" test

test-syscall-trap:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_TIMEOUT="$(TEST_TIMEOUT)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x40" test

test-syscall: test-syscall-trap

test-vfs-ipc:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_TIMEOUT="$(TEST_TIMEOUT)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x80" test

test-socket:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_TIMEOUT="$(TEST_TIMEOUT)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x100" test

test-device-virtio:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_TIMEOUT="$(TEST_TIMEOUT)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x200" test

test-devmodel: test-device-virtio

test-tty:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_TIMEOUT="$(TEST_TIMEOUT)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x400" test

test-soak-pr:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" RUN_ID="$(RUN_ID)" TEST_TIMEOUT="$(SOAK_PR_TIMEOUT)" TEST_LOG="$(SOAK_PR_LOG)" \
		TEST_EXTRA_CFLAGS="$(TEST_EXTRA_CFLAGS) -DCONFIG_KERNEL_TEST_MASK=0x800 $(SOAK_PR_EXTRA_CFLAGS)" test

gc-runs:
	$(Q)mkdir -p "$(TEST_RUNS_ROOT)"
	$(Q)keep="$(RUNS_KEEP)"; \
	if ! printf '%s' "$$keep" | grep -Eq '^[0-9]+$$'; then \
		echo "gc-runs: RUNS_KEEP must be a non-negative integer, got '$$keep'" >&2; \
		exit 2; \
	fi; \
	if [ "$$keep" -eq 0 ]; then \
		find "$(TEST_RUNS_ROOT)" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +; \
		echo "gc-runs: kept 0 runs (removed all)"; \
		exit 0; \
	fi; \
	i=0; \
	ls -1dt "$(TEST_RUNS_ROOT)"/* 2>/dev/null | while IFS= read -r run_dir; do \
		if [ -d "$$run_dir" ]; then \
			i=$$((i+1)); \
			if [ "$$i" -gt "$$keep" ]; then \
				rm -rf "$$run_dir"; \
			fi; \
		fi; \
	done; \
	echo "gc-runs: kept latest $$keep runs under $(TEST_RUNS_ROOT)"

lock-status:
	@echo "lock-status: scanning build lock files"
	@{ \
		find build -type f \( -path '*/.locks/*.lock' -o -path '*/.locks/*.lock.meta' \) 2>/dev/null | sort -u; \
	} | while IFS= read -r p; do \
		if [ -z "$$p" ]; then continue; fi; \
		case "$$p" in \
			*.lock.meta) \
				lock="$${p%.meta}"; \
				pid="$$(awk -F= '$$1=="pid"{print $$2; exit}' "$$p" 2>/dev/null)"; \
				state="dead"; \
				if [ -n "$$pid" ] && kill -0 "$$pid" >/dev/null 2>&1; then state="alive"; fi; \
				echo "$$lock (meta pid=$${pid:-?} state=$$state)"; \
				;; \
			*) \
				echo "$$p"; \
				;; \
		esac; \
	done

lock-clean-stale:
	@echo "lock-clean-stale: cleaning stale lock metadata and legacy qemu-run locks"
	@legacy=0; dead=0; missing=0; kept=0; \
	while IFS= read -r -d '' p; do \
		rm -f "$$p"; \
		legacy=$$((legacy+1)); \
	done < <(find build -type f \( -path '*/.locks/qemu-run.lock' -o -path '*/.locks/qemu-run.lock.meta' \) -print0 2>/dev/null); \
	while IFS= read -r -d '' meta; do \
		lock="$${meta%.meta}"; \
		pid="$$(awk -F= '$$1=="pid"{print $$2; exit}' "$$meta" 2>/dev/null)"; \
		if [ ! -f "$$lock" ]; then \
			rm -f "$$meta"; \
			missing=$$((missing+1)); \
		elif [ -z "$$pid" ]; then \
			rm -f "$$meta"; \
			dead=$$((dead+1)); \
		elif kill -0 "$$pid" >/dev/null 2>&1; then \
			kept=$$((kept+1)); \
		else \
			rm -f "$$meta"; \
			dead=$$((dead+1)); \
		fi; \
	done < <(find build -type f -path '*/.locks/*.lock.meta' -print0 2>/dev/null); \
	echo "lock-clean-stale: removed legacy=$$legacy dead_meta=$$dead missing_lock_meta=$$missing kept_live_meta=$$kept"

test-soak: check-tools $(KAIROS_DEPS) scripts/run-qemu-test.sh
	$(Q)TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
		$(KAIROS_CMD) run test-soak --extra-cflags "$(SOAK_EXTRA_CFLAGS)" --timeout "$(SOAK_TIMEOUT)" --log "$(SOAK_LOG)"

test-matrix: check-tools $(KAIROS_DEPS) scripts/test-matrix.sh
	$(Q)TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
		$(KAIROS_CMD) run test-matrix

test-debug: check-tools $(KAIROS_DEPS) scripts/run-qemu-test.sh
	$(Q)TEST_LOCK_WAIT="$(TEST_LOCK_WAIT)" UEFI_BOOT_MODE="$(UEFI_BOOT_MODE)" QEMU_UEFI_BOOT_MODE="$(QEMU_UEFI_BOOT_MODE)" \
		$(KAIROS_CMD) run test-debug --extra-cflags "$(TEST_EXTRA_CFLAGS) -DCONFIG_DEBUG=1" --timeout "$(TEST_TIMEOUT)" --log "$(TEST_LOG)"

test-concurrent-smoke: check-tools scripts/test-concurrent.sh
	$(Q)ARCH="$(ARCH)" TEST_TARGET="$(TEST_CONCURRENT_TARGET)" TEST_CONCURRENCY="$(TEST_CONCURRENCY)" \
		TEST_ROUNDS="$(TEST_ROUNDS)" TEST_TIMEOUT="$(TEST_CONCURRENT_TIMEOUT)" \
		bash ./scripts/test-concurrent.sh

test-concurrent-vfs-ipc:
	$(Q)$(MAKE) --no-print-directory ARCH="$(ARCH)" TEST_CONCURRENT_TARGET="test-vfs-ipc" \
		TEST_CONCURRENCY="$(TEST_CONCURRENCY)" TEST_ROUNDS="$(TEST_ROUNDS)" \
		TEST_CONCURRENT_TIMEOUT="$(TEST_CONCURRENT_TIMEOUT)" test-concurrent-smoke

print-config:
	@echo "Kairos Effective Configuration"
	@echo ""
	@echo "Core:"
	@echo "  ARCH=$(ARCH)"
	@echo "  BUILD_ROOT=$(BUILD_ROOT)"
	@echo "  BUILD_DIR=$(BUILD_DIR)"
	@echo "  RUN_ID=$(RUN_ID)"
	@echo ""
	@echo "Run/Test Isolation:"
	@echo "  RUN_ISOLATED=$(RUN_ISOLATED)"
	@echo "  TEST_ISOLATED=$(TEST_ISOLATED)"
	@echo "  RUN_BUILD_ROOT=$(RUN_BUILD_ROOT)"
	@echo "  TEST_BUILD_ROOT=$(TEST_BUILD_ROOT)"
	@echo ""
	@echo "Timeouts:"
	@echo "  RUN_TIMEOUT=$(RUN_TIMEOUT)"
	@echo "  TEST_TIMEOUT=$(TEST_TIMEOUT)"
	@echo "  SOAK_TIMEOUT=$(SOAK_TIMEOUT)"
	@echo "  SOAK_PR_TIMEOUT=$(SOAK_PR_TIMEOUT)"
	@echo ""
	@echo "Logs:"
	@echo "  RUN_LOG=$(RUN_LOG)"
	@echo "  TEST_LOG=$(TEST_LOG)"
	@echo "  SOAK_LOG=$(SOAK_LOG)"
	@echo "  SOAK_PR_LOG=$(SOAK_PR_LOG)"
	@echo ""
	@echo "Locks and Retention:"
	@echo "  LOCK_WAIT=$(LOCK_WAIT)"
	@echo "  RUN_LOCK_WAIT=$(RUN_LOCK_WAIT)"
	@echo "  TEST_LOCK_WAIT=$(TEST_LOCK_WAIT)"
	@echo "  GC_RUNS_AUTO=$(GC_RUNS_AUTO)"
	@echo "  RUN_GC_AUTO=$(RUN_GC_AUTO)"
	@echo "  RUNS_KEEP=$(RUNS_KEEP)"
	@echo "  RUNS_KEEP_RUN=$(RUNS_KEEP_RUN)"

# Show help
help:
	@echo "Kairos Kernel Build System"
	@echo ""
	@echo "Common Targets:"
	@echo "  all      - Build kernel (default)"
	@echo "  run      - Run in QEMU (isolated by default)"
	@echo "  run-e1000 - Run in QEMU with e1000 NIC (isolated by default)"
	@echo "  debug    - Run with GDB server"
	@echo "  test     - Run kernel tests (isolated by default)"
	@echo "  test-mm  - Run memory test module only"
	@echo "  test-sched - Run scheduler test module only"
	@echo "  test-vfs-ipc - Run vfs/tmpfs/pipe/epoll test module only"
	@echo "  test-device-virtio - Run device model + virtio probe-path module only"
	@echo "  test-concurrent-vfs-ipc - Concurrent smoke preset for test-vfs-ipc"
	@echo "  print-config - Show effective build/run/test configuration"
	@echo "  gc-runs  - Keep only latest N isolated runs"
	@echo "  lock-status - List lock files and metadata (pid/state)"
	@echo "  clean    - Remove current BUILD_ROOT/ARCH artifacts"
	@echo "  clean-all - Remove all build/ artifacts"
	@echo ""
	@echo "Daily Variables:"
	@echo "  ARCH     - Target architecture (riscv64, x86_64, aarch64)"
	@echo "  TEST_TIMEOUT - Timeout seconds for test targets (default: 180)"
	@echo "  LOCK_WAIT - Wait seconds for run/test lock acquisition (default: 0)"
	@echo "  V        - Verbose mode (V=1)"
	@echo ""
	@echo "Isolation/Path Variables:"
	@echo "  RUN_ID   - Explicit isolated session id (default: YYMMDD-HHMM-xxxx)"
	@echo "  BUILD_ROOT - Build root base (default: build)"
	@echo "  TEST_LOG - Test log path (default: <BUILD_ROOT>/<arch>/test.log)"
	@echo "  RUN_LOG  - Run log path (default: <BUILD_ROOT>/<arch>/run.log)"
	@echo "  SOAK_PR_LOG - Soak-pr log (isolated: <TEST_BUILD_ROOT>/<arch>/test.log; non-isolated: build/<arch>/soak-pr.log)"
	@echo ""
	@echo "Examples:"
	@echo "  make ARCH=riscv64 test-vfs-ipc"
	@echo "  make LOCK_WAIT=5 test-mm"
	@echo "  make TEST_TIMEOUT=300 test-sched"
	@echo "  make run"
	@echo "  make print-config"
	@echo ""
	@echo "Advanced:"
	@echo "  make HELP_ADVANCED=1 help"
ifneq ($(HELP_ADVANCED),0)
	@echo ""
	@echo "Advanced Targets:"
	@echo "  user     - Build userland init"
	@echo "  initramfs - Build initramfs image"
	@echo "  compiler-rt - Build clang compiler-rt builtins"
	@echo "  busybox  - Build busybox for userland"
	@echo "  tcc      - Build TCC (Tiny C Compiler) for userland"
	@echo "  rootfs-base    - Stage rootfs base"
	@echo "  rootfs-busybox - Stage busybox + applets"
	@echo "  rootfs-init    - Stage init"
	@echo "  rootfs-tcc     - Stage tcc + musl sysroot"
	@echo "  rootfs         - Stage full rootfs"
	@echo "  disk     - Create disk image"
	@echo "  uefi     - Prepare UEFI boot image"
	@echo "  check-tools - Verify host toolchain"
	@echo "  doctor   - Verify host toolchain (alias of check-tools)"
	@echo "  test     - Run kernel tests (isolated by default)"
	@echo "  test-ci-default - Run default CI gates (test + exec/ELF smoke + errno smoke + busybox applet smoke)"
	@echo "  test-exec-elf-smoke - Run exec/ELF interactive smoke regression"
	@echo "  test-busybox-applets-smoke - Run busybox applet interactive smoke regression"
	@echo "  test-errno-smoke - Run errno interactive smoke regression"
	@echo "  test-tcc-smoke - Run tcc interactive smoke regression"
	@echo "  test-isolated - Alias of isolated test mode"
	@echo "  test-driver - Run driver test module only"
	@echo "  test-mm  - Run memory test module only"
	@echo "  test-sync - Run sync test module only"
	@echo "  test-vfork - Run vfork test module only"
	@echo "  test-sched - Run scheduler test module only"
	@echo "  test-crash - Run crash test module only"
	@echo "  test-syscall-trap - Run syscall/trap test module only"
	@echo "  test-syscall - Alias of test-syscall-trap"
	@echo "  test-vfs-ipc - Run vfs/tmpfs/pipe/epoll test module only"
	@echo "  test-socket - Run socket module only (AF_UNIX/AF_INET)"
	@echo "  test-device-virtio - Run device model + virtio probe-path module only"
	@echo "  test-devmodel - Alias of test-device-virtio"
	@echo "  test-tty - Run tty stack module only (tty_core/n_tty/pty)"
	@echo "  test-soak-pr - Run PR soak + low-rate fault injection module only"
	@echo "  print-config - Show effective build/run/test configuration"
	@echo "  gc-runs  - Keep only latest N isolated runs (RUNS_KEEP, default 20)"
	@echo "  lock-status - List lock files and metadata (pid/state)"
	@echo "  lock-clean-stale - Remove dead .lock.meta and legacy qemu-run locks"
	@echo "  test-soak - Run long SMP soak test (timeout-driven)"
	@echo "  test-debug - Run tests with CONFIG_DEBUG=1"
	@echo "  test-matrix - Run SMP x DEBUG test matrix"
	@echo "  test-concurrent-smoke - Run configurable concurrent test smoke"
	@echo ""
	@echo "Advanced Variables:"
	@echo "  EMBEDDED_INIT - Build embedded init blob (riscv64 only)"
	@echo "  TOOLCHAIN_MODE - Toolchain policy (auto, clang, gcc)"
	@echo "  WITH_TCC - Include tcc in rootfs for disk/run (default: 1)"
	@echo "  TEST_RUNS_ROOT - Isolated test runs root (default: build/runs)"
	@echo "  RUNS_KEEP - Number of isolated runs to keep on GC (default: 20)"
	@echo "  GC_RUNS_AUTO - Auto run gc-runs before test (default: 1)"
	@echo "  TEST_ISOLATED - Enable isolated test run (default: 1)"
	@echo "  TEST_CONCURRENCY - Parallel jobs per concurrent smoke round (default: 3)"
	@echo "  TEST_ROUNDS - Rounds for concurrent smoke (default: 3)"
	@echo "  TEST_CONCURRENT_TARGET - Target used by concurrent smoke (default: test-vfs-ipc)"
	@echo "  TEST_CONCURRENT_TIMEOUT - TEST_TIMEOUT override for concurrent smoke jobs"
	@echo "  RUN_RUNS_ROOT - Isolated run sessions root (default: build/runs/run)"
	@echo "  RUNS_KEEP_RUN - Number of isolated run sessions to keep (default: 5)"
	@echo "  RUN_GC_AUTO - Auto run gc-runs before run (default: 1)"
	@echo "  RUN_ISOLATED - Enable isolated run session (default: 1)"
	@echo "  RUN_TIMEOUT - Session timeout seconds for run (0 means no timeout)"
	@echo "  RUN_REQUIRE_BOOT - Require boot marker for run success (default: 1)"
	@echo "  LOCK_WAIT - Default lock wait seconds for run/test lock acquisition (default: 0)"
	@echo "  RUN_LOCK_WAIT - Seconds to wait for run qemu lock before lock_busy (default: 0)"
	@echo "  TEST_LOCK_WAIT - Seconds to wait for test qemu lock before lock_busy (default: 0)"
	@echo "  TOOLCHAIN_LOCK_WAIT - Seconds to wait for global toolchain lock (default: 900)"
	@echo "  SOAK_PR_LOG - test-soak-pr log path (isolated default: <TEST_BUILD_ROOT>/<arch>/test.log)"
	@echo "  QEMU_FILTER_UEFI_NOISE - Filter known non-fatal UEFI noise on run (aarch64 default: 1)"
	@echo "  HELP_ADVANCED - Show advanced help sections (set 1)"
	@echo ""
	@echo "Advanced Examples:"
	@echo "  make ARCH=x86_64 run"
	@echo "  make RUN_LOCK_WAIT=10 run"
	@echo "  make TEST_CONCURRENCY=4 TEST_ROUNDS=2 test-concurrent-smoke"
endif
