ARCH ?= riscv64
USE_GCC ?= 0
V ?= 0
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
DOOM := $(OUT_DIR)/doom
DOOM_DIR := $(ROOT_DIR)/third_party/doomgeneric/doomgeneric

CFLAGS := -Os -static -fno-stack-protector -fno-pie --sysroot=$(SYSROOT)
CFLAGS += -isystem $(SYSROOT)/include
ifeq ($(ARCH),riscv64)
CFLAGS += -march=rv64gc -mabi=lp64
endif
CFLAGS += -Wall -Wextra
LDFLAGS := --sysroot=$(SYSROOT)
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

ifeq ($(V),0)
  Q := @
else
  Q :=
endif

.PHONY: all clean initramfs

all: $(INIT) $(DOOM)

$(INIT): init/main.c
	@mkdir -p $(OUT_DIR)
	@echo "  CC      user/init"
	$(Q)$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

initramfs: $(INITRAMFS)

$(INITRAMFS): initramfs/init.c
	@mkdir -p $(dir $@)
	@echo "  CC      user/initramfs/init"
	$(Q)$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

DOOM_CFLAGS := $(CFLAGS) -I$(DOOM_DIR) -DDOOMGENERIC_RESX=320 \
	-DDOOMGENERIC_RESY=200 -w
DOOM_LDFLAGS := $(LDFLAGS)
DOOM_SRCS := \
	$(DOOM_DIR)/dummy.c \
	$(DOOM_DIR)/am_map.c \
	$(DOOM_DIR)/doomdef.c \
	$(DOOM_DIR)/doomstat.c \
	$(DOOM_DIR)/dstrings.c \
	$(DOOM_DIR)/d_event.c \
	$(DOOM_DIR)/d_items.c \
	$(DOOM_DIR)/d_iwad.c \
	$(DOOM_DIR)/d_loop.c \
	$(DOOM_DIR)/d_main.c \
	$(DOOM_DIR)/d_mode.c \
	$(DOOM_DIR)/d_net.c \
	$(DOOM_DIR)/f_finale.c \
	$(DOOM_DIR)/f_wipe.c \
	$(DOOM_DIR)/g_game.c \
	$(DOOM_DIR)/hu_lib.c \
	$(DOOM_DIR)/hu_stuff.c \
	$(DOOM_DIR)/info.c \
	$(DOOM_DIR)/i_cdmus.c \
	$(DOOM_DIR)/i_endoom.c \
	$(DOOM_DIR)/i_joystick.c \
	$(DOOM_DIR)/i_scale.c \
	$(DOOM_DIR)/i_sound.c \
	$(DOOM_DIR)/i_system.c \
	$(DOOM_DIR)/i_timer.c \
	$(DOOM_DIR)/memio.c \
	$(DOOM_DIR)/m_argv.c \
	$(DOOM_DIR)/m_bbox.c \
	$(DOOM_DIR)/m_cheat.c \
	$(DOOM_DIR)/m_config.c \
	$(DOOM_DIR)/m_controls.c \
	$(DOOM_DIR)/m_fixed.c \
	$(DOOM_DIR)/m_menu.c \
	$(DOOM_DIR)/m_misc.c \
	$(DOOM_DIR)/m_random.c \
	$(DOOM_DIR)/p_ceilng.c \
	$(DOOM_DIR)/p_doors.c \
	$(DOOM_DIR)/p_enemy.c \
	$(DOOM_DIR)/p_floor.c \
	$(DOOM_DIR)/p_inter.c \
	$(DOOM_DIR)/p_lights.c \
	$(DOOM_DIR)/p_map.c \
	$(DOOM_DIR)/p_maputl.c \
	$(DOOM_DIR)/p_mobj.c \
	$(DOOM_DIR)/p_plats.c \
	$(DOOM_DIR)/p_pspr.c \
	$(DOOM_DIR)/p_saveg.c \
	$(DOOM_DIR)/p_setup.c \
	$(DOOM_DIR)/p_sight.c \
	$(DOOM_DIR)/p_spec.c \
	$(DOOM_DIR)/p_switch.c \
	$(DOOM_DIR)/p_telept.c \
	$(DOOM_DIR)/p_tick.c \
	$(DOOM_DIR)/p_user.c \
	$(DOOM_DIR)/r_bsp.c \
	$(DOOM_DIR)/r_data.c \
	$(DOOM_DIR)/r_draw.c \
	$(DOOM_DIR)/r_main.c \
	$(DOOM_DIR)/r_plane.c \
	$(DOOM_DIR)/r_segs.c \
	$(DOOM_DIR)/r_sky.c \
	$(DOOM_DIR)/r_things.c \
	$(DOOM_DIR)/sha1.c \
	$(DOOM_DIR)/sounds.c \
	$(DOOM_DIR)/statdump.c \
	$(DOOM_DIR)/st_lib.c \
	$(DOOM_DIR)/st_stuff.c \
	$(DOOM_DIR)/s_sound.c \
	$(DOOM_DIR)/tables.c \
	$(DOOM_DIR)/v_video.c \
	$(DOOM_DIR)/wi_stuff.c \
	$(DOOM_DIR)/w_checksum.c \
	$(DOOM_DIR)/w_file.c \
	$(DOOM_DIR)/w_main.c \
	$(DOOM_DIR)/w_wad.c \
	$(DOOM_DIR)/z_zone.c \
	$(DOOM_DIR)/w_file_stdc.c \
	$(DOOM_DIR)/i_input.c \
	$(DOOM_DIR)/i_video.c \
	$(DOOM_DIR)/doomgeneric.c \
	$(DOOM_DIR)/doomgeneric_kairos.c

$(DOOM): $(DOOM_SRCS)
	@mkdir -p $(OUT_DIR)
	@echo "  CC      user/doom ($(words $(DOOM_SRCS)) sources)"
	$(Q)$(CC) $(DOOM_CFLAGS) -o $@ $(DOOM_SRCS) $(DOOM_LDFLAGS)

clean:
	rm -rf $(OUT_DIR)
