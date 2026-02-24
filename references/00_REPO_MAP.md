# 00 — Repo Map

## Top-Level Directories

- `kernel/` — kernel core, all kernel-space code
- `user/` — userspace (init process; shell and libc currently provided by busybox/musl)
- `third_party/` — third-party sources (busybox, musl, lwip, fatfs, limine, etc.)
- `tools/` — build utilities
- `scripts/` — build/test/QEMU scripts
- `build/` — build artifacts, split by architecture subdirectory

## kernel/ Subdirectories

- `arch/` — architecture-specific (riscv64, x86_64, aarch64, common); unified external interface via include/kairos/arch.h
- `core/` — kernel core (init, mm, sched, sync, proc, syscall, trap, time, dev, net, tests)
- `drivers/` — device drivers (virtio, block, char, tty, net, gpu, fb, pci, usb)
- `fs/` — filesystems (vfs, ext2, fat32, tmpfs, devfs, procfs, sysfs, initramfs, bio, poll, ipc)
- `bus/` — bus subsystem (platform, pci)
- `net/` — network stack (socket dispatch, af_unix, af_inet/lwIP)
- `firmware/` — firmware interfaces (FDT, ACPI)
- `lib/` — kernel library functions (printk, string, vsprintf, ringbuf, rbtree)
- `boot/` — Limine bootloader integration and boot_info management
- `include/kairos/` — public headers
- `ipc/` — currently empty; pipe implementation lives in fs/ipc/
- `subsystems/` — currently empty, reserved for future extensions

## Key Entry Points

- Boot: `arch/<arch>/boot.S` → `boot/limine.c` → `core/main.c:kernel_main()`
- Syscall: `arch/<arch>/trapasm.S` → `core/syscall/syscall.c` (Linux ABI compatible)
- Interrupt: `arch/<arch>/trapasm.S` → `arch/<arch>/trap.c` → `core/trap/trap_core.c`
- Userspace launch: `core/init/user.c` → `core/proc/proc_init.c` → tries embedded init (riscv64 only), then `/init` → `/sbin/init` → `/bin/init`, falls back to built-in user test

## Subsystem Boundaries

- Architecture isolation: arch/ exposes only through include/kairos/arch.h
- Device discovery: firmware/ → bus/ → core/dev/
- Filesystems: all fs implementations go through fs/vfs/; block devices through fs/bio/
- Networking: syscall → net/socket.c protocol family dispatch → af_unix or af_inet(lwIP)

Related references:
- references/10_BOOT_FIRMWARE_TRAP_SYSCALL_TIME.md
- references/20_MEMORY.md
- references/30_PROCESS_SCHED_SYNC_IPC.md
- references/40_VFS_BLOCK_FS.md
- references/50_DRIVERS_BUS_DISCOVERY.md
- references/90_BUILD_TEST_DEBUG.md
