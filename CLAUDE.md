# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
make                     # Build for RISC-V 64 (default)
make ARCH=riscv64        # Explicit RISC-V 64
make ARCH=x86_64         # Build for x86_64
make ARCH=aarch64        # Build for AArch64
make V=1                 # Verbose output

make run                 # Run in QEMU
make run-e1000           # Run with e1000 network card
make debug               # Run with GDB server on localhost:1234
make test                # Run kernel tests (passes "test" to kernel cmdline)

make disk                # Create 64MB ext2 disk image
make iso                 # Create bootable ISO (x86_64)
make uefi                # Prepare UEFI firmware + Limine boot image
make disasm              # Generate disassembly (build/ARCH/kairos.asm)
make symbols             # Generate symbol table

make clean               # Remove all build artifacts
```

Cross-compiler prefixes: `riscv64-unknown-elf-` (RISC-V), `aarch64-none-elf-` (AArch64), native (x86_64).

## Architecture

Kairos is a **monolithic kernel** written in C targeting RISC-V 64 (primary), x86_64, and AArch64.

### Layer Structure

```
User Space (musl libc, busybox, init, shell)
            │ syscall
System Call Layer (dispatch, validation)
            │
Core Subsystems:
  - Process Manager (fork/exec/exit, struct process)
  - CFS Scheduler (red-black tree, vruntime tracking)
  - Memory Manager (buddy allocator for pages, power-of-2 for kmalloc)
  - Time/Signal/IPC (pipes, signals)
  - VFS Layer (ext2, FAT32, devfs)
            │
Device Drivers (virtio-blk, virtio-net, NVMe, e1000, framebuffer, PCI)
            │
Hardware Abstraction Layer (arch_* functions)
            │
Architecture Implementation (kernel/arch/{riscv64,x86_64,aarch64}/)
```

### Key Design Principles

1. **Compile-time architecture selection** - Only one arch is compiled, no runtime dispatch
2. **Interface-driven** - Core code uses HAL functions (`arch_irq_*`, `arch_mmu_*`, `arch_context_*`), never architecture-specific code directly
3. **Two-phase abstraction** - Write concrete code first, extract interface when adding second architecture
4. **Minimal interfaces** - Each interface has minimum functions needed

### HAL Functions (kernel/include/kairos/arch.h)

All architecture-specific operations go through these interfaces:
- `arch_cpu_*` - CPU control (init, halt, reset)
- `arch_irq_*` - Interrupt control (enable, disable, save, restore)
- `arch_context_switch()` - Context switching
- `arch_mmu_*` - Memory management (create_table, map, switch, flush_tlb)
- `arch_timer_*` - Timer control

### Directory Layout

- `kernel/arch/ARCH/` - Architecture-specific (boot.S, entry.c, trapasm.S, mmu.c, switch.S, timer.c, context.c)
- `kernel/core/` - Core subsystems (mm/, proc/, sched/, time/, trap/)
- `kernel/fs/` - File systems (vfs/, ext2/, fat32/, devfs/)
- `kernel/drivers/` - Device drivers (block/, net/, fb/, pci/)
- `kernel/ipc/` - Inter-process communication (pipe.c, signal.c)
- `kernel/lib/` - Kernel libraries (rbtree.c, string.c, printk.c)
- `kernel/syscall/` - System call implementations
- `kernel/include/kairos/` - Public kernel headers

## Code Style

- **4 spaces** for indentation (no tabs except Makefile)
- **K&R braces** - opening brace on same line
- **Always use braces** - even for single statements
- **snake_case** for functions/variables, **UPPER_SNAKE_CASE** for constants
- **Module prefix** for public functions: `sched_init()`, `proc_create()`, `vfs_open()`
- **Return 0 on success, negative errno on failure** (`-ENOENT`, `-ENOMEM`)
- **Early returns** to reduce nesting
- **`goto` cleanup** pattern for functions with multiple cleanup steps
- Code must compile with `-Wall -Wextra` without warnings

## Error Handling Convention

```c
int vfs_open(const char *path, int flags)
{
    struct vnode *vn = lookup(path);
    if (!vn) {
        return -ENOENT;
    }
    /* ... */
    return 0;
}
```

## Commit Messages

Format: `<subsystem>: <short description>`

Examples:
- `sched: implement CFS scheduler`
- `mm: fix use-after-free in page allocator`

## Third-Party Dependencies

Fetched via `scripts/fetch-deps.sh`:
- Limine (bootloader)
- lwIP (TCP/IP stack)
- TinyUSB (USB stack)
- FatFs (FAT filesystem)
- musl (user space C library)
