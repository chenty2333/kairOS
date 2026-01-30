# Kairos Architecture Summary

Kairos is a monolithic kernel with a strict Hardware Abstraction Layer (HAL).

## 1. System Layers
- **User**: musl libc + user applications (busybox, etc.).
- **Syscall**: Argument validation and dispatch.
- **Core**: Process (CFS scheduler), Memory (Buddy + Kmalloc), VFS, IPC, Signals.
- **HAL**: Architecture-independent interface (`arch_*`, `mmu_*`, `irq_*`).
- **Arch**: Implementation for `riscv64`, `aarch64`, `x86_64`.

## 2. Core Subsystems

### Process & Scheduling
- **Model**: `struct process` tracks PID, state (RUNNABLE/RUNNING/SLEEPING/ZOMBIE), `vruntime` (CFS), and `arch_context`.
- **Scheduler**: CFS using a per-CPU Red-Black tree.
- **Weighting**: Linux-style `nice` (-20 to +19) to weight mapping.

### Memory Management
- **V-Space**: High half kernel (0xFFFFFFFF80000000+), direct mapping of physical memory, device MMIO.
- **Physical**: Buddy System allocator (Order 0-10, 4KB-4MB blocks).
- **Heap**: Power-of-2 `kmalloc` (32B to 2KB), larger via page allocator.

### VFS (Virtual File System)
- **Objects**: `mount` (fs root), `vnode` (file/dir/dev), `file_ops` (read/write/readdir).
- **Path**: dentry-based namei (component walk), symlink depth limit, negative dentry cache.
- **Namespaces**: per-process mount namespace root (used by `chroot`/`pivot_root`).
- **Filesystems**: `ext2` (root), `FAT32` (boot/USB via FatFs), `devfs` (/dev).

## 3. Hardware Abstraction Layer (HAL)
- **CPU**: `arch_cpu_init/halt/reset`.
- **Interrupts**: `arch_irq_enable/disable/save/restore`.
- **Context**: `arch_context_switch`, `arch_enter_user`.
- **MMU**: `arch_mmu_map`, `arch_mmu_switch`, `arch_mmu_flush_tlb`.
- **Timer**: `arch_timer_init`, `arch_timer_set_next`.

## 4. Execution Flow
1. **Traps**: `arch_trap_entry` (asm) -> `trap_dispatch` (C) -> (Syscall/IRQ/Fault) -> Signal/Resched Check -> `arch_trap_return`.
2. **Boot**: Limine -> `_start` -> `kernel_main` -> (Subsystem Init) -> initramfs `/init` -> pivot_root -> disk `/init`.

## 5. Syscall Interface
- **Calling**: RISC-V (`a7`), AArch64 (`x8`), x86_64 (`rax`).
- **Groups**: Proc (exit, fork, exec), IO (open, read, write), Mem (brk, mmap), IPC (pipe, signal).

## 6. Constraints (Default)
- **Memory**: 64MB Min, 256MB Rec.
- **Limits**: 256 Procs, 64 FDs/Proc, 8KB Kernel Stack, 100Hz Timer.
