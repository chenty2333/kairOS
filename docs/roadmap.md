# Kairos Implementation Roadmap

This document outlines the step-by-step implementation plan for Kairos.
Each phase builds on the previous one. **Test after each step before moving on.**

---

## Phase 0: Foundation (Week 1-2)

### 0.1 Build System & Boot
- [x] Set up Makefile with multi-arch support
- [x] Create linker script for RISC-V
- [x] Implement `_start` (boot.S) - set up stack, call kernel_main
- [x] Get "Hello, World!" printing via SBI ecall (RISC-V)
- [ ] Set up Limine bootloader configuration (x86_64 only, Phase 10)

**Test**: Kernel prints to serial console and halts. ✓

### 0.2 Early Console
- [x] Implement `arch_early_putchar()` using SBI
- [x] Implement basic `printk()` (no format strings yet)
- [x] Implement `vsprintf()` with %d, %x, %s, %p
- [x] Full `printk()` with format strings

**Test**: `printk("Value: %d, Hex: 0x%x\n", 42, 0xDEAD);` ✓

### 0.3 Basic Memory Setup
- [x] Parse memory map from bootloader (FDT/DTB)
- [x] Define physical memory layout
- [x] Implement simple page allocator (bitmap for now)
- [x] Test: allocate and free pages

**Test**: Allocate 100 pages, free them, allocate again - should succeed. ✓

---

## Phase 1: Memory Management (Week 3-4)

### 1.1 Buddy Allocator
- [x] Implement buddy allocator data structures
- [x] Implement `alloc_pages(order)`
- [x] Implement `free_pages(page, order)`
- [x] Stress test: random alloc/free patterns

**Test**: Allocate various sizes, check for fragmentation. ✓

### 1.2 Virtual Memory
- [x] Implement page table creation (`arch_mmu_create_table`)
- [x] Implement page mapping (`arch_mmu_map`)
- [x] Implement `arch_mmu_switch`
- [x] Set up kernel virtual address space (identity mapping)
- [x] Map kernel code/data
- [x] Map physical memory to direct mapping region

**Test**: Access memory through virtual addresses. ✓

### 1.3 Kernel Heap
- [x] Implement power-of-2 allocator
- [x] Implement `kmalloc()` and `kfree()`
- [x] Implement `kzalloc()`

**Test**: `struct foo *p = kmalloc(sizeof(*p)); kfree(p);` ✓

---

## Phase 2: Trap Handling (Week 5)

### 2.1 Trap Entry
- [x] Implement `trap_entry.S` (save registers, switch stack)
- [x] Implement `trap_dispatch()` in C
- [x] Set up trap vector (stvec on RISC-V)
- [x] Handle unknown traps (print and halt)

**Test**: Trigger illegal instruction, see trap message. ✓

### 2.2 Timer & Interrupts
- [x] Implement `arch_timer_init()`
- [x] Implement `arch_timer_set_next()`
- [x] Handle timer interrupts
- [x] Implement global tick counter

**Test**: Print "tick" every second. ✓

### 2.3 System Call Entry
- [x] Implement syscall dispatch in trap handler
- [x] Implement `SYS_write` (print to console)
- [x] Implement `SYS_exit`

**Test**: Kernel-mode code calls syscall, returns correctly. ✓

---

## Phase 3: Process Management (Week 6-8)

### 3.1 Process Structure
- [x] Define `struct process`
- [x] Implement process table
- [x] Implement `proc_alloc()` - allocate PCB
- [x] Implement `arch_context_alloc()` - kernel stack
- [x] Implement idle process (PID 0)

**Test**: Create idle process, it runs. ✓

### 3.2 Context Switching
- [x] Implement `arch_context_switch()`
- [ ] Implement `arch_enter_user()`
- [x] Implement basic scheduler (round-robin for now)
- [x] Create two kernel threads, switch between them

**Test**: Two threads print alternating messages. ✓

### 3.3 User Mode
- [ ] Set up user address space
- [ ] Implement user stack setup
- [ ] Transition to user mode
- [ ] Handle syscalls from user mode

**Test**: User program calls write() syscall.

### 3.4 Process Creation
- [ ] Implement ELF loader (basic)
- [ ] Implement `proc_create()` from ELF
- [ ] Implement `sys_fork()`
- [ ] Implement `sys_exec()`
- [ ] Implement `sys_wait()`

**Test**: Fork a process, child exits, parent continues.

---

## Phase 4: CFS Scheduler (Week 9-10)

### 4.1 Red-Black Tree
- [ ] Implement rb_insert_color()
- [ ] Implement rb_erase()
- [ ] Implement rb_first(), rb_next()
- [ ] Test with integers

**Test**: Insert 1000 numbers, verify order.

### 4.2 CFS Implementation
- [ ] Implement per-CPU run queue
- [ ] Implement vruntime tracking
- [ ] Implement `enqueue_task()`, `dequeue_task()`
- [ ] Implement `pick_next_task()` (leftmost in RB tree)
- [ ] Implement nice value support

**Test**: Higher-nice process gets less CPU.

### 4.3 SMP Support
- [ ] Implement per-CPU data structure
- [ ] Implement `arch_cpu_id()`
- [ ] Boot secondary CPUs
- [ ] Implement IPI (reschedule)
- [ ] Per-CPU run queues

**Test**: Multiple CPUs run different processes.

---

## Phase 5: File System (Week 11-14)

### 5.1 VFS Layer
- [ ] Implement mount table
- [ ] Implement path parsing
- [ ] Implement vnode operations
- [ ] Implement file descriptor table

**Test**: Mount devfs, open /dev/null.

### 5.2 Device Filesystem
- [ ] Implement devfs
- [ ] Implement /dev/null, /dev/zero
- [ ] Implement /dev/console
- [ ] Redirect stdin/stdout to console

**Test**: write(1, "hello", 5) outputs to console.

### 5.3 Block Device Layer
- [ ] Implement `struct blkdev`
- [ ] Implement virtio-blk driver
- [ ] Implement block read/write API

**Test**: Read sector 0 from disk.

### 5.4 ext2 File System
- [ ] Parse superblock
- [ ] Parse block group descriptors
- [ ] Implement inode reading
- [ ] Implement directory listing
- [ ] Implement file reading
- [ ] Implement file writing
- [ ] Implement file creation
- [ ] Implement directory creation

**Test**: Mount ext2, ls /, cat /etc/passwd.

---

## Phase 6: IPC & Signals (Week 15-16)

### 6.1 Pipes
- [ ] Implement pipe buffer
- [ ] Implement pipe_read(), pipe_write()
- [ ] Handle blocking I/O
- [ ] Handle SIGPIPE

**Test**: `echo hello | cat`

### 6.2 Signals
- [ ] Implement signal delivery
- [ ] Implement signal frame on user stack
- [ ] Implement sigreturn
- [ ] Implement signal mask
- [ ] Implement SIGINT, SIGTERM, SIGKILL
- [ ] Implement SIGCHLD
- [ ] Implement SIGSEGV

**Test**: Ctrl+C kills foreground process.

### 6.3 Wait Queues
- [ ] Implement wait queue structure
- [ ] Implement sleep/wakeup
- [ ] Refactor I/O to use wait queues

---

## Phase 7: I/O & Network (Week 17-20)

### 7.1 Poll
- [ ] Implement poll syscall
- [ ] Implement pollable file operations
- [ ] Test with pipes

**Test**: poll() on multiple fds.

### 7.2 Network Stack
- [ ] Port lwIP
- [ ] Implement virtio-net driver
- [ ] Implement socket API shim
- [ ] Test ping

**Test**: Ping from QEMU host.

### 7.3 HTTP Server
- [ ] Write simple HTTP server in user space
- [ ] Test from browser

---

## Phase 8: User Space (Week 21-24)

### 8.1 C Library (musl)
- [ ] Port musl startup code
- [ ] Port musl syscall wrappers
- [ ] Port stdio
- [ ] Port stdlib
- [ ] Port string
- [ ] Port pthread (basic)

**Test**: Hello world with printf().

### 8.2 BusyBox
- [ ] Static compile busybox
- [ ] Test basic commands (ls, cat, echo)
- [ ] Test shell (ash)
- [ ] Test more commands

**Test**: Interactive shell session.

### 8.3 TCC (Tiny C Compiler)
- [ ] Port TCC
- [ ] Compile simple program
- [ ] Self-compile TCC

**Test**: TCC compiles and runs hello.c.

---

## Phase 9: Drivers (Week 25-28)

### 9.1 PCI Enumeration
- [ ] Implement PCI config space access
- [ ] Enumerate all PCI devices
- [ ] Match drivers to devices

### 9.2 NVMe Driver
- [ ] Implement admin queue
- [ ] Implement I/O queues
- [ ] Implement read/write
- [ ] Test on real hardware

### 9.3 USB Stack (tinyusb)
- [ ] Port tinyusb
- [ ] Implement XHCI driver
- [ ] Implement HID (keyboard)
- [ ] Test USB keyboard

### 9.4 Framebuffer
- [ ] Get framebuffer from Limine
- [ ] Implement pixel plotting
- [ ] Implement text console on framebuffer
- [ ] Basic graphics demo

---

## Phase 10: Second Architecture (Week 29-32)

### 10.1 x86_64 Port
- [ ] Implement boot.S for x86_64
- [ ] Implement trap handling (IDT)
- [ ] Implement paging (4-level)
- [ ] Implement APIC timer
- [ ] Implement context switch
- [ ] Test all previous functionality

### 10.2 Limine Integration
- [ ] Create ISO with Limine
- [ ] Boot on QEMU
- [ ] Boot on real hardware

---

## Phase 11: Polish (Week 33+)

### 11.1 AArch64 Port
- [ ] Implement boot.S
- [ ] Implement exception handling
- [ ] Implement MMU
- [ ] Test

### 11.2 Real Hardware
- [ ] Boot on x86 laptop
- [ ] Boot on RISC-V board
- [ ] Debug hardware-specific issues

### 11.3 DOOM!
- [ ] Port DOOM
- [ ] Get it running
- [ ] Optimize if needed

---

## Milestone Checklist

| Milestone | Description | Target | Status |
|-----------|-------------|--------|--------|
| M1 | Boot and print | Week 2 | ✓ Done |
| M2 | Memory management working | Week 4 | ✓ Done |
| M2.5 | Trap handling working | Week 5 | ✓ Done |
| M3 | First user process | Week 8 | |
| M4 | Shell running | Week 16 | |
| M5 | Network working | Week 20 | |
| M6 | BusyBox complete | Week 24 | |
| M7 | TCC working | Week 24 | |
| M8 | x86_64 port | Week 32 | |
| M9 | Real hardware boot | Week 34 | |
| M10 | DOOM running | Week 36 | |

---

## Development Tips

### Always Test
After completing each item, write a test. Don't move on until it passes.

### Git Commits
Commit after each working feature. Use descriptive messages.

### Debug Early
Set up GDB early. Use printk liberally during development.

### Keep It Simple
Resist the urge to over-engineer. Get it working first.

### Document As You Go
Update comments when code changes. Future you will thank present you.
