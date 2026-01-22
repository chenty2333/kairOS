# Kairos Architecture Design

## Overview

Kairos is a monolithic kernel with clean module separation. All code runs in kernel mode, but modules communicate through well-defined interfaces.

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Space                               │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │ busybox │  │   TCC   │  │  DOOM   │  │  httpd  │            │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │
│                            │                                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    musl libc                              │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                             │ syscall
┌─────────────────────────────────────────────────────────────────┐
│                      Kernel Space                               │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   System Call Layer                       │  │
│  │              (syscall dispatch, argument validation)      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                             │                                   │
│  ┌─────────────────────────────────────────────────────────────┐
│  │                    Core Subsystems                          │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  │ Process  │  │ Scheduler│  │  Memory  │  │   Time   │   │
│  │  │ Manager  │  │  (CFS)   │  │ Manager  │  │ Manager  │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │  │  Signal  │  │   IPC    │  │   VFS    │                  │
│  │  │ Handler  │  │(pipe,shm)│  │  Layer   │                  │
│  │  └──────────┘  └──────────┘  └──────────┘                  │
│  └─────────────────────────────────────────────────────────────┘
│                             │                                   │
│  ┌─────────────────────────────────────────────────────────────┐
│  │                    Device Drivers                           │
│  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐            │
│  │  │virtio- │  │  NVMe  │  │ lwIP   │  │tinyusb │            │
│  │  │  blk   │  │        │  │(TCP/IP)│  │ (USB)  │            │
│  │  └────────┘  └────────┘  └────────┘  └────────┘            │
│  │  ┌────────┐  ┌────────┐                                     │
│  │  │ Frame  │  │ virtio │                                     │
│  │  │ buffer │  │  net   │                                     │
│  │  └────────┘  └────────┘                                     │
│  └─────────────────────────────────────────────────────────────┘
│                             │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Hardware Abstraction Layer (HAL)             │  │
│  │         (arch_*, mmu_*, timer_*, irq_* interfaces)        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                             │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Architecture Implementation                  │  │
│  │     ┌──────────┐  ┌──────────┐  ┌──────────┐             │  │
│  │     │ RISC-V64 │  │  AArch64 │  │  x86_64  │             │  │
│  │     └──────────┘  └──────────┘  └──────────┘             │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                             │
┌─────────────────────────────────────────────────────────────────┐
│                        Hardware                                 │
│    CPU, Memory, NVMe, USB, Network Card, Framebuffer           │
└─────────────────────────────────────────────────────────────────┘
```

## Design Principles

### 1. Interface-Driven Design

Every subsystem exposes a minimal, stable interface. Implementation details are hidden.

```c
// Good: Core code uses abstract interface
void scheduler_tick(void) {
    arch_timer_ack();           // HAL interface
    current->timeslice--;
}

// Bad: Core code uses architecture-specific code
void scheduler_tick(void) {
    WRITE_CSR(sip, 0);          // RISC-V specific!
    current->timeslice--;
}
```

### 2. Two-Phase Abstraction

1. **Write concrete code first** - Get it working for one architecture
2. **Extract interface when needed** - When adding second architecture

Don't over-abstract before you have two implementations.

### 3. Minimal Interface Surface

Each interface should have the minimum number of functions needed.

```c
// Good: Simple block device interface
struct blkdev_ops {
    int (*read)(struct blkdev *dev, uint64_t lba, void *buf, size_t n);
    int (*write)(struct blkdev *dev, uint64_t lba, const void *buf, size_t n);
};

// Bad: Overly complex interface
struct blkdev_ops {
    int (*read)(struct blkdev *dev, ...);
    int (*write)(struct blkdev *dev, ...);
    int (*flush)(struct blkdev *dev);
    int (*ioctl)(struct blkdev *dev, int cmd, void *arg);
    int (*get_status)(struct blkdev *dev, struct status *s);
    int (*set_config)(struct blkdev *dev, struct config *c);
    // ... 15 more functions that might never be used
};
```

### 4. Compile-Time Architecture Selection

Architecture-specific code is selected at compile time, not runtime.

```c
// Implemented in arch/riscv64/irq.c OR arch/x86_64/irq.c
// Only one is compiled
void arch_irq_enable(void);
void arch_irq_disable(void);

// NOT function pointers
// struct arch_ops { void (*irq_enable)(void); } // Don't do this
```

---

## Memory Layout

### Virtual Address Space (64-bit)

```
┌─────────────────────────────────────┐ 0xFFFFFFFFFFFFFFFF
│                                     │
│         Kernel Space                │
│                                     │
│  ┌─────────────────────────────┐   │ 0xFFFFFFFF80000000 (Kernel base)
│  │     Kernel code + data      │   │
│  ├─────────────────────────────┤   │
│  │     Kernel heap (kmalloc)   │   │
│  ├─────────────────────────────┤   │
│  │     Direct mapping          │   │ Physical memory mapped here
│  │     (physical memory)       │   │
│  ├─────────────────────────────┤   │
│  │     Device MMIO             │   │
│  └─────────────────────────────┘   │
│                                     │
├─────────────────────────────────────┤ 0x0000800000000000 (Kernel/User split)
│                                     │
│         User Space                  │
│                                     │
│  ┌─────────────────────────────┐   │ 0x00007FFFFFFFFFFF (Stack top)
│  │         Stack ↓             │   │
│  │           ...               │   │
│  ├─────────────────────────────┤   │
│  │         mmap area           │   │ Dynamic allocations, shared libs
│  ├─────────────────────────────┤   │
│  │         Heap ↑              │   │ brk() grows upward
│  ├─────────────────────────────┤   │
│  │         BSS                 │   │
│  ├─────────────────────────────┤   │
│  │         Data                │   │
│  ├─────────────────────────────┤   │
│  │         Text (code)         │   │ 0x0000000000400000 (typical)
│  └─────────────────────────────┘   │
│                                     │
└─────────────────────────────────────┘ 0x0000000000000000
```

### Physical Memory Management

**Buddy System** for page allocation:

```
Order 0:  4KB pages     (single page)
Order 1:  8KB blocks    (2 pages)
Order 2:  16KB blocks   (4 pages)
...
Order 10: 4MB blocks    (1024 pages)
```

**Power-of-2 allocator** for kernel heap (kmalloc):

```
Size classes: 32, 64, 128, 256, 512, 1024, 2048 bytes
Larger allocations use page allocator directly
```

---

## Process Model

### Process Structure

```c
struct process {
    // Identity
    pid_t pid;
    pid_t ppid;                     // Parent PID
    char name[16];

    // Credentials (simple: all root initially)
    uid_t uid;
    gid_t gid;

    // State
    enum proc_state state;          // RUNNABLE, RUNNING, SLEEPING, ZOMBIE
    int exit_code;

    // Scheduling (CFS)
    uint64_t vruntime;              // Virtual runtime
    int nice;                       // Priority (-20 to +19)
    struct rb_node sched_node;      // Red-black tree node

    // Memory
    struct mm_struct *mm;           // Address space

    // Files
    struct file *files[MAX_FILES];  // Open file descriptors

    // Signals
    uint64_t sig_pending;           // Pending signals bitmap
    uint64_t sig_blocked;           // Blocked signals mask
    struct sigaction sigactions[NSIG];

    // Architecture-specific (hidden behind pointer)
    struct arch_context *arch_ctx;  // Registers, kernel stack, etc.

    // Linkage
    struct list_head children;      // Child processes
    struct list_head sibling;       // Sibling list
};
```

### Process States

```
                    fork()
                      │
                      ▼
    ┌─────────────────────────────────┐
    │           RUNNABLE              │◄────────────────┐
    │    (in scheduler run queue)     │                 │
    └─────────────────────────────────┘                 │
                      │                                 │
                      │ scheduled                       │ wakeup()
                      ▼                                 │
    ┌─────────────────────────────────┐                 │
    │           RUNNING               │                 │
    │      (currently executing)      │─────────────────┤
    └─────────────────────────────────┘                 │
           │              │                             │
           │ sleep()      │ exit()                      │
           ▼              ▼                             │
    ┌──────────────┐  ┌──────────────┐                 │
    │   SLEEPING   │  │    ZOMBIE    │                 │
    │(waiting for  │  │  (waiting    │                 │
    │   event)     │──┤  for parent) │                 │
    └──────────────┘  └──────────────┘                 │
           │                 │                          │
           │ event           │ wait()                   │
           └─────────────────┴──────────────────────────┘
                                      │
                                      ▼
                              (process freed)
```

---

## Scheduler Design (CFS)

### Core Data Structures

```c
struct cfs_rq {
    struct rb_root tasks_timeline;  // Red-black tree of runnable tasks
    uint64_t min_vruntime;          // Minimum vruntime (baseline)
    unsigned int nr_running;        // Number of runnable tasks
    struct process *curr;           // Currently running task
};

// Per-CPU run queue
DEFINE_PER_CPU(struct cfs_rq, runqueue);
```

### Key Operations

```c
// Pick next task to run (O(1) - leftmost node in RB tree)
struct process *pick_next_task(struct cfs_rq *rq);

// Update vruntime after task runs
void update_curr(struct cfs_rq *rq, uint64_t delta_exec);

// Add task to run queue
void enqueue_task(struct cfs_rq *rq, struct process *p);

// Remove task from run queue
void dequeue_task(struct cfs_rq *rq, struct process *p);
```

### Vruntime Calculation

```c
// nice value to weight mapping (from Linux)
static const int nice_to_weight[40] = {
    /* -20 */ 88761, 71755, 56483, 46273, 36291,
    /* -15 */ 29154, 23254, 18705, 14949, 11916,
    /* -10 */  9548,  7620,  6100,  4904,  3906,
    /*  -5 */  3121,  2501,  1991,  1586,  1277,
    /*   0 */  1024,   820,   655,   526,   423,  // nice 0 = weight 1024
    /*   5 */   335,   272,   215,   172,   137,
    /*  10 */   110,    87,    70,    56,    45,
    /*  15 */    36,    29,    23,    18,    15,
};

// vruntime increases slower for high-priority tasks
delta_vruntime = delta_exec * NICE_0_WEIGHT / weight[nice + 20];
```

---

## File System Architecture

### VFS Layer

```c
// Mount point
struct mount {
    char *mountpoint;           // e.g., "/", "/mnt/usb"
    struct vfs_ops *ops;        // File system operations
    struct vnode *root;         // Root vnode
    void *fs_data;              // File system private data
};

// Virtual node (file/directory)
struct vnode {
    enum vnode_type type;       // FILE, DIRECTORY, DEVICE, PIPE
    uint64_t size;
    struct file_ops *ops;       // File operations
    void *fs_data;              // File system private data
};

// File system operations
struct vfs_ops {
    int (*mount)(struct mount *mnt, struct blkdev *dev);
    int (*unmount)(struct mount *mnt);
    struct vnode *(*lookup)(struct vnode *dir, const char *name);
    int (*create)(struct vnode *dir, const char *name, int mode);
    int (*mkdir)(struct vnode *dir, const char *name, int mode);
    int (*unlink)(struct vnode *dir, const char *name);
};

// File operations
struct file_ops {
    ssize_t (*read)(struct vnode *vn, void *buf, size_t len, off_t off);
    ssize_t (*write)(struct vnode *vn, const void *buf, size_t len, off_t off);
    int (*close)(struct vnode *vn);
    int (*readdir)(struct vnode *vn, struct dirent *ent, off_t off);
};
```

### File Systems

| File System | Use Case | Implementation |
|-------------|----------|----------------|
| ext2 | Root filesystem | Custom (~2500 lines) |
| FAT32 | Boot partition, USB | FatFs library |
| devfs | /dev devices | Custom (~300 lines) |
| procfs | /proc (optional) | Custom (~500 lines) |

---

## Device Driver Model

### Block Device Interface

```c
struct blkdev {
    char name[16];              // e.g., "nvme0", "vda"
    uint64_t sector_count;      // Total sectors
    uint32_t sector_size;       // Usually 512
    struct blkdev_ops *ops;
    void *private;              // Driver private data
};

struct blkdev_ops {
    int (*read)(struct blkdev *dev, uint64_t lba, void *buf, size_t count);
    int (*write)(struct blkdev *dev, uint64_t lba, const void *buf, size_t count);
};
```

### Network Interface

```c
struct netif {
    char name[8];               // e.g., "eth0"
    uint8_t mac[6];
    uint32_t ip;
    uint32_t netmask;
    struct netif_ops *ops;
    void *private;
};

struct netif_ops {
    int (*send)(struct netif *nif, void *buf, size_t len);
    void (*set_recv_callback)(struct netif *nif, void (*cb)(void *buf, size_t len));
};
```

### Device Discovery

```c
// PCI enumeration (x86)
void pci_scan(void) {
    for (bus = 0; bus < 256; bus++) {
        for (slot = 0; slot < 32; slot++) {
            uint32_t id = pci_config_read(bus, slot, 0, 0);
            if (id == 0xFFFFFFFF) continue;

            uint16_t vendor = id & 0xFFFF;
            uint16_t device = id >> 16;
            pci_device_probe(bus, slot, vendor, device);
        }
    }
}

// Device tree (RISC-V, ARM)
void dt_scan(void *dtb) {
    // Parse FDT, find devices, call probe functions
}
```

---

## Hardware Abstraction Layer

### Core HAL Functions

```c
// === CPU Control ===
void arch_cpu_init(void);                   // Initialize CPU
void arch_cpu_halt(void);                   // Halt CPU (idle)
void arch_cpu_relax(void);                  // Spin-wait hint
noreturn void arch_cpu_reset(void);         // Reboot

// === Interrupt Control ===
void arch_irq_enable(void);
void arch_irq_disable(void);
bool arch_irq_save(void);                   // Save and disable
void arch_irq_restore(bool state);          // Restore state

// === Context Switch ===
void arch_context_switch(struct arch_context *old, struct arch_context *new);
noreturn void arch_enter_user(struct arch_context *ctx);

// === Memory Management ===
void arch_mmu_init(void);
paddr_t arch_mmu_create_table(void);        // Create page table
void arch_mmu_map(paddr_t table, vaddr_t va, paddr_t pa, uint64_t flags);
void arch_mmu_switch(paddr_t table);        // Switch address space
void arch_mmu_flush_tlb(void);

// === Timer ===
void arch_timer_init(uint64_t hz);          // Initialize with frequency
uint64_t arch_timer_get_ticks(void);        // Current tick count
void arch_timer_set_next(uint64_t ticks);   // Set next interrupt

// === IPI (Inter-Processor Interrupt) ===
void arch_send_ipi(int cpu, int type);
```

---

## Interrupt and Trap Handling

### Flow

```
Hardware Interrupt / Exception / Syscall
              │
              ▼
┌──────────────────────────────────┐
│     arch_trap_entry (assembly)   │  Save registers, switch to kernel stack
└──────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────┐
│     trap_dispatch (C code)       │  Identify trap type
└──────────────────────────────────┘
              │
    ┌─────────┼─────────┐
    ▼         ▼         ▼
┌────────┐ ┌────────┐ ┌────────┐
│syscall │ │  IRQ   │ │ fault  │
│handler │ │handler │ │handler │
└────────┘ └────────┘ └────────┘
              │
              ▼
┌──────────────────────────────────┐
│     Check pending signals        │
│     Check need_resched           │
└──────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────┐
│     arch_trap_return (assembly)  │  Restore registers, return
└──────────────────────────────────┘
```

---

## System Calls

### Calling Convention

| Architecture | Syscall Number | Arguments | Return |
|-------------|----------------|-----------|--------|
| RISC-V | a7 | a0-a5 | a0 |
| AArch64 | x8 | x0-x5 | x0 |
| x86_64 | rax | rdi, rsi, rdx, r10, r8, r9 | rax |

### System Call List (Initial)

```c
// Process
SYS_exit        // Exit process
SYS_fork        // Create child process
SYS_exec        // Execute program
SYS_wait        // Wait for child
SYS_getpid      // Get process ID
SYS_getppid     // Get parent PID
SYS_yield       // Yield CPU

// File I/O
SYS_open        // Open file
SYS_close       // Close file
SYS_read        // Read from file
SYS_write       // Write to file
SYS_lseek       // Seek in file
SYS_stat        // Get file status
SYS_fstat       // Get file status by fd
SYS_readdir     // Read directory

// Memory
SYS_brk         // Adjust data segment
SYS_mmap        // Map memory
SYS_munmap      // Unmap memory

// IPC
SYS_pipe        // Create pipe
SYS_dup         // Duplicate fd
SYS_dup2        // Duplicate fd to specific number

// Signals
SYS_kill        // Send signal
SYS_signal      // Set signal handler (simple)
SYS_sigaction   // Set signal handler (full)
SYS_sigprocmask // Set signal mask
SYS_sigreturn   // Return from signal handler

// Time
SYS_time        // Get time
SYS_nanosleep   // Sleep

// I/O Multiplexing
SYS_poll        // Wait for events

// Misc
SYS_ioctl       // Device control
SYS_getcwd      // Get current directory
SYS_chdir       // Change directory
```

---

## Boot Sequence

### Limine Protocol

```
Firmware (UEFI/BIOS)
        │
        ▼
┌───────────────────┐
│      Limine       │  Load kernel, set up framebuffer, memory map
└───────────────────┘
        │
        ▼
┌───────────────────┐
│   _start (asm)    │  Set up initial stack, call kernel_main
└───────────────────┘
        │
        ▼
┌───────────────────┐
│   kernel_main()   │
│   ├─ arch_init()  │  Architecture-specific init
│   ├─ mm_init()    │  Memory management
│   ├─ sched_init() │  Scheduler
│   ├─ trap_init()  │  Interrupt handlers
│   ├─ timer_init() │  System timer
│   ├─ pci_init()   │  Device discovery
│   ├─ vfs_init()   │  Virtual file system
│   ├─ drivers_init()│  Load drivers
│   └─ start_init() │  Start /init process
└───────────────────┘
        │
        ▼
┌───────────────────┐
│   /init (user)    │  First user process
│   └─ /bin/sh      │  Shell
└───────────────────┘
```

---

## Memory Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Kernel code + data | 2 MB | 4 MB |
| Kernel heap | 4 MB | 16 MB |
| Per-process (kernel stack + page tables) | 20 KB | 32 KB |
| File cache | 4 MB | 32 MB |
| Network buffers | 2 MB | 8 MB |
| **Total minimum** | **64 MB** | **256 MB** |

---

## Configuration

```c
// config.h

// Memory
#define CONFIG_MIN_MEMORY_MB        64
#define CONFIG_KERNEL_HEAP_MB       16
#define CONFIG_PAGE_SIZE            4096

// Process
#define CONFIG_MAX_PROCESSES        256
#define CONFIG_KERNEL_STACK_SIZE    (8 * 1024)
#define CONFIG_MAX_FILES_PER_PROC   64

// Scheduler
#define CONFIG_HZ                   100     // Timer frequency
#define CONFIG_TIMESLICE_MS         10      // Default timeslice

// File System
#define CONFIG_MAX_MOUNTS           16
#define CONFIG_MAX_OPEN_FILES       1024
#define CONFIG_PATH_MAX             256

// Network
#define CONFIG_NET_BUFFER_SIZE      (2 * 1024 * 1024)

// Debug
#define CONFIG_DEBUG                1
#define CONFIG_VERBOSE              0
```
