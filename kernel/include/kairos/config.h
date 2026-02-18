/**
 * kairos/config.h - Kernel configuration
 */

#ifndef _KAIROS_CONFIG_H
#define _KAIROS_CONFIG_H

/*
 * Memory Configuration
 */
#define CONFIG_PAGE_SIZE 4096
#define CONFIG_PAGE_SHIFT 12

#define CONFIG_MIN_MEMORY_MB 64
#define CONFIG_RECOMMENDED_MB 256

#define CONFIG_KERNEL_HEAP_INIT_MB 4
#define CONFIG_KERNEL_HEAP_MAX_MB 64

/*
 * Process Configuration
 */
#define CONFIG_MAX_PROCESSES 256
#define CONFIG_KERNEL_STACK_SIZE (8 * 1024)      /* 8 KB */
#define CONFIG_USER_STACK_SIZE (8 * 1024 * 1024) /* 8 MB virtual */
#define CONFIG_MAX_FILES_PER_PROC 64
#define CONFIG_MAX_THREADS 1024

/*
 * Scheduler Configuration
 */
#define CONFIG_HZ 100          /* Timer ticks per second */
#define CONFIG_TIMESLICE_MS 10 /* Default timeslice */
#define CONFIG_MAX_CPUS 16

/*
 * File System Configuration
 */
#define CONFIG_MAX_MOUNTS 16
#define CONFIG_MAX_OPEN_FILES 1024
#define CONFIG_PATH_MAX 256
#define CONFIG_NAME_MAX 64
#define CONFIG_SYMLINK_MAX 8 /* Max symlink depth */
#define CONFIG_DCACHE_MAX 4096
#define CONFIG_DCACHE_NEG_TTL_SEC 2

/*
 * Network Configuration
 */
#define CONFIG_NET_BUFFER_SIZE (2 * 1024 * 1024)
#define CONFIG_MAX_SOCKETS 256

/*
 * IPC Configuration
 */
#define CONFIG_PIPE_SIZE (64 * 1024) /* 64 KB pipe buffer */

/*
 * Signal Configuration
 */
#define CONFIG_NSIG 32 /* Number of signals */

/*
 * Debug Configuration
 */
#define CONFIG_DEBUG 0
#define CONFIG_VERBOSE 0
#ifndef CONFIG_KERNEL_TESTS
#define CONFIG_KERNEL_TESTS 0
#endif
#ifndef CONFIG_EMBEDDED_INIT
#define CONFIG_EMBEDDED_INIT 0
#endif
#ifndef CONFIG_PMM_DEBUG
#define CONFIG_PMM_DEBUG 1
#endif
/*
 * PCP mode:
 *   0 = disabled
 *   1 = debug (enabled with integrity checks)
 *   2 = enabled
 */
#ifndef CONFIG_PMM_PCP_MODE
#define CONFIG_PMM_PCP_MODE 1
#endif
#ifndef CONFIG_PMM_REMOTE_FREE_BATCH
#define CONFIG_PMM_REMOTE_FREE_BATCH 32
#endif
#ifndef CONFIG_PMM_REMOTE_FREE_HIGH
#define CONFIG_PMM_REMOTE_FREE_HIGH 512
#endif
#ifndef CONFIG_PMM_INTEGRITY_PANIC
#define CONFIG_PMM_INTEGRITY_PANIC 0
#endif
/* #define CONFIG_SLUB_DEBUG           1 */

/*
 * Lock debugging
 */
#ifndef CONFIG_DEBUG_LOCKS
#define CONFIG_DEBUG_LOCKS 0
#endif
#ifndef CONFIG_LOCKDEP
#define CONFIG_LOCKDEP 0
#endif

/*
 * Architecture-specific (set by build system)
 */
#ifndef CONFIG_ARCH
#define CONFIG_ARCH "riscv64"
#endif

#endif /* _KAIROS_CONFIG_H */
