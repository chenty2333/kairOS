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
#define CONFIG_DEBUG 1
#define CONFIG_VERBOSE 0
#define CONFIG_KERNEL_TESTS 1
/* #define CONFIG_SLUB_DEBUG           1 */

/*
 * Architecture-specific (set by build system)
 */
#ifndef CONFIG_ARCH
#define CONFIG_ARCH "riscv64"
#endif

#endif /* _KAIROS_CONFIG_H */
