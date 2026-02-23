/**
 * kernel/include/kairos/clone.h - Linux clone flag definitions
 *
 * Shared between syscall layer and process fork implementation.
 */

#ifndef KAIROS_CLONE_H
#define KAIROS_CLONE_H

enum {
    CLONE_VM             = 0x00000100,
    CLONE_FS             = 0x00000200,
    CLONE_FILES          = 0x00000400,
    CLONE_SIGHAND        = 0x00000800,
    CLONE_SYSVSEM        = 0x00040000,
    CLONE_VFORK          = 0x00004000,
    CLONE_THREAD         = 0x00010000,
    CLONE_SETTLS         = 0x00080000,
    CLONE_PARENT_SETTID  = 0x00100000,
    CLONE_CHILD_CLEARTID = 0x00200000,
    CLONE_CHILD_SETTID   = 0x01000000,
};

#endif /* KAIROS_CLONE_H */
