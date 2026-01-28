/**
 * kernel/core/syscall/abi_linux.c - Linux syscall dispatch
 */

#include <kairos/syscall.h>

int64_t linux_syscall_dispatch(uint64_t num, uint64_t a0, uint64_t a1,
                               uint64_t a2, uint64_t a3, uint64_t a4,
                               uint64_t a5) {
    switch (num) {
#define X(nr, name, handler) case LINUX_NR_##name: return handler(a0, a1, a2, a3, a4, a5);
#include <kairos/linux_syscalls.def>
#undef X
    default:
        return -ENOSYS;
    }
}
