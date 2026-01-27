/**
 * kernel/core/syscall/sys_mm.c - Memory-related syscalls
 */

#include <kairos/mm.h>
#include <kairos/process.h>

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_STACK 0x20000

static uint32_t prot_to_vm(uint64_t prot) {
    uint32_t vm = 0;
    if (prot & PROT_READ)
        vm |= VM_READ;
    if (prot & PROT_WRITE)
        vm |= VM_WRITE;
    if (prot & PROT_EXEC)
        vm |= VM_EXEC;
    return vm;
}

int64_t sys_brk(uint64_t addr, uint64_t a1, uint64_t a2, uint64_t a3,
                uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return (int64_t)mm_brk(proc_current()->mm, (vaddr_t)addr);
}

int64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
                 uint64_t fd, uint64_t off) {
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    (void)fd;

    bool fixed = (flags & MAP_FIXED) != 0;
    bool anon = (flags & MAP_ANONYMOUS) != 0;
    bool priv = (flags & MAP_PRIVATE) != 0;
    bool shared = (flags & MAP_SHARED) != 0;

    if (!priv && !shared)
        return -EINVAL;
    if (!anon)
        return -ENOSYS;
    if (off != 0)
        return -ENOSYS;

    uint32_t vm_flags = prot_to_vm(prot);
    vaddr_t start = fixed ? (vaddr_t)addr : 0;
    vaddr_t res = mm_mmap(p->mm, start, (size_t)len, vm_flags, 0, NULL, 0);
    return (int64_t)res;
}

int64_t sys_munmap(uint64_t addr, uint64_t len, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    return (int64_t)mm_munmap(p->mm, (vaddr_t)addr, (size_t)len);
}

int64_t sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    return (int64_t)mm_mprotect(p->mm, (vaddr_t)addr, (size_t)len,
                                prot_to_vm(prot));
}
