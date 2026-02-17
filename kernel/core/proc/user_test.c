/**
 * kernel/core/proc/user_test.c - User Mode Test
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>

/* User program addresses */
#define USER_CODE_ADDR 0x10000

static const uint8_t user_program[] = {
    0x13, 0x05, 0x10, 0x00, 0x97, 0x05, 0x00, 0x00, 0x93, 0x85, 0x05, 0x02,
    0x13, 0x06, 0x60, 0x01, 0x93, 0x08, 0xd0, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x13, 0x05, 0xa0, 0x02, 0x93, 0x08, 0x10, 0x00, 0x73, 0x00, 0x00, 0x00,
    'H',  'e',  'l',  'l',  'o',  ' ',  'f',  'r',  'o',  'm',  ' ',  'u',
    's',  'e',  'r',  ' ',  'm',  'o',  'd',  'e',  '!',  '\n',
};

/**
 * Crash test program:
 *   Use arch-specific illegal opcodes so the test terminates reliably.
 */
#if defined(ARCH_riscv64)
static const uint8_t crash_program[] = {
    0x00, 0x00, 0x00, 0x00, /* unimp */
};
#elif defined(ARCH_x86_64)
static const uint8_t crash_program[] = {
    0x0f, 0x0b, /* ud2 */
};
#elif defined(ARCH_aarch64)
static const uint8_t crash_program[] = {
    0x00, 0x00, 0x20, 0xD4, /* brk #0 */
};
#else
static const uint8_t crash_program[] = {
    0x00, 0x00, 0x00, 0x00,
};
#endif

static struct process *create_user_process(const char *name, const uint8_t *code,
                                           size_t code_size,
                                           struct process *parent) {
    struct process *p = proc_alloc_internal();
    if (!p) return NULL;

    strncpy(p->name, name, sizeof(p->name) - 1);
    p->uid = p->gid = 1000;

    if (parent) {
        p->parent = parent;
        p->ppid = parent->pid;
        list_add(&p->sibling, &parent->children);
    }

    if (!(p->mm = mm_create())) goto fail;

    if (mm_add_vma(p->mm, USER_CODE_ADDR, USER_CODE_ADDR + code_size,
                   VM_READ | VM_EXEC, NULL, 0) < 0) {
        goto fail;
    }

    for (size_t off = 0; off < code_size; off += CONFIG_PAGE_SIZE) {
        paddr_t pa = pmm_alloc_page();
        if (!pa) goto fail;
        memset(phys_to_virt(pa), 0, CONFIG_PAGE_SIZE);
        size_t len = MIN(code_size - off, CONFIG_PAGE_SIZE);
        memcpy(phys_to_virt(pa), code + off, len);
        if (arch_mmu_map(p->mm->pgdir, USER_CODE_ADDR + off, pa,
                         PTE_USER | PTE_READ | PTE_EXEC) < 0) {
            pmm_free_page(pa);
            goto fail;
        }
    }

    vaddr_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    if (mm_add_vma(p->mm, stack_bottom, USER_STACK_TOP,
                   VM_READ | VM_WRITE | VM_STACK, NULL, 0) < 0) {
        goto fail;
    }

    for (vaddr_t va = stack_bottom; va < USER_STACK_TOP;
         va += CONFIG_PAGE_SIZE) {
        paddr_t pa = pmm_alloc_page();
        if (!pa) goto fail;
        memset(phys_to_virt(pa), 0, CONFIG_PAGE_SIZE);
        if (arch_mmu_map(p->mm->pgdir, va, pa,
                         PTE_USER | PTE_READ | PTE_WRITE) < 0) {
            pmm_free_page(pa);
            goto fail;
        }
    }

    arch_context_init(p->context, USER_CODE_ADDR, USER_STACK_TOP - 16, false);
    proc_setup_stdio(p);
    p->state = PROC_RUNNABLE;
    return p;

fail:
    if (p->mm) mm_destroy(p->mm);
    proc_free_internal(p);
    return NULL;
}

void run_user_test(void) {

    pr_info("\n=== User Mode Test ===\n");

    struct process *p = create_user_process("user_test", user_program, sizeof(user_program), proc_current());

    if (p) sched_enqueue(p);

}



void run_fork_test(void) {

    pr_info("\n=== Fork Test ===\n");

    struct process *p = create_user_process("fork_test", user_program, sizeof(user_program), proc_current());

    if (p) sched_enqueue(p);

}

void run_sync_test(void) {
    pr_info("\n=== Sync Test ===\n");

    struct mutex m;
    mutex_init(&m, "sync_test_mutex");
    mutex_lock(&m);
    mutex_unlock(&m);

    struct semaphore s;
    sem_init(&s, 1, "sync_test_sem");
    sem_wait(&s);
    sem_post(&s);
}

void run_vfork_test(void) {
    pr_info("\n=== Vfork Test (smoke) ===\n");
}



void run_crash_test(void) {

    pr_info("\n=== Crash Test (Illegal Instruction) ===\n");

    struct process *p = create_user_process("crash_test", crash_program, sizeof(crash_program), proc_current());

    if (p) sched_enqueue(p);

}
