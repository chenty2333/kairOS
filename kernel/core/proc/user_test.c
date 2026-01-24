/**
 * user_test.c - User Mode Test
 *
 * Creates simple user processes to test user mode functionality.
 * Since we don't have an ELF loader yet, we embed RISC-V machine code directly.
 */

#include <kairos/types.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/mm.h>
#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/config.h>

/* User program address */
#define USER_CODE_ADDR      0x10000
#define USER_STACK_TOP      0x80000000UL
#define USER_STACK_SIZE     (16 * 4096)  /* 64KB stack */

/**
 * Simple user program (RISC-V machine code):
 *
 * This program does:
 *   1. write(1, "Hello from user mode!\n", 22)
 *   2. exit(42)
 */
static const uint8_t user_program[] = {
    /* 0x00: li a0, 1 (addi a0, zero, 1) */
    0x13, 0x05, 0x10, 0x00,

    /* 0x04: auipc a1, 0 (load PC-relative address) */
    0x97, 0x05, 0x00, 0x00,

    /* 0x08: addi a1, a1, 32 (offset to msg at 0x24) */
    0x93, 0x85, 0x05, 0x02,

    /* 0x0c: li a2, 22 (addi a2, zero, 22) */
    0x13, 0x06, 0x60, 0x01,

    /* 0x10: li a7, 13 (addi a7, zero, 13) - SYS_write */
    0x93, 0x08, 0xd0, 0x00,

    /* 0x14: ecall */
    0x73, 0x00, 0x00, 0x00,

    /* 0x18: li a0, 42 (addi a0, zero, 42) */
    0x13, 0x05, 0xa0, 0x02,

    /* 0x1c: li a7, 1 (addi a7, zero, 1) - SYS_exit */
    0x93, 0x08, 0x10, 0x00,

    /* 0x20: ecall */
    0x73, 0x00, 0x00, 0x00,

    /* 0x24: message "Hello from user mode!\n" */
    'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r',
    'o', 'm', ' ', 'u', 's', 'e', 'r', ' ',
    'm', 'o', 'd', 'e', '!', '\n',
};

/**
 * Fork test program (RISC-V machine code):
 *
 * This program tests fork():
 *   1. fork()
 *   2. If child: write "Child!\n", exit(0)
 *   3. If parent: wait(), write "Parent: child done!\n", exit(0)
 *
 * Assembly (at base 0x10000):
 *   0x00: li a7, 2              # SYS_fork
 *   0x04: ecall
 *   0x08: bnez a0, parent       # if a0 != 0, goto parent (0x34)
 *
 *   child:
 *   0x0c: li a0, 1              # fd = stdout
 *   0x10: auipc a1, 0           # PC-relative address
 *   0x14: addi a1, a1, 76       # offset to child_msg (0x5c)
 *   0x18: li a2, 7              # len("Child!\n")
 *   0x1c: li a7, 13             # SYS_write
 *   0x20: ecall
 *   0x24: li a0, 0              # status = 0
 *   0x28: li a7, 1              # SYS_exit
 *   0x2c: ecall
 *   0x30: j .                   # infinite loop (shouldn't reach)
 *
 *   parent:
 *   0x34: mv s0, a0             # save child pid in s0
 *   0x38: li a1, 0              # status = NULL
 *   0x3c: li a2, 0              # options = 0
 *   0x40: li a7, 4              # SYS_wait
 *   0x44: ecall
 *   0x48: li a0, 1              # fd = stdout
 *   0x4c: auipc a1, 0           # PC-relative address
 *   0x50: addi a1, a1, 19       # offset to parent_msg (0x63)
 *   0x54: li a2, 20             # len("Parent: child done!\n")
 *   0x58: li a7, 13             # SYS_write
 *   0x5c: ecall
 *   0x60: li a0, 0              # status = 0
 *   0x64: li a7, 1              # SYS_exit
 *   0x68: ecall
 *
 *   0x6c: child_msg: "Child!\n"
 *   0x73: parent_msg: "Parent: child done!\n"
 */
static const uint8_t fork_test_program[] = {
    /* 0x00: li a7, 2 (SYS_fork) */
    0x93, 0x08, 0x20, 0x00,

    /* 0x04: ecall */
    0x73, 0x00, 0x00, 0x00,

    /* 0x08: bnez a0, parent (offset +0x2c = 44 bytes to 0x34) */
    0x63, 0x16, 0x05, 0x02,

    /* === CHILD === */
    /* 0x0c: li a0, 1 */
    0x13, 0x05, 0x10, 0x00,

    /* 0x10: auipc a1, 0 */
    0x97, 0x05, 0x00, 0x00,

    /* 0x14: addi a1, a1, 92 (0x5c from 0x10 = 0x6c - 0x10 = 92) */
    0x93, 0x85, 0xc5, 0x05,

    /* 0x18: li a2, 7 */
    0x13, 0x06, 0x70, 0x00,

    /* 0x1c: li a7, 13 (SYS_write) */
    0x93, 0x08, 0xd0, 0x00,

    /* 0x20: ecall */
    0x73, 0x00, 0x00, 0x00,

    /* 0x24: li a0, 0 */
    0x13, 0x05, 0x00, 0x00,

    /* 0x28: li a7, 1 (SYS_exit) */
    0x93, 0x08, 0x10, 0x00,

    /* 0x2c: ecall */
    0x73, 0x00, 0x00, 0x00,

    /* 0x30: j . (infinite loop) - jal x0, 0 */
    0x6f, 0x00, 0x00, 0x00,

    /* === PARENT === */
    /* 0x34: mv s0, a0 (addi s0, a0, 0) */
    0x13, 0x04, 0x05, 0x00,

    /* 0x38: li a1, 0 */
    0x93, 0x05, 0x00, 0x00,

    /* 0x3c: li a2, 0 */
    0x13, 0x06, 0x00, 0x00,

    /* 0x40: li a7, 4 (SYS_wait) */
    0x93, 0x08, 0x40, 0x00,

    /* 0x44: ecall */
    0x73, 0x00, 0x00, 0x00,

    /* 0x48: li a0, 1 */
    0x13, 0x05, 0x10, 0x00,

    /* 0x4c: auipc a1, 0 */
    0x97, 0x05, 0x00, 0x00,

    /* 0x50: addi a1, a1, 39 (0x73 - 0x4c = 39) */
    0x93, 0x85, 0x75, 0x02,

    /* 0x54: li a2, 20 */
    0x13, 0x06, 0x40, 0x01,

    /* 0x58: li a7, 13 (SYS_write) */
    0x93, 0x08, 0xd0, 0x00,

    /* 0x5c: ecall */
    0x73, 0x00, 0x00, 0x00,

    /* 0x60: li a0, 0 */
    0x13, 0x05, 0x00, 0x00,

    /* 0x64: li a7, 1 (SYS_exit) */
    0x93, 0x08, 0x10, 0x00,

    /* 0x68: ecall */
    0x73, 0x00, 0x00, 0x00,

    /* 0x6c: child_msg "Child!\n" (7 bytes) */
    'C', 'h', 'i', 'l', 'd', '!', '\n',

    /* 0x73: parent_msg "Parent: child done!\n" (20 bytes) */
    'P', 'a', 'r', 'e', 'n', 't', ':', ' ',
    'c', 'h', 'i', 'l', 'd', ' ', 'd', 'o',
    'n', 'e', '!', '\n',
};

/**
 * create_user_process - Create a user process from code bytes
 *
 * @name: Process name
 * @code: Code bytes to copy into user space
 * @code_size: Size of code
 * @parent: Parent process (can be NULL)
 *
 * Returns the new process, or NULL on failure.
 */
static struct process *create_user_process(const char *name,
                                           const uint8_t *code,
                                           size_t code_size,
                                           struct process *parent)
{
    /* Allocate process structure using the proper allocator */
    struct process *p = proc_alloc_internal();
    if (!p) {
        pr_err("Failed to allocate process structure\n");
        return NULL;
    }

    /* Set name */
    int i;
    for (i = 0; name[i] && i < 15; i++) {
        p->name[i] = name[i];
    }
    p->name[i] = '\0';

    p->uid = 1000;
    p->gid = 1000;

    /* Set parent */
    if (parent) {
        p->parent = parent;
        p->ppid = parent->pid;
        list_add(&p->sibling, &parent->children);
    }

    /* Create address space */
    p->mm = mm_create();
    if (!p->mm) {
        pr_err("Failed to create address space\n");
        proc_free_internal(p);
        return NULL;
    }

    /* Allocate and copy code pages */
    size_t code_pages_needed = (code_size + CONFIG_PAGE_SIZE - 1) / CONFIG_PAGE_SIZE;
    for (size_t pg = 0; pg < code_pages_needed; pg++) {
        paddr_t code_page = pmm_alloc_page();
        if (code_page == 0) {
            pr_err("Failed to allocate code page\n");
            goto fail;
        }

        /* Copy code to page (convert physical to virtual address) */
        uint8_t *code_ptr = (uint8_t *)phys_to_virt(code_page);
        size_t offset = pg * CONFIG_PAGE_SIZE;
        size_t copy_size = code_size - offset;
        if (copy_size > CONFIG_PAGE_SIZE) {
            copy_size = CONFIG_PAGE_SIZE;
        }

        for (size_t j = 0; j < copy_size; j++) {
            code_ptr[j] = code[offset + j];
        }
        /* Zero rest of page */
        for (size_t j = copy_size; j < CONFIG_PAGE_SIZE; j++) {
            code_ptr[j] = 0;
        }

        vaddr_t va = USER_CODE_ADDR + pg * CONFIG_PAGE_SIZE;
        int ret = arch_mmu_map(p->mm->pgdir, va, code_page,
                               PTE_USER | PTE_READ | PTE_EXEC);
        if (ret < 0) {
            pr_err("Failed to map code page\n");
            pmm_free_page(code_page);
            goto fail;
        }
    }

    /* Allocate and map user stack */
    vaddr_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    for (vaddr_t va = stack_bottom; va < USER_STACK_TOP; va += CONFIG_PAGE_SIZE) {
        paddr_t stack_page = pmm_alloc_page();
        if (stack_page == 0) {
            pr_err("Failed to allocate stack page\n");
            goto fail;
        }

        /* Clear stack page (convert physical to virtual address) */
        uint8_t *stack_ptr = (uint8_t *)phys_to_virt(stack_page);
        for (size_t j = 0; j < CONFIG_PAGE_SIZE; j++) {
            stack_ptr[j] = 0;
        }

        int ret = arch_mmu_map(p->mm->pgdir, va, stack_page,
                               PTE_USER | PTE_READ | PTE_WRITE);
        if (ret < 0) {
            pr_err("Failed to map stack page\n");
            pmm_free_page(stack_page);
            goto fail;
        }
    }

    /* Initialize context for user mode */
    arch_context_init(p->context, USER_CODE_ADDR, USER_STACK_TOP - 16, false);

    p->state = PROC_RUNNABLE;

    pr_debug("Created user process '%s' (pid %d)\n", p->name, p->pid);
    return p;

fail:
    if (p->mm) {
        mm_destroy(p->mm);
        p->mm = NULL;
    }
    proc_free_internal(p);
    return NULL;
}

/**
 * proc_create_user_test - Create a test user process
 *
 * Creates a simple user process for testing user mode.
 */
struct process *proc_create_user_test(void)
{
    pr_info("Creating test user process...\n");
    struct process *p = create_user_process("user_test", user_program,
                                             sizeof(user_program), NULL);
    if (p) {
        pr_info("Test user process created (pid %d)\n", p->pid);
    }
    return p;
}

/**
 * run_user_test - Run the user mode test
 *
 * Creates a test user process and switches to it.
 */
void run_user_test(void)
{
    pr_info("\n=== User Mode Test ===\n");

    struct process *p = proc_create_user_test();
    if (!p) {
        pr_err("Failed to create user test process\n");
        return;
    }

    pr_info("Switching to user mode...\n");

    /* Add to scheduler */
    sched_enqueue(p);

    /* Switch to user page table */
    arch_mmu_switch(p->mm->pgdir);

    /* Set current process */
    proc_set_current(p);

    /* Enter user mode (does not return) */
    arch_enter_user(p->context);

    /* Should never reach here */
    panic("arch_enter_user returned!");
}

/**
 * run_fork_test - Run the fork test
 *
 * Creates a user process that tests fork().
 * The process forks, child prints and exits, parent waits and exits.
 */
void run_fork_test(void)
{
    pr_info("\n=== Fork Test ===\n");

    struct process *p = create_user_process("fork_test", fork_test_program,
                                             sizeof(fork_test_program), NULL);
    if (!p) {
        pr_err("Failed to create fork test process\n");
        return;
    }

    pr_info("Running fork test process (pid %d)...\n", p->pid);

    /* Add to scheduler */
    sched_enqueue(p);

    /* Switch to user page table */
    arch_mmu_switch(p->mm->pgdir);

    /* Set current process */
    proc_set_current(p);

    /* Enter user mode */
    arch_enter_user(p->context);

    /* Should never reach here */
    panic("arch_enter_user returned!");
}
