/**
 * kernel/core/proc/elf.c - ELF Binary Loader
 *
 * Loads ELF64 executables into a process address space.
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/elf.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/types.h>

/* User stack configuration */
#define USER_STACK_TOP 0x80000000UL
#define USER_STACK_SIZE (64 * 1024) /* 64KB initial stack */

/**
 * elf_load - Load an ELF binary into a process address space
 */
int elf_load(struct mm_struct *mm, const void *elf, size_t size,
             vaddr_t *entry_out) {
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf;
    int ret;

    if (size < sizeof(Elf64_Ehdr) || elf_validate(ehdr) < 0) {
        pr_err("ELF: invalid or too small header\n");
        return -ENOEXEC;
    }

    size_t phdr_end = ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize);
    if (phdr_end > size) {
        pr_err("ELF: program headers extend past file\n");
        return -ENOEXEC;
    }

    const uint8_t *elf_bytes = (const uint8_t *)elf;
    const Elf64_Phdr *phdr = (const Elf64_Phdr *)(elf_bytes + ehdr->e_phoff);

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }

        if (phdr[i].p_offset + phdr[i].p_filesz > size) {
            return -ENOEXEC;
        }

        vaddr_t seg_start = phdr[i].p_vaddr;
        vaddr_t seg_end = seg_start + phdr[i].p_memsz;
        vaddr_t page_start = ALIGN_DOWN(seg_start, CONFIG_PAGE_SIZE);
        vaddr_t page_end = ALIGN_UP(seg_end, CONFIG_PAGE_SIZE);

        /* Map ELF flags to page table flags */
        uint64_t flags = PTE_USER;
        if (phdr[i].p_flags & PF_R)
            flags |= PTE_READ;
        if (phdr[i].p_flags & PF_W)
            flags |= PTE_WRITE;
        if (phdr[i].p_flags & PF_X)
            flags |= PTE_EXEC;

        for (vaddr_t va = page_start; va < page_end; va += CONFIG_PAGE_SIZE) {
            paddr_t pa = pmm_alloc_page();
            if (!pa) {
                return -ENOMEM;
            }

            memset((void *)pa, 0, CONFIG_PAGE_SIZE);

            /* Copy file data if this page overlaps with segment's file data */
            vaddr_t file_data_end = seg_start + phdr[i].p_filesz;
            vaddr_t copy_start = (va < seg_start) ? seg_start : va;
            vaddr_t copy_end = (va + CONFIG_PAGE_SIZE < file_data_end)
                                   ? va + CONFIG_PAGE_SIZE
                                   : file_data_end;

            if (copy_start < copy_end) {
                size_t page_off = copy_start - va;
                size_t file_off = phdr[i].p_offset + (copy_start - seg_start);
                size_t copy_len = copy_end - copy_start;
                memcpy((void *)(pa + page_off), elf_bytes + file_off, copy_len);
            }

            if ((ret = arch_mmu_map(mm->pgdir, va, pa, flags)) < 0) {
                pmm_free_page(pa);
                return ret;
            }
        }
    }

    *entry_out = ehdr->e_entry;
    return 0;
}

/**
 * elf_setup_stack - Set up user stack with arguments
 */
int elf_setup_stack(struct mm_struct *mm, char *const argv[],
                    char *const envp[], vaddr_t *sp_out) {
    vaddr_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;

    for (vaddr_t va = stack_bottom; va < USER_STACK_TOP;
         va += CONFIG_PAGE_SIZE) {
        paddr_t pa = pmm_alloc_page();
        if (!pa) {
            return -ENOMEM;
        }

        memset((void *)pa, 0, CONFIG_PAGE_SIZE);
        if (arch_mmu_map(mm->pgdir, va, pa, PTE_USER | PTE_READ | PTE_WRITE) <
            0) {
            pmm_free_page(pa);
            return -ENOMEM;
        }
    }

    vaddr_t sp = USER_STACK_TOP - 16;
    (void)argv;
    (void)envp;

    mm->start_stack = sp;
    *sp_out = sp;
    return 0;
}

/**
 * proc_create - Create a process from an ELF binary
 */
struct process *proc_create(const char *name, const void *elf, size_t size) {
    struct process *p = proc_alloc_internal();
    vaddr_t entry, sp;

    if (!p) {
        return NULL;
    }

    strncpy(p->name, name, sizeof(p->name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';

    if (!(p->mm = mm_create())) {
        proc_free_internal(p);
        return NULL;
    }

    if (elf_load(p->mm, elf, size, &entry) < 0 ||
        elf_setup_stack(p->mm, NULL, NULL, &sp) < 0) {
        mm_destroy(p->mm);
        proc_free_internal(p);
        return NULL;
    }

    arch_context_init(p->context, entry, sp, false);
    p->state = PROC_RUNNABLE;

    pr_info("proc_create: created '%s' (pid %d) entry=%p sp=%p\n", p->name,
            p->pid, (void *)entry, (void *)sp);

    return p;
}