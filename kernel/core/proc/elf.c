/**
 * elf.c - ELF Binary Loader
 *
 * Loads ELF64 executables into a process address space.
 */

#include <kairos/types.h>
#include <kairos/elf.h>
#include <kairos/process.h>
#include <kairos/mm.h>
#include <kairos/arch.h>
#include <kairos/printk.h>
#include <kairos/config.h>

/* User stack configuration */
#define USER_STACK_TOP      0x80000000UL
#define USER_STACK_SIZE     (64 * 1024)     /* 64KB initial stack */
#define USER_STACK_PAGES    (USER_STACK_SIZE / CONFIG_PAGE_SIZE)

/**
 * elf_load - Load an ELF binary into a process address space
 *
 * @mm: Memory management structure with page table
 * @elf: Pointer to ELF binary data
 * @size: Size of ELF binary
 * @entry_out: Output parameter for entry point
 *
 * Returns 0 on success, negative error code on failure.
 */
int elf_load(struct mm_struct *mm, const void *elf, size_t size, vaddr_t *entry_out)
{
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf;
    int ret;

    /* Validate header */
    if (size < sizeof(Elf64_Ehdr)) {
        pr_err("ELF: file too small for header\n");
        return -ENOEXEC;
    }

    ret = elf_validate(ehdr);
    if (ret < 0) {
        pr_err("ELF: invalid header\n");
        return ret;
    }

    /* Validate program headers fit in file */
    size_t phdr_end = ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize);
    if (phdr_end > size) {
        pr_err("ELF: program headers extend past file\n");
        return -ENOEXEC;
    }

    pr_debug("ELF: loading %u segments, entry=%p\n",
             ehdr->e_phnum, (void *)ehdr->e_entry);

    /* Load each PT_LOAD segment */
    const uint8_t *elf_bytes = (const uint8_t *)elf;
    const Elf64_Phdr *phdr = (const Elf64_Phdr *)(elf_bytes + ehdr->e_phoff);

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }

        /* Validate segment bounds */
        if (phdr[i].p_offset + phdr[i].p_filesz > size) {
            pr_err("ELF: segment %u extends past file\n", i);
            return -ENOEXEC;
        }

        vaddr_t seg_start = phdr[i].p_vaddr;
        vaddr_t seg_end = seg_start + phdr[i].p_memsz;

        /* Align to page boundaries */
        vaddr_t page_start = ALIGN_DOWN(seg_start, CONFIG_PAGE_SIZE);
        vaddr_t page_end = ALIGN_UP(seg_end, CONFIG_PAGE_SIZE);

        pr_debug("ELF: segment %u: vaddr=%p memsz=%lu filesz=%lu flags=0x%x\n",
                 i, (void *)seg_start, phdr[i].p_memsz, phdr[i].p_filesz,
                 phdr[i].p_flags);

        /* Convert ELF flags to page table flags */
        uint64_t flags = PTE_USER;
        if (phdr[i].p_flags & PF_R) {
            flags |= PTE_READ;
        }
        if (phdr[i].p_flags & PF_W) {
            flags |= PTE_WRITE;
        }
        if (phdr[i].p_flags & PF_X) {
            flags |= PTE_EXEC;
        }

        /* Allocate and map pages for this segment */
        for (vaddr_t va = page_start; va < page_end; va += CONFIG_PAGE_SIZE) {
            paddr_t pa = pmm_alloc_page();
            if (pa == 0) {
                pr_err("ELF: failed to allocate page for segment\n");
                return -ENOMEM;
            }

            /* Zero the page first */
            uint8_t *page = (uint8_t *)pa;
            for (size_t j = 0; j < CONFIG_PAGE_SIZE; j++) {
                page[j] = 0;
            }

            /* Copy file data if applicable */
            if (va < seg_start + phdr[i].p_filesz) {
                /* Calculate how much to copy */
                size_t page_off = 0;
                size_t file_off = phdr[i].p_offset;

                if (va < seg_start) {
                    /* First page, segment doesn't start at page boundary */
                    page_off = seg_start - va;
                    file_off = phdr[i].p_offset;
                } else {
                    file_off = phdr[i].p_offset + (va - seg_start);
                }

                size_t copy_size = CONFIG_PAGE_SIZE - page_off;
                size_t file_remain = phdr[i].p_filesz - (va + page_off - seg_start);
                if (va + page_off < seg_start) {
                    file_remain = phdr[i].p_filesz;
                }
                if (copy_size > file_remain) {
                    copy_size = file_remain;
                }

                if (copy_size > 0 && file_off < size) {
                    const uint8_t *src = elf_bytes + file_off;
                    for (size_t j = 0; j < copy_size; j++) {
                        page[page_off + j] = src[j];
                    }
                }
            }

            /* Map the page */
            ret = arch_mmu_map(mm->pgdir, va, pa, flags);
            if (ret < 0) {
                pr_err("ELF: failed to map page at %p\n", (void *)va);
                pmm_free_page(pa);
                return ret;
            }
        }
    }

    /* Set entry point */
    *entry_out = ehdr->e_entry;

    return 0;
}

/**
 * elf_setup_stack - Set up user stack with arguments
 *
 * @mm: Memory management structure
 * @argv: Argument vector (can be NULL)
 * @envp: Environment vector (can be NULL)
 * @sp_out: Output parameter for initial stack pointer
 *
 * Returns 0 on success, negative error code on failure.
 */
int elf_setup_stack(struct mm_struct *mm, char *const argv[], char *const envp[],
                    vaddr_t *sp_out)
{
    int ret;

    /* Calculate stack region */
    vaddr_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;

    /* Allocate and map stack pages */
    for (vaddr_t va = stack_bottom; va < USER_STACK_TOP; va += CONFIG_PAGE_SIZE) {
        paddr_t pa = pmm_alloc_page();
        if (pa == 0) {
            pr_err("ELF: failed to allocate stack page\n");
            return -ENOMEM;
        }

        /* Zero the page */
        uint8_t *page = (uint8_t *)pa;
        for (size_t i = 0; i < CONFIG_PAGE_SIZE; i++) {
            page[i] = 0;
        }

        ret = arch_mmu_map(mm->pgdir, va, pa, PTE_USER | PTE_READ | PTE_WRITE);
        if (ret < 0) {
            pr_err("ELF: failed to map stack page at %p\n", (void *)va);
            pmm_free_page(pa);
            return ret;
        }
    }

    /* For now, just set stack pointer to top (minus some space for alignment) */
    vaddr_t sp = USER_STACK_TOP - 16;

    /* TODO: Push argv, envp, auxv onto stack for complete exec support */
    (void)argv;
    (void)envp;

    mm->start_stack = sp;
    *sp_out = sp;

    return 0;
}

/**
 * proc_create - Create a process from an ELF binary
 *
 * @name: Process name
 * @elf: Pointer to ELF binary data
 * @size: Size of ELF binary
 *
 * Returns process structure on success, NULL on failure.
 */
struct process *proc_create(const char *name, const void *elf, size_t size)
{
    struct process *p;
    vaddr_t entry, sp;
    int ret;

    /* Allocate process structure */
    p = proc_alloc_internal();
    if (!p) {
        pr_err("proc_create: failed to allocate process\n");
        return NULL;
    }

    /* Set name */
    for (int i = 0; i < 15 && name[i]; i++) {
        p->name[i] = name[i];
    }
    p->name[15] = '\0';

    /* Create address space */
    p->mm = mm_create();
    if (!p->mm) {
        pr_err("proc_create: failed to create address space\n");
        proc_free_internal(p);
        return NULL;
    }

    /* Load ELF binary */
    ret = elf_load(p->mm, elf, size, &entry);
    if (ret < 0) {
        pr_err("proc_create: failed to load ELF\n");
        mm_destroy(p->mm);
        proc_free_internal(p);
        return NULL;
    }

    /* Set up user stack */
    ret = elf_setup_stack(p->mm, NULL, NULL, &sp);
    if (ret < 0) {
        pr_err("proc_create: failed to setup stack\n");
        mm_destroy(p->mm);
        proc_free_internal(p);
        return NULL;
    }

    /* Initialize context for user mode */
    arch_context_init(p->context, entry, sp, false);

    p->state = PROC_RUNNABLE;

    pr_info("proc_create: created '%s' (pid %d) entry=%p sp=%p\n",
            p->name, p->pid, (void *)entry, (void *)sp);

    return p;
}
