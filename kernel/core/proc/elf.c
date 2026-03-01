/**
 * kernel/core/proc/elf.c - ELF Binary Loader
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/elf.h>
#include <kairos/mm.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

static int elf_check_ehdr(const Elf64_Ehdr *ehdr, size_t size) {
    if (size < sizeof(Elf64_Ehdr)) {
        pr_err("ELF: too small header\n");
        return -ENOEXEC;
    }
    if (ehdr->e_ident[EI_MAG0] != 0x7f || ehdr->e_ident[EI_MAG1] != 'E' ||
        ehdr->e_ident[EI_MAG2] != 'L' || ehdr->e_ident[EI_MAG3] != 'F') {
        pr_err("ELF: bad magic\n");
        return -ENOEXEC;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        pr_err("ELF: unsupported class\n");
        return -ENOEXEC;
    }
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        pr_err("ELF: unsupported endianness\n");
        return -ENOEXEC;
    }
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        pr_err("ELF: unsupported type %u\n", ehdr->e_type);
        return -ENOEXEC;
    }
#if defined(ARCH_riscv64)
    if (ehdr->e_machine != EM_RISCV) {
        pr_err("ELF: unsupported machine %u\n", ehdr->e_machine);
        return -ENOEXEC;
    }
#elif defined(ARCH_x86_64)
    if (ehdr->e_machine != EM_X86_64) {
        pr_err("ELF: unsupported machine %u\n", ehdr->e_machine);
        return -ENOEXEC;
    }
#elif defined(ARCH_aarch64)
    if (ehdr->e_machine != EM_AARCH64) {
        pr_err("ELF: unsupported machine %u\n", ehdr->e_machine);
        return -ENOEXEC;
    }
#else
    pr_err("ELF: unsupported architecture\n");
    return -ENOEXEC;
#endif
    if (ehdr->e_ehsize != sizeof(Elf64_Ehdr)) {
        pr_err("ELF: unexpected ehdr size\n");
        return -ENOEXEC;
    }
    if (ehdr->e_phnum == 0 || ehdr->e_phoff == 0) {
        pr_err("ELF: missing program headers\n");
        return -ENOEXEC;
    }

    if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
        pr_err("ELF: unexpected program header size\n");
        return -ENOEXEC;
    }

    if (ehdr->e_phnum > (SIZE_MAX - ehdr->e_phoff) / ehdr->e_phentsize) {
        pr_err("ELF: program header size overflow\n");
        return -ENOEXEC;
    }
    size_t ph_end = ehdr->e_phoff +
                    (size_t)ehdr->e_phnum * ehdr->e_phentsize;
    if (ph_end > size) {
        pr_err("ELF: program header table out of range\n");
        return -ENOEXEC;
    }

    return 0;
}

static int elf_check_phdr(const Elf64_Phdr *ph, size_t size,
                          bool check_align) {
    if (ph->p_type != PT_LOAD) {
        return 0;
    }
    if (ph->p_memsz < ph->p_filesz) {
        pr_err("ELF: segment filesz > memsz\n");
        return -ENOEXEC;
    }
    if (ph->p_offset + ph->p_filesz > size) {
        pr_err("ELF: segment outside file\n");
        return -ENOEXEC;
    }
    if (check_align &&
        ((ph->p_offset & (CONFIG_PAGE_SIZE - 1)) !=
         (ph->p_vaddr & (CONFIG_PAGE_SIZE - 1)))) {
        pr_err("ELF: segment alignment mismatch\n");
        return -ENOEXEC;
    }

    vaddr_t seg_start = ph->p_vaddr;
    vaddr_t seg_end = seg_start + ph->p_memsz;
    if (seg_end < seg_start ||
        seg_start < USER_SPACE_START ||
        seg_end > USER_SPACE_END + 1) {
        pr_err("ELF: segment outside user space\n");
        return -ENOEXEC;
    }

    return 0;
}

/**
 * elf_load - Load an ELF binary into a process address space
 */
int elf_load(struct mm_struct *mm, const void *elf, size_t size,
             vaddr_t *entry_out, struct elf_auxv_info *aux_out) {
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf;
    int ret;
    vaddr_t base = 0;
    vaddr_t phdr_addr = 0;
    bool base_set = false;
    bool entry_in_load = false;
    bool entry_exec_ok = false;

    ret = elf_check_ehdr(ehdr, size);
    if (ret < 0) {
        return ret;
    }

    const uint8_t *elf_bytes = (const uint8_t *)elf;
    const Elf64_Phdr *phdr = (const Elf64_Phdr *)(elf_bytes + ehdr->e_phoff);

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && !base_set) {
            base = phdr[i].p_vaddr - phdr[i].p_offset;
            base_set = true;
        }
        if (phdr[i].p_type == PT_PHDR) {
            phdr_addr = phdr[i].p_vaddr;
        }
        ret = elf_check_phdr(&phdr[i], size, false);
        if (ret < 0) {
            return ret;
        }
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }

        vaddr_t seg_start = phdr[i].p_vaddr;
        vaddr_t seg_end = seg_start + phdr[i].p_memsz;
        if (ehdr->e_entry >= seg_start && ehdr->e_entry < seg_end) {
            entry_in_load = true;
            if (phdr[i].p_flags & PF_X)
                entry_exec_ok = true;
        }
        vaddr_t page_start = ALIGN_DOWN(seg_start, CONFIG_PAGE_SIZE);
        vaddr_t page_end = ALIGN_UP(seg_end, CONFIG_PAGE_SIZE);

        uint64_t flags = PTE_USER;
        uint32_t vma_flags = 0;
        if (phdr[i].p_flags & PF_R) flags |= PTE_READ;
        if (phdr[i].p_flags & PF_R) vma_flags |= VM_READ;
        if (phdr[i].p_flags & PF_W) {
            flags |= PTE_WRITE;
            vma_flags |= VM_WRITE;
        }
        if (phdr[i].p_flags & PF_X) {
            flags |= PTE_EXEC;
            vma_flags |= VM_EXEC;
        }

        ret = mm_add_vma(mm, page_start, page_end, vma_flags, NULL, 0);
        if (ret < 0) {
            return ret;
        }

        for (vaddr_t va = page_start; va < page_end; va += CONFIG_PAGE_SIZE) {
            paddr_t pa = arch_mmu_translate(mm->pgdir, va);
            bool new_page = false;
            if (pa) {
                pa = ALIGN_DOWN(pa, CONFIG_PAGE_SIZE);
            } else {
                pa = pmm_alloc_page();
                if (!pa) return -ENOMEM;
                memset(phys_to_virt(pa), 0, CONFIG_PAGE_SIZE);
                new_page = true;
            }

            vaddr_t file_data_end = seg_start + phdr[i].p_filesz;
            vaddr_t copy_start = (va < seg_start) ? seg_start : va;
            vaddr_t copy_end = (va + CONFIG_PAGE_SIZE < file_data_end) ? va + CONFIG_PAGE_SIZE : file_data_end;

            if (copy_start < copy_end) {
                size_t page_off = copy_start - va;
                size_t file_off = phdr[i].p_offset + (copy_start - seg_start);
                size_t copy_len = copy_end - copy_start;
                memcpy((uint8_t *)phys_to_virt(pa) + page_off, elf_bytes + file_off, copy_len);
            }

            if ((ret = arch_mmu_map_merge(mm->pgdir, va, pa, flags)) < 0) {
                if (new_page) pmm_free_page(pa);
                return ret;
            }
        }
    }

    if (!entry_in_load) {
        pr_err("ELF: entry outside load segments\n");
        return -ENOEXEC;
    }
    if (!entry_exec_ok) {
        pr_err("ELF: entry not in executable segment\n");
        return -EACCES;
    }

    *entry_out = ehdr->e_entry;
    if (aux_out) {
        aux_out->phent = ehdr->e_phentsize;
        aux_out->phnum = ehdr->e_phnum;
        aux_out->entry = ehdr->e_entry;
        if (!phdr_addr && base_set)
            phdr_addr = base + ehdr->e_phoff;
        aux_out->phdr = phdr_addr;
    }
    return 0;
}

static int vnode_read_exact(struct vnode *vn, void *buf, size_t len,
                            off_t offset) {
    if (!vn || !vn->ops || !vn->ops->read) {
        pr_err("ELF: vnode read unsupported\n");
        return -EINVAL;
    }
    ssize_t rd = vn->ops->read(vn, buf, len, offset, 0);
    if (rd < 0) {
        pr_err("ELF: vnode read failed (off=%ld)\n", (long)offset);
        return (int)rd;
    }
    if ((size_t)rd != len) {
        pr_err("ELF: vnode short read (off=%ld)\n", (long)offset);
        return -EIO;
    }
    return 0;
}

static int elf_load_vnode_internal(struct mm_struct *mm, struct vnode *vn,
                                   size_t size, vaddr_t load_bias,
                                   vaddr_t *entry_out,
                                   struct elf_auxv_info *aux_out) {
    Elf64_Ehdr ehdr;
    int ret;
    vaddr_t base = 0;
    vaddr_t phdr_addr = 0;
    bool base_set = false;
    bool entry_in_load = false;
    bool entry_exec_ok = false;

    if (!mm || !vn || !entry_out) {
        return -EINVAL;
    }
    if (size < sizeof(Elf64_Ehdr)) {
        pr_err("ELF: invalid or too small header\n");
        return -ENOEXEC;
    }
    ret = vnode_read_exact(vn, &ehdr, sizeof(ehdr), 0);
    if (ret < 0) {
        return ret;
    }
    ret = elf_check_ehdr(&ehdr, size);
    if (ret < 0) {
        return ret;
    }
    size_t ph_size = (size_t)ehdr.e_phnum * ehdr.e_phentsize;

    Elf64_Phdr *phdrs = kmalloc(ph_size);
    if (!phdrs) {
        return -ENOMEM;
    }
    ret = vnode_read_exact(vn, phdrs, ph_size, (off_t)ehdr.e_phoff);
    if (ret < 0) {
        kfree(phdrs);
        return ret;
    }

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        const Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type == PT_LOAD && !base_set) {
            base = (load_bias + ph->p_vaddr) - ph->p_offset;
            base_set = true;
        }
        if (ph->p_type == PT_PHDR) {
            phdr_addr = load_bias + ph->p_vaddr;
        }
        ret = elf_check_phdr(ph, size, true);
        if (ret < 0) {
            kfree(phdrs);
            return ret;
        }
        if (ph->p_type != PT_LOAD) {
            continue;
        }

        vaddr_t seg_start = load_bias + ph->p_vaddr;
        vaddr_t seg_end = seg_start + ph->p_memsz;
        if (seg_end < seg_start || seg_start < USER_SPACE_START ||
            seg_end > USER_SPACE_END + 1) {
            kfree(phdrs);
            return -ENOEXEC;
        }

        vaddr_t entry = load_bias + ehdr.e_entry;
        if (entry >= seg_start && entry < seg_end) {
            entry_in_load = true;
            if (ph->p_flags & PF_X)
                entry_exec_ok = true;
        }
        vaddr_t page_start = ALIGN_DOWN(seg_start, CONFIG_PAGE_SIZE);
        vaddr_t page_end = ALIGN_UP(seg_end, CONFIG_PAGE_SIZE);
        off_t file_off = (off_t)ALIGN_DOWN(ph->p_offset, CONFIG_PAGE_SIZE);

        uint32_t vma_flags = 0;
        if (ph->p_flags & PF_R) {
            vma_flags |= VM_READ;
        }
        if (ph->p_flags & PF_W) {
            vma_flags |= VM_WRITE;
        }
        if (ph->p_flags & PF_X) {
            vma_flags |= VM_EXEC;
        }

        vaddr_t file_end = seg_start + ph->p_filesz;
        if (file_end > page_end) {
            file_end = page_end;
        }
        ret = mm_add_vma_file(mm, page_start, page_end, vma_flags, vn,
                              file_off, seg_start, file_end);
        if (ret < 0) {
            kfree(phdrs);
            return ret;
        }
    }

    if (!entry_in_load) {
        pr_err("ELF: entry outside load segments\n");
        kfree(phdrs);
        return -ENOEXEC;
    }
    if (!entry_exec_ok) {
        pr_err("ELF: entry not in executable segment\n");
        kfree(phdrs);
        return -EACCES;
    }

    *entry_out = load_bias + ehdr.e_entry;
    if (aux_out) {
        aux_out->phent = ehdr.e_phentsize;
        aux_out->phnum = ehdr.e_phnum;
        aux_out->entry = load_bias + ehdr.e_entry;
        if (!phdr_addr && base_set)
            phdr_addr = base + ehdr.e_phoff;
        aux_out->phdr = phdr_addr;
        aux_out->base = base_set ? base : load_bias;
    }

    kfree(phdrs);
    return 0;
}

int elf_load_vnode(struct mm_struct *mm, struct vnode *vn, size_t size,
                   vaddr_t *entry_out, struct elf_auxv_info *aux_out) {
    return elf_load_vnode_internal(mm, vn, size, 0, entry_out, aux_out);
}

int elf_load_vnode_bias(struct mm_struct *mm, struct vnode *vn, size_t size,
                        vaddr_t load_bias, vaddr_t *entry_out,
                        struct elf_auxv_info *aux_out) {
    return elf_load_vnode_internal(mm, vn, size, load_bias, entry_out, aux_out);
}

int elf_read_interp_vnode(struct vnode *vn, size_t size, char *out,
                          size_t out_sz) {
    if (!vn || !out || out_sz == 0)
        return -EINVAL;
    if (size < sizeof(Elf64_Ehdr))
        return -ENOEXEC;

    Elf64_Ehdr ehdr;
    int ret = vnode_read_exact(vn, &ehdr, sizeof(ehdr), 0);
    if (ret < 0)
        return ret;
    ret = elf_check_ehdr(&ehdr, size);
    if (ret < 0)
        return ret;

    size_t ph_size = (size_t)ehdr.e_phnum * ehdr.e_phentsize;
    Elf64_Phdr *phdrs = kmalloc(ph_size);
    if (!phdrs)
        return -ENOMEM;

    ret = vnode_read_exact(vn, phdrs, ph_size, (off_t)ehdr.e_phoff);
    if (ret < 0) {
        kfree(phdrs);
        return ret;
    }

    ret = -ENOENT;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_INTERP)
            continue;
        if (ph->p_filesz == 0 || ph->p_filesz > size ||
            ph->p_offset + ph->p_filesz > size) {
            ret = -ENOEXEC;
            break;
        }
        if (ph->p_filesz > out_sz) {
            ret = -ENAMETOOLONG;
            break;
        }
        ret = vnode_read_exact(vn, out, (size_t)ph->p_filesz,
                               (off_t)ph->p_offset);
        if (ret < 0)
            break;
        out[out_sz - 1] = '\0';
        if (!memchr(out, '\0', (size_t)ph->p_filesz))
            out[(size_t)ph->p_filesz - 1] = '\0';
        ret = 0;
        break;
    }
    kfree(phdrs);
    return ret;
}

#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_BASE 7
#define AT_PAGESZ 6
#define AT_ENTRY 9
#define AT_UID 11
#define AT_EUID 12
#define AT_GID 13
#define AT_EGID 14
#define AT_RANDOM 25

struct auxv_entry {
    uint64_t a_type;
    uint64_t a_val;
};

static int stack_reserve(vaddr_t *sp, vaddr_t floor, size_t len) {
    if (!sp)
        return -EINVAL;
    if (*sp < floor)
        return -EFAULT;
    if ((vaddr_t)len > (*sp - floor))
        return -E2BIG;
    *sp -= len;
    return 0;
}

static int stack_write(struct mm_struct *mm, vaddr_t dst, const void *src,
                       size_t len) {
    size_t off = 0;
    while (off < len) {
        vaddr_t va = dst + off;
        vaddr_t page_va = ALIGN_DOWN(va, CONFIG_PAGE_SIZE);
        paddr_t pa = arch_mmu_translate(mm->pgdir, page_va);
        if (!pa) {
            int fret = mm_handle_fault(mm, va, PTE_WRITE);
            if (fret < 0)
                return fret;
            pa = arch_mmu_translate(mm->pgdir, page_va);
            if (!pa)
                return -EFAULT;
        }
        size_t chunk = MIN(len - off, CONFIG_PAGE_SIZE - (va % CONFIG_PAGE_SIZE));
        memcpy((uint8_t *)phys_to_virt(pa) + (va % CONFIG_PAGE_SIZE),
               (const uint8_t *)src + off, chunk);
        off += chunk;
    }
    return 0;
}

/**
 * elf_setup_stack - Set up user stack with arguments (argc, argv)
 */
int elf_setup_stack(struct mm_struct *mm, char *const argv[],
                    char *const envp[], vaddr_t *sp_out,
                    const struct elf_auxv_info *aux) {
    if (USER_STACK_SIZE <= CONFIG_PAGE_SIZE)
        return -EINVAL;

    vaddr_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    vaddr_t stack_floor = stack_bottom + CONFIG_PAGE_SIZE;
    vaddr_t stack_initial = USER_STACK_TOP - CONFIG_PAGE_SIZE;
    int ret;

    ret = mm_add_vma(mm, stack_initial, USER_STACK_TOP,
                     VM_READ | VM_WRITE | VM_STACK, NULL, 0);
    if (ret < 0) {
        return ret;
    }

    /* Map only the top page. Lower pages are faulted in on demand. */
    paddr_t pa = pmm_alloc_page();
    if (!pa)
        return -ENOMEM;
    memset(phys_to_virt(pa), 0, CONFIG_PAGE_SIZE);
    ret = arch_mmu_map(mm->pgdir, stack_initial, pa, PTE_USER | PTE_READ | PTE_WRITE);
    if (ret < 0) {
        pmm_free_page(pa);
        return ret;
    }

    /* 2. Push arguments to stack */
    vaddr_t sp = USER_STACK_TOP;
    int argc = 0;
    if (argv) {
        while (argv[argc]) argc++;
    }

    int envc = 0;
    if (envp) {
        while (envp[envc]) envc++;
    }

    vaddr_t u_argv[argc + 1];
    vaddr_t u_envp[envc + 1];
    
    /* Push strings first */
    for (int i = argc - 1; i >= 0; i--) {
        size_t len = strlen(argv[i]) + 1;
        ret = stack_reserve(&sp, stack_floor, len);
        if (ret < 0)
            return ret;
        
        ret = stack_write(mm, sp, argv[i], len);
        if (ret < 0)
            return ret;
        u_argv[i] = sp;
    }
    u_argv[argc] = 0;

    for (int i = envc - 1; i >= 0; i--) {
        size_t len = strlen(envp[i]) + 1;
        ret = stack_reserve(&sp, stack_floor, len);
        if (ret < 0)
            return ret;
        ret = stack_write(mm, sp, envp[i], len);
        if (ret < 0)
            return ret;
        u_envp[i] = sp;
    }
    u_envp[envc] = 0;

    /* Align SP to 16 bytes */
    sp = ALIGN_DOWN(sp, 16);
    if (sp < stack_floor)
        return -E2BIG;

    /* random bytes for AT_RANDOM */
    uint8_t rand_bytes[16] = {0};
    ret = stack_reserve(&sp, stack_floor, sizeof(rand_bytes));
    if (ret < 0)
        return ret;
    ret = stack_write(mm, sp, rand_bytes, sizeof(rand_bytes));
    if (ret < 0)
        return ret;
    vaddr_t rand_addr = sp;

    struct auxv_entry auxv[14];
    int auxc = 0;
    if (aux && aux->phdr) {
        auxv[auxc++] = (struct auxv_entry){AT_PHDR, aux->phdr};
        auxv[auxc++] = (struct auxv_entry){AT_PHENT, aux->phent};
        auxv[auxc++] = (struct auxv_entry){AT_PHNUM, aux->phnum};
        auxv[auxc++] = (struct auxv_entry){AT_ENTRY, aux->entry};
    }
    if (aux && aux->base) {
        auxv[auxc++] = (struct auxv_entry){AT_BASE, aux->base};
    }
    auxv[auxc++] = (struct auxv_entry){AT_PAGESZ, CONFIG_PAGE_SIZE};
    struct process *cur = proc_current();
    uint64_t uid = cur ? cur->uid : 0;
    uint64_t gid = cur ? cur->gid : 0;
    auxv[auxc++] = (struct auxv_entry){AT_UID, uid};
    auxv[auxc++] = (struct auxv_entry){AT_EUID, uid};
    auxv[auxc++] = (struct auxv_entry){AT_GID, gid};
    auxv[auxc++] = (struct auxv_entry){AT_EGID, gid};
    auxv[auxc++] = (struct auxv_entry){AT_RANDOM, rand_addr};
    auxv[auxc++] = (struct auxv_entry){AT_NULL, 0};

    size_t argv_sz = (argc + 1) * sizeof(vaddr_t);
    size_t env_sz = (envc + 1) * sizeof(vaddr_t);
    size_t aux_sz = (size_t)auxc * sizeof(struct auxv_entry);
    size_t ptr_bytes = sizeof(vaddr_t) + argv_sz + env_sz + aux_sz;
    ret = stack_reserve(&sp, stack_floor, ptr_bytes);
    if (ret < 0)
        return ret;
    sp = ALIGN_DOWN(sp, 16);
    if (sp < stack_floor)
        return -E2BIG;

    vaddr_t p = sp;
    uint64_t argc64 = (uint64_t)argc;
    ret = stack_write(mm, p, &argc64, sizeof(argc64));
    if (ret < 0)
        return ret;
    p += sizeof(vaddr_t);
    ret = stack_write(mm, p, u_argv, argv_sz);
    if (ret < 0)
        return ret;
    p += argv_sz;
    ret = stack_write(mm, p, u_envp, env_sz);
    if (ret < 0)
        return ret;
    p += env_sz;
    ret = stack_write(mm, p, auxv, aux_sz);
    if (ret < 0)
        return ret;

    /* Final alignment */
    sp = ALIGN_DOWN(sp, 16);
    if (sp < stack_floor)
        return -E2BIG;

    mm->start_stack = stack_floor;
    *sp_out = sp;
    return 0;
}

/**
 * proc_create - Create a process from an ELF binary
 */
struct process *proc_create(const char *name, const void *elf, size_t size) {
    struct process *p = proc_alloc_internal();
    vaddr_t entry, sp;

    if (!p) return NULL;

    strncpy(p->name, name, sizeof(p->name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';

    if (!(p->mm = mm_create())) {
        proc_free_internal(p);
        return NULL;
    }

    struct elf_auxv_info aux;
    if (elf_load(p->mm, elf, size, &entry, &aux) < 0 ||
        elf_setup_stack(p->mm, NULL, NULL, &sp, &aux) < 0) {
        mm_destroy(p->mm);
        proc_free_internal(p);
        return NULL;
    }

    arch_context_init(p->context, entry, sp, false);
    proc_setup_stdio(p);

    pr_info("proc_create: created '%s' (pid %d) entry=%p sp=%p\n", p->name,
            p->pid, (void *)entry, (void *)sp);

    return p;
}
