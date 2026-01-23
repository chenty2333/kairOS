/**
 * kairos/elf.h - ELF binary format definitions
 *
 * Supports ELF64 for RISC-V 64-bit.
 */

#ifndef _KAIROS_ELF_H
#define _KAIROS_ELF_H

#include <kairos/types.h>

/* ELF magic number */
#define ELF_MAGIC       0x464c457f      /* "\x7fELF" */

/* ELF identification indices */
#define EI_MAG0         0               /* Magic number byte 0 */
#define EI_MAG1         1               /* Magic number byte 1 */
#define EI_MAG2         2               /* Magic number byte 2 */
#define EI_MAG3         3               /* Magic number byte 3 */
#define EI_CLASS        4               /* File class */
#define EI_DATA         5               /* Data encoding */
#define EI_VERSION      6               /* File version */
#define EI_OSABI        7               /* OS/ABI identification */
#define EI_ABIVERSION   8               /* ABI version */
#define EI_PAD          9               /* Start of padding bytes */
#define EI_NIDENT       16              /* Size of e_ident[] */

/* ELF class (32 or 64 bit) */
#define ELFCLASSNONE    0               /* Invalid class */
#define ELFCLASS32      1               /* 32-bit objects */
#define ELFCLASS64      2               /* 64-bit objects */

/* ELF data encoding */
#define ELFDATANONE     0               /* Invalid encoding */
#define ELFDATA2LSB     1               /* Little-endian */
#define ELFDATA2MSB     2               /* Big-endian */

/* ELF file type */
#define ET_NONE         0               /* No file type */
#define ET_REL          1               /* Relocatable file */
#define ET_EXEC         2               /* Executable file */
#define ET_DYN          3               /* Shared object file */
#define ET_CORE         4               /* Core file */

/* Machine types */
#define EM_RISCV        243             /* RISC-V */

/* Program header types */
#define PT_NULL         0               /* Unused entry */
#define PT_LOAD         1               /* Loadable segment */
#define PT_DYNAMIC      2               /* Dynamic linking info */
#define PT_INTERP       3               /* Interpreter path */
#define PT_NOTE         4               /* Auxiliary information */
#define PT_SHLIB        5               /* Reserved */
#define PT_PHDR         6               /* Program header table */
#define PT_TLS          7               /* Thread-local storage */

/* Program header flags */
#define PF_X            (1 << 0)        /* Executable */
#define PF_W            (1 << 1)        /* Writable */
#define PF_R            (1 << 2)        /* Readable */

/**
 * ELF64 file header
 */
typedef struct {
    uint8_t     e_ident[EI_NIDENT];     /* ELF identification */
    uint16_t    e_type;                 /* Object file type */
    uint16_t    e_machine;              /* Machine type */
    uint32_t    e_version;              /* Object file version */
    uint64_t    e_entry;                /* Entry point virtual address */
    uint64_t    e_phoff;                /* Program header table offset */
    uint64_t    e_shoff;                /* Section header table offset */
    uint32_t    e_flags;                /* Processor-specific flags */
    uint16_t    e_ehsize;               /* ELF header size */
    uint16_t    e_phentsize;            /* Program header entry size */
    uint16_t    e_phnum;                /* Number of program headers */
    uint16_t    e_shentsize;            /* Section header entry size */
    uint16_t    e_shnum;                /* Number of section headers */
    uint16_t    e_shstrndx;             /* Section name string table index */
} Elf64_Ehdr;

/**
 * ELF64 program header
 */
typedef struct {
    uint32_t    p_type;                 /* Segment type */
    uint32_t    p_flags;                /* Segment flags */
    uint64_t    p_offset;               /* Segment offset in file */
    uint64_t    p_vaddr;                /* Virtual address in memory */
    uint64_t    p_paddr;                /* Physical address (unused) */
    uint64_t    p_filesz;               /* Size in file */
    uint64_t    p_memsz;                /* Size in memory */
    uint64_t    p_align;                /* Segment alignment */
} Elf64_Phdr;

/**
 * ELF64 section header
 */
typedef struct {
    uint32_t    sh_name;                /* Section name (string table index) */
    uint32_t    sh_type;                /* Section type */
    uint64_t    sh_flags;               /* Section flags */
    uint64_t    sh_addr;                /* Virtual address */
    uint64_t    sh_offset;              /* File offset */
    uint64_t    sh_size;                /* Section size */
    uint32_t    sh_link;                /* Link to another section */
    uint32_t    sh_info;                /* Additional section info */
    uint64_t    sh_addralign;           /* Address alignment */
    uint64_t    sh_entsize;             /* Entry size if table */
} Elf64_Shdr;

/**
 * Validate ELF header
 *
 * @ehdr: ELF header to validate
 *
 * Returns 0 if valid, negative error code otherwise.
 */
static inline int elf_validate(const Elf64_Ehdr *ehdr)
{
    /* Check magic number */
    if (ehdr->e_ident[EI_MAG0] != 0x7f ||
        ehdr->e_ident[EI_MAG1] != 'E' ||
        ehdr->e_ident[EI_MAG2] != 'L' ||
        ehdr->e_ident[EI_MAG3] != 'F') {
        return -ENOEXEC;
    }

    /* Check class (64-bit) */
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        return -ENOEXEC;
    }

    /* Check endianness (little-endian for RISC-V) */
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        return -ENOEXEC;
    }

    /* Check file type (executable) */
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        return -ENOEXEC;
    }

    /* Check machine type (RISC-V) */
    if (ehdr->e_machine != EM_RISCV) {
        return -ENOEXEC;
    }

    /* Check program header presence */
    if (ehdr->e_phnum == 0 || ehdr->e_phoff == 0) {
        return -ENOEXEC;
    }

    return 0;
}

#endif /* _KAIROS_ELF_H */
