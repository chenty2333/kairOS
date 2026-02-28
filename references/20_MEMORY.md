# 20 — Memory Management

## Initialization Sequence

init_mm() (core/init/mm.c) calls in order:
1. pmm_init_from_memmap() — initialize physical memory from boot_info memory map
2. kmalloc_init() — initialize kernel heap allocator
3. arch_mmu_init() — architecture-specific MMU initialization
4. vmm_init() — virtual memory manager initialization (currently empty)

## Physical Memory: Buddy Allocator (core/mm/buddy.c)

- Classic buddy system, MAX_ORDER=11 (max allocation 2^10 = 4MB contiguous pages)
- Global free_lists[] + buddy_lock manage free pages
- page struct array (page_array) tracks each physical page frame's state (flags, order, refcount)
- Reference counting: pmm_get_page() / pmm_put_page() / pmm_page_refcount(), used for COW and shared page scenarios

Per-CPU page cache (PCP):
- Each CPU maintains a local free page list (pcp_areas[]) to reduce global lock contention
- Three modes (CONFIG_PMM_PCP_MODE): 0=disabled, 1=debug mode (with integrity checks), 2=normal mode
- Batch operations: PCP_BATCH=16 pages refilled/returned from buddy at a time
- Cross-CPU frees go through remote_free_queues[] to avoid directly touching another CPU's PCP

Initialization: pmm_init_from_memmap() parses memory regions from boot_info, reserves pages occupied by kernel image and page_array, adds remaining pages to buddy by contiguous zones.

Runtime reservations:
- pmm_reserve_range() flushes PCP/remote-free queues and removes free pages from buddy before marking them PG_RESERVED.
- Reserved pages are not returned to PCP/buddy on free, so reserved ranges stay non-allocatable.

## Kernel Heap: SLUB-like Allocator (core/mm/kmalloc.c)

- 9 size classes: 32, 64, 96, 128, 192, 256, 512, 1024, 2048 bytes
- One kmem_cache per size class, internally maintains a freelist chain
- Per-CPU cache: each cache per CPU maintains a local object array (up to KMALLOC_LIMIT=32), batch refill KMALLOC_BATCH=16
- Allocations over 2048 bytes go directly through buddy (alloc_pages)
- Bootstrap phase uses a static buffer (64KB) to avoid recursive dependency
- kfree() checks page's PG_SLAB flag to distinguish slab objects from large page allocations
- kmalloc_aligned() / kfree_aligned() provide aligned allocations (power-of-two alignment).
- Fault injection hook exists in `kmalloc()` (`fault_inject_should_fail(FAULT_INJECT_POINT_KMALLOC)`), gated by `CONFIG_KERNEL_FAULT_INJECT`; even when enabled it still requires explicit test scope enablement.

## MMU and Page Tables

- Architecture-independent PTE flags defined in mm.h: PTE_VALID, PTE_READ, PTE_WRITE, PTE_EXEC, PTE_USER, PTE_COW, PTE_DEVICE, etc.
- Each architecture's flags_to_pte() translates HAL flags to hardware PTE bits
- arch_mmu_get_pte()/arch_mmu_set_pte() use a generic core encoding:
  - low 10 bits are HAL PTE_* flags
  - upper bits store physical page number ((pa >> PAGE_SHIFT) << 10)
- Common page table walk logic in arch/common/mmu_common.c: mmu_walk_pgtable() supports multi-level page table creation and lookup
- x86_64 map path uses an arch-local walker that propagates `PTE_U` to all parent levels when mapping user pages, so user leaf mappings remain executable/readable from CPL3 after lazy page-table allocation
- Each architecture implements arch_mmu_map/unmap/translate/flush_tlb interfaces
- arch_mmu_destroy_table(): recursively frees user page table pages (x86_64: lower 256 PML4 slots only)
- ioremap() uses HHDM; iounmap() is a no-op (no vmalloc VA allocator)

## User Address Space (core/mm/vmm.c + vma.c)

Address space layout:
- USER_SPACE_START: 0x0
- USER_HEAP_START: 0x1000000 (16MB)
- USER_STACK_TOP: 0x3FF0000000
- USER_STACK_SIZE: `CONFIG_USER_STACK_SIZE` (default 8MB)
- User stack guard: lowest stack page is intentionally left unmapped (guard page)
- USER_SPACE_END: 0x3FFFFFFFFF

mm_struct manages each process's address space:
- pgdir: page table root physical address
- vma_list + mm_rb: VMA dual index (linked list + red-black tree)
- brk: heap top
- start_stack: lowest valid stack VA (just above guard page), used as heap/mmap upper bound
- refcount: reference count (atomic), supports sharing (CLONE_VM)

VMA management (vma.c):
- mm_add_vma() / mm_add_vma_file(): add anonymous/file-mapped VMAs; anonymous VMAs support automatic merging
- mm_mmap() / mm_munmap() / mm_mremap() / mm_mprotect(): standard mmap family interfaces
- Linux syscall ABI compatibility: `mmap`/`mprotect` decode `prot` as 32-bit `int`, `mmap`/`mremap` decode `flags` as 32-bit `int`, and file-backed `mmap` decodes `fd` as Linux ABI `int` (32-bit)
- mm_find_vma(): red-black tree lookup
- mm_brk(): heap management, checks for conflicts with other VMAs

COW (Copy-on-Write):
- mm_clone() marks writable non-shared pages as PTE_COW when copying address spaces, shares physical pages and increments refcount
- mm_handle_fault() handles copy-on-write: if refcount==1, directly changes permissions; otherwise allocates new page and copies
- File-mapped page faults: reads content from vnode into newly allocated page
- Stack faults: `VM_STACK` mappings now grow down on demand in the fault path; ELF stack setup maps only the top page initially and relies on demand paging for deeper stack pages.

Related references:
- references/00_REPO_MAP.md
- references/10_BOOT_FIRMWARE.md
- references/30_PROCESS.md
