# Kairos Coding Style Guide

This document defines the coding conventions for the Kairos kernel.
Consistency makes code easier to read and maintain.

---

## General Principles

1. **Clarity over cleverness** - Write code that's easy to understand
2. **Explicit over implicit** - Be obvious about what's happening
3. **Minimal comments** - Good code is self-documenting; comments explain *why*, not *what*
4. **No magic numbers** - Use named constants

---

## Formatting

### Indentation
- Use **4 spaces** (no tabs)
- Exception: Makefile uses tabs (required)

### Line Length
- Soft limit: **80 characters**
- Hard limit: **100 characters**
- Prefer breaking long lines for readability

### Braces
- Opening brace on same line as statement (K&R style)
- Always use braces, even for single statements

```c
/* Good */
if (condition) {
    do_something();
}

/* Bad */
if (condition)
    do_something();  /* No braces */

/* Bad */
if (condition)
{                    /* Brace on new line */
    do_something();
}
```

### Spaces
- Space after keywords: `if (`, `for (`, `while (`
- No space after function names: `func(arg)`
- Space around binary operators: `a + b`, `x = y`
- No space for unary operators: `!flag`, `*ptr`, `&var`
- Space after commas: `func(a, b, c)`

```c
/* Good */
if (x > 0) {
    result = calculate(a, b);
}

/* Bad */
if(x>0){
    result=calculate(a,b);
}
```

### Blank Lines
- One blank line between functions
- One blank line to separate logical sections within a function
- No multiple consecutive blank lines

---

## Naming Conventions

### Variables
- Use `snake_case`
- Be descriptive but concise
- Loop variables can be short (`i`, `j`, `n`)

```c
int page_count;
struct process *current_proc;
size_t buffer_size;

for (int i = 0; i < n; i++) {
    /* ... */
}
```

### Functions
- Use `snake_case`
- Prefix with module name for public functions
- Use verbs: `get_`, `set_`, `init_`, `create_`, `destroy_`

```c
/* Public API - prefixed */
void sched_init(void);
struct process *proc_create(const char *name);
int vfs_open(const char *path, int flags);

/* Static (file-local) - no prefix needed */
static void update_vruntime(struct process *p);
```

### Types
- Use `snake_case` for struct/union/enum names
- Use `_t` suffix for typedefs

```c
struct process {
    /* ... */
};

typedef uint64_t paddr_t;

enum proc_state {
    PROC_UNUSED,
    PROC_RUNNABLE,
    /* ... */
};
```

### Constants and Macros
- Use `UPPER_SNAKE_CASE`

```c
#define MAX_PROCESSES   256
#define PAGE_SIZE       4096
#define KERNEL_STACK_SIZE (8 * 1024)

enum {
    EPERM = 1,
    ENOENT = 2,
};
```

### Files
- Use `snake_case.c` and `snake_case.h`
- Header guards: `_KAIROS_FILENAME_H`

```c
/* process.h */
#ifndef _KAIROS_PROCESS_H
#define _KAIROS_PROCESS_H

/* ... */

#endif /* _KAIROS_PROCESS_H */
```

---

## Code Organization

### Header Files
- Include guards at top
- Minimal includes (forward declare when possible)
- Group: system headers, then kairos headers

```c
#ifndef _KAIROS_SCHED_H
#define _KAIROS_SCHED_H

#include <kairos/types.h>
#include <kairos/list.h>

/* Forward declarations */
struct process;

/* Type definitions */
struct cfs_rq {
    /* ... */
};

/* Function declarations */
void sched_init(void);
void schedule(void);

#endif /* _KAIROS_SCHED_H */
```

### Source Files
- Include own header first
- Then system headers
- Then kairos headers
- Then static declarations
- Then implementations

```c
/* sched.c */
#include <kairos/sched.h>     /* Own header first */

#include <kairos/types.h>
#include <kairos/process.h>
#include <kairos/printk.h>

/* Static (private) data */
static struct cfs_rq cpu_rq[MAX_CPUS];

/* Static (private) functions */
static void update_vruntime(struct process *p)
{
    /* ... */
}

/* Public functions */
void sched_init(void)
{
    /* ... */
}
```

---

## Comments

### When to Comment
- Explain **why**, not **what**
- Document non-obvious behavior
- Explain complex algorithms
- Note workarounds or hacks

### Function Documentation
- Brief description for public functions
- Document parameters and return values for complex functions

```c
/**
 * Find the next process to run.
 *
 * Returns the process with the smallest vruntime in the current
 * CPU's run queue, or the idle process if the queue is empty.
 */
struct process *pick_next_task(void)
{
    /* ... */
}
```

### Inline Comments
```c
/* Good: explains why */
x = x & ~0x3;  /* Align down to 4-byte boundary */

/* Bad: explains what (obvious from code) */
x = x + 1;  /* Add 1 to x */
```

### TODO Comments
- Use `TODO:` for future improvements
- Use `FIXME:` for known bugs
- Use `HACK:` for temporary workarounds

```c
/* TODO: implement proper load balancing */
/* FIXME: this can race with interrupt handler */
/* HACK: work around hardware bug on specific board */
```

---

## Error Handling

### Return Values
- Return 0 on success, negative errno on failure
- Use `-ENOENT`, `-ENOMEM`, etc.

```c
int vfs_open(const char *path, int flags)
{
    struct vnode *vn = lookup(path);
    if (!vn) {
        return -ENOENT;
    }

    /* ... */
    return 0;
}
```

### Error Checking
- Check errors immediately
- Use early returns to reduce nesting

```c
/* Good: early return */
int do_something(struct foo *f)
{
    if (!f) {
        return -EINVAL;
    }

    int err = step_one(f);
    if (err) {
        return err;
    }

    err = step_two(f);
    if (err) {
        return err;
    }

    return 0;
}

/* Bad: deep nesting */
int do_something(struct foo *f)
{
    if (f) {
        int err = step_one(f);
        if (!err) {
            err = step_two(f);
            if (!err) {
                return 0;
            }
        }
        return err;
    }
    return -EINVAL;
}
```

### Cleanup with goto
For functions with multiple cleanup steps, `goto` is acceptable:

```c
int complex_init(void)
{
    struct foo *a = kmalloc(sizeof(*a));
    if (!a) {
        return -ENOMEM;
    }

    struct bar *b = kmalloc(sizeof(*b));
    if (!b) {
        goto err_free_a;
    }

    int err = setup(a, b);
    if (err) {
        goto err_free_b;
    }

    return 0;

err_free_b:
    kfree(b);
err_free_a:
    kfree(a);
    return err;
}
```

---

## Specific Guidelines

### Pointers
- Check for NULL when appropriate
- Use `const` for read-only pointers

```c
int process_name(const struct process *p, char *buf, size_t size)
{
    if (!p || !buf) {
        return -EINVAL;
    }
    /* ... */
}
```

### Integers
- Use fixed-width types for hardware interaction: `uint32_t`, `uint64_t`
- Use `size_t` for sizes and counts
- Use `ssize_t` for sizes that can be negative (error returns)
- Use `int` for general integers

### Structures
- Initialize all fields explicitly
- Use designated initializers

```c
struct process proc = {
    .pid = 1,
    .state = PROC_RUNNABLE,
    .vruntime = 0,
};
```

### Macros
- Wrap macro bodies in `do { } while (0)` for statement macros
- Parenthesize macro parameters

```c
/* Good */
#define SET_FLAG(x, f) do { (x) |= (f); } while (0)
#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((a) - 1))

/* Bad */
#define SET_FLAG(x, f) x |= f
#define ALIGN_UP(x, a) ((x + a - 1) & ~(a - 1))
```

### Static Analysis
- Code should compile with `-Wall -Wextra` without warnings
- Use `__attribute__((unused))` for intentionally unused parameters

```c
static int idle_thread(void *arg __attribute__((unused)))
{
    while (1) {
        arch_cpu_halt();
    }
}
```

---

## Commit Messages

Format:
```
<subsystem>: <short description>

<longer explanation if needed>
```

Examples:
```
sched: implement CFS scheduler

Replace the simple round-robin scheduler with CFS.
This provides better fairness and responsiveness.

mm: fix use-after-free in page allocator

The page was being returned to the free list before
clearing its flags, causing corruption.

Fixes: abc1234 ("mm: add buddy allocator")
```

---

## File Headers

Each source file should have a brief header:

```c
/**
 * kairos/core/sched/cfs.c - CFS Scheduler implementation
 *
 * Implements the Completely Fair Scheduler (CFS) using a red-black
 * tree to maintain runnable processes sorted by vruntime.
 */

#include <kairos/sched.h>
/* ... */
```
