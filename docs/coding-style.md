# Kairos Coding Style Guide

We prioritize clarity and consistency. Formatting is automatically handled by `clang-format`.

---

## 1. Automation
- **Formatting**: Run `clang-format -i path/to/file.c` before committing.
- **Rules**: We follow **K&R style** (braces on the same line) with 4-space indentation and an 80-character line limit. See `.clang-format` for details.

---

## 2. Naming Conventions
- **General**: Use `snake_case` for everything except constants.
- **Constants/Macros**: Use `UPPER_SNAKE_CASE`.
- **Typedefs**: Use `_t` suffix (e.g., `paddr_t`).
- **Functions**: Prefix public functions with the module name (e.g., `sched_init()`).

---

## 3. Principles
- **Clarity over cleverness**: Write code that is easy to reason about.
- **Comments**: Explain **why**, not **what**. If the code is complex, refactor it; only comment if an algorithm or workaround is non-obvious.
- **No Magic Numbers**: Use named constants or enums.
- **Explicit Braces**: Always use braces for control flow (`if`, `for`, `while`), even for single-line statements.

---

## 4. Error Handling
- **Return Values**: Success is `0`, failure is a negative error code (e.g., `-ENOMEM`).
- **Early Returns**: Check for errors immediately and return to reduce nesting.
- **Cleanup**: Use `goto` for multi-step cleanup to avoid code duplication.

---

## 5. File Headers
Each source file must start with a path-based header:
```c
/**
 * kernel/path/to/file.c - Brief description
 */
```