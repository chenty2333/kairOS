# 12 — Syscall

Part of the boot/trap/syscall/time subsystem. See also:
- 10_BOOT_FIRMWARE.md — Boot and firmware path
- 11_TRAP_INTERRUPT.md — Trap and interrupt dispatch
- 13_TIME.md — Time-related syscall behavior

## Syscall

Path: userspace trap instruction → trapasm.S → arch trap.c identifies as syscall → syscall_dispatch()

- riscv64: ecall instruction, syscall number in a7, args a0-a5
- x86_64: int 0x80, syscall number in rax, args rdi/rsi/rdx/r10/r8/r9
- aarch64: svc #0, syscall number in x8, args x0-x5
- Linux `clone` ABI argument order differs by architecture:
  - x86_64: `(flags, newsp, ptid, ctid, tls)`
  - riscv64/aarch64: `(flags, newsp, ptid, tls, ctid)`

syscall_dispatch() (core/syscall/syscall.c):
- Checks process ABI flag
- Linux ABI: maps through linux_syscalls.def X-macro expansion to sys_*()
- Kairos ABI: direct syscall_table[] lookup
- Return value written back to trap frame return register

Syscall implementations are split by subsystem in core/syscall/sys_*.c.


Related references:
- references/00_REPO_MAP.md
- references/10_BOOT_FIRMWARE.md
- references/11_TRAP_INTERRUPT.md
- references/13_TIME.md
- references/30_PROCESS.md
- references/33_IPC.md
- references/41_VFS_CORE_PATH_MOUNT_IO.md
