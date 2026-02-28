# 30 — Process Model

Part of the Process/Scheduler/Sync/IPC subsystem. See also:
- 31_SCHEDULER.md — Scheduling
- 32_SYNC.md — Synchronization primitives
- 33_IPC.md — Inter-process communication

## Process Model

Process table: global static array proc_table[CONFIG_MAX_PROCESSES] (default 256), protected by proc_table_lock.

Process states: PROC_UNUSED → PROC_EMBRYO → PROC_RUNNABLE → PROC_RUNNING → PROC_SLEEPING → PROC_ZOMBIE → PROC_REAPING

process struct (include/kairos/process.h) key fields:
- pid/ppid/pgid/sid/tgid, uid/gid/umask
- state, exit_code, syscall_abi (Linux or Legacy)
- sched_flags: scheduler migration policy bits (`PROC_SCHEDF_STEALABLE`, `PROC_SCHEDF_KTHREAD`)
- sched_affinity: CPU affinity bitmask used by enqueue/steal placement
- se: scheduling entity (sched_entity)
- mm: address space (mm_struct)
- fdtable: file descriptor table (refcounted, supports CLONE_FILES sharing)
- sighand: signal handler table (refcounted, supports CLONE_SIGHAND sharing)
- context: architecture-specific context (arch_context)
- children/sibling: process tree
- thread_group: thread group list (CLONE_THREAD)
- wait_entry/exit_wait/vfork_completion: waiting and synchronization

Lifecycle (core/proc/):
- proc_alloc(): allocate free slot from proc_table, initialize fdtable, cwd, signals, context
- proc_fork() / proc_fork_ex(): fork/clone, supports CLONE_VM/CLONE_FILES/CLONE_SIGHAND/CLONE_THREAD/CLONE_SETTLS, COW address space copy
- proc_exec(): ELF loading (core/proc/elf.c), replaces address space and context
- proc_exec() failure path preserves underlying `-errno` (instead of collapsing to `-ENOEXEC`) across main ELF load, interpreter resolve/load, and user stack setup
- proc_exec() failure diagnostics emit structured kernel log with `reason + stage + errno(number/name)` to classify missing interp, invalid ELF, permission, and resource faults
- exec path copy now reports `ENAMETOOLONG` on userspace path truncation (instead of `EFAULT`), and `execveat` relative-path join rejects truncated composed paths with `ENAMETOOLONG`
- proc_exit(): sets ZOMBIE, wakes parent, notifies reaper
- proc_wait(): reaps child processes

Other:
- kthread_create(): create detached kernel threads (not parent-linked, not reaped via proc_wait)
- kthread_create_joinable(): create kernel threads linked to current parent for proc_wait-based reaping
- kthread default placement policy: creator CPU affinity bit + non-stealable (can be relaxed explicitly)
- proc_idle_init(): create idle process
- userspace `/init` supervises the login shell in a restart loop, logs exit cause (exit code / signal), and uses bounded exponential backoff on repeated failures
- signal.c: signal delivery, sighand sharing/copying, sigaction, sigaltstack
- default signal handling now treats `SIGSTOP` as suspend-until-`SIGCONT` (or `SIGKILL`) and consumes `SIGCONT` as a resume event
- procfs per-pid control endpoint: `/proc/<pid>/control` (mode `0600`) accepts `stop|cont|resume|kill|term|sig N|signal N`; write path emits signals via `signal_send_authorized`, and read path returns a structured snapshot (`schema`, `last.*`, `audit.*`) with per-action (`stop/cont/term/kill/signal`) attempt/ok/fail counters and error audit counters (`parse`, `too_long`, `perm`, `noent`, `other`)
- Linux ABI process compatibility: `wait`/`wait4`/`waitid` decode `options` as 32-bit `int`; `execveat` decodes `flags` and `dirfd` as 32-bit `int`; `setuid`/`setgid` and `setre*id`/`setres*id` decode uid/gid arguments as 32-bit values (`-1` sentinel is `0xffffffff`)
- Linux ABI process compatibility also normalizes `pid`/`signal`/`priority` scalar args to 32-bit ABI width for `tgkill`/`tkill`, `getpriority`/`setpriority`, `prlimit64`, `sched_{get,set}affinity`, `setpgid`, `getpgid`, and `getsid`
- Linux ABI pidfd baseline: `pidfd_open`, `pidfd_send_signal`, and `pidfd_getfd` are wired; pidfd is pollable (`POLLIN|POLLHUP` after target exit), `pidfd_open` enforces Linux-style `O_CLOEXEC` on returned fd, `pidfd_send_signal` supports `flags=0` plus optional `siginfo_t *info` user-pointer validation, `waitid(P_PIDFD, ...)` resolves pidfd targets through the fd table (including `WNOWAIT` no-reap path for exited children), and `pidfd_getfd` duplicates target fds with `FD_CLOEXEC`

Related references:
- references/00_REPO_MAP.md
- references/10_BOOT_FIRMWARE.md — Boot sequence
- references/20_MEMORY.md — Address space management
- references/31_SCHEDULER.md — Process scheduling
- references/32_SYNC.md — Process synchronization
- references/33_IPC.md — Process communication
