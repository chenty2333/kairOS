# 42C — poll/select/path/fd ABI Details

Part of the VFS/Block/Filesystems subsystem. See also:
- 42_POLL_EPOLL.md — poll/epoll index
- 42_POLL_EPOLL__A_WAIT_CORE_FD_EVENTS.md — wait-core and fd-event surfaces
- 42_POLL_EPOLL__B_SOCKET_MESSAGE_ABI.md — socket message ABI

## poll/select and Path/FD ABI Details

- `poll`/`ppoll` with `nfds=0` now sleep for the requested timeout (or until signal) instead of returning immediately
- `select`/`pselect6` with no watched fds also honor timeout sleep semantics
- `select` updates user `timeval` with remaining time on return (`success`/`EINTR`)
- `ppoll`/`pselect6` now temporarily install the provided signal mask during wait and restore the original mask on return
- raw `ppoll`/`pselect6` also update user `timespec` with remaining timeout on return (`success`/`EINTR`), matching Linux syscall-level ABI
- `renameat2` supports `flags=0` and `RENAME_NOREPLACE` (`EEXIST` when destination already exists), with Linux ABI `unsigned int` flag decoding (upper 32 bits ignored)
- aarch64 `open/openat` performs userspace `O_*` bit translation at syscall boundary (`O_DIRECTORY`/`O_NOFOLLOW`/`O_LARGEFILE`), while unsupported `O_DIRECT` still returns `EINVAL`
- `getdents64` follows Linux ABI argument width for `count` (`unsigned int`): upper 32 bits are ignored
- `newfstatat` accepts `AT_NO_AUTOMOUNT` as a compatibility no-op
- `statx` and `newfstatat` both decode `flags` using Linux ABI width (`int`/32-bit)
- `fstatfs`/`fstat`/`getdents64` decode `fd` as Linux ABI `int` (32-bit), and `newfstatat`/`statx` decode `dirfd` as 32-bit `int` before `AT_FDCWD` checks and path resolution
- path-based `*at` syscalls (`fchmodat`, `fchownat`, `utimensat`, `faccessat(2)`, `unlinkat`, `mkdirat`, `mknodat`, `renameat*`, `readlinkat`, `symlinkat`, `linkat`) decode `dirfd`/`olddirfd`/`newdirfd` as Linux ABI `int` (32-bit) before `AT_FDCWD` checks and path resolution
- path-based `*at` syscalls decode `flags` via Linux ABI width (`int`/32-bit); `faccessat*` also decodes `mode` as 32-bit, and `fchownat` uses Linux 32-bit sentinel semantics (`owner/group == 0xffffffff` means no change)
- `dup3` and `pipe2` decode `flags` via Linux ABI width (`int`/32-bit)
- `fcntl` decodes `cmd`/`arg` via Linux ABI `int` width (32-bit)
- fd-based metadata/control syscalls (`dup`/`dup2`/`dup3`/`fcntl`/`ftruncate`/`fchmod`/`fchown`) decode `fd` as Linux ABI `int` (32-bit); `fchown` also uses Linux 32-bit sentinel semantics (`uid/gid == 0xffffffff` means no change)
- `ioctl` decodes `fd`/`cmd` via Linux ABI width (`unsigned int`/32-bit) before in-kernel command routing

Related references:
- references/00_REPO_MAP.md
- references/12_SYSCALL.md
- references/41_VFS_CORE_PATH_MOUNT_IO.md
- references/42_POLL_EPOLL.md
- references/42_POLL_EPOLL__A_WAIT_CORE_FD_EVENTS.md
- references/42_POLL_EPOLL__B_SOCKET_MESSAGE_ABI.md
