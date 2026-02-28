# 42B — poll/epoll Socket Message ABI

Part of the VFS/Block/Filesystems subsystem. See also:
- 42_POLL_EPOLL.md — poll/epoll index
- 42_POLL_EPOLL__A_WAIT_CORE_FD_EVENTS.md — wait-core and fd-event surfaces
- 42_POLL_EPOLL__C_SELECT_PATH_ABI.md — poll/select/path/fd ABI details

## Socket Message and Nonblocking Poll ABI

- `sendmsg`/`recvmsg` support iovec payload and optional peer address; ancillary data supports `SOL_SOCKET` `SCM_RIGHTS`/`SCM_CREDENTIALS` with real AF_UNIX transport (`SCM_RIGHTS` installs new fds on receive, `SCM_CREDENTIALS` returns sender pid/uid/gid)
- `SCM_RIGHTS` now carries sender fd-rights masks end-to-end and installs received fds via `fd_alloc_rights`, preventing rights expansion relative to sender descriptors
- ancillary parser accepts structurally valid non-`SOL_SOCKET` control segments as compatibility no-ops (not transported yet); unknown `SOL_SOCKET` control types still return `EOPNOTSUPP`
- AF_UNIX ancillary transport is enabled for both `SOCK_DGRAM` and `SOCK_STREAM`
- `SOCK_STREAM` control payload is bound to stream byte offsets (not recv-call count): control is delivered only when its corresponding bytes are consumed, and data paths without ancillary buffers (`recvfrom`/`read`) still consume and drop crossed control payload to avoid stale later delivery
- AF_UNIX `SOCK_STREAM` `sendmsg` with zero-byte payload plus ancillary returns `0` (Linux-compatible call acceptance) and does not surface ancillary payload on a later receive
- `recvmsg(MSG_PEEK)` on AF_UNIX `SOCK_STREAM` does not consume stream bytes or ancillary payload; non-peek receive sees the same boundary afterward
- `recvmmsg(MSG_PEEK)` on AF_UNIX `SOCK_STREAM` follows the same non-consuming rule for both data and ancillary payload; subsequent non-peek reads still observe the original stream/control boundary order
- If one AF_UNIX stream `recvmsg` spans multiple ancillary attachment points, payload is merged in stream order; rights overflow in the merged kernel control set raises `MSG_CTRUNC`
- `recvmsg` sets `MSG_CTRUNC` when user ancillary buffer is too small to hold returned control payload
- `recvmsg(MSG_CMSG_CLOEXEC)` installs received `SCM_RIGHTS` file descriptors with `FD_CLOEXEC`
- `recvmsg` bounds source-address copy length by `min(user_msg_namelen, kernel_sockaddr_len)` using width-safe arithmetic (no signed wrap on large `msg_namelen`)
- AF_UNIX stream send paths honor `MSG_NOSIGNAL` (suppress `SIGPIPE`, return `EPIPE` only)
- socket syscalls now merge fd `O_NONBLOCK` into runtime message flags (`MSG_DONTWAIT`) for `connect`/`accept`/`send*`/`recv*` paths, so `fcntl(F_SETFL)` and `ioctl(FIONBIO)` affect behavior consistently
- AF_INET stream/dgram and AF_UNIX stream now implement non-blocking `connect`/`accept`/`recv` return paths (`EINPROGRESS`/`EALREADY`/`EAGAIN`) and expose connect completion/failure via `poll(POLLOUT|POLLERR)` + `getsockopt(SO_ERROR)`
- Nonblocking connect failures keep `POLLERR`/`POLLOUT` visible until `SO_ERROR` is consumed; after `SO_ERROR` readback, error poll visibility is cleared
- AF_UNIX and AF_INET `setsockopt`/`getsockopt` no longer use silent-success defaults: supported `SOL_SOCKET` options include `SO_REUSEADDR`, `SO_KEEPALIVE`, `SO_SNDBUF`, `SO_RCVBUF`, plus read paths `SO_TYPE`, `SO_ACCEPTCONN`, `SO_ERROR`; unsupported options return `EOPNOTSUPP`
- `EWOULDBLOCK` is aliased to `EAGAIN`, and nonblocking `fcntl(F_SETFL, O_NONBLOCK)` behavior is regression-tested across socket/tty/pipe paths
- `recvmmsg` supports `MSG_WAITFORONE` batching behavior and kernel timeout waits (timespec deadline)
- socket message/accept syscall `flags` are decoded using Linux ABI width (`int`/32-bit) for `accept4`, `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`
- socket control/int arguments are decoded with Linux ABI `int` width (`socket`/`socketpair` domain/type/protocol, socket syscalls `fd`, `listen` backlog, `shutdown` how, `setsockopt`/`getsockopt` level/optname/optlen, `getsockopt` user `optlen_ptr` value, `sendto`/`recvfrom` flags, sockaddr lengths)
- `sendmmsg`/`recvmmsg` decode `vlen` using Linux ABI width (`unsigned int`/32-bit), ignoring upper 32 syscall argument bits
- socket send/recv paths keep Linux ABI semantics while adding small-message inline buffer fast paths (heap allocation fallback for larger payloads)
- socket address-length values read from userspace (`accept*`, `recvfrom`, `getsockname`, `getpeername`) are decoded as 32-bit ABI values before range checks

Related references:
- references/00_REPO_MAP.md
- references/13_TIME.md
- references/33_IPC.md
- references/41_VFS_CORE_PATH_MOUNT_IO.md
- references/42_POLL_EPOLL.md
- references/42_POLL_EPOLL__A_WAIT_CORE_FD_EVENTS.md
- references/42_POLL_EPOLL__C_SELECT_PATH_ABI.md
