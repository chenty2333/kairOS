/*
 * user/init/init.S - User-mode init for Kairos (RISC-V)
 * Exercises: console IO, pipe, fork/wait.
 */

    .section .text
    .globl _start

    .equ O_NONBLOCK, 04000
    .equ F_GETFL, 3
    .equ F_SETFL, 4
    .equ EPOLL_CTL_ADD, 1
    .equ EPOLLIN, 0x0001
    .equ EAGAIN, -11
    .equ EPIPE, -32
    .equ HEAP_START, 0x00000001000000
    .equ PAGE_SIZE, 4096
    .equ AT_FDCWD, -100
    .equ SIGCHLD, 17
    .equ SIGUSR1, 10
    .equ RLIMIT_NOFILE, 7
    .equ PROT_READ, 0x1
    .equ MAP_PRIVATE, 0x02

    .equ SYS_openat, 56
    .equ SYS_close, 57
    .equ SYS_pipe2, 59
    .equ SYS_read, 63
    .equ SYS_write, 64
    .equ SYS_dup3, 24
    .equ SYS_fcntl, 25
    .equ SYS_epoll_create1, 20
    .equ SYS_epoll_ctl, 21
    .equ SYS_epoll_pwait, 22
    .equ SYS_exit, 93
    .equ SYS_brk, 214
    .equ SYS_clone, 220
    .equ SYS_wait4, 260
    .equ SYS_getcwd, 17
    .equ SYS_chdir, 49
    .equ SYS_unlinkat, 35
    .equ SYS_symlinkat, 36
    .equ SYS_readlinkat, 78
    .equ SYS_gettimeofday, 169
    .equ SYS_prlimit64, 261
    .equ SYS_tgkill, 131
    .equ SYS_getpid, 172
    .equ SYS_mmap, 222
    .equ SYS_munmap, 215
    .equ SYS_mkdirat, 34
    .equ SYS_mount, 40
    .equ SYS_umount2, 39
    .equ SYS_chroot, 51
    .equ SYS_pivot_root, 155
    .equ SYS_execve, 221

    .equ MS_BIND, 0x1000
    .equ MS_SHARED, 0x100000
    .equ MS_PRIVATE, 0x40000
    .equ O_RDONLY, 0

_start:
    /* fd = openat(AT_FDCWD, "/dev/console", O_RDWR, 0) */
    li a0, AT_FDCWD
    la a1, path
    li a2, 2
    li a3, 0
    li a7, SYS_openat
    ecall
    mv s0, a0

    /* if fd >= 0, dup3 to stdin/out/err */
    blt s0, zero, 1f
    mv a0, s0
    li a1, 0
    li a2, 0
    li a7, SYS_dup3
    ecall
    mv a0, s0
    li a1, 1
    li a2, 0
    li a7, SYS_dup3
    ecall
    mv a0, s0
    li a1, 2
    li a2, 0
    li a7, SYS_dup3
    ecall
1:

    /* write(stdout, msg, msg_len) */
    li a0, 1
    la a1, msg_boot
    li a2, 22 /* strlen(msg_boot) */
    li a7, SYS_write
    ecall

    /* pipe test */
    la a0, pipe_fds
    li a1, 0
    li a7, SYS_pipe2
    ecall
    blt a0, zero, pipe_fail
    la t0, pipe_fds
    lw t1, 0(t0)   /* read fd */
    lw t2, 4(t0)   /* write fd */

    /* write to pipe */
    mv a0, t2
    la a1, msg_pipe_data
    li a2, 5 /* "ping\n" */
    li a7, SYS_write
    ecall

    /* read from pipe */
    mv a0, t1
    la a1, buf
    li a2, 5
    li a7, SYS_read
    ecall
    mv t3, a0

    /* write pipe output */
    li a0, 1
    la a1, msg_pipe
    li a2, 6 /* "pipe: " */
    li a7, SYS_write
    ecall
    li a0, 1
    la a1, buf
    mv a2, t3
    li a7, SYS_write
    ecall

    /* close pipe fds */
    mv a0, t1
    li a7, SYS_close
    ecall
    mv a0, t2
    li a7, SYS_close
    ecall
    j after_pipe

pipe_fail:
    li a0, 1
    la a1, msg_pipe_fail
    li a2, 12 /* "pipe failed\n" */
    li a7, SYS_write
    ecall

after_pipe:
    /* pipe2(O_NONBLOCK) + poll test */
    la a0, pipe_fds
    li a1, O_NONBLOCK
    li a7, SYS_pipe2
    ecall
    blt a0, zero, pipe2_fail

    la t0, pipe_fds
    lw t1, 0(t0)   /* read fd */
    lw t2, 4(t0)   /* write fd */

    /* nonblocking read on empty pipe -> -EAGAIN */
    mv a0, t1
    la a1, buf
    li a2, 1
    li a7, SYS_read
    ecall
    li t3, EAGAIN
    bne a0, t3, nonblock_fail

    li a0, 1
    la a1, msg_nonblock_ok
    li a2, 13
    li a7, SYS_write
    ecall

    /* write one byte and check readability via epoll */
    mv a0, t2
    la a1, msg_nb_data
    li a2, 1
    li a7, SYS_write
    ecall

    li a0, 0
    li a7, SYS_epoll_create1
    ecall
    blt a0, zero, epoll_fail
    mv t4, a0

    la t5, epoll_in
    li t6, EPOLLIN
    sw t6, 0(t5)
    sd t1, 8(t5)

    mv a0, t4
    li a1, EPOLL_CTL_ADD
    mv a2, t1
    la a3, epoll_in
    li a7, SYS_epoll_ctl
    ecall
    blt a0, zero, epoll_fail_close

    mv a0, t4
    la a1, epoll_out
    li a2, 1
    li a3, 0
    li a4, 0
    li a5, 0
    li a7, SYS_epoll_pwait
    ecall
    blez a0, epoll_fail_close
    la t5, epoll_out
    lw t6, 0(t5)
    andi t6, t6, EPOLLIN
    beqz t6, epoll_fail_close

    li a0, 1
    la a1, msg_epoll_ok
    li a2, 10
    li a7, SYS_write
    ecall

    mv a0, t4
    li a7, SYS_close
    ecall

    /* read the byte back */
    mv a0, t1
    la a1, buf
    li a2, 1
    li a7, SYS_read
    ecall
    j pipe2_close

pipe2_fail:
    li a0, 1
    la a1, msg_pipe2_fail
    li a2, 13
    li a7, SYS_write
    ecall
    j fcntl_test

nonblock_fail:
    li a0, 1
    la a1, msg_nonblock_fail
    li a2, 15
    li a7, SYS_write
    ecall
    j pipe2_close

epoll_fail_close:
    mv a0, t4
    li a7, SYS_close
    ecall

epoll_fail:
    li a0, 1
    la a1, msg_epoll_fail
    li a2, 11
    li a7, SYS_write
    ecall

pipe2_close:
    mv a0, t1
    li a7, SYS_close
    ecall
    mv a0, t2
    li a7, SYS_close
    ecall

fcntl_test:
    /* fcntl(F_SETFL, O_NONBLOCK) + SIGPIPE test */
    la a0, pipe_fds
    li a1, 0
    li a7, SYS_pipe2
    ecall
    blt a0, zero, fcntl_fail

    la t0, pipe_fds
    lw t1, 0(t0)
    lw t2, 4(t0)

    mv a0, t1
    li a1, F_SETFL
    li a2, O_NONBLOCK
    li a7, SYS_fcntl
    ecall
    blt a0, zero, fcntl_fail_close

    /* nonblocking read on empty pipe -> -EAGAIN */
    mv a0, t1
    la a1, buf
    li a2, 1
    li a7, SYS_read
    ecall
    li t3, EAGAIN
    bne a0, t3, fcntl_fail_close

    li a0, 1
    la a1, msg_fcntl_ok
    li a2, 10
    li a7, SYS_write
    ecall

    /* close reader, write should raise SIGPIPE and return -EPIPE */
    mv a0, t1
    li a7, SYS_close
    ecall
    mv a0, t2
    la a1, msg_nb_data
    li a2, 1
    li a7, SYS_write
    ecall
    li t3, EPIPE
    bne a0, t3, sigpipe_fail

    li a0, 1
    la a1, msg_sigpipe_ok
    li a2, 12
    li a7, SYS_write
    ecall
    mv a0, t2
    li a7, SYS_close
    ecall
    j cow_test

fcntl_fail_close:
    mv a0, t1
    li a7, SYS_close
    ecall
    mv a0, t2
    li a7, SYS_close
    ecall

fcntl_fail:
    li a0, 1
    la a1, msg_fcntl_fail
    li a2, 12
    li a7, SYS_write
    ecall
    j cow_test

sigpipe_fail:
    li a0, 1
    la a1, msg_sigpipe_fail
    li a2, 13
    li a7, SYS_write
    ecall
    mv a0, t2
    li a7, SYS_close
    ecall

cow_test:
    /* COW test: parent value should remain unchanged */
    li a0, HEAP_START + PAGE_SIZE
    li a7, SYS_brk
    ecall

    li t0, HEAP_START
    li t1, 0x11111111
    sw t1, 0(t0)

    li a0, SIGCHLD
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, SYS_clone
    ecall
    blt a0, zero, cow_fail
    beqz a0, cow_child

    /* parent waits and verifies value */
    li a0, -1
    la a1, status
    li a2, 0
    li a3, 0
    li a7, SYS_wait4
    ecall

    li t0, HEAP_START
    lw t1, 0(t0)
    li t2, 0x11111111
    bne t1, t2, cow_fail

    li a0, 1
    la a1, msg_cow_ok
    li a2, 8
    li a7, SYS_write
    ecall
    j fork_test

cow_child:
    li t0, HEAP_START
    li t1, 0x22222222
    sw t1, 0(t0)
    li a0, 0
    li a7, SYS_exit
    ecall

cow_fail:
    li a0, 1
    la a1, msg_cow_fail
    li a2, 10
    li a7, SYS_write
    ecall

fork_test:
    /* fork test */
    li a0, SIGCHLD
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, SYS_clone
    ecall
    blt a0, zero, fork_fail
    beqz a0, child

    /* parent: wait */
    li a0, -1
    la a1, status
    li a2, 0
    li a3, 0
    li a7, SYS_wait4
    ecall
    li a0, 1
    la a1, msg_parent
    li a2, 18 /* "parent: wait done\n" */
    li a7, SYS_write
    ecall
    j after_fork

child:
    li a0, 1
    la a1, msg_child
    li a2, 13 /* "child: hello\n" */
    li a7, SYS_write
    ecall
    li a0, 42
    li a7, SYS_exit
    ecall

fork_fail:
    li a0, 1
    la a1, msg_fork_fail
    li a2, 12 /* "fork failed\n" */
    li a7, SYS_write
    ecall

after_fork:
    /* chdir/getcwd test */
    la a0, path_root
    li a7, SYS_chdir
    ecall
    blt a0, zero, chdir_fail
    la a0, cwd_buf
    li a1, 64
    li a7, SYS_getcwd
    ecall
    blt a0, zero, chdir_fail
    li a0, 1
    la a1, msg_chdir_ok
    li a2, 10
    li a7, SYS_write
    ecall
    j gettimeofday_test

chdir_fail:
    li a0, 1
    la a1, msg_chdir_fail
    li a2, 12
    li a7, SYS_write
    ecall

gettimeofday_test:
    la a0, tv_buf
    li a1, 0
    li a7, SYS_gettimeofday
    ecall
    blt a0, zero, gettimeofday_fail
    li a0, 1
    la a1, msg_gettimeofday_ok
    li a2, 17
    li a7, SYS_write
    ecall
    j prlimit_test

gettimeofday_fail:
    li a0, 1
    la a1, msg_gettimeofday_fail
    li a2, 19
    li a7, SYS_write
    ecall

prlimit_test:
    li a0, 0
    li a1, RLIMIT_NOFILE
    li a2, 0
    la a3, rlimit_buf
    li a7, SYS_prlimit64
    ecall
    blt a0, zero, prlimit_fail
    li a0, 1
    la a1, msg_prlimit_ok
    li a2, 12
    li a7, SYS_write
    ecall
    j tgkill_test

prlimit_fail:
    li a0, 1
    la a1, msg_prlimit_fail
    li a2, 13
    li a7, SYS_write
    ecall

tgkill_test:
    li a7, SYS_getpid
    ecall
    mv t0, a0
    mv a0, t0
    mv a1, t0
    li a2, SIGUSR1
    li a7, SYS_tgkill
    ecall
    blt a0, zero, tgkill_fail
    li a0, 1
    la a1, msg_tgkill_ok
    li a2, 11
    li a7, SYS_write
    ecall
    j chroot_test

tgkill_fail:
    li a0, 1
    la a1, msg_tgkill_fail
    li a2, 15
    li a7, SYS_write
    ecall
    j chroot_test

chroot_test:
    /* mkdir /chroot and /chroot/dir */
    li a0, AT_FDCWD
    la a1, path_chroot
    li a2, 0755
    li a7, SYS_mkdirat
    ecall
    li a0, AT_FDCWD
    la a1, path_chroot_dir
    li a2, 0755
    li a7, SYS_mkdirat
    ecall

    /* fork for chroot test */
    li a0, SIGCHLD
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, SYS_clone
    ecall
    blt a0, zero, chroot_fail
    beqz a0, chroot_child

    /* parent wait */
    li a0, -1
    la a1, status
    li a2, 0
    li a3, 0
    li a7, SYS_wait4
    ecall
    j mount_test

chroot_child:
    la a0, path_chroot
    li a7, SYS_chroot
    ecall
    blt a0, zero, chroot_fail_child

    la a0, cwd_buf
    li a1, 64
    li a7, SYS_getcwd
    ecall
    blt a0, zero, chroot_fail_child
    la t0, cwd_buf
    lbu t1, 0(t0)
    lbu t2, 1(t0)
    li t3, '/'
    bne t1, t3, chroot_fail_child
    bnez t2, chroot_fail_child
    li a0, 1
    la a1, msg_chroot_ok
    li a2, 11
    li a7, SYS_write
    ecall
    li a0, 0
    li a7, SYS_exit
    ecall

chroot_fail_child:
    li a0, 1
    la a1, msg_chroot_fail
    li a2, 13
    li a7, SYS_write
    ecall
    li a0, 1
    li a7, SYS_exit
    ecall

chroot_fail:
    li a0, 1
    la a1, msg_chroot_fail
    li a2, 13
    li a7, SYS_write
    ecall
    j mount_test

mount_test:
    /* mkdir /mnt and /mnt_bind */
    li a0, AT_FDCWD
    la a1, path_mnt
    li a2, 0755
    li a7, SYS_mkdirat
    ecall
    blt a0, zero, 1f
    j 2f
1:
    li t0, -17
    bne a0, t0, mount_fail
2:
    li a0, AT_FDCWD
    la a1, path_mnt_bind
    li a2, 0755
    li a7, SYS_mkdirat
    ecall
    blt a0, zero, 3f
    j 4f
3:
    li t0, -17
    bne a0, t0, mount_fail
4:
    /* bind mount /mnt to /mnt_bind */
    la a0, path_mnt
    la a1, path_mnt_bind
    li a2, 0
    li a3, MS_BIND
    li a4, 0
    li a7, SYS_mount
    ecall
    blt a0, zero, mount_bind_fail
    /* mark shared then private */
    li a0, 0
    la a1, path_mnt_bind
    li a2, 0
    li a3, MS_SHARED
    li a4, 0
    li a7, SYS_mount
    ecall
    blt a0, zero, mount_shared_fail
    li a0, 0
    la a1, path_mnt_bind
    li a2, 0
    li a3, MS_PRIVATE
    li a4, 0
    li a7, SYS_mount
    ecall
    blt a0, zero, mount_private_fail
    /* umount2 /mnt_bind */
    la a0, path_mnt_bind
    li a1, 0
    li a7, SYS_umount2
    ecall
    blt a0, zero, mount_umount_fail
    li a0, 1
    la a1, msg_mount_ok
    li a2, 10
    li a7, SYS_write
    ecall
    j symlink_test

mount_fail:
    li a0, 1
    la a1, msg_mount_fail
    li a2, 12
    li a7, SYS_write
    ecall
    j symlink_test

mount_bind_fail:
    li a0, 1
    la a1, msg_mount_bind_fail
    li a2, 17
    li a7, SYS_write
    ecall
    j symlink_test

mount_shared_fail:
    li a0, 1
    la a1, msg_mount_shared_fail
    li a2, 19
    li a7, SYS_write
    ecall
    j symlink_test

mount_private_fail:
    li a0, 1
    la a1, msg_mount_private_fail
    li a2, 20
    li a7, SYS_write
    ecall
    j symlink_test

mount_umount_fail:
    li a0, 1
    la a1, msg_mount_umount_fail
    li a2, 19
    li a7, SYS_write
    ecall
    j symlink_test

symlink_test:
    li a0, AT_FDCWD
    la a1, path_tmpfile
    li a2, 0
    li a7, SYS_unlinkat
    ecall
    li a0, AT_FDCWD
    la a1, path_tmplink
    li a2, 0
    li a7, SYS_unlinkat
    ecall

    li a0, AT_FDCWD
    la a1, path_tmpfile
    li a2, 0100 | 01000 | 1
    li a3, 0644
    li a7, SYS_openat
    ecall
    blt a0, zero, symlink_open_fail
    mv s1, a0
    mv a0, s1
    la a1, msg_mmap_data
    li a2, 8
    li a7, SYS_write
    ecall
    mv a0, s1
    li a7, SYS_close
    ecall

    la a0, path_tmpfile
    li a1, AT_FDCWD
    la a2, path_tmplink
    li a7, SYS_symlinkat
    ecall
    blt a0, zero, symlink_link_check
    j symlink_link_ok

symlink_link_check:
    li t0, -17
    beq a0, t0, symlink_link_ok
    j symlink_link_fail

symlink_link_ok:

    li a0, AT_FDCWD
    la a1, path_tmplink
    la a2, buf
    li a3, 64
    li a7, SYS_readlinkat
    ecall
    blt a0, zero, symlink_read_fail
    mv t1, a0

    li a0, 1
    la a1, msg_readlink
    li a2, 10
    li a7, SYS_write
    ecall
    li a0, 1
    la a1, buf
    mv a2, t1
    li a7, SYS_write
    ecall
    li a0, 1
    la a1, msg_newline
    li a2, 1
    li a7, SYS_write
    ecall
    j mmap_test

symlink_open_fail:
    li a0, 1
    la a1, msg_symlink_open_fail
    li a2, 20
    li a7, SYS_write
    ecall
    j mmap_test

symlink_link_fail:
    li a0, 1
    la a1, msg_symlink_link_fail
    li a2, 20
    li a7, SYS_write
    ecall
    j mmap_test

symlink_read_fail:
    li a0, 1
    la a1, msg_symlink_read_fail
    li a2, 24
    li a7, SYS_write
    ecall

mmap_test:
    li a0, AT_FDCWD
    la a1, path_tmpfile
    li a2, 0
    li a3, 0
    li a7, SYS_openat
    ecall
    blt a0, zero, mmap_fail
    mv s2, a0

    li a0, 0
    li a1, PAGE_SIZE
    li a2, PROT_READ
    li a3, MAP_PRIVATE
    mv a4, s2
    li a5, 0
    li a7, SYS_mmap
    ecall
    beqz a0, mmap_fail_close
    mv s3, a0

    li a0, 1
    mv a1, s3
    li a2, 8
    li a7, SYS_write
    ecall

    mv a0, s3
    li a1, PAGE_SIZE
    li a7, SYS_munmap
    ecall

    mv a0, s2
    li a7, SYS_close
    ecall

    li a0, 1
    la a1, msg_mmap_ok
    li a2, 9
    li a7, SYS_write
    ecall
    j pivot_root_test

mmap_fail_close:
    mv a0, s2
    li a7, SYS_close
    ecall

mmap_fail:
    li a0, 1
    la a1, msg_mmap_fail
    li a2, 11
    li a7, SYS_write
    ecall
    j pivot_root_test

pivot_root_test:
    /* mkdir /newroot and /newroot/oldroot */
    li a0, AT_FDCWD
    la a1, path_newroot
    li a2, 0755
    li a7, SYS_mkdirat
    ecall
    li a0, AT_FDCWD
    la a1, path_oldroot
    li a2, 0755
    li a7, SYS_mkdirat
    ecall

    /* bind mount / to /newroot */
    la a0, path_root
    la a1, path_newroot
    li a2, 0
    li a3, MS_BIND
    li a4, 0
    li a7, SYS_mount
    ecall
    blt a0, zero, pivot_fail

    la a0, path_newroot
    la a1, path_oldroot
    li a7, SYS_pivot_root
    ecall
    blt a0, zero, pivot_fail

    /* open /oldroot */
    li a0, AT_FDCWD
    la a1, path_oldroot_short
    li a2, O_RDONLY
    li a3, 0
    li a7, SYS_openat
    ecall
    blt a0, zero, pivot_fail
    mv t0, a0
    mv a0, t0
    li a7, SYS_close
    ecall

    li a0, 1
    la a1, msg_pivot_ok
    li a2, 15
    li a7, SYS_write
    ecall
    j exit_now

pivot_fail:
    li a0, 1
    la a1, msg_pivot_fail
    li a2, 17
    li a7, SYS_write
    ecall

exit_now:
    /* sanity check: open /bin/busybox */
    li a0, AT_FDCWD
    la a1, path_sh
    li a2, O_RDONLY
    li a3, 0
    li a7, SYS_openat
    ecall
    blt a0, zero, open_busybox_fail
    mv t0, a0
    mv a0, t0
    li a7, SYS_close
    ecall
    li a0, 1
    la a1, msg_open_busybox_ok
    li a2, 22
    li a7, SYS_write
    ecall
    j open_old_busybox
open_busybox_fail:
    li a0, 1
    la a1, msg_open_busybox_fail
    li a2, 24
    li a7, SYS_write
    ecall
open_old_busybox:
    /* sanity check: open /oldroot/bin/busybox */
    li a0, AT_FDCWD
    la a1, path_old_sh
    li a2, O_RDONLY
    li a3, 0
    li a7, SYS_openat
    ecall
    blt a0, zero, open_old_busybox_fail
    mv t0, a0
    mv a0, t0
    li a7, SYS_close
    ecall
    li a0, 1
    la a1, msg_open_old_busybox_ok
    li a2, 30
    li a7, SYS_write
    ecall
    j exec_busybox
open_old_busybox_fail:
    li a0, 1
    la a1, msg_open_old_busybox_fail
    li a2, 32
    li a7, SYS_write
    ecall

exec_busybox:
    /* execve("/bin/busybox", ["sh", NULL], NULL) */
    la a0, path_sh
    la a1, argv_sh
    li a2, 0
    li a7, SYS_execve
    ecall
    /* if exec failed, log and try oldroot */
    li a0, 1
    la a1, msg_exec_fail
    li a2, 26
    li a7, SYS_write
    ecall
    /* if pivot_root succeeded, try /oldroot/bin/busybox */
    la a0, path_old_sh
    la a1, argv_old_sh
    li a2, 0
    li a7, SYS_execve
    ecall
    li a0, 1
    la a1, msg_exec_old_fail
    li a2, 34
    li a7, SYS_write
    ecall

    /* exit(42) */
    li a0, 42
    li a7, SYS_exit
    ecall

1:  j 1b

    .section .rodata
path:
    .asciz "/dev/console"
msg_boot:
    .asciz "Hello from user init!\n"
msg_pipe:
    .asciz "pipe: "
msg_pipe_data:
    .asciz "ping\n"
msg_pipe_fail:
    .asciz "pipe failed\n"
msg_pipe2_fail:
    .asciz "pipe2 failed\n"
msg_nonblock_ok:
    .asciz "nonblock: ok\n"
msg_nonblock_fail:
    .asciz "nonblock: fail\n"
msg_epoll_ok:
    .asciz "epoll: ok\n"
msg_epoll_fail:
    .asciz "epoll: fail\n"
msg_fcntl_ok:
    .asciz "fcntl: ok\n"
msg_fcntl_fail:
    .asciz "fcntl: fail\n"
msg_sigpipe_ok:
    .asciz "sigpipe: ok\n"
msg_sigpipe_fail:
    .asciz "sigpipe: fail\n"
msg_cow_ok:
    .asciz "cow: ok\n"
msg_cow_fail:
    .asciz "cow: fail\n"
msg_nb_data:
    .asciz "X"
msg_child:
    .asciz "child: hello\n"
msg_parent:
    .asciz "parent: wait done\n"
msg_fork_fail:
    .asciz "fork failed\n"
path_root:
    .asciz "/"
path_tmpfile:
    .asciz "/tmpfile"
path_tmplink:
    .asciz "/tmplink"
msg_chdir_ok:
    .asciz "chdir: ok\n"
msg_chdir_fail:
    .asciz "chdir: fail\n"
msg_gettimeofday_ok:
    .asciz "gettimeofday: ok\n"
msg_gettimeofday_fail:
    .asciz "gettimeofday: fail\n"
msg_prlimit_ok:
    .asciz "prlimit: ok\n"
msg_prlimit_fail:
    .asciz "prlimit: fail\n"
msg_tgkill_ok:
    .asciz "tgkill: ok\n"
msg_tgkill_fail:
    .asciz "tgkill: fail\n"
msg_chroot_ok:
    .asciz "chroot: ok\n"
msg_chroot_fail:
    .asciz "chroot: fail\n"
msg_mount_ok:
    .asciz "mount: ok\n"
msg_mount_fail:
    .asciz "mount: fail\n"
msg_mount_bind_fail:
    .asciz "mount: bind fail\n"
msg_mount_shared_fail:
    .asciz "mount: shared fail\n"
msg_mount_private_fail:
    .asciz "mount: private fail\n"
msg_mount_umount_fail:
    .asciz "mount: umount fail\n"
msg_symlink_open_fail:
    .asciz "symlink: open fail\n"
msg_symlink_link_fail:
    .asciz "symlink: link fail\n"
msg_symlink_read_fail:
    .asciz "symlink: readlink fail\n"
msg_readlink:
    .asciz "readlink: "
msg_newline:
    .asciz "\n"
msg_mmap_ok:
    .asciz "mmap: ok\n"
msg_mmap_fail:
    .asciz "mmap: fail\n"
msg_mmap_data:
    .asciz "mmap ok\n"
msg_pivot_ok:
    .asciz "pivot_root: ok\n"
msg_pivot_fail:
    .asciz "pivot_root: fail\n"
msg_exec_fail:
    .asciz "exec: /bin/busybox failed\n"
msg_exec_old_fail:
    .asciz "exec: /oldroot/bin/busybox failed\n"
msg_open_busybox_ok:
    .asciz "open: /bin/busybox ok\n"
msg_open_busybox_fail:
    .asciz "open: /bin/busybox fail\n"
msg_open_old_busybox_ok:
    .asciz "open: /oldroot/bin/busybox ok\n"
msg_open_old_busybox_fail:
    .asciz "open: /oldroot/bin/busybox fail\n"

path_sh:
    .asciz "/bin/busybox"
    .align 3
argv_sh:
    .dword arg_sh
    .dword 0
path_old_sh:
    .asciz "/oldroot/bin/busybox"
    .align 3
argv_old_sh:
    .dword arg_sh
    .dword 0
arg_sh:
    .asciz "sh"

path_chroot:
    .asciz "/chroot"
path_chroot_dir:
    .asciz "/chroot/dir"
path_mnt:
    .asciz "/mnt"
path_mnt_bind:
    .asciz "/mnt_bind"
path_newroot:
    .asciz "/newroot"
path_oldroot:
    .asciz "/newroot/oldroot"
path_oldroot_short:
    .asciz "/oldroot"

    .section .bss
    .align 4
pipe_fds:
    .space 8
status:
    .space 4
epoll_in:
    .space 16
epoll_out:
    .space 16
    .align 8
buf:
    .space 64
cwd_buf:
    .space 64
tv_buf:
    .space 16
rlimit_buf:
    .space 16
