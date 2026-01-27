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

_start:
    /* fd = open("/dev/console", O_RDWR, 0) */
    la a0, path
    li a1, 2
    li a2, 0
    li a7, 10 /* SYS_open */
    ecall
    mv s0, a0

    /* if fd >= 0, dup2 to stdin/out/err */
    blt s0, zero, 1f
    mv a0, s0
    li a1, 0
    li a7, 19 /* SYS_dup2 */
    ecall
    mv a0, s0
    li a1, 1
    li a7, 19 /* SYS_dup2 */
    ecall
    mv a0, s0
    li a1, 2
    li a7, 19 /* SYS_dup2 */
    ecall
1:

    /* write(stdout, msg, msg_len) */
    li a0, 1
    la a1, msg_boot
    li a2, 22 /* strlen(msg_boot) */
    li a7, 13 /* SYS_write */
    ecall

    /* pipe test */
    la a0, pipe_fds
    li a7, 50 /* SYS_pipe */
    ecall
    blt a0, zero, pipe_fail
    la t0, pipe_fds
    lw t1, 0(t0)   /* read fd */
    lw t2, 4(t0)   /* write fd */

    /* write to pipe */
    mv a0, t2
    la a1, msg_pipe_data
    li a2, 5 /* "ping\n" */
    li a7, 13 /* SYS_write */
    ecall

    /* read from pipe */
    mv a0, t1
    la a1, buf
    li a2, 5
    li a7, 12 /* SYS_read */
    ecall
    mv t3, a0

    /* write pipe output */
    li a0, 1
    la a1, msg_pipe
    li a2, 6 /* "pipe: " */
    li a7, 13 /* SYS_write */
    ecall
    li a0, 1
    la a1, buf
    mv a2, t3
    li a7, 13 /* SYS_write */
    ecall

    /* close pipe fds */
    mv a0, t1
    li a7, 11 /* SYS_close */
    ecall
    mv a0, t2
    li a7, 11 /* SYS_close */
    ecall
    j after_pipe

pipe_fail:
    li a0, 1
    la a1, msg_pipe_fail
    li a2, 12 /* "pipe failed\n" */
    li a7, 13
    ecall

after_pipe:
    /* pipe2(O_NONBLOCK) + poll test */
    la a0, pipe_fds
    li a1, O_NONBLOCK
    li a7, 51 /* SYS_pipe2 */
    ecall
    blt a0, zero, pipe2_fail

    la t0, pipe_fds
    lw t1, 0(t0)   /* read fd */
    lw t2, 4(t0)   /* write fd */

    /* nonblocking read on empty pipe -> -EAGAIN */
    mv a0, t1
    la a1, buf
    li a2, 1
    li a7, 12 /* SYS_read */
    ecall
    li t3, EAGAIN
    bne a0, t3, nonblock_fail

    li a0, 1
    la a1, msg_nonblock_ok
    li a2, 13
    li a7, 13
    ecall

    /* write one byte and check readability via epoll */
    mv a0, t2
    la a1, msg_nb_data
    li a2, 1
    li a7, 13
    ecall

    li a0, 0
    li a7, 82 /* SYS_epoll_create1 */
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
    li a7, 83 /* SYS_epoll_ctl */
    ecall
    blt a0, zero, epoll_fail_close

    mv a0, t4
    la a1, epoll_out
    li a2, 1
    li a3, 0
    li a7, 84 /* SYS_epoll_wait */
    ecall
    blez a0, epoll_fail_close
    la t5, epoll_out
    lw t6, 0(t5)
    andi t6, t6, EPOLLIN
    beqz t6, epoll_fail_close

    li a0, 1
    la a1, msg_epoll_ok
    li a2, 10
    li a7, 13
    ecall

    mv a0, t4
    li a7, 11
    ecall

    /* read the byte back */
    mv a0, t1
    la a1, buf
    li a2, 1
    li a7, 12
    ecall
    j pipe2_close

pipe2_fail:
    li a0, 1
    la a1, msg_pipe2_fail
    li a2, 13
    li a7, 13
    ecall
    j fcntl_test

nonblock_fail:
    li a0, 1
    la a1, msg_nonblock_fail
    li a2, 15
    li a7, 13
    ecall
    j pipe2_close

epoll_fail_close:
    mv a0, t4
    li a7, 11
    ecall

epoll_fail:
    li a0, 1
    la a1, msg_epoll_fail
    li a2, 12
    li a7, 13
    ecall

pipe2_close:
    mv a0, t1
    li a7, 11
    ecall
    mv a0, t2
    li a7, 11
    ecall

fcntl_test:
    /* fcntl(F_SETFL, O_NONBLOCK) + SIGPIPE test */
    la a0, pipe_fds
    li a7, 50 /* SYS_pipe */
    ecall
    blt a0, zero, fcntl_fail

    la t0, pipe_fds
    lw t1, 0(t0)
    lw t2, 4(t0)

    mv a0, t1
    li a1, F_SETFL
    li a2, O_NONBLOCK
    li a7, 20 /* SYS_fcntl */
    ecall
    blt a0, zero, fcntl_fail_close

    /* nonblocking read on empty pipe -> -EAGAIN */
    mv a0, t1
    la a1, buf
    li a2, 1
    li a7, 12
    ecall
    li t3, EAGAIN
    bne a0, t3, fcntl_fail_close

    li a0, 1
    la a1, msg_fcntl_ok
    li a2, 10
    li a7, 13
    ecall

    /* close reader, write should raise SIGPIPE and return -EPIPE */
    mv a0, t1
    li a7, 11
    ecall
    mv a0, t2
    la a1, msg_nb_data
    li a2, 1
    li a7, 13
    ecall
    li t3, EPIPE
    bne a0, t3, sigpipe_fail

    li a0, 1
    la a1, msg_sigpipe_ok
    li a2, 12
    li a7, 13
    ecall
    mv a0, t2
    li a7, 11
    ecall
    j cow_test

fcntl_fail_close:
    mv a0, t1
    li a7, 11
    ecall
    mv a0, t2
    li a7, 11
    ecall

fcntl_fail:
    li a0, 1
    la a1, msg_fcntl_fail
    li a2, 12
    li a7, 13
    ecall
    j cow_test

sigpipe_fail:
    li a0, 1
    la a1, msg_sigpipe_fail
    li a2, 14
    li a7, 13
    ecall
    mv a0, t2
    li a7, 11
    ecall

cow_test:
    /* COW test: parent value should remain unchanged */
    li a0, HEAP_START + PAGE_SIZE
    li a7, 40 /* SYS_brk */
    ecall

    li t0, HEAP_START
    li t1, 0x11111111
    sw t1, 0(t0)

    li a7, 2 /* SYS_fork */
    ecall
    blt a0, zero, cow_fail
    beqz a0, cow_child

    /* parent waits and verifies value */
    li a0, -1
    la a1, status
    li a2, 0
    li a7, 4
    ecall

    li t0, HEAP_START
    lw t1, 0(t0)
    li t2, 0x11111111
    bne t1, t2, cow_fail

    li a0, 1
    la a1, msg_cow_ok
    li a2, 8
    li a7, 13
    ecall
    j fork_test

cow_child:
    li t0, HEAP_START
    li t1, 0x22222222
    sw t1, 0(t0)
    li a0, 0
    li a7, 1
    ecall

cow_fail:
    li a0, 1
    la a1, msg_cow_fail
    li a2, 10
    li a7, 13
    ecall

fork_test:
    /* fork test */
    li a7, 2 /* SYS_fork */
    ecall
    blt a0, zero, fork_fail
    beqz a0, child

    /* parent: wait */
    li a0, -1
    la a1, status
    li a2, 0
    li a7, 4 /* SYS_wait */
    ecall
    li a0, 1
    la a1, msg_parent
    li a2, 18 /* "parent: wait done\n" */
    li a7, 13
    ecall
    j after_fork

child:
    li a0, 1
    la a1, msg_child
    li a2, 13 /* "child: hello\n" */
    li a7, 13
    ecall
    li a0, 42
    li a7, 1 /* SYS_exit */
    ecall

fork_fail:
    li a0, 1
    la a1, msg_fork_fail
    li a2, 12 /* "fork failed\n" */
    li a7, 13
    ecall

after_fork:
    /* exit(42) */
    li a0, 42
    li a7, 1 /* SYS_exit */
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
