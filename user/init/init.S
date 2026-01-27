/*
 * user/init/init.S - User-mode init for Kairos (RISC-V)
 * Exercises: console IO, pipe, fork/wait.
 */

    .section .text
    .globl _start
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
    .align 8
buf:
    .space 64
