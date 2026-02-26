/**
 * kernel/include/kairos/signal.h - Signal handling
 */

#ifndef _KAIROS_SIGNAL_H
#define _KAIROS_SIGNAL_H

#include <kairos/arch.h>
#include <kairos/types.h>

#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGWINCH 28
#define NSIG 32

#define SIG_DFL ((void (*)(int))0)
#define SIG_IGN ((void (*)(int))1)

typedef uint64_t sigset_t;

union sigval {
    int sival_int;
    void *sival_ptr;
};

typedef struct {
    int si_signo;
    int si_errno;
    int si_code;
    int __si_pad0;
    union {
        struct {
            union {
                struct {
                    pid_t si_pid;
                    uid_t si_uid;
                } __piduid;
                struct {
                    int si_timerid;
                    int si_overrun;
                } __timer;
            } __first;
            union {
                union sigval si_value;
                struct {
                    int si_status;
                    uint64_t si_utime;
                    uint64_t si_stime;
                } __sigchld;
            } __second;
        } __si_common;
        struct {
            void *si_addr;
            short si_addr_lsb;
            union {
                struct {
                    void *si_lower;
                    void *si_upper;
                } __addr_bnd;
                unsigned si_pkey;
            } __first;
        } __sigfault;
        struct {
            long si_band;
            int si_fd;
        } __sigpoll;
        struct {
            void *si_call_addr;
            int si_syscall;
            unsigned si_arch;
        } __sigsys;
    } __si_fields;
} siginfo_t;

#define si_pid     __si_fields.__si_common.__first.__piduid.si_pid
#define si_uid     __si_fields.__si_common.__first.__piduid.si_uid
#define si_status  __si_fields.__si_common.__second.__sigchld.si_status
#define si_utime   __si_fields.__si_common.__second.__sigchld.si_utime
#define si_stime   __si_fields.__si_common.__second.__sigchld.si_stime
#define si_value   __si_fields.__si_common.__second.si_value
#define si_addr    __si_fields.__sigfault.si_addr
#define si_addr_lsb __si_fields.__sigfault.si_addr_lsb
#define si_lower   __si_fields.__sigfault.__first.__addr_bnd.si_lower
#define si_upper   __si_fields.__sigfault.__first.__addr_bnd.si_upper
#define si_pkey    __si_fields.__sigfault.__first.si_pkey
#define si_band    __si_fields.__sigpoll.si_band
#define si_fd      __si_fields.__sigpoll.si_fd
#define si_timerid __si_fields.__si_common.__first.__timer.si_timerid
#define si_overrun __si_fields.__si_common.__first.__timer.si_overrun
#define si_ptr     si_value.sival_ptr
#define si_int     si_value.sival_int
#define si_call_addr __si_fields.__sigsys.si_call_addr
#define si_syscall __si_fields.__sigsys.si_syscall
#define si_arch    __si_fields.__sigsys.si_arch

typedef struct sigaltstack {
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
} stack_t;

#define SS_ONSTACK 1
#define SS_DISABLE 2

#define SA_ONSTACK   0x08000000
#define SA_RESTART   0x10000000
#define SA_NODEFER   0x40000000
#define SA_RESETHAND 0x80000000

/* siginfo codes */
#define CLD_EXITED 1

/* sigprocmask how values */
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

struct sigaction {
    union {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, siginfo_t *, void *);
    } __sa_handler;
    sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
};

#define sa_handler __sa_handler.sa_handler
#define sa_sigaction __sa_handler.sa_sigaction

/* Context saved on user stack during signal handling */
#if defined(ARCH_riscv64)
struct sigcontext {
    uint64_t regs[31];
    uint64_t sepc;
    uint64_t sstatus;
    sigset_t sigmask;
    uint64_t trampoline[2]; /* li a7, SYS_sigreturn; ecall */
};
#elif defined(ARCH_x86_64)
struct sigcontext {
    struct trap_frame tf;
    sigset_t sigmask;
    uint8_t trampoline[8]; /* mov eax, SYS_sigreturn; int 0x80 */
};
#elif defined(ARCH_aarch64)
struct sigcontext {
    struct trap_frame tf;
    sigset_t sigmask;
    uint32_t trampoline[2]; /* mov x8, SYS_sigreturn; svc #0 */
};
#else
struct sigcontext {
    sigset_t sigmask;
};
#endif

struct process;
int signal_send(pid_t pid, int sig);
int signal_send_authorized(pid_t pid, int sig, uid_t sender_uid,
                           bool sender_is_superuser);
int signal_send_pgrp(pid_t pgrp, int sig);
void signalfd_notify_pending_signal(struct process *p, int sig);
void signal_deliver_pending(void);
void signal_init_process(struct process *p);

#endif
