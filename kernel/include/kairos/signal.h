/**
 * kernel/include/kairos/signal.h - Signal handling
 */

#ifndef _KAIROS_SIGNAL_H
#define _KAIROS_SIGNAL_H

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
#define NSIG 32

#define SIG_DFL ((void (*)(int))0)
#define SIG_IGN ((void (*)(int))1)

typedef uint64_t sigset_t;

struct sigaction {
    void (*sa_handler)(int);
    sigset_t sa_mask;
    int sa_flags;
};

/* Context saved on user stack during signal handling */
struct sigcontext {
    uint64_t regs[31];
    uint64_t sepc;
    uint64_t sstatus;
    uint64_t trampoline[2]; /* li a7, SYS_sigreturn; ecall */
};

struct process;
int signal_send(pid_t pid, int sig);
void signal_deliver_pending(void);
void signal_init_process(struct process *p);

#endif