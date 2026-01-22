/**
 * kairos/signal.h - Signal handling
 */

#ifndef _KAIROS_SIGNAL_H
#define _KAIROS_SIGNAL_H

#include <kairos/types.h>
#include <kairos/config.h>

/*
 * Signal Numbers
 */
#define SIGHUP      1       /* Hangup */
#define SIGINT      2       /* Interrupt (Ctrl+C) */
#define SIGQUIT     3       /* Quit */
#define SIGILL      4       /* Illegal instruction */
#define SIGTRAP     5       /* Trace trap */
#define SIGABRT     6       /* Abort */
#define SIGBUS      7       /* Bus error */
#define SIGFPE      8       /* Floating point exception */
#define SIGKILL     9       /* Kill (cannot be caught) */
#define SIGUSR1     10      /* User defined 1 */
#define SIGSEGV     11      /* Segmentation fault */
#define SIGUSR2     12      /* User defined 2 */
#define SIGPIPE     13      /* Broken pipe */
#define SIGALRM     14      /* Alarm */
#define SIGTERM     15      /* Termination */
#define SIGCHLD     17      /* Child status changed */
#define SIGCONT     18      /* Continue */
#define SIGSTOP     19      /* Stop (cannot be caught) */
#define SIGTSTP     20      /* Terminal stop */
#define SIGTTIN     21      /* Background read */
#define SIGTTOU     22      /* Background write */

#define NSIG        32      /* Number of signals */

/*
 * Signal Actions
 */
#define SIG_DFL     ((void (*)(int))0)  /* Default action */
#define SIG_IGN     ((void (*)(int))1)  /* Ignore signal */
#define SIG_ERR     ((void (*)(int))-1) /* Error return */

/*
 * sigaction flags
 */
#define SA_NOCLDSTOP    (1 << 0)    /* Don't notify on child stop */
#define SA_NOCLDWAIT    (1 << 1)    /* Don't create zombie */
#define SA_SIGINFO      (1 << 2)    /* Use sa_sigaction instead of sa_handler */
#define SA_RESTART      (1 << 3)    /* Restart syscall after signal */
#define SA_NODEFER      (1 << 4)    /* Don't block signal during handler */
#define SA_RESETHAND    (1 << 5)    /* Reset to SIG_DFL after handler */

/*
 * sigprocmask how values
 */
#define SIG_BLOCK       0   /* Add signals to mask */
#define SIG_UNBLOCK     1   /* Remove signals from mask */
#define SIG_SETMASK     2   /* Set mask */

/*
 * Signal Set (bitmap)
 */
typedef uint64_t sigset_t;

#define sigemptyset(set)        (*(set) = 0)
#define sigfillset(set)         (*(set) = ~0ULL)
#define sigaddset(set, sig)     (*(set) |= (1ULL << ((sig) - 1)))
#define sigdelset(set, sig)     (*(set) &= ~(1ULL << ((sig) - 1)))
#define sigismember(set, sig)   ((*(set) & (1ULL << ((sig) - 1))) != 0)

/*
 * sigaction structure
 */
struct sigaction {
    union {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, void *, void *);  /* siginfo_t, ucontext_t */
    };
    sigset_t sa_mask;       /* Signals to block during handler */
    int sa_flags;
};

/*
 * Signal API
 */

/* Send signal to process */
int signal_send(pid_t pid, int sig);

/* Send signal to process group */
int signal_send_group(pid_t pgid, int sig);

/* Set signal handler (simple interface) */
void (*signal_handler(int sig, void (*handler)(int)))(int);

/* Set signal action (full interface) */
int signal_action(int sig, const struct sigaction *act,
                  struct sigaction *oldact);

/* Get/set signal mask */
int signal_procmask(int how, const sigset_t *set, sigset_t *oldset);

/* Wait for signal */
int signal_pause(void);

/* Wait for signal with temporary mask */
int signal_suspend(const sigset_t *mask);

/* Check for pending signals */
int signal_pending(sigset_t *set);

/*
 * Internal functions
 */

/* Check and deliver pending signals (called on return to user) */
void signal_deliver_pending(void);

/* Handle signal (setup stack frame and jump to handler) */
void signal_handle(int sig);

/* Return from signal handler (sigreturn syscall) */
void signal_return(void);

/* Initialize signal state for new process */
void signal_init_process(struct process *p);

/* Clone signal state (for fork) */
void signal_clone(struct process *child, struct process *parent);

#endif /* _KAIROS_SIGNAL_H */
