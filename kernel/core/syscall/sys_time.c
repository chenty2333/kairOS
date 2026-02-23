/**
 * kernel/core/syscall/sys_time.c - Time-related syscalls
 */

#include <kairos/arch.h>
#include <kairos/config.h>
#include <kairos/pollwait.h>
#include <kairos/mm.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/uaccess.h>
#include <kairos/time.h>

#include "sys_time_helpers.h"

#define NS_PER_SEC 1000000000ULL
#define TIMER_ABSTIME 1U

struct linux_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct linux_sysinfo {
    int64_t uptime;
    uint64_t loads[3];
    uint64_t totalram;
    uint64_t freeram;
    uint64_t sharedram;
    uint64_t bufferram;
    uint64_t totalswap;
    uint64_t freeswap;
    uint16_t procs;
    uint16_t pad;
    uint64_t totalhigh;
    uint64_t freehigh;
    uint32_t mem_unit;
    char _f[20 - 2 * sizeof(uint64_t) - sizeof(uint32_t)];
};

struct linux_tms {
    long tms_utime;
    long tms_stime;
    long tms_cutime;
    long tms_cstime;
};

static uint64_t ns_to_sched_ticks(uint64_t ns) {
    if (ns == 0)
        return 0;
    uint64_t ticks = (ns * CONFIG_HZ + NS_PER_SEC - 1) / NS_PER_SEC;
    return ticks ? ticks : 1;
}

static int clockid_now_ns(uint64_t clockid, uint64_t *out_ns) {
    if (!out_ns)
        return -EINVAL;
    switch (clockid) {
    case CLOCK_MONOTONIC:
        *out_ns = time_now_ns();
        return 0;
    case CLOCK_REALTIME:
        *out_ns = time_realtime_ns();
        return 0;
    default:
        return -EINVAL;
    }
}

static int64_t sleep_until_deadline(uint64_t deadline, uint64_t rem_ptr,
                                    bool report_remaining) {
    struct process *curr = proc_current();
    if (!curr)
        return -EINVAL;

    while (arch_timer_get_ticks() < deadline) {
        struct poll_sleep sleep = {0};
        INIT_LIST_HEAD(&sleep.node);
        poll_sleep_arm(&sleep, curr, deadline);
        int sleep_rc = proc_sleep_on(NULL, &sleep, true);
        poll_sleep_cancel(&sleep);
        if (sleep_rc == -EINTR) {
            if (report_remaining && rem_ptr) {
                uint64_t now = arch_timer_get_ticks();
                uint64_t rem_ticks = (deadline > now) ? (deadline - now) : 0;
                uint64_t rem_ns = arch_timer_ticks_to_ns(rem_ticks);
                struct timespec rem = {
                    .tv_sec = (time_t)(rem_ns / NS_PER_SEC),
                    .tv_nsec = (int64_t)(rem_ns % NS_PER_SEC),
                };
                if (copy_to_user((void *)rem_ptr, &rem, sizeof(rem)) < 0)
                    return -EFAULT;
            }
            return -EINTR;
        }
    }
    return 0;
}

static char uts_domainname[65] = "kairos";
static char uts_nodename[65] = "kairos";

static const char *uname_machine(void) {
#if defined(ARCH_aarch64)
    return "aarch64";
#elif defined(ARCH_x86_64)
    return "x86_64";
#elif defined(ARCH_riscv64)
    return "riscv64";
#else
    return CONFIG_ARCH;
#endif
}

int64_t sys_clock_gettime(uint64_t clockid, uint64_t tp_ptr, uint64_t a2,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!tp_ptr)
        return -EFAULT;
    uint64_t ns = 0;
    int rc = clockid_now_ns(clockid, &ns);
    if (rc < 0)
        return rc;
    struct timespec ts = {
        .tv_sec = (time_t)(ns / NS_PER_SEC),
        .tv_nsec = (int64_t)(ns % NS_PER_SEC),
    };
    if (copy_to_user((void *)tp_ptr, &ts, sizeof(ts)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_clock_settime(uint64_t clockid, uint64_t tp_ptr, uint64_t a2,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
        return -EINVAL;
    if (clockid == CLOCK_MONOTONIC)
        return -EINVAL;
    struct timespec ts;
    int rc = sys_copy_timespec(tp_ptr, &ts, false);
    if (rc < 0)
        return rc;

    uint64_t req_ns =
        (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
    return time_set_realtime_ns(req_ns);
}

int64_t sys_clock_getres(uint64_t clockid, uint64_t tp_ptr, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!tp_ptr)
        return -EFAULT;
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
        return -EINVAL;

    uint64_t res_ns = (NS_PER_SEC + CONFIG_HZ - 1) / CONFIG_HZ;
    if (res_ns == 0)
        res_ns = 1;
    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = (int64_t)res_ns,
    };
    if (copy_to_user((void *)tp_ptr, &ts, sizeof(ts)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_nanosleep(uint64_t req_ptr, uint64_t rem_ptr, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    struct timespec req;
    int rc = sys_copy_timespec(req_ptr, &req, false);
    if (rc < 0)
        return rc;

    uint64_t ns = (uint64_t)req.tv_sec * NS_PER_SEC + (uint64_t)req.tv_nsec;
    uint64_t delta = ns_to_sched_ticks(ns);
    if (delta == 0)
        return 0;
    uint64_t deadline = arch_timer_get_ticks() + delta;
    return sleep_until_deadline(deadline, rem_ptr, true);
}

int64_t sys_clock_nanosleep(uint64_t clockid, uint64_t flags, uint64_t req_ptr,
                            uint64_t rem_ptr, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (flags & ~TIMER_ABSTIME)
        return -EINVAL;
    uint64_t now_ns = 0;
    int rc = clockid_now_ns(clockid, &now_ns);
    if (rc < 0)
        return rc;
    struct timespec req;
    rc = sys_copy_timespec(req_ptr, &req, false);
    if (rc < 0)
        return rc;

    uint64_t req_ns = (uint64_t)req.tv_sec * NS_PER_SEC + (uint64_t)req.tv_nsec;
    if (flags & TIMER_ABSTIME) {
        while (1) {
            rc = clockid_now_ns(clockid, &now_ns);
            if (rc < 0)
                return rc;
            if (req_ns <= now_ns)
                return 0;
            uint64_t rem_ns = req_ns - now_ns;
            uint64_t delta = ns_to_sched_ticks(rem_ns);
            if (delta == 0)
                return 0;
            uint64_t deadline = arch_timer_get_ticks() + delta;
            rc = sleep_until_deadline(deadline, 0, false);
            if (rc < 0)
                return rc;
        }
    }

    uint64_t delta = ns_to_sched_ticks(req_ns);
    if (delta == 0)
        return 0;
    uint64_t deadline = arch_timer_get_ticks() + delta;
    return sleep_until_deadline(deadline, rem_ptr,
                                (flags & TIMER_ABSTIME) == 0);
}

int64_t sys_gettimeofday(uint64_t tv_ptr, uint64_t tz_ptr, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (tv_ptr) {
        uint64_t ns = time_realtime_ns();
        struct timeval tv = {
            .tv_sec = (time_t)(ns / NS_PER_SEC),
            .tv_usec = (suseconds_t)((ns % NS_PER_SEC) / 1000),
        };
        if (copy_to_user((void *)tv_ptr, &tv, sizeof(tv)) < 0)
            return -EFAULT;
    }
    (void)tz_ptr;
    return 0;
}

int64_t sys_times(uint64_t tms_ptr, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (tms_ptr) {
        struct linux_tms tms = {0};
        struct process *p = proc_current();
        if (p) {
            tms.tms_utime = (long)p->utime;
            tms.tms_stime = (long)p->stime;
        }
        if (copy_to_user((void *)tms_ptr, &tms, sizeof(tms)) < 0)
            return -EFAULT;
    }
    return (int64_t)arch_timer_ticks();
}

int64_t sys_getitimer(uint64_t which, uint64_t value_ptr, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (which != ITIMER_REAL)
        return -EINVAL;
    if (!value_ptr)
        return -EFAULT;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (copy_to_user((void *)value_ptr, &p->itimer_real,
                     sizeof(p->itimer_real)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_setitimer(uint64_t which, uint64_t new_ptr, uint64_t old_ptr,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;
    if (which != ITIMER_REAL)
        return -EINVAL;
    if (!new_ptr)
        return -EFAULT;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    if (old_ptr) {
        if (copy_to_user((void *)old_ptr, &p->itimer_real,
                         sizeof(p->itimer_real)) < 0)
            return -EFAULT;
    }
    struct itimerval val;
    if (copy_from_user(&val, (void *)new_ptr, sizeof(val)) < 0)
        return -EFAULT;
    p->itimer_real = val;
    return 0;
}

int64_t sys_getrusage(uint64_t who, uint64_t rusage_ptr, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)who; (void)a2; (void)a3; (void)a4; (void)a5;
    if (!rusage_ptr)
        return -EFAULT;
    struct process *p = proc_current();
    if (!p)
        return -EINVAL;
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));
    ru.ru_utime.tv_sec = (time_t)(p->utime / CONFIG_HZ);
    ru.ru_utime.tv_usec =
        (suseconds_t)((p->utime % CONFIG_HZ) * 1000000ULL / CONFIG_HZ);
    ru.ru_stime.tv_sec = (time_t)(p->stime / CONFIG_HZ);
    ru.ru_stime.tv_usec =
        (suseconds_t)((p->stime % CONFIG_HZ) * 1000000ULL / CONFIG_HZ);
    if (copy_to_user((void *)rusage_ptr, &ru, sizeof(ru)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_sysinfo(uint64_t info_ptr, uint64_t a1, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (!info_ptr)
        return -EFAULT;

    struct linux_sysinfo info;
    memset(&info, 0, sizeof(info));
    uint64_t ns = time_now_ns();
    info.uptime = (int64_t)(ns / NS_PER_SEC);

    size_t total_pages = pmm_total_pages();
    size_t free_pages = pmm_num_free_pages();
    info.totalram = (uint64_t)total_pages * CONFIG_PAGE_SIZE;
    info.freeram = (uint64_t)free_pages * CONFIG_PAGE_SIZE;
    info.mem_unit = 1;

    if (copy_to_user((void *)info_ptr, &info, sizeof(info)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_uname(uint64_t buf_ptr, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (!buf_ptr)
        return -EFAULT;
    struct linux_utsname uts;
    memset(&uts, 0, sizeof(uts));
    strcpy(uts.sysname, "Kairos");
    strncpy(uts.nodename, uts_nodename, sizeof(uts.nodename) - 1);
    strcpy(uts.release, "0.1.0");
    strcpy(uts.version, "kairos");
    strncpy(uts.machine, uname_machine(), sizeof(uts.machine) - 1);
    strncpy(uts.domainname, uts_domainname, sizeof(uts.domainname) - 1);
    if (copy_to_user((void *)buf_ptr, &uts, sizeof(uts)) < 0)
        return -EFAULT;
    return 0;
}

int64_t sys_sethostname(uint64_t name_ptr, uint64_t len, uint64_t a2,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (len > sizeof(uts_nodename) - 1)
        return -EINVAL;
    if (len > 0 && !name_ptr)
        return -EFAULT;
    char tmp[65];
    memset(tmp, 0, sizeof(tmp));
    if (len > 0) {
        if (copy_from_user(tmp, (const void *)name_ptr, (size_t)len) < 0)
            return -EFAULT;
    }
    memset(uts_nodename, 0, sizeof(uts_nodename));
    memcpy(uts_nodename, tmp, (size_t)len);
    return 0;
}

int64_t sys_setdomainname(uint64_t name_ptr, uint64_t len, uint64_t a2,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (len > sizeof(uts_domainname) - 1)
        return -EINVAL;
    if (len > 0 && !name_ptr)
        return -EFAULT;
    char tmp[65];
    memset(tmp, 0, sizeof(tmp));
    if (len > 0) {
        if (copy_from_user(tmp, (const void *)name_ptr, (size_t)len) < 0)
            return -EFAULT;
    }
    memset(uts_domainname, 0, sizeof(uts_domainname));
    memcpy(uts_domainname, tmp, (size_t)len);
    return 0;
}
