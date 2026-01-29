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

#define NS_PER_SEC 1000000000ULL

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
    uint64_t ticks = (ns * CONFIG_HZ + NS_PER_SEC - 1) / NS_PER_SEC;
    return ticks ? ticks : 1;
}

static int copy_timespec_from_user(uint64_t ptr, struct timespec *out) {
    if (!ptr || !out)
        return -EFAULT;
    if (copy_from_user(out, (const void *)ptr, sizeof(*out)) < 0)
        return -EFAULT;
    if (out->tv_sec < 0 || out->tv_nsec < 0 || out->tv_nsec >= (int64_t)NS_PER_SEC)
        return -EINVAL;
    return 1;
}

int64_t sys_clock_gettime(uint64_t clockid, uint64_t tp_ptr, uint64_t a2,
                          uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!tp_ptr)
        return -EFAULT;
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
        return -EINVAL;

    uint64_t ns = arch_timer_ticks_to_ns(arch_timer_ticks());
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
    struct timespec ts;
    int rc = copy_timespec_from_user(tp_ptr, &ts);
    if (rc < 0)
        return rc;
    /* No RTC or time-setting support yet. */
    return -EPERM;
}

int64_t sys_nanosleep(uint64_t req_ptr, uint64_t rem_ptr, uint64_t a2,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)rem_ptr; (void)a2; (void)a3; (void)a4; (void)a5;
    struct timespec req;
    int rc = copy_timespec_from_user(req_ptr, &req);
    if (rc < 0)
        return rc;

    uint64_t ns = (uint64_t)req.tv_sec * NS_PER_SEC + (uint64_t)req.tv_nsec;
    uint64_t delta = ns_to_sched_ticks(ns);
    uint64_t deadline = arch_timer_get_ticks() + delta;

    struct process *curr = proc_current();
    while (arch_timer_get_ticks() < deadline) {
        struct poll_sleep sleep = {0};
        INIT_LIST_HEAD(&sleep.node);
        poll_sleep_arm(&sleep, curr, deadline);
        curr->state = PROC_SLEEPING;
        curr->wait_channel = NULL;
        schedule();
        poll_sleep_cancel(&sleep);
        if (curr->sig_pending)
            return -EINTR;
    }
    return 0;
}

int64_t sys_clock_nanosleep(uint64_t clockid, uint64_t flags, uint64_t req_ptr,
                            uint64_t rem_ptr, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (flags != 0)
        return -EINVAL;
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
        return -EINVAL;
    return sys_nanosleep(req_ptr, rem_ptr, 0, 0, 0, 0);
}

int64_t sys_gettimeofday(uint64_t tv_ptr, uint64_t tz_ptr, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (tv_ptr) {
        uint64_t ns = arch_timer_ticks_to_ns(arch_timer_ticks());
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

int64_t sys_sysinfo(uint64_t info_ptr, uint64_t a1, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (!info_ptr)
        return -EFAULT;

    struct linux_sysinfo info;
    memset(&info, 0, sizeof(info));
    uint64_t ns = arch_timer_ticks_to_ns(arch_timer_ticks());
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
    strcpy(uts.nodename, "kairos");
    strcpy(uts.release, "0.1.0");
    strcpy(uts.version, "kairos");
    strcpy(uts.machine, "riscv64");
    if (copy_to_user((void *)buf_ptr, &uts, sizeof(uts)) < 0)
        return -EFAULT;
    return 0;
}
