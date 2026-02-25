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
#define CLOCK_TAI_UTC_BASE_OFFSET_SEC 10ULL
#define CLOCK_TAI_UTC_BASE_OFFSET_NS (CLOCK_TAI_UTC_BASE_OFFSET_SEC * NS_PER_SEC)
#define CLOCK_TAI_OFFSET_MAX_NS (~(1ULL << 63))

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

struct tai_utc_step {
    uint64_t realtime_ns;
    int64_t offset_ns;
};

static const struct tai_utc_step clock_tai_utc_steps[] = {
    { 78796800ULL * NS_PER_SEC, 11LL * NS_PER_SEC },   /* 1972-07-01 */
    { 94694400ULL * NS_PER_SEC, 12LL * NS_PER_SEC },   /* 1973-01-01 */
    { 126230400ULL * NS_PER_SEC, 13LL * NS_PER_SEC },  /* 1974-01-01 */
    { 157766400ULL * NS_PER_SEC, 14LL * NS_PER_SEC },  /* 1975-01-01 */
    { 189302400ULL * NS_PER_SEC, 15LL * NS_PER_SEC },  /* 1976-01-01 */
    { 220924800ULL * NS_PER_SEC, 16LL * NS_PER_SEC },  /* 1977-01-01 */
    { 252460800ULL * NS_PER_SEC, 17LL * NS_PER_SEC },  /* 1978-01-01 */
    { 283996800ULL * NS_PER_SEC, 18LL * NS_PER_SEC },  /* 1979-01-01 */
    { 315532800ULL * NS_PER_SEC, 19LL * NS_PER_SEC },  /* 1980-01-01 */
    { 362793600ULL * NS_PER_SEC, 20LL * NS_PER_SEC },  /* 1981-07-01 */
    { 394329600ULL * NS_PER_SEC, 21LL * NS_PER_SEC },  /* 1982-07-01 */
    { 425865600ULL * NS_PER_SEC, 22LL * NS_PER_SEC },  /* 1983-07-01 */
    { 489024000ULL * NS_PER_SEC, 23LL * NS_PER_SEC },  /* 1985-07-01 */
    { 567993600ULL * NS_PER_SEC, 24LL * NS_PER_SEC },  /* 1988-01-01 */
    { 631152000ULL * NS_PER_SEC, 25LL * NS_PER_SEC },  /* 1990-01-01 */
    { 662688000ULL * NS_PER_SEC, 26LL * NS_PER_SEC },  /* 1991-01-01 */
    { 709948800ULL * NS_PER_SEC, 27LL * NS_PER_SEC },  /* 1992-07-01 */
    { 741484800ULL * NS_PER_SEC, 28LL * NS_PER_SEC },  /* 1993-07-01 */
    { 773020800ULL * NS_PER_SEC, 29LL * NS_PER_SEC },  /* 1994-07-01 */
    { 820454400ULL * NS_PER_SEC, 30LL * NS_PER_SEC },  /* 1996-01-01 */
    { 867715200ULL * NS_PER_SEC, 31LL * NS_PER_SEC },  /* 1997-07-01 */
    { 915148800ULL * NS_PER_SEC, 32LL * NS_PER_SEC },  /* 1999-01-01 */
    { 1136073600ULL * NS_PER_SEC, 33LL * NS_PER_SEC }, /* 2006-01-01 */
    { 1230768000ULL * NS_PER_SEC, 34LL * NS_PER_SEC }, /* 2009-01-01 */
    { 1341100800ULL * NS_PER_SEC, 35LL * NS_PER_SEC }, /* 2012-07-01 */
    { 1435708800ULL * NS_PER_SEC, 36LL * NS_PER_SEC }, /* 2015-07-01 */
    { 1483228800ULL * NS_PER_SEC, 37LL * NS_PER_SEC }, /* 2017-01-01 */
};

static int64_t clock_tai_user_offset_ns = 0;

static int64_t saturating_add_i64(int64_t a, int64_t b) {
    __int128 sum = (__int128)a + (__int128)b;
    if (sum > INT64_MAX)
        return INT64_MAX;
    if (sum < INT64_MIN)
        return INT64_MIN;
    return (int64_t)sum;
}

static int64_t clock_tai_base_offset_ns(uint64_t realtime_ns) {
    int64_t off = (int64_t)CLOCK_TAI_UTC_BASE_OFFSET_NS;
    for (size_t i = 0; i < ARRAY_SIZE(clock_tai_utc_steps); i++) {
        if (realtime_ns < clock_tai_utc_steps[i].realtime_ns)
            break;
        off = clock_tai_utc_steps[i].offset_ns;
    }
    return off;
}

static int64_t clock_tai_total_offset_ns(uint64_t realtime_ns) {
    int64_t base = clock_tai_base_offset_ns(realtime_ns);
    int64_t user = __atomic_load_n(&clock_tai_user_offset_ns, __ATOMIC_RELAXED);
    return saturating_add_i64(base, user);
}

static uint64_t time_quantum_ns_from_hz(uint64_t hz) {
    if (hz == 0)
        return 1;
    uint64_t q = (NS_PER_SEC + hz - 1) / hz;
    return q ? q : 1;
}

static uint64_t monotonic_raw_now_ns(void) {
    return arch_timer_ticks_to_ns(arch_timer_ticks());
}

static uint64_t monotonic_now_ns(void) {
    return time_now_ns();
}

static uint64_t realtime_now_ns(void) {
    return time_realtime_ns();
}

static uint64_t coarse_quantum_ns(void) {
    return time_quantum_ns_from_hz(CONFIG_HZ);
}

static uint64_t monotonic_coarse_now_ns(void) {
    uint64_t quantum = coarse_quantum_ns();
    uint64_t now = monotonic_now_ns();
    return (now / quantum) * quantum;
}

static uint64_t realtime_coarse_now_ns(void) {
    uint64_t quantum = coarse_quantum_ns();
    uint64_t now = realtime_now_ns();
    return (now / quantum) * quantum;
}

static uint64_t highres_quantum_ns(void) {
    return time_quantum_ns_from_hz(arch_timer_freq());
}

static uint64_t cpu_clock_quantum_ns(void) {
    return time_quantum_ns_from_hz(CONFIG_HZ);
}

static uint64_t ns_to_sched_ticks(uint64_t ns) {
    if (ns == 0)
        return 0;
    uint64_t ticks = (ns * CONFIG_HZ + NS_PER_SEC - 1) / NS_PER_SEC;
    return ticks ? ticks : 1;
}

static uint64_t sched_ticks_to_ns(uint64_t ticks) {
    if (ticks == 0)
        return 0;
    if (ticks > UINT64_MAX / NS_PER_SEC)
        return UINT64_MAX;
    return (ticks * NS_PER_SEC) / CONFIG_HZ;
}

static inline int32_t systime_abi_i32(uint64_t raw) {
    return (int32_t)(uint32_t)raw;
}

static uint64_t apply_signed_offset_ns(uint64_t base_ns, int64_t off_ns) {
    if (off_ns >= 0) {
        uint64_t off = (uint64_t)off_ns;
        if (base_ns > UINT64_MAX - off)
            return UINT64_MAX;
        return base_ns + off;
    }
    uint64_t neg = (uint64_t)(-(off_ns + 1)) + 1ULL;
    return (base_ns > neg) ? (base_ns - neg) : 0;
}

static uint64_t realtime_to_tai_ns(uint64_t realtime_ns) {
    int64_t off = clock_tai_total_offset_ns(realtime_ns);
    return apply_signed_offset_ns(realtime_ns, off);
}

static uint64_t tai_to_realtime_ns(uint64_t tai_ns) {
    uint64_t guess = apply_signed_offset_ns(
        tai_ns, -clock_tai_total_offset_ns(time_realtime_ns()));
    for (int i = 0; i < 4; i++) {
        int64_t off = clock_tai_total_offset_ns(guess);
        uint64_t next = apply_signed_offset_ns(tai_ns, -off);
        if (next == guess)
            break;
        guess = next;
    }
    return guess;
}

static int time_set_tai_ns(uint64_t tai_ns, uint64_t realtime_ns) {
    int64_t desired_off = 0;
    if (tai_ns >= realtime_ns) {
        uint64_t delta = tai_ns - realtime_ns;
        if (delta > CLOCK_TAI_OFFSET_MAX_NS)
            return -ERANGE;
        desired_off = (int64_t)delta;
    } else {
        uint64_t delta = realtime_ns - tai_ns;
        if (delta > CLOCK_TAI_OFFSET_MAX_NS)
            return -ERANGE;
        desired_off = -(int64_t)delta;
    }
    int64_t base = clock_tai_base_offset_ns(realtime_ns);
    __int128 user = (__int128)desired_off - (__int128)base;
    if (user > INT64_MAX || user < INT64_MIN)
        return -ERANGE;
    __atomic_store_n(&clock_tai_user_offset_ns, (int64_t)user, __ATOMIC_RELAXED);
    return 0;
}

static int clockid_sleep_base(int32_t clockid, int32_t *base_clockid) {
    if (!base_clockid)
        return -EINVAL;

    switch (clockid) {
    case CLOCK_MONOTONIC:
    case CLOCK_BOOTTIME:
        *base_clockid = CLOCK_MONOTONIC;
        return 0;
    case CLOCK_REALTIME:
        *base_clockid = CLOCK_REALTIME;
        return 0;
    case CLOCK_TAI:
        /* CLOCK_TAI sleeps use realtime base with explicit deadline conversion. */
        *base_clockid = CLOCK_REALTIME;
        return 0;
    default:
        return -EINVAL;
    }
}

static int clockid_now_ns(int32_t clockid, uint64_t *out_ns) {
    if (!out_ns)
        return -EINVAL;
    switch (clockid) {
    case CLOCK_PROCESS_CPUTIME_ID:
    case CLOCK_THREAD_CPUTIME_ID: {
        struct process *p = proc_current();
        if (!p)
            return -EINVAL;
        *out_ns = sched_ticks_to_ns(p->utime + p->stime);
        return 0;
    }
    case CLOCK_MONOTONIC:
        *out_ns = monotonic_now_ns();
        return 0;
    case CLOCK_MONOTONIC_RAW:
        *out_ns = monotonic_raw_now_ns();
        return 0;
    case CLOCK_BOOTTIME:
    case CLOCK_BOOTTIME_ALARM:
        *out_ns = monotonic_now_ns();
        return 0;
    case CLOCK_MONOTONIC_COARSE:
        *out_ns = monotonic_coarse_now_ns();
        return 0;
    case CLOCK_REALTIME:
    case CLOCK_REALTIME_ALARM:
        *out_ns = realtime_now_ns();
        return 0;
    case CLOCK_REALTIME_COARSE:
        *out_ns = realtime_coarse_now_ns();
        return 0;
    case CLOCK_TAI:
        *out_ns = realtime_to_tai_ns(realtime_now_ns());
        return 0;
    default:
        return -EINVAL;
    }
}

static int clockid_resolution_ns(int32_t clockid, uint64_t *out_res_ns) {
    if (!out_res_ns)
        return -EINVAL;
    switch (clockid) {
    case CLOCK_PROCESS_CPUTIME_ID:
    case CLOCK_THREAD_CPUTIME_ID:
        *out_res_ns = cpu_clock_quantum_ns();
        return 0;
    case CLOCK_MONOTONIC_RAW:
        *out_res_ns = highres_quantum_ns();
        return 0;
    case CLOCK_MONOTONIC_COARSE:
    case CLOCK_REALTIME_COARSE:
        *out_res_ns = coarse_quantum_ns();
        return 0;
    case CLOCK_MONOTONIC:
    case CLOCK_BOOTTIME:
    case CLOCK_BOOTTIME_ALARM:
    case CLOCK_REALTIME:
    case CLOCK_REALTIME_ALARM:
    case CLOCK_TAI:
        *out_res_ns = highres_quantum_ns();
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

static int64_t clock_nanosleep_abstime(int32_t clockid, uint64_t req_ns) {
    while (1) {
        uint64_t now_ns = 0;
        int rc = clockid_now_ns(clockid, &now_ns);
        if (rc < 0)
            return rc;
        if (req_ns <= now_ns)
            return 0;

        uint64_t rem_ns = req_ns - now_ns;
        uint64_t delta = ns_to_sched_ticks(rem_ns);
        if (delta == 0)
            return 0;
        /*
         * CLOCK_REALTIME absolute sleep must observe wall-clock adjustments.
         * Re-check once per scheduler tick so clock_settime() deltas are
         * reflected promptly.
         */
        if (clockid == CLOCK_REALTIME && delta > 1)
            delta = 1;
        uint64_t deadline = arch_timer_get_ticks() + delta;
        rc = sleep_until_deadline(deadline, 0, false);
        if (rc < 0)
            return rc;
    }
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
    int32_t kclockid = systime_abi_i32(clockid);
    uint64_t ns = 0;
    int rc = clockid_now_ns(kclockid, &ns);
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
    int32_t kclockid = systime_abi_i32(clockid);
    struct timespec ts;
    int rc = sys_copy_timespec(tp_ptr, &ts, false);
    if (rc < 0)
        return rc;

    uint64_t req_ns =
        (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
    if (kclockid == CLOCK_REALTIME)
        return time_set_realtime_ns(req_ns);
    if (kclockid == CLOCK_TAI)
        return time_set_tai_ns(req_ns, time_realtime_ns());
    return -EINVAL;
}

int64_t sys_clock_getres(uint64_t clockid, uint64_t tp_ptr, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    if (!tp_ptr)
        return -EFAULT;
    int32_t kclockid = systime_abi_i32(clockid);
    uint64_t res_ns = 0;
    if (clockid_resolution_ns(kclockid, &res_ns) < 0)
        return -EINVAL;
    struct timespec ts = {
        .tv_sec = (time_t)(res_ns / NS_PER_SEC),
        .tv_nsec = (int64_t)(res_ns % NS_PER_SEC),
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
    uint32_t uflags = (uint32_t)flags;
    int32_t kclockid = systime_abi_i32(clockid);
    if (uflags & ~TIMER_ABSTIME)
        return -EINVAL;
    int32_t sleep_clockid = 0;
    int rc = clockid_sleep_base(kclockid, &sleep_clockid);
    if (rc < 0)
        return rc;
    struct timespec req;
    rc = sys_copy_timespec(req_ptr, &req, false);
    if (rc < 0)
        return rc;

    uint64_t req_ns = (uint64_t)req.tv_sec * NS_PER_SEC + (uint64_t)req.tv_nsec;
    if ((uflags & TIMER_ABSTIME) && kclockid == CLOCK_TAI)
        req_ns = tai_to_realtime_ns(req_ns);
    if (uflags & TIMER_ABSTIME)
        return clock_nanosleep_abstime(sleep_clockid, req_ns);

    uint64_t delta = ns_to_sched_ticks(req_ns);
    if (delta == 0)
        return 0;
    uint64_t deadline = arch_timer_get_ticks() + delta;
    return sleep_until_deadline(deadline, rem_ptr,
                                (uflags & TIMER_ABSTIME) == 0);
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
    int32_t kwhich = systime_abi_i32(which);
    if (kwhich != ITIMER_REAL)
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
    int32_t kwhich = systime_abi_i32(which);
    if (kwhich != ITIMER_REAL)
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
