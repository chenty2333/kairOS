/**
 * kernel/fs/procfs/procfs.c - Process filesystem
 *
 * Virtual filesystem providing process and system information at /proc.
 * Supports static global entries (meminfo, uptime, stat, version) and
 * dynamic per-PID entries (stat, status, cmdline, maps).
 */

#include <kairos/config.h>
#include <kairos/boot.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/platform_core.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/signal.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/time.h>
#include <kairos/types.h>
#include <kairos/vfs.h>

#define PROC_SUPER_MAGIC 0x9FA0
#define PROCFS_BUF_SIZE  4096

/* Entry types */
enum procfs_type {
    PROCFS_ROOT,
    PROCFS_STATIC,
    PROCFS_PID_DIR,
    PROCFS_PID_ENTRY,
    PROCFS_SELF_LINK
};

/* Generator function type */
typedef int (*procfs_gen_t)(pid_t pid, char *buf, size_t bufsz);

struct procfs_entry {
    char name[CONFIG_NAME_MAX];
    enum procfs_type type;
    ino_t ino;
    pid_t pid;
    procfs_gen_t generate;
    struct vnode vn;
    struct procfs_entry *next;
};

struct procfs_mount {
    struct procfs_entry *root;
    struct procfs_entry *entries;
    ino_t next_ino;
    spinlock_t lock;
    struct mount *mnt;
};

/* Forward declarations */
static struct vnode *procfs_lookup(struct vnode *dir, const char *name);
static int procfs_readdir(struct vnode *vn, struct dirent *ent, off_t *off);
static ssize_t procfs_read(struct vnode *vn, void *buf, size_t len, off_t off,
                           uint32_t flags);
static ssize_t procfs_write(struct vnode *vn, const void *buf, size_t len,
                            off_t off, uint32_t flags);
static ssize_t procfs_self_read(struct vnode *vn, void *buf, size_t len,
                                off_t off, uint32_t flags);
static int procfs_dir_poll(struct file *file, uint32_t events);
static int procfs_file_poll(struct file *file, uint32_t events);
static int procfs_close(struct vnode *vn);

/* Generator functions */
static int gen_meminfo(pid_t pid, char *buf, size_t bufsz);
static int gen_uptime(pid_t pid, char *buf, size_t bufsz);
static int gen_stat(pid_t pid, char *buf, size_t bufsz);
static int gen_interrupts(pid_t pid, char *buf, size_t bufsz);
static int gen_sched(pid_t pid, char *buf, size_t bufsz);
static int gen_version(pid_t pid, char *buf, size_t bufsz);
static int gen_cmdline(pid_t pid, char *buf, size_t bufsz);
static int gen_mounts(pid_t pid, char *buf, size_t bufsz);
static int gen_mm_pcp(pid_t pid, char *buf, size_t bufsz);
static int gen_mm_integrity(pid_t pid, char *buf, size_t bufsz);
static int gen_mm_remote_free(pid_t pid, char *buf, size_t bufsz);
static int gen_pid_stat(pid_t pid, char *buf, size_t bufsz);
static int gen_pid_status(pid_t pid, char *buf, size_t bufsz);
static int gen_pid_cmdline(pid_t pid, char *buf, size_t bufsz);
static int gen_pid_maps(pid_t pid, char *buf, size_t bufsz);

static size_t procfs_self_target(char *buf, size_t bufsz) {
    struct process *cur = proc_current();
    pid_t pid = cur ? cur->pid : 1;
    int n = snprintf(buf, bufsz, "%d", pid);
    if (n < 0)
        return 0;
    if ((size_t)n >= bufsz)
        return bufsz ? (bufsz - 1) : 0;
    return (size_t)n;
}

static struct file_ops procfs_dir_ops = {
    .readdir = procfs_readdir,
    .poll = procfs_dir_poll,
    .close = procfs_close,
};

static struct file_ops procfs_file_ops = {
    .read = procfs_read,
    .write = procfs_write,
    .poll = procfs_file_poll,
    .close = procfs_close,
};

static struct file_ops procfs_symlink_ops = {
    .read = procfs_self_read,
    .poll = procfs_file_poll,
    .close = procfs_close,
};

/* ------------------------------------------------------------------ */
/*  vnode helpers                                                      */
/* ------------------------------------------------------------------ */

static void procfs_init_vnode(struct vnode *vn, struct mount *mnt,
                              struct procfs_entry *ent, enum vnode_type type,
                              mode_t mode, struct file_ops *ops) {
    vn->type = type;
    vn->mode = mode;
    vn->uid = 0;
    vn->gid = 0;
    vn->size = 0;
    vn->ino = ent->ino;
    vn->nlink = 1;
    vn->atime = vn->mtime = vn->ctime = 0;
    vn->rdev = 0;
    vn->ops = ops;
    vn->fs_data = ent;
    vn->mount = mnt;
    atomic_init(&vn->refcount, 1);
    vn->parent = NULL;
    vn->name[0] = '\0';
    rwlock_init(&vn->lock, "procfs_vn");
    poll_wait_head_init(&vn->pollers);
}

static struct procfs_entry *procfs_alloc_entry(struct procfs_mount *pm,
                                               const char *name,
                                               enum procfs_type type,
                                               procfs_gen_t gen,
                                               pid_t pid) {
    struct procfs_entry *ent = kzalloc(sizeof(*ent));
    if (!ent)
        return NULL;
    strncpy(ent->name, name, CONFIG_NAME_MAX - 1);
    ent->type = type;
    ent->ino = pm->next_ino++;
    ent->pid = pid;
    ent->generate = gen;
    ent->next = pm->entries;
    pm->entries = ent;
    return ent;
}

/* ------------------------------------------------------------------ */
/*  Static entry generators                                            */
/* ------------------------------------------------------------------ */

static int gen_meminfo(pid_t pid __attribute__((unused)),
                       char *buf, size_t bufsz) {
    size_t total = pmm_total_pages();
    size_t free = pmm_num_free_pages();
    size_t total_kb = (total * CONFIG_PAGE_SIZE) / 1024;
    size_t free_kb = (free * CONFIG_PAGE_SIZE) / 1024;
    return snprintf(buf, bufsz,
                    "MemTotal:       %lu kB\n"
                    "MemFree:        %lu kB\n"
                    "MemAvailable:   %lu kB\n",
                    (unsigned long)total_kb, (unsigned long)free_kb,
                    (unsigned long)free_kb);
}

static int gen_uptime(pid_t pid __attribute__((unused)),
                      char *buf, size_t bufsz) {
    uint64_t ns = time_now_ns();
    uint64_t sec = ns / 1000000000ULL;
    uint64_t frac = (ns % 1000000000ULL) / 10000000ULL;
    return snprintf(buf, bufsz, "%lu.%02lu 0.00\n",
                    (unsigned long)sec, (unsigned long)frac);
}

static int gen_stat(pid_t pid __attribute__((unused)),
                    char *buf, size_t bufsz) {
    int ncpu = sched_cpu_count();
    int len = 0;
    uint64_t total_ticks = 0;
    for (int i = 0; i < ncpu; i++) {
        struct percpu_data *cd = sched_cpu_data(i);
        if (cd) {
            total_ticks += cd->ticks;
        }
    }
    len += snprintf(buf + len, bufsz - (size_t)len,
                    "cpu  %lu 0 0 0 0 0 0 0 0 0\n",
                    (unsigned long)total_ticks);
    for (int i = 0; i < ncpu && (size_t)len < bufsz; i++) {
        struct percpu_data *cd = sched_cpu_data(i);
        uint64_t t = cd ? cd->ticks : 0;
        len += snprintf(buf + len, bufsz - (size_t)len,
                        "cpu%d %lu 0 0 0 0 0 0 0 0 0\n",
                        i, (unsigned long)t);
    }
    return len;
}

static int gen_interrupts(pid_t pid __attribute__((unused)),
                          char *buf, size_t bufsz)
{
    return platform_irq_format_proc_interrupts(buf, bufsz, true);
}

static int gen_sched(pid_t pid __attribute__((unused)),
                     char *buf, size_t bufsz) {
    struct sched_stats stats;
    sched_get_stats(&stats);

    int len = 0;
    len += snprintf(buf + len, bufsz - (size_t)len,
                    "cpus %u\n"
                    "steal_enabled %u\n",
                    stats.cpu_count, stats.steal_enabled ? 1U : 0U);

    for (uint32_t i = 0; i < stats.cpu_count && (size_t)len < bufsz; i++) {
        uint32_t nr_running = sched_rq_nr_running((int)i);
        uint64_t min_vruntime = sched_rq_min_vruntime((int)i);
        struct percpu_data *cd = sched_cpu_data((int)i);
        uint64_t ticks = cd ? cd->ticks : 0;
        struct sched_cpu_stats *cpu = &stats.cpu[i];
        len += snprintf(
            buf + len, bufsz - (size_t)len,
            "cpu%u rq=%u min_vruntime=%llu ticks=%llu "
            "enq=%llu deq=%llu pick=%llu switch=%llu idle_pick=%llu "
            "steal=%llu/%llu violations=%llu\n",
            i, nr_running, (unsigned long long)min_vruntime,
            (unsigned long long)ticks,
            (unsigned long long)cpu->enqueue_count,
            (unsigned long long)cpu->dequeue_count,
            (unsigned long long)cpu->pick_count,
            (unsigned long long)cpu->switch_count,
            (unsigned long long)cpu->idle_pick_count,
            (unsigned long long)cpu->steal_success_count,
            (unsigned long long)cpu->steal_attempt_count,
            (unsigned long long)cpu->state_violation_count);
    }

    return len;
}

static int gen_version(pid_t pid __attribute__((unused)),
                       char *buf, size_t bufsz) {
    return snprintf(buf, bufsz,
                    "Kairos version 0.1.0 (kairos@build) "
                    "(clang) #1 SMP\n");
}

static int gen_cmdline(pid_t pid __attribute__((unused)),
                       char *buf, size_t bufsz) {
    const struct boot_info *bi = boot_info_get();
    const char *cmd = (bi && bi->cmdline) ? bi->cmdline : "";
    return snprintf(buf, bufsz, "%s\n", cmd);
}

static int gen_mounts(pid_t pid __attribute__((unused)),
                      char *buf, size_t bufsz) {
    const char *paths[] = {"/", "/proc", "/dev", "/tmp", "/sys", "/oldroot"};
    struct mount *seen[ARRAY_SIZE(paths)] = {0};
    size_t seen_count = 0;
    int len = 0;

    for (size_t i = 0; i < ARRAY_SIZE(paths); i++) {
        struct mount *mnt = vfs_mount_for_path(paths[i]);
        if (!mnt)
            continue;

        bool duplicate = false;
        for (size_t j = 0; j < seen_count; j++) {
            if (seen[j] == mnt) {
                duplicate = true;
                break;
            }
        }
        if (duplicate)
            continue;
        seen[seen_count++] = mnt;

        const char *target =
            (mnt->mountpoint && mnt->mountpoint[0] != '\0') ?
                mnt->mountpoint :
                paths[i];
        const char *fstype =
            (mnt->ops && mnt->ops->name) ? mnt->ops->name : "unknown";

        if ((size_t)len >= bufsz)
            break;
        int n = snprintf(buf + len, bufsz - (size_t)len, "none %s %s rw 0 0\n",
                         target, fstype);
        if (n < 0)
            return len;
        if ((size_t)n >= bufsz - (size_t)len) {
            len = (int)bufsz - 1;
            break;
        }
        len += n;
    }

    if (len == 0)
        len = snprintf(buf, bufsz, "none / rootfs rw 0 0\n");
    return len;
}

static int gen_mm_pcp(pid_t pid __attribute__((unused)),
                      char *buf, size_t bufsz) {
    int n = pmm_pcp_report(buf, bufsz);
    if (n < 0)
        return snprintf(buf, bufsz, "pmm_pcp_report unavailable (%d)\n", n);
    return n;
}

static int gen_mm_integrity(pid_t pid __attribute__((unused)),
                            char *buf, size_t bufsz) {
    int n = pmm_integrity_report(buf, bufsz);
    if (n < 0)
        return snprintf(buf, bufsz, "pmm_integrity_report unavailable (%d)\n",
                        n);
    return n;
}

static int gen_mm_remote_free(pid_t pid __attribute__((unused)),
                              char *buf, size_t bufsz) {
    int n = pmm_remote_free_report(buf, bufsz);
    if (n < 0)
        return snprintf(buf, bufsz,
                        "pmm_remote_free_report unavailable (%d)\n", n);
    return n;
}

/* ------------------------------------------------------------------ */
/*  Per-PID entry generators                                           */
/* ------------------------------------------------------------------ */

static const char *proc_state_char(enum proc_state s) {
    switch (s) {
    case PROC_RUNNING:  return "R";
    case PROC_RUNNABLE: return "R";
    case PROC_SLEEPING: return "S";
    case PROC_ZOMBIE:   return "Z";
    default:            return "?";
    }
}

static inline struct process *pid_to_proc(pid_t pid) {
    return proc_find(pid);
}

static void procfs_calc_vsz_rss(const struct process *p, uint64_t *vsz_bytes,
                                uint64_t *rss_pages) {
    if (!p || !p->mm) {
        *vsz_bytes = 0;
        *rss_pages = 0;
        return;
    }

    uint64_t total = 0;
    mutex_lock(&p->mm->lock);
    struct vm_area *vma;
    list_for_each_entry(vma, &p->mm->vma_list, list) {
        if (vma->end > vma->start)
            total += (uint64_t)(vma->end - vma->start);
    }
    mutex_unlock(&p->mm->lock);

    *vsz_bytes = total;
    *rss_pages = (total + CONFIG_PAGE_SIZE - 1) / CONFIG_PAGE_SIZE;
}

static int gen_pid_stat(pid_t pid, char *buf, size_t bufsz) {
    struct process *p = pid_to_proc(pid);
    if (!p)
        return -ENOENT;

    uint64_t vsz_bytes = 0;
    uint64_t rss_pages = 0;
    procfs_calc_vsz_rss(p, &vsz_bytes, &rss_pages);

    int priority = 20 + p->se.nice;
    int num_threads = 1;

    return snprintf(
        buf, bufsz,
        "%d (%s) %s "     /* pid, comm, state */
        "%d %d %d "       /* ppid, pgrp, session */
        "0 0 "            /* tty_nr, tpgid */
        "0 "              /* flags */
        "0 0 0 0 "        /* minflt, cminflt, majflt, cmajflt */
        "%lu %lu "        /* utime, stime */
        "0 0 "            /* cutime, cstime */
        "%d %d "          /* priority, nice */
        "%d 0 "           /* num_threads, itrealvalue */
        "%lu "            /* start_time */
        "%llu "           /* vsize */
        "%lu "            /* rss */
        "0 0 0 0 0 0 0 0 "/* rsslim..kstkeip */
        "0 0 0 0 "        /* signal..sigcatch */
        "0 0 0 "          /* wchan, nswap, cnswap */
        "0 "              /* exit_signal */
        "0 0 0 0 "        /* processor, rt_priority, policy, delayacct */
        "0 0 0 0 0 0 0 "  /* guest_time..env_end */
        "0\n",            /* exit_code */
        p->pid, p->name, proc_state_char(p->state), p->ppid, p->pgid, p->sid,
        (unsigned long)p->utime, (unsigned long)p->stime, priority, p->se.nice,
        num_threads, (unsigned long)p->start_time,
        (unsigned long long)vsz_bytes, (unsigned long)rss_pages);
}

static int gen_pid_status(pid_t pid, char *buf, size_t bufsz) {
    struct process *p = pid_to_proc(pid);
    if (!p)
        return -ENOENT;
    return snprintf(buf, bufsz,
                    "Name:\t%s\n"
                    "State:\t%s\n"
                    "Pid:\t%d\n"
                    "PPid:\t%d\n"
                    "Uid:\t%u\n"
                    "Gid:\t%u\n",
                    p->name, proc_state_char(p->state),
                    p->pid, p->ppid, p->uid, p->gid);
}

static int gen_pid_cmdline(pid_t pid, char *buf, size_t bufsz) {
    struct process *p = pid_to_proc(pid);
    if (!p)
        return -ENOENT;
    size_t nlen = strlen(p->name);
    if (nlen >= bufsz)
        nlen = bufsz - 1;
    memcpy(buf, p->name, nlen);
    buf[nlen] = '\0';
    return (int)nlen;
}

static int gen_pid_maps(pid_t pid, char *buf, size_t bufsz) {
    struct process *p = pid_to_proc(pid);
    if (!p || !p->mm)
        return -ENOENT;
    int len = 0;
    struct vm_area *vma;
    list_for_each_entry(vma, &p->mm->vma_list, list) {
        if ((size_t)len >= bufsz - 1)
            break;
        char r = (vma->flags & VM_READ)  ? 'r' : '-';
        char w = (vma->flags & VM_WRITE) ? 'w' : '-';
        char x = (vma->flags & VM_EXEC)  ? 'x' : '-';
        char s = (vma->flags & VM_SHARED) ? 's' : 'p';
        len += snprintf(buf + len, bufsz - (size_t)len,
                        "%08lx-%08lx %c%c%c%c %08lx 00:00 0\n",
                        (unsigned long)vma->start, (unsigned long)vma->end,
                        r, w, x, s, (unsigned long)vma->offset);
    }
    return len;
}

/* ------------------------------------------------------------------ */
/*  Symlink support for /proc/self                                     */
/* ------------------------------------------------------------------ */

static ssize_t procfs_self_read(struct vnode *vn __attribute__((unused)),
                                void *buf, size_t len, off_t off,
                                uint32_t flags __attribute__((unused))) {
    char tmp[16];
    size_t total = procfs_self_target(tmp, sizeof(tmp));
    if (off < 0)
        return -EINVAL;
    size_t offu = (size_t)off;
    if (offu >= total)
        return 0;
    size_t avail = total - offu;
    if (len > avail)
        len = avail;
    memcpy(buf, tmp + offu, len);
    return (ssize_t)len;
}

/* ------------------------------------------------------------------ */
/*  File operations                                                    */
/* ------------------------------------------------------------------ */

static ssize_t procfs_read(struct vnode *vn, void *buf, size_t len,
                           off_t off,
                           uint32_t flags __attribute__((unused))) {
    struct procfs_entry *ent = vn->fs_data;
    if (!ent || !ent->generate)
        return -EINVAL;

    char *kbuf = kmalloc(PROCFS_BUF_SIZE);
    if (!kbuf)
        return -ENOMEM;

    int total = ent->generate(ent->pid, kbuf, PROCFS_BUF_SIZE);
    if (total < 0) {
        kfree(kbuf);
        return total;
    }

    if (off >= total) {
        kfree(kbuf);
        return 0;
    }

    size_t avail = (size_t)(total - (int)off);
    if (len > avail)
        len = avail;
    memcpy(buf, kbuf + off, len);
    kfree(kbuf);
    return (ssize_t)len;
}

static const char *procfs_skip_space(const char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
        s++;
    return s;
}

static void procfs_rstrip(char *s) {
    size_t n = strlen(s);
    while (n > 0) {
        char c = s[n - 1];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            break;
        s[n - 1] = '\0';
        n--;
    }
}

static int procfs_parse_u32(const char *s, uint32_t *out) {
    if (!s || !*s || !out)
        return -EINVAL;
    uint64_t v = 0;
    const char *p = s;
    while (*p) {
        if (*p < '0' || *p > '9')
            return -EINVAL;
        v = v * 10 + (uint64_t)(*p - '0');
        if (v > 0xFFFFFFFFULL)
            return -EINVAL;
        p++;
    }
    *out = (uint32_t)v;
    return 0;
}

static int procfs_control_signal_from_cmd(const char *cmd) {
    if (strcmp(cmd, "stop") == 0)
        return SIGSTOP;
    if (strcmp(cmd, "cont") == 0 || strcmp(cmd, "resume") == 0)
        return SIGCONT;
    if (strcmp(cmd, "term") == 0)
        return SIGTERM;
    if (strcmp(cmd, "kill") == 0)
        return SIGKILL;

    const char *arg = NULL;
    if (strncmp(cmd, "sig ", 4) == 0)
        arg = cmd + 4;
    else if (strncmp(cmd, "signal ", 7) == 0)
        arg = cmd + 7;
    else
        arg = cmd;

    arg = procfs_skip_space(arg);
    if (!*arg)
        return -EINVAL;

    uint32_t sig = 0;
    if (procfs_parse_u32(arg, &sig) < 0)
        return -EINVAL;
    if (sig == 0 || sig > NSIG)
        return -EINVAL;
    return (int)sig;
}

static ssize_t procfs_write(struct vnode *vn, const void *buf, size_t len,
                            off_t off,
                            uint32_t flags __attribute__((unused))) {
    if (!vn || (!buf && len > 0))
        return -EINVAL;
    (void)off;

    struct procfs_entry *ent = vn->fs_data;
    if (!ent || ent->type != PROCFS_PID_ENTRY ||
        strcmp(ent->name, "control") != 0) {
        return -EACCES;
    }
    if (len == 0)
        return 0;

    char cmd[64];
    size_t n = len;
    if (n >= sizeof(cmd))
        n = sizeof(cmd) - 1;
    memcpy(cmd, buf, n);
    cmd[n] = '\0';
    procfs_rstrip(cmd);
    const char *trim = procfs_skip_space(cmd);
    if (!*trim)
        return -EINVAL;

    struct process *target = proc_find(ent->pid);
    if (!target)
        return -ESRCH;
    struct process *curr = proc_current();
    if (curr && curr->uid != 0 && curr->uid != target->uid)
        return -EPERM;

    int sig = procfs_control_signal_from_cmd(trim);
    if (sig < 0)
        return sig;
    int rc = signal_send(ent->pid, sig);
    if (rc < 0)
        return rc;
    return (ssize_t)len;
}

static int procfs_close(struct vnode *vn __attribute__((unused))) {
    return 0;
}

static int procfs_dir_poll(struct file *file __attribute__((unused)),
                           uint32_t events) {
    return (int)(events & (POLLIN | POLLOUT));
}

static int procfs_file_poll(struct file *file __attribute__((unused)),
                            uint32_t events) {
    return (int)(events & (POLLIN | POLLOUT));
}

/* ------------------------------------------------------------------ */
/*  Per-PID sub-entry table                                            */
/* ------------------------------------------------------------------ */

struct pid_entry_def {
    const char *name;
    procfs_gen_t gen;
    mode_t mode;
};

static const struct pid_entry_def pid_entries[] = {
    {"stat",    gen_pid_stat,    S_IFREG | 0444},
    {"status",  gen_pid_status,  S_IFREG | 0444},
    {"cmdline", gen_pid_cmdline, S_IFREG | 0444},
    {"mounts",  gen_mounts,      S_IFREG | 0444},
    {"maps",    gen_pid_maps,    S_IFREG | 0444},
    {"control", NULL,            S_IFREG | 0200},
};

#define NUM_PID_ENTRIES ARRAY_SIZE(pid_entries)

/* ------------------------------------------------------------------ */
/*  Dynamic PID directory/entry vnodes                                 */
/* ------------------------------------------------------------------ */

static struct procfs_entry *procfs_create_pid_entry(struct procfs_mount *pm,
                                                    pid_t pid,
                                                    const char *name,
                                                    procfs_gen_t gen,
                                                    mode_t mode) {
    struct procfs_entry *ent = procfs_alloc_entry(pm, name, PROCFS_PID_ENTRY,
                                                  gen, pid);
    if (!ent)
        return NULL;
    procfs_init_vnode(&ent->vn, pm->mnt, ent, VNODE_FILE, mode,
                      &procfs_file_ops);
    return ent;
}

static struct procfs_entry *procfs_create_pid_dir(struct procfs_mount *pm,
                                                  pid_t pid) {
    char name[16];
    snprintf(name, sizeof(name), "%d", pid);
    struct procfs_entry *ent = procfs_alloc_entry(pm, name, PROCFS_PID_DIR,
                                                  NULL, pid);
    if (!ent)
        return NULL;
    procfs_init_vnode(&ent->vn, pm->mnt, ent, VNODE_DIR,
                      S_IFDIR | 0555, &procfs_dir_ops);
    return ent;
}

/* ------------------------------------------------------------------ */
/*  Directory operations                                               */
/* ------------------------------------------------------------------ */

/* Get the nth active PID (0-indexed) */
static pid_t procfs_get_nth_pid(int n) {
    return proc_get_nth_pid(n);
}

/* Static entries in root */
struct static_entry_def {
    const char *name;
    procfs_gen_t gen;
};

static const struct static_entry_def static_entries[] = {
    {"meminfo", gen_meminfo},
    {"uptime",  gen_uptime},
    {"stat",    gen_stat},
    {"interrupts", gen_interrupts},
    {"sched",   gen_sched},
    {"version", gen_version},
    {"cmdline", gen_cmdline},
    {"mounts", gen_mounts},
    {"mm_pcp", gen_mm_pcp},
    {"mm_integrity", gen_mm_integrity},
    {"mm_remote_free", gen_mm_remote_free},
};

#define NUM_STATIC_ENTRIES ARRAY_SIZE(static_entries)
/* "self" is an extra root entry (symlink) */
#define NUM_ROOT_FIXED (NUM_STATIC_ENTRIES + 1)

static int procfs_readdir(struct vnode *vn, struct dirent *ent, off_t *off) {
    struct procfs_entry *pe = vn->fs_data;
    struct procfs_mount *pm = vn->mount->fs_data;
    if (!pe || !pm)
        return -EINVAL;

    if (pe->type == PROCFS_ROOT) {
        /* Root directory: static entries, "self" symlink, then PID dirs */
        off_t idx = *off;

        /* Static entries */
        if (idx < (off_t)NUM_STATIC_ENTRIES) {
            ent->d_ino = idx + 2;
            ent->d_off = idx;
            ent->d_reclen = sizeof(*ent);
            ent->d_type = DT_REG;
            strncpy(ent->d_name, static_entries[idx].name,
                    CONFIG_NAME_MAX - 1);
            *off = idx + 1;
            return 1;
        }

        /* "self" symlink */
        if (idx == (off_t)NUM_STATIC_ENTRIES) {
            ent->d_ino = NUM_STATIC_ENTRIES + 2;
            ent->d_off = idx;
            ent->d_reclen = sizeof(*ent);
            ent->d_type = DT_LNK;
            strncpy(ent->d_name, "self", CONFIG_NAME_MAX - 1);
            *off = idx + 1;
            return 1;
        }

        /* PID directories */
        int pid_idx = (int)(idx - (off_t)NUM_ROOT_FIXED);
        pid_t pid = procfs_get_nth_pid(pid_idx);
        if (pid < 0)
            return 0;
        ent->d_ino = (ino_t)(1000 + pid);
        ent->d_off = idx;
        ent->d_reclen = sizeof(*ent);
        ent->d_type = DT_DIR;
        snprintf(ent->d_name, CONFIG_NAME_MAX, "%d", pid);
        *off = idx + 1;
        return 1;
    }

    if (pe->type == PROCFS_PID_DIR) {
        /* Per-PID directory */
        off_t idx = *off;
        if (idx >= (off_t)NUM_PID_ENTRIES)
            return 0;

        /* Verify PID still exists */
        struct process *p = pid_to_proc(pe->pid);
        if (!p)
            return 0;

        ent->d_ino = (ino_t)(2000 + pe->pid * 10 + idx);
        ent->d_off = idx;
        ent->d_reclen = sizeof(*ent);
        ent->d_type = DT_REG;
        strncpy(ent->d_name, pid_entries[idx].name, CONFIG_NAME_MAX - 1);
        *off = idx + 1;
        return 1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Lookup                                                             */
/* ------------------------------------------------------------------ */

static struct vnode *procfs_lookup(struct vnode *dir, const char *name) {
    struct procfs_entry *pe = dir->fs_data;
    struct procfs_mount *pm = dir->mount->fs_data;
    if (!pe || !pm)
        return NULL;

    if (pe->type == PROCFS_ROOT) {
        /* Check static entries */
        for (size_t i = 0; i < NUM_STATIC_ENTRIES; i++) {
            if (strcmp(name, static_entries[i].name) == 0) {
                /* Find or create the entry */
                spin_lock(&pm->lock);
                for (struct procfs_entry *e = pm->entries; e; e = e->next) {
                    if (e->type == PROCFS_STATIC &&
                        strcmp(e->name, name) == 0) {
                        vnode_get(&e->vn);
                        spin_unlock(&pm->lock);
                        return &e->vn;
                    }
                }
                spin_unlock(&pm->lock);
                return NULL;
            }
        }

        /* Check "self" */
        if (strcmp(name, "self") == 0) {
            spin_lock(&pm->lock);
            for (struct procfs_entry *e = pm->entries; e; e = e->next) {
                if (e->type == PROCFS_SELF_LINK) {
                    char tmp[16];
                    e->vn.size = procfs_self_target(tmp, sizeof(tmp));
                    vnode_get(&e->vn);
                    spin_unlock(&pm->lock);
                    return &e->vn;
                }
            }
            spin_unlock(&pm->lock);
            return NULL;
        }

        /* Try as PID directory */
        pid_t pid = 0;
        for (const char *s = name; *s; s++) {
            if (*s < '0' || *s > '9')
                return NULL;
            pid = pid * 10 + (*s - '0');
        }
        if (pid <= 0)
            return NULL;

        /* Verify process exists */
        struct process *p = pid_to_proc(pid);
        if (!p)
            return NULL;

        /* Create a dynamic PID dir entry (or reuse existing) */
        spin_lock(&pm->lock);
        for (struct procfs_entry *e = pm->entries; e; e = e->next) {
            if (e->type == PROCFS_PID_DIR && e->pid == pid) {
                vnode_get(&e->vn);
                spin_unlock(&pm->lock);
                return &e->vn;
            }
        }
        struct procfs_entry *pdir = procfs_create_pid_dir(pm, pid);
        spin_unlock(&pm->lock);
        if (!pdir)
            return NULL;
        vnode_get(&pdir->vn);
        return &pdir->vn;
    }

    if (pe->type == PROCFS_PID_DIR) {
        /* Lookup inside a PID directory (reuse existing or create) */
        for (size_t i = 0; i < NUM_PID_ENTRIES; i++) {
            if (strcmp(name, pid_entries[i].name) == 0) {
                spin_lock(&pm->lock);
                for (struct procfs_entry *e = pm->entries; e; e = e->next) {
                    if (e->type == PROCFS_PID_ENTRY && e->pid == pe->pid &&
                        strcmp(e->name, pid_entries[i].name) == 0) {
                        vnode_get(&e->vn);
                        spin_unlock(&pm->lock);
                        return &e->vn;
                    }
                }
                struct procfs_entry *e =
                    procfs_create_pid_entry(pm, pe->pid, pid_entries[i].name,
                                            pid_entries[i].gen,
                                            pid_entries[i].mode);
                spin_unlock(&pm->lock);
                if (!e)
                    return NULL;
                vnode_get(&e->vn);
                return &e->vn;
            }
        }
        return NULL;
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Mount / unmount                                                    */
/* ------------------------------------------------------------------ */

static int procfs_mount_op(struct mount *mnt) {
    struct procfs_mount *pm = kzalloc(sizeof(*pm));
    if (!pm)
        return -ENOMEM;

    pm->next_ino = 1;
    spin_init(&pm->lock);
    pm->mnt = mnt;

    /* Root entry */
    pm->root = kzalloc(sizeof(*pm->root));
    if (!pm->root) {
        kfree(pm);
        return -ENOMEM;
    }
    strncpy(pm->root->name, "/", CONFIG_NAME_MAX - 1);
    pm->root->type = PROCFS_ROOT;
    pm->root->ino = pm->next_ino++;
    procfs_init_vnode(&pm->root->vn, mnt, pm->root, VNODE_DIR,
                      S_IFDIR | 0555, &procfs_dir_ops);

    /* Create static entries */
    for (size_t i = 0; i < NUM_STATIC_ENTRIES; i++) {
        struct procfs_entry *ent =
            procfs_alloc_entry(pm, static_entries[i].name, PROCFS_STATIC,
                               static_entries[i].gen, 0);
        if (ent) {
            procfs_init_vnode(&ent->vn, mnt, ent, VNODE_FILE,
                              S_IFREG | 0444, &procfs_file_ops);
        }
    }

    /* Create "self" symlink */
    struct procfs_entry *self_ent =
        procfs_alloc_entry(pm, "self", PROCFS_SELF_LINK, NULL, 0);
    if (self_ent) {
        procfs_init_vnode(&self_ent->vn, mnt, self_ent, VNODE_SYMLINK,
                          S_IFLNK | 0777, &procfs_symlink_ops);
        self_ent->vn.size = 1; /* updated dynamically on lookup */
    }

    mnt->fs_data = pm;
    mnt->root = &pm->root->vn;
    pr_info("procfs: mounted\n");
    return 0;
}

static int procfs_unmount_op(struct mount *mnt) {
    struct procfs_mount *pm = mnt->fs_data;
    if (!pm)
        return 0;
    struct procfs_entry *ent = pm->entries;
    while (ent) {
        struct procfs_entry *next = ent->next;
        kfree(ent);
        ent = next;
    }
    kfree(pm->root);
    kfree(pm);
    return 0;
}

static int procfs_statfs_op(struct mount *mnt __attribute__((unused)),
                            struct kstatfs *st) {
    memset(st, 0, sizeof(*st));
    st->f_type = PROC_SUPER_MAGIC;
    st->f_bsize = CONFIG_PAGE_SIZE;
    st->f_frsize = CONFIG_PAGE_SIZE;
    st->f_namelen = CONFIG_NAME_MAX;
    return 0;
}

static struct vfs_ops procfs_vfs_ops = {
    .name = "procfs",
    .mount = procfs_mount_op,
    .unmount = procfs_unmount_op,
    .lookup = procfs_lookup,
    .statfs = procfs_statfs_op,
};

static struct fs_type procfs_type = {
    .name = "procfs",
    .ops = &procfs_vfs_ops,
};

void procfs_init(void) {
    if (vfs_register_fs(&procfs_type) < 0) {
        pr_err("procfs: registration failed\n");
    } else {
        pr_info("procfs: initialized\n");
    }
}
