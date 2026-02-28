/**
 * kernel/core/init/fs.c - Filesystem initialization
 */

#include <kairos/buf.h>
#include <kairos/boot.h>
#include <kairos/initramfs.h>
#include <kairos/printk.h>
#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>
#include <kairos/devfs.h>
#include <kairos/ext2.h>
#include <kairos/fat32.h>
#include <kairos/procfs.h>
#include <kairos/tmpfs.h>
#include <kairos/sysfs.h>
#include <kairos/tracepoint.h>

extern int dev_tty_init(void);
extern int pty_driver_init(void);
extern int console_tty_driver_init(void);
extern void ipc_registry_sysfs_bootstrap(void);

static const char *init_find_line_with_prefix(const char *buf,
                                              const char *prefix) {
    if (!buf || !prefix || !prefix[0])
        return NULL;
    size_t plen = strlen(prefix);
    const char *line = buf;
    while (line && *line) {
        if (strncmp(line, prefix, plen) == 0)
            return line;
        line = strchr(line, '\n');
        if (!line)
            break;
        line++;
    }
    return NULL;
}

static const char *init_line_end(const char *line, const char *buf_end) {
    if (!line || !buf_end || line >= buf_end)
        return line;
    const void *nl = memchr(line, '\n', (size_t)(buf_end - line));
    if (nl)
        return (const char *)nl;
    return buf_end;
}

static bool init_parse_u64_kv_in_line(const char *line, const char *line_end,
                                      const char *key, uint64_t *out) {
    if (!line || !line_end || !key || !key[0] || line >= line_end)
        return false;

    const char *p = line;
    size_t key_len = strlen(key);
    while (p < line_end) {
        const char *hit = strstr(p, key);
        if (!hit || hit >= line_end)
            return false;
        p = hit + key_len;
        break;
    }
    if (p >= line_end || *p < '0' || *p > '9')
        return false;

    uint64_t v = 0;
    while (p < line_end && *p != ' ') {
        if (*p < '0' || *p > '9')
            return false;
        uint64_t digit = (uint64_t)(*p - '0');
        if (v > (UINT64_MAX - digit) / 10ULL)
            return false;
        v = v * 10ULL + digit;
        p++;
    }
    if (out)
        *out = v;
    return true;
}

static bool init_validate_hash_stats_table_line(const char *line,
                                                const char *buf_end,
                                                bool has_ready) {
    if (!line || !buf_end)
        return false;
    const char *end = init_line_end(line, buf_end);
    uint64_t tmp = 0;
    if (has_ready && !init_parse_u64_kv_in_line(line, end, "ready=", &tmp))
        return false;
    return init_parse_u64_kv_in_line(line, end, "buckets=", &tmp) &&
           init_parse_u64_kv_in_line(line, end, "used_buckets=", &tmp) &&
           init_parse_u64_kv_in_line(line, end, "entries=", &tmp) &&
           init_parse_u64_kv_in_line(line, end, "load_per_mille=", &tmp) &&
           init_parse_u64_kv_in_line(line, end, "avg_chain_per_mille=", &tmp) &&
           init_parse_u64_kv_in_line(line, end, "collision_entries=", &tmp) &&
           init_parse_u64_kv_in_line(line, end, "max_bucket_depth=", &tmp) &&
           init_parse_u64_kv_in_line(line, end, "rehash_recommended=", &tmp);
}

static int init_validate_ipc_hash_stats_blob(const char *buf, size_t len) {
    if (!buf || len == 0)
        return -EINVAL;
    const char *buf_end = buf + len;
    if (!strstr(buf, "schema=sysfs_ipc_hash_stats_v1\n"))
        return -EINVAL;

    const char *reg_line = init_find_line_with_prefix(buf, "table=ipc_registry_id ");
    const char *kcap_line = init_find_line_with_prefix(buf, "table=kcap_id ");
    if (!reg_line || !kcap_line)
        return -EINVAL;
    if (!init_validate_hash_stats_table_line(reg_line, buf_end, false))
        return -EINVAL;
    if (!init_validate_hash_stats_table_line(kcap_line, buf_end, true))
        return -EINVAL;
    return 0;
}

static void init_fs_ipc_hash_stats_selftest(void) {
    struct file *f = NULL;
    char buf[1024];
    int rc = vfs_open("/sys/ipc/hash_stats", O_RDONLY, 0, &f);
    if (rc < 0 || !f) {
        pr_warn("init_fs: ipc hash_stats selftest open failed (ret=%d)\n", rc);
        return;
    }
    ssize_t n = vfs_read(f, buf, sizeof(buf) - 1);
    vfs_close(f);
    if (n < 0) {
        pr_warn("init_fs: ipc hash_stats selftest read failed (ret=%zd)\n", n);
        return;
    }
    buf[n] = '\0';
    rc = init_validate_ipc_hash_stats_blob(buf, (size_t)n);
    if (rc < 0) {
        pr_warn("init_fs: ipc hash_stats selftest validation failed (ret=%d)\n",
                rc);
        return;
    }
    pr_info("init_fs: ipc hash_stats selftest ok\n");
}

void init_fs(void) {
    pr_debug("init_fs: begin\n");
    binit();
    pr_debug("init_fs: after binit\n");
    vfs_init();
    pr_debug("init_fs: after vfs_init\n");
    devfs_init();
    pr_debug("init_fs: after devfs_init\n");
    console_tty_driver_init();
    pr_debug("init_fs: after console_tty_driver_init\n");
    dev_tty_init();
    pr_debug("init_fs: after dev_tty_init\n");
    pty_driver_init();
    pr_debug("init_fs: after pty_driver_init\n");
    procfs_init();
    pr_debug("init_fs: after procfs_init\n");
    tmpfs_init();
    pr_debug("init_fs: after tmpfs_init\n");
    sysfs_init();
    pr_debug("init_fs: after sysfs_init\n");
    tracepoint_sysfs_init();
    pr_debug("init_fs: after tracepoint_sysfs_init\n");
    initramfs_init();
    pr_debug("init_fs: after initramfs_init\n");
    ext2_init();
    pr_debug("init_fs: after ext2_init\n");
    fat32_init();
    pr_debug("init_fs: after fat32_init\n");

    int ret = -1;
    bool root_ok = false;

    const struct boot_module *mod = boot_find_module("initramfs");
    if (mod && mod->addr && mod->size > 0) {
        initramfs_set_image(mod->addr, (size_t)mod->size);
        ret = vfs_mount(NULL, "/", "initramfs", 0);
        if (ret == 0) {
            pr_info("initramfs root: mounted (%u bytes)\n",
                    (unsigned int)mod->size);
            root_ok = true;
        } else {
            pr_warn("initramfs root: mount failed (ret=%d)\n", ret);
        }
    }

    char root_dev[4] = {0};
    if (!root_ok) {
        for (char dev = 'a'; dev <= 'z'; dev++) {
            root_dev[0] = 'v';
            root_dev[1] = 'd';
            root_dev[2] = dev;
            root_dev[3] = '\0';
            ret = vfs_mount(root_dev, "/", "ext2", 0);
            if (ret == 0) {
                pr_info("ext2 root: mounted (%s)\n", root_dev);
                root_ok = true;
                break;
            }
        }
    }

    if (root_ok) {
        int mkret = vfs_mkdir("/dev", 0755);
        if (mkret < 0 && mkret != -EEXIST)
            pr_warn("devfs: failed to create /dev (ret=%d)\n", mkret);
        ret = vfs_mount(NULL, "/dev", "devfs", 0);
        if (ret < 0)
            pr_warn("devfs: mount failed (ret=%d)\n", ret);

        mkret = vfs_mkdir("/proc", 0555);
        if (mkret < 0 && mkret != -EEXIST)
            pr_warn("procfs: failed to create /proc (ret=%d)\n", mkret);
        ret = vfs_mount(NULL, "/proc", "procfs", 0);
        if (ret < 0)
            pr_warn("procfs: mount failed (ret=%d)\n", ret);

        mkret = vfs_mkdir("/tmp", 01777);
        if (mkret < 0 && mkret != -EEXIST)
            pr_warn("tmpfs: failed to create /tmp (ret=%d)\n", mkret);
        ret = vfs_mount(NULL, "/tmp", "tmpfs", 0);
        if (ret < 0)
            pr_warn("tmpfs: mount failed (ret=%d)\n", ret);

        mkret = vfs_mkdir("/sys", 0555);
        if (mkret < 0 && mkret != -EEXIST)
            pr_warn("sysfs: failed to create /sys (ret=%d)\n", mkret);
        ret = vfs_mount(NULL, "/sys", "sysfs", 0);
        if (ret < 0)
            pr_warn("sysfs: mount failed (ret=%d)\n", ret);
    } else {
        pr_warn("ext2 root: mount failed on any vda..vdz (ret=%d)\n", ret);
        ret = vfs_mount(NULL, "/", "devfs", 0);
        if (ret < 0) {
            pr_warn("devfs: root mount failed (ret=%d)\n", ret);
        } else {
            pr_info("devfs: mounted as root (no disk root)\n");
        }
    }

    ipc_registry_sysfs_bootstrap();
    init_fs_ipc_hash_stats_selftest();
    pr_debug("init_fs: after ipc_registry_sysfs_bootstrap\n");
}
