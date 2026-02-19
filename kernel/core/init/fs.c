/**
 * kernel/core/init/fs.c - Filesystem initialization
 */

#include <kairos/buf.h>
#include <kairos/boot.h>
#include <kairos/initramfs.h>
#include <kairos/printk.h>
#include <kairos/types.h>
#include <kairos/vfs.h>
#include <kairos/devfs.h>
#include <kairos/ext2.h>
#include <kairos/fat32.h>
#include <kairos/procfs.h>
#include <kairos/tmpfs.h>
#include <kairos/sysfs.h>

extern int dev_tty_init(void);
extern int pty_driver_init(void);
extern int console_tty_driver_init(void);

void init_fs(void) {
    binit();
    vfs_init();
    devfs_init();
    console_tty_driver_init();
    dev_tty_init();
    pty_driver_init();
    procfs_init();
    tmpfs_init();
    sysfs_init();
    initramfs_init();
    ext2_init();
    fat32_init();

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
}
