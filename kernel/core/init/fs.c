/**
 * kernel/core/init/fs.c - Filesystem initialization
 */

#include <kairos/buf.h>
#include <kairos/printk.h>
#include <kairos/types.h>
#include <kairos/vfs.h>
#include <kairos/devfs.h>
#include <kairos/ext2.h>
#include <kairos/fat32.h>

void init_fs(void) {
    binit();
    vfs_init();
    devfs_init();
    ext2_init();
    fat32_init();

    int ret = -1;
    char root_dev[4] = {0};
    for (char dev = 'a'; dev <= 'z'; dev++) {
        root_dev[0] = 'v';
        root_dev[1] = 'd';
        root_dev[2] = dev;
        root_dev[3] = '\0';
        ret = vfs_mount(root_dev, "/", "ext2", 0);
        if (ret == 0) {
            pr_info("ext2 root: mounted (%s)\n", root_dev);
            break;
        }
    }
    if (ret == 0) {
        int mkret = vfs_mkdir("/dev", 0755);
        if (mkret < 0 && mkret != -EEXIST)
            pr_warn("devfs: failed to create /dev (ret=%d)\n", mkret);
        ret = vfs_mount(NULL, "/dev", "devfs", 0);
        if (ret < 0)
            pr_warn("devfs: mount failed (ret=%d)\n", ret);
    } else {
        pr_warn("ext2 root: mount failed on any vda..vdz (ret=%d)\n", ret);
    }
}
