/**
 * kernel/fs/vfs/path.c - VFS path helpers
 */

#include <kairos/string.h>
#include <kairos/types.h>
#include <kairos/vfs.h>
#include <kairos/dentry.h>

int vfs_build_relpath(struct dentry *root, struct dentry *target,
                      char *out, size_t len) {
    if (!root || !target || !out || len == 0)
        return -EINVAL;
    if (root->mnt != target->mnt)
        return -EXDEV;
    if (root == target) {
        if (len < 2)
            return -ENAMETOOLONG;
        out[0] = '.';
        out[1] = '\0';
        return 0;
    }
    char tmp[CONFIG_PATH_MAX];
    size_t pos = sizeof(tmp) - 1;
    tmp[pos] = '\0';
    struct dentry *cur = target;
    while (cur && cur != root) {
        size_t nlen = strlen(cur->name);
        if (nlen + 1 > pos)
            return -ENAMETOOLONG;
        pos -= nlen;
        memcpy(&tmp[pos], cur->name, nlen);
        if (pos == 0)
            return -ENAMETOOLONG;
        tmp[--pos] = '/';
        cur = cur->parent;
    }
    if (cur != root)
        return -ENOENT;
    if (pos < sizeof(tmp) - 1 && tmp[pos] == '/')
        pos++;
    size_t plen = strlen(&tmp[pos]);
    if (plen + 1 > len)
        return -ENAMETOOLONG;
    memcpy(out, &tmp[pos], plen + 1);
    return 0;
}

int vfs_build_path_dentry(struct dentry *d, char *out, size_t len) {
    if (!d || !out || len == 0)
        return -EINVAL;
    if (!d->mnt || !d->mnt->root_dentry)
        return -EINVAL;

    char tmp[CONFIG_PATH_MAX];
    size_t pos = sizeof(tmp) - 1;
    tmp[pos] = '\0';

    struct dentry *cur = d;
    struct mount *mnt = d->mnt;
    struct dentry *ns_root = vfs_root_dentry();
    while (cur) {
        if (ns_root && cur == ns_root) {
            if (pos == sizeof(tmp) - 1) {
                if (pos == 0)
                    return -ENAMETOOLONG;
                tmp[--pos] = '/';
            }
            break;
        }
        if (cur == mnt->root_dentry) {
            if (!mnt->parent || !mnt->mountpoint_dentry) {
                if (pos == sizeof(tmp) - 1) {
                    if (pos == 0)
                        return -ENAMETOOLONG;
                    tmp[--pos] = '/';
                }
                break;
            }
            cur = mnt->mountpoint_dentry;
            mnt = mnt->parent;
            continue;
        }
        if (!cur->name[0])
            return -ENOENT;
        size_t nlen = strlen(cur->name);
        if (nlen + 1 > pos)
            return -ENAMETOOLONG;
        pos -= nlen;
        memcpy(&tmp[pos], cur->name, nlen);
        if (pos == 0)
            return -ENAMETOOLONG;
        tmp[--pos] = '/';
        cur = cur->parent;
    }
    if (!cur)
        return -ENOENT;

    size_t plen = strlen(&tmp[pos]);
    if (plen + 1 > len)
        return -ERANGE;
    memcpy(out, &tmp[pos], plen + 1);
    return (int)plen;
}
