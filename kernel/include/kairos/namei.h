/**
 * kernel/include/kairos/namei.h - Path resolution (skeleton)
 */

#ifndef _KAIROS_NAMEI_H
#define _KAIROS_NAMEI_H

#include <kairos/dentry.h>

#define NAMEI_FOLLOW      0x1
#define NAMEI_DIRECTORY   0x2
#define NAMEI_CREATE      0x4
#define NAMEI_EXCL        0x8
#define NAMEI_NOFOLLOW    0x10

int vfs_namei_at(const struct path *base, const char *path,
                 struct path *out, int flags);
int vfs_namei(const char *path, struct path *out, int flags);

#endif
