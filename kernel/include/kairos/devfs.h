/**
 * kernel/include/kairos/devfs.h - devfs init
 */

#ifndef _KAIROS_DEVFS_H
#define _KAIROS_DEVFS_H

struct file_ops;
struct vnode;

void devfs_init(void);
int devfs_register_node(const char *path, struct file_ops *ops, void *priv);
int devfs_register_dir(const char *path);
void *devfs_get_priv(struct vnode *vn);

#endif
