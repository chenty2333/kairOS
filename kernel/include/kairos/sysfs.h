/**
 * kernel/include/kairos/sysfs.h - Kernel attribute tree filesystem
 *
 * Provides /sys with a tree of directories and attribute files
 * managed entirely by kernel APIs.
 */

#ifndef _KAIROS_SYSFS_H
#define _KAIROS_SYSFS_H

#include <kairos/types.h>

struct sysfs_node;

/* Attribute callback interface for sysfs files */
struct sysfs_attribute {
    const char *name;
    mode_t mode;    /* 0444 read-only, 0644 read-write */
    ssize_t (*show)(void *priv, char *buf, size_t bufsz);
    ssize_t (*store)(void *priv, const char *buf, size_t len);
    void *priv;
    void (*release_priv)(void *priv);
};

/* Directory management */
struct sysfs_node *sysfs_mkdir(struct sysfs_node *parent, const char *name);
void sysfs_rmdir(struct sysfs_node *node);

/* Attribute file management */
struct sysfs_node *sysfs_create_file(struct sysfs_node *parent,
                                     const struct sysfs_attribute *attr);
void sysfs_remove_file(struct sysfs_node *node);

/* Batch creation */
int sysfs_create_files(struct sysfs_node *parent,
                       const struct sysfs_attribute *attrs, size_t count);

/* Symlink */
struct sysfs_node *sysfs_create_link(struct sysfs_node *parent,
                                     const char *name,
                                     struct sysfs_node *target);

/* Predefined top-level directories */
struct sysfs_node *sysfs_root(void);
struct sysfs_node *sysfs_bus_dir(void);
struct sysfs_node *sysfs_class_dir(void);
struct sysfs_node *sysfs_devices_dir(void);
struct sysfs_node *sysfs_kernel_dir(void);
struct sysfs_node *sysfs_find_child(struct sysfs_node *parent, const char *name);

void sysfs_init(void);

#endif
