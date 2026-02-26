/**
 * kernel/include/kairos/handle_bridge.h - Internal fd<->kobj bridge helpers
 */

#ifndef _KAIROS_HANDLE_BRIDGE_H
#define _KAIROS_HANDLE_BRIDGE_H

#include <kairos/types.h>

struct kobj;
struct file;
struct process;

uint32_t handle_bridge_fd_to_krights(uint32_t fd_rights);
uint32_t handle_bridge_krights_to_fd(uint32_t krights);

int handle_bridge_kobj_from_fd(struct process *p, int fd, uint32_t rights_mask,
                               struct kobj **out_obj, uint32_t *out_rights);
int handle_bridge_transfer_from_fd(struct process *p, int fd,
                                   uint32_t rights_mask,
                                   struct kobj **out_obj,
                                   uint32_t *out_rights);
int handle_bridge_fd_from_kobj(struct process *p, struct kobj *obj,
                               uint32_t krights, uint32_t fd_flags,
                               int *out_fd);
int handle_bridge_pin_fd(struct process *p, int fd, uint32_t required_rights,
                         struct file **out_file, uint32_t *out_rights);
int handle_bridge_dup_fd(struct process *src, int src_fd, struct process *dst,
                         uint32_t fd_flags, int *out_fd);

#endif
