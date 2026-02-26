/**
 * kernel/include/kairos/handle.h - Capability handles and channel/port IPC
 */

#ifndef _KAIROS_HANDLE_H
#define _KAIROS_HANDLE_H

#include <kairos/atomic.h>
#include <kairos/sync.h>
#include <kairos/types.h>

struct process;
struct file;
struct vnode;

#ifndef CONFIG_MAX_HANDLES_PER_PROC
#define CONFIG_MAX_HANDLES_PER_PROC 256
#endif

#define KOBJ_TYPE_CHANNEL 1U
#define KOBJ_TYPE_PORT    2U
#define KOBJ_TYPE_FILE    3U
#define KOBJ_TYPE_BUFFER  4U

#define KRIGHT_READ      (1U << 0)
#define KRIGHT_WRITE     (1U << 1)
#define KRIGHT_TRANSFER  (1U << 2)
#define KRIGHT_DUPLICATE (1U << 3)
#define KRIGHT_WAIT      (1U << 4)
#define KRIGHT_MANAGE    (1U << 5)

#define KRIGHT_CHANNEL_DEFAULT \
    (KRIGHT_READ | KRIGHT_WRITE | KRIGHT_TRANSFER | KRIGHT_DUPLICATE)
#define KRIGHT_PORT_DEFAULT (KRIGHT_WAIT | KRIGHT_MANAGE | KRIGHT_DUPLICATE)
#define KRIGHT_FILE_DEFAULT \
    (KRIGHT_READ | KRIGHT_WRITE | KRIGHT_TRANSFER | KRIGHT_DUPLICATE)
#define KRIGHT_BUFFER_DEFAULT \
    (KRIGHT_READ | KRIGHT_WRITE | KRIGHT_TRANSFER | KRIGHT_DUPLICATE | KRIGHT_WAIT)

#define KCHANNEL_OPT_NONBLOCK   (1U << 0)
#define KCHANNEL_OPT_RENDEZVOUS (1U << 1)

#define KOBJ_IO_NONBLOCK   (1U << 0)
#define KOBJ_IO_RENDEZVOUS (1U << 1)

#define KPORT_BIND_READABLE    (1U << 0)
#define KPORT_BIND_PEER_CLOSED (1U << 1)
#define KPORT_BIND_ALL (KPORT_BIND_READABLE | KPORT_BIND_PEER_CLOSED)

#define KPORT_WAIT_NONBLOCK (1U << 0)

#define KCHANNEL_MAX_MSG_BYTES 1024U
#define KCHANNEL_INLINE_MSG_BYTES 128U
#define KCHANNEL_MAX_MSG_HANDLES 8U
#define KCHANNEL_MAX_QUEUE 64U
#define KPORT_MAX_QUEUE 128U
#define KOBJ_REFCOUNT_HISTORY_DEPTH 16U
#define KHANDLE_INVALID_CAP_ID 0ULL
#define KHANDLE_CLOSE_F_REVOKE_DESCENDANTS (1U << 0)
#define KOBJ_TRANSFER_HISTORY_DEPTH 32U

struct kobj;

enum kobj_access_op {
    KOBJ_ACCESS_READ = 1,
    KOBJ_ACCESS_WRITE = 2,
    KOBJ_ACCESS_POLL = 3,
    KOBJ_ACCESS_SIGNAL = 4,
    KOBJ_ACCESS_WAIT = 5,
    KOBJ_ACCESS_MANAGE = 6,
    KOBJ_ACCESS_DUPLICATE = 7,
    KOBJ_ACCESS_TRANSFER = 8,
};

enum kobj_refcount_event {
    KOBJ_REFCOUNT_INIT = 1,
    KOBJ_REFCOUNT_GET = 2,
    KOBJ_REFCOUNT_PUT = 3,
    KOBJ_REFCOUNT_LAST_PUT = 4,
};

enum kobj_transfer_event {
    KOBJ_TRANSFER_TAKE = 1,
    KOBJ_TRANSFER_ENQUEUE = 2,
    KOBJ_TRANSFER_DELIVER = 3,
    KOBJ_TRANSFER_INSTALL = 4,
    KOBJ_TRANSFER_RESTORE = 5,
    KOBJ_TRANSFER_DROP = 6,
};

struct kobj_refcount_history_entry {
    uint64_t ticks;
    uint32_t seq;
    int32_t pid;
    uint32_t refcount;
    uint16_t event;
    uint16_t cpu;
};

struct kobj_transfer_history_entry {
    uint64_t ticks;
    uint32_t seq;
    int32_t from_pid;
    int32_t to_pid;
    uint32_t rights;
    uint16_t event;
    uint16_t cpu;
};

struct kobj_ops {
    void (*release)(struct kobj *obj);
    int (*read)(struct kobj *obj, void *buf, size_t len, size_t *out_len,
                uint32_t options);
    int (*write)(struct kobj *obj, const void *buf, size_t len, size_t *out_len,
                 uint32_t options);
    int (*wait)(struct kobj *obj, void *out, uint64_t timeout_ns,
                uint32_t options);
    int (*poll)(struct kobj *obj, uint32_t events, uint32_t *out_revents);
    int (*signal)(struct kobj *obj, uint32_t signal, uint32_t flags);
    int (*poll_attach_vnode)(struct kobj *obj, struct vnode *vn);
    int (*poll_detach_vnode)(struct kobj *obj, struct vnode *vn);
};

struct kobj {
    atomic_t refcount;
    atomic_t refcount_hist_head;
    atomic_t transfer_hist_head;
    uint32_t id;
    uint32_t type;
    const struct kobj_ops *ops;
    struct wait_queue waitq;
    struct kobj_refcount_history_entry
        refcount_hist[KOBJ_REFCOUNT_HISTORY_DEPTH];
    struct kobj_transfer_history_entry
        transfer_hist[KOBJ_TRANSFER_HISTORY_DEPTH];
};

struct khandle_entry {
    struct kobj *obj;
    uint32_t rights;
    uint64_t cap_id;
};

struct handletable {
    struct khandle_entry entries[CONFIG_MAX_HANDLES_PER_PROC];
    struct mutex lock;
    atomic_t refcount;
    atomic_t seq;
    uint64_t cache_epoch;
};

struct kairos_channel_msg_user {
    uint64_t bytes;
    uint64_t handles;
    uint32_t num_bytes;
    uint32_t num_handles;
};

struct kairos_port_packet_user {
    uint64_t key;
    uint32_t observed;
    uint32_t reserved;
};

struct khandle_transfer {
    struct kobj *obj;
    uint32_t rights;
    uint64_t cap_id;
};

void kobj_init(struct kobj *obj, uint32_t type, const struct kobj_ops *ops);
void kobj_get(struct kobj *obj);
void kobj_put(struct kobj *obj);
uint32_t kobj_id(const struct kobj *obj);
const char *kobj_type_name(uint32_t type);
int kobj_read(struct kobj *obj, void *buf, size_t len, size_t *out_len,
              uint32_t options);
int kobj_write(struct kobj *obj, const void *buf, size_t len, size_t *out_len,
               uint32_t options);
int kobj_wait(struct kobj *obj, void *out, uint64_t timeout_ns,
              uint32_t options);
int kobj_poll(struct kobj *obj, uint32_t events, uint32_t *out_revents);
int kobj_poll_revents(struct kobj *obj, uint32_t events,
                      uint32_t *out_revents);
int kobj_signal(struct kobj *obj, uint32_t signal, uint32_t flags);
int kobj_poll_attach_vnode(struct kobj *obj, struct vnode *vn);
int kobj_poll_detach_vnode(struct kobj *obj, struct vnode *vn);
size_t kobj_refcount_history_snapshot(struct kobj *obj,
                                      struct kobj_refcount_history_entry *out,
                                      size_t max_entries);
void kobj_transfer_record(struct kobj *obj, enum kobj_transfer_event event,
                          int32_t from_pid, int32_t to_pid, uint32_t rights);
size_t kobj_transfer_history_snapshot(struct kobj *obj,
                                      struct kobj_transfer_history_entry *out,
                                      size_t max_entries);
int kobj_lookup_type_by_id(uint32_t obj_id, uint32_t *out_type);
int kobj_registry_get_nth(size_t index, uint32_t *out_id, uint32_t *out_type);
int kobj_transfer_history_page_by_id(
    uint32_t obj_id, uint32_t cursor, uint32_t page_size,
    struct kobj_transfer_history_entry *out, size_t out_cap,
    uint32_t *out_returned, uint32_t *out_next_cursor, bool *out_end,
    uint32_t *out_type);

struct handletable *handletable_alloc(void);
struct handletable *handletable_copy(struct handletable *src);
void handletable_get(struct handletable *ht);
void handletable_put(struct handletable *ht);

int khandle_alloc(struct process *p, struct kobj *obj, uint32_t rights);
int khandle_get(struct process *p, int32_t handle, uint32_t required_rights,
                struct kobj **out_obj, uint32_t *out_rights);
int khandle_get_for_access(struct process *p, int32_t handle,
                           enum kobj_access_op access, struct kobj **out_obj,
                           uint32_t *out_rights);
int khandle_take(struct process *p, int32_t handle, uint32_t required_rights,
                 struct kobj **out_obj, uint32_t *out_rights);
int khandle_take_with_cap(struct process *p, int32_t handle,
                          uint32_t required_rights, struct kobj **out_obj,
                          uint32_t *out_rights, uint64_t *out_cap_id);
int khandle_take_for_access(struct process *p, int32_t handle,
                            enum kobj_access_op access, struct kobj **out_obj,
                            uint32_t *out_rights);
int khandle_take_for_access_with_cap(struct process *p, int32_t handle,
                                     enum kobj_access_op access,
                                     struct kobj **out_obj,
                                     uint32_t *out_rights,
                                     uint64_t *out_cap_id);
int khandle_restore(struct process *p, int32_t handle, struct kobj *obj,
                    uint32_t rights);
int khandle_restore_cap(struct process *p, int32_t handle, struct kobj *obj,
                        uint32_t rights, uint64_t cap_id);
int khandle_close(struct process *p, int32_t handle);
int khandle_duplicate(struct process *p, int32_t handle, uint32_t rights_mask,
                      int32_t *out_new_handle);
int khandle_revoke_descendants(struct process *p, int32_t handle);
void khandle_transfer_drop_cap(struct kobj *obj, uint32_t rights,
                               uint64_t cap_id);
void khandle_transfer_drop(struct kobj *obj);
void khandle_transfer_drop_with_rights(struct kobj *obj, uint32_t rights);
int khandle_install_transferred_cap(struct process *p, struct kobj *obj,
                                    uint32_t rights, uint64_t cap_id,
                                    int32_t *out_handle);
int khandle_install_transferred(struct process *p, struct kobj *obj,
                                uint32_t rights, int32_t *out_handle);

int kchannel_create_pair(struct kobj **out0, struct kobj **out1);
int kchannel_send(struct kobj *obj, const void *bytes, size_t num_bytes,
                  const struct khandle_transfer *handles, size_t num_handles,
                  uint32_t options);
int kchannel_recv(struct kobj *obj, void *bytes, size_t bytes_cap,
                  size_t *out_bytes, struct khandle_transfer *handles,
                  size_t handles_cap, size_t *out_handles,
                  bool *out_handles_truncated, uint32_t options);
int kchannel_poll_revents(struct kobj *channel_obj, uint32_t events,
                          uint32_t *out_revents);
int kchannel_poll_attach_vnode(struct kobj *channel_obj, struct vnode *vn);
int kchannel_poll_detach_vnode(struct kobj *channel_obj, struct vnode *vn);

int kport_create(struct kobj **out);
int kport_bind_channel(struct kobj *port_obj, struct kobj *channel_obj,
                       uint64_t key, uint32_t signals);
int kport_wait(struct kobj *port_obj, struct kairos_port_packet_user *out,
               uint64_t timeout_ns, uint32_t options);
int kport_poll_ready(struct kobj *port_obj, bool *out_ready);
int kport_poll_attach_vnode(struct kobj *port_obj, struct vnode *vn);
int kport_poll_detach_vnode(struct kobj *port_obj, struct vnode *vn);

int kfile_create(struct file *file, struct kobj **out);
int kfile_get_file(struct kobj *obj, struct file **out_file);

#endif
