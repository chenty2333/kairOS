/**
 * kernel/include/kairos/handle.h - Capability handles and channel/port IPC
 */

#ifndef _KAIROS_HANDLE_H
#define _KAIROS_HANDLE_H

#include <kairos/atomic.h>
#include <kairos/sync.h>
#include <kairos/types.h>

struct process;

#ifndef CONFIG_MAX_HANDLES_PER_PROC
#define CONFIG_MAX_HANDLES_PER_PROC 256
#endif

#define KOBJ_TYPE_CHANNEL 1U
#define KOBJ_TYPE_PORT    2U

#define KRIGHT_READ      (1U << 0)
#define KRIGHT_WRITE     (1U << 1)
#define KRIGHT_TRANSFER  (1U << 2)
#define KRIGHT_DUPLICATE (1U << 3)
#define KRIGHT_WAIT      (1U << 4)
#define KRIGHT_MANAGE    (1U << 5)

#define KRIGHT_CHANNEL_DEFAULT \
    (KRIGHT_READ | KRIGHT_WRITE | KRIGHT_TRANSFER | KRIGHT_DUPLICATE)
#define KRIGHT_PORT_DEFAULT (KRIGHT_WAIT | KRIGHT_MANAGE | KRIGHT_DUPLICATE)

#define KCHANNEL_OPT_NONBLOCK (1U << 0)

#define KPORT_BIND_READABLE    (1U << 0)
#define KPORT_BIND_PEER_CLOSED (1U << 1)
#define KPORT_BIND_ALL (KPORT_BIND_READABLE | KPORT_BIND_PEER_CLOSED)

#define KPORT_WAIT_NONBLOCK (1U << 0)

#define KCHANNEL_MAX_MSG_BYTES 1024U
#define KCHANNEL_MAX_MSG_HANDLES 8U
#define KCHANNEL_MAX_QUEUE 64U
#define KPORT_MAX_QUEUE 128U

struct kobj;

struct kobj_ops {
    void (*release)(struct kobj *obj);
};

struct kobj {
    atomic_t refcount;
    uint32_t type;
    const struct kobj_ops *ops;
};

struct khandle_entry {
    struct kobj *obj;
    uint32_t rights;
};

struct handletable {
    struct khandle_entry entries[CONFIG_MAX_HANDLES_PER_PROC];
    struct mutex lock;
    atomic_t refcount;
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
};

void kobj_init(struct kobj *obj, uint32_t type, const struct kobj_ops *ops);
void kobj_get(struct kobj *obj);
void kobj_put(struct kobj *obj);

struct handletable *handletable_alloc(void);
struct handletable *handletable_copy(struct handletable *src);
void handletable_get(struct handletable *ht);
void handletable_put(struct handletable *ht);

int khandle_alloc(struct process *p, struct kobj *obj, uint32_t rights);
int khandle_get(struct process *p, int32_t handle, uint32_t required_rights,
                struct kobj **out_obj, uint32_t *out_rights);
int khandle_take(struct process *p, int32_t handle, uint32_t required_rights,
                 struct kobj **out_obj, uint32_t *out_rights);
int khandle_restore(struct process *p, int32_t handle, struct kobj *obj,
                    uint32_t rights);
int khandle_close(struct process *p, int32_t handle);
int khandle_duplicate(struct process *p, int32_t handle, uint32_t rights_mask,
                      int32_t *out_new_handle);
void khandle_transfer_drop(struct kobj *obj);

int kchannel_create_pair(struct kobj **out0, struct kobj **out1);
int kchannel_send(struct kobj *obj, const void *bytes, size_t num_bytes,
                  const struct khandle_transfer *handles, size_t num_handles,
                  uint32_t options);
int kchannel_recv(struct kobj *obj, void *bytes, size_t bytes_cap,
                  size_t *out_bytes, struct khandle_transfer *handles,
                  size_t handles_cap, size_t *out_handles,
                  bool *out_handles_truncated, uint32_t options);

int kport_create(struct kobj **out);
int kport_bind_channel(struct kobj *port_obj, struct kobj *channel_obj,
                       uint64_t key, uint32_t signals);
int kport_wait(struct kobj *port_obj, struct kairos_port_packet_user *out,
               uint64_t timeout_ns, uint32_t options);

#endif
