/**
 * kernel/core/ipc/handle.c - Capability handles + channel/port objects
 */

#include <kairos/arch.h>
#include <kairos/handle.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/sysfs.h>
#include <kairos/vfs.h>

struct kchannel;
struct kport;

struct kchannel_binding {
    struct kport *port;
    uint64_t key;
    uint32_t signals;
};

struct kchannel_msg {
    struct list_head node;
    size_t num_bytes;
    uint8_t *bytes;
    bool inline_bytes_used;
    size_t num_handles;
    bool owns_caps;
    struct khandle_transfer handles[KCHANNEL_MAX_MSG_HANDLES];
    uint8_t inline_bytes[KCHANNEL_INLINE_MSG_BYTES];
};

struct kchannel_rendezvous {
    bool active;
    bool completed;
    void *bytes;
    size_t bytes_cap;
    struct khandle_transfer *handles;
    size_t handles_cap;
    size_t got_bytes;
    size_t got_handles;
    bool handles_truncated;
    int status;
};

struct kchannel {
    struct kobj obj;
    atomic_t handle_refs;
    struct mutex lock;
    struct poll_wait_source rd_src;
    struct poll_wait_source wr_src;
    struct list_head rxq;
    struct list_head rxq_free;
    size_t rxq_len;
    struct kchannel_msg rxq_slots[KCHANNEL_MAX_QUEUE];
    struct list_head poll_vnodes;
    struct kchannel *peer;
    bool peer_closed;
    bool endpoint_closed;
    struct kchannel_rendezvous *recv_waiter;
    struct kchannel_binding bind;
};

struct kport_packet {
    struct list_head node;
    uint64_t key;
    uint32_t observed;
};

struct kport_watch {
    struct list_head node;
    struct vnode *vn;
};

struct kchannel_watch {
    struct list_head node;
    struct vnode *vn;
};

struct kport {
    struct kobj obj;
    struct mutex lock;
    struct poll_wait_source rd_src;
    struct list_head queue;
    struct list_head poll_vnodes;
    size_t queue_len;
};

struct kfile {
    struct kobj obj;
    struct file *file;
};

struct ipc_registry_entry {
    struct list_head node;
    struct kobj *obj;
};

static LIST_HEAD(ipc_channel_registry);
static LIST_HEAD(ipc_port_registry);
static struct mutex ipc_registry_lock;
static bool ipc_registry_lock_ready;
static spinlock_t ipc_registry_init_lock = SPINLOCK_INIT;
static struct sysfs_node *ipc_sysfs_root;
static bool ipc_sysfs_ready;
static atomic_t kobj_id_next = ATOMIC_INIT(0);

static void kchannel_release_obj(struct kobj *obj);
static void kport_release_obj(struct kobj *obj);
static void kfile_release_obj(struct kobj *obj);
static int kchannel_obj_read(struct kobj *obj, void *buf, size_t len,
                             size_t *out_len, uint32_t options);
static int kchannel_obj_write(struct kobj *obj, const void *buf, size_t len,
                              size_t *out_len, uint32_t options);
static int kchannel_obj_poll_revents(struct kobj *obj, uint32_t events,
                                     uint32_t *out_revents);
static int kchannel_obj_signal(struct kobj *obj, uint32_t signal,
                               uint32_t flags);
static int kport_obj_read(struct kobj *obj, void *buf, size_t len,
                          size_t *out_len, uint32_t options);
static int kchannel_obj_poll_attach(struct kobj *obj, struct vnode *vn);
static int kchannel_obj_poll_detach(struct kobj *obj, struct vnode *vn);
static int kport_obj_wait(struct kobj *obj, void *out, uint64_t timeout_ns,
                          uint32_t options);
static int kport_obj_poll_revents(struct kobj *obj, uint32_t events,
                                  uint32_t *out_revents);
static int kport_obj_poll_attach(struct kobj *obj, struct vnode *vn);
static int kport_obj_poll_detach(struct kobj *obj, struct vnode *vn);
static bool kchannel_try_rendezvous_locked(struct kchannel *peer,
                                           struct kchannel_msg *msg);
static bool kchannel_try_rendezvous_raw_locked(
    struct kchannel *peer, const void *bytes, size_t num_bytes,
    const struct khandle_transfer *handles, size_t num_handles);
static void ipc_registry_register_obj(struct kobj *obj);
static void ipc_registry_unregister_obj(struct kobj *obj);
static void ipc_sysfs_ensure_ready(void);

static const struct kobj_ops kchannel_ops = {
    .release = kchannel_release_obj,
    .read = kchannel_obj_read,
    .write = kchannel_obj_write,
    .poll = kchannel_obj_poll_revents,
    .signal = kchannel_obj_signal,
    .poll_attach_vnode = kchannel_obj_poll_attach,
    .poll_detach_vnode = kchannel_obj_poll_detach,
};

static const struct kobj_ops kport_ops = {
    .release = kport_release_obj,
    .read = kport_obj_read,
    .wait = kport_obj_wait,
    .poll = kport_obj_poll_revents,
    .poll_attach_vnode = kport_obj_poll_attach,
    .poll_detach_vnode = kport_obj_poll_detach,
};

static const struct kobj_ops kfile_ops = {
    .release = kfile_release_obj,
};

static inline struct handletable *proc_handletable(struct process *p) {
    return p ? p->handletable : NULL;
}

static inline struct kchannel *kchannel_from_obj(struct kobj *obj) {
    if (!obj || obj->type != KOBJ_TYPE_CHANNEL)
        return NULL;
    return (struct kchannel *)obj;
}

static inline struct kport *kport_from_obj(struct kobj *obj) {
    if (!obj || obj->type != KOBJ_TYPE_PORT)
        return NULL;
    return (struct kport *)obj;
}

static inline struct kfile *kfile_from_obj(struct kobj *obj) {
    if (!obj || obj->type != KOBJ_TYPE_FILE)
        return NULL;
    return (struct kfile *)obj;
}

static const char *kobj_type_name(uint32_t type) {
    switch (type) {
    case KOBJ_TYPE_CHANNEL:
        return "channel";
    case KOBJ_TYPE_PORT:
        return "port";
    case KOBJ_TYPE_FILE:
        return "file";
    default:
        return "unknown";
    }
}

static const char *kobj_transfer_event_name(uint16_t event) {
    switch (event) {
    case KOBJ_TRANSFER_TAKE:
        return "take";
    case KOBJ_TRANSFER_ENQUEUE:
        return "enqueue";
    case KOBJ_TRANSFER_DELIVER:
        return "deliver";
    case KOBJ_TRANSFER_INSTALL:
        return "install";
    case KOBJ_TRANSFER_RESTORE:
        return "restore";
    case KOBJ_TRANSFER_DROP:
        return "drop";
    default:
        return "unknown";
    }
}

static void ipc_registry_ensure_lock(void) {
    if (__atomic_load_n(&ipc_registry_lock_ready, __ATOMIC_ACQUIRE))
        return;

    bool irq_flags;
    spin_lock_irqsave(&ipc_registry_init_lock, &irq_flags);
    if (!ipc_registry_lock_ready) {
        mutex_init(&ipc_registry_lock, "ipc_registry");
        __atomic_store_n(&ipc_registry_lock_ready, true, __ATOMIC_RELEASE);
    }
    spin_unlock_irqrestore(&ipc_registry_init_lock, irq_flags);
}

static struct list_head *ipc_registry_list_for_type(uint32_t type) {
    switch (type) {
    case KOBJ_TYPE_CHANNEL:
        return &ipc_channel_registry;
    case KOBJ_TYPE_PORT:
        return &ipc_port_registry;
    default:
        return NULL;
    }
}

static ssize_t ipc_sysfs_show_objects(void *priv __attribute__((unused)),
                                      char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    size_t len = 0;
    int n = snprintf(buf, bufsz, "id type refcount\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)(bufsz - 1);
    len = (size_t)n;

    ipc_registry_ensure_lock();
    mutex_lock(&ipc_registry_lock);

    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_channel_registry, node) {
        struct kobj *obj = ent->obj;
        if (!obj)
            continue;
        n = snprintf(buf + len, bufsz - len, "%u %s %u\n", obj->id,
                     kobj_type_name(obj->type), atomic_read(&obj->refcount));
        if (n < 0 || (size_t)n >= bufsz - len) {
            len = bufsz;
            break;
        }
        len += (size_t)n;
    }
    if (len < bufsz) {
        list_for_each_entry(ent, &ipc_port_registry, node) {
            struct kobj *obj = ent->obj;
            if (!obj)
                continue;
            n = snprintf(buf + len, bufsz - len, "%u %s %u\n", obj->id,
                         kobj_type_name(obj->type), atomic_read(&obj->refcount));
            if (n < 0 || (size_t)n >= bufsz - len) {
                len = bufsz;
                break;
            }
            len += (size_t)n;
        }
    }

    mutex_unlock(&ipc_registry_lock);
    return (ssize_t)((len < bufsz) ? len : bufsz);
}

static ssize_t ipc_sysfs_show_channels(void *priv __attribute__((unused)),
                                       char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    size_t len = 0;
    int n = snprintf(buf, bufsz,
                     "id refcount handle_refs rxq_len peer_closed endpoint_closed\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)(bufsz - 1);
    len = (size_t)n;

    ipc_registry_ensure_lock();
    mutex_lock(&ipc_registry_lock);

    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_channel_registry, node) {
        struct kobj *obj = ent->obj;
        struct kchannel *ch = kchannel_from_obj(obj);
        if (!obj || !ch)
            continue;

        size_t rxq_len = 0;
        bool peer_closed = false;
        bool endpoint_closed = false;
        mutex_lock(&ch->lock);
        rxq_len = ch->rxq_len;
        peer_closed = ch->peer_closed;
        endpoint_closed = ch->endpoint_closed;
        mutex_unlock(&ch->lock);

        n = snprintf(buf + len, bufsz - len, "%u %u %u %zu %u %u\n", obj->id,
                     atomic_read(&obj->refcount), atomic_read(&ch->handle_refs),
                     rxq_len, peer_closed ? 1U : 0U, endpoint_closed ? 1U : 0U);
        if (n < 0 || (size_t)n >= bufsz - len) {
            len = bufsz;
            break;
        }
        len += (size_t)n;
    }

    mutex_unlock(&ipc_registry_lock);
    return (ssize_t)((len < bufsz) ? len : bufsz);
}

static ssize_t ipc_sysfs_show_ports(void *priv __attribute__((unused)), char *buf,
                                    size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    size_t len = 0;
    int n = snprintf(buf, bufsz, "id refcount queue_len\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)(bufsz - 1);
    len = (size_t)n;

    ipc_registry_ensure_lock();
    mutex_lock(&ipc_registry_lock);

    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_port_registry, node) {
        struct kobj *obj = ent->obj;
        struct kport *port = kport_from_obj(obj);
        if (!obj || !port)
            continue;

        size_t queue_len = 0;
        mutex_lock(&port->lock);
        queue_len = port->queue_len;
        mutex_unlock(&port->lock);

        n = snprintf(buf + len, bufsz - len, "%u %u %zu\n", obj->id,
                     atomic_read(&obj->refcount), queue_len);
        if (n < 0 || (size_t)n >= bufsz - len) {
            len = bufsz;
            break;
        }
        len += (size_t)n;
    }

    mutex_unlock(&ipc_registry_lock);
    return (ssize_t)((len < bufsz) ? len : bufsz);
}

static ssize_t ipc_sysfs_show_transfers(void *priv __attribute__((unused)),
                                        char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    size_t len = 0;
    int n = snprintf(buf, bufsz,
                     "obj_id seq event from_pid to_pid rights cpu ticks\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)(bufsz - 1);
    len = (size_t)n;

    ipc_registry_ensure_lock();
    mutex_lock(&ipc_registry_lock);

    struct kobj_transfer_history_entry hist[KOBJ_TRANSFER_HISTORY_DEPTH] = {0};
    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_channel_registry, node) {
        struct kobj *obj = ent->obj;
        if (!obj)
            continue;
        size_t count =
            kobj_transfer_history_snapshot(obj, hist, KOBJ_TRANSFER_HISTORY_DEPTH);
        for (size_t i = 0; i < count; i++) {
            if (hist[i].seq == 0)
                continue;
            n = snprintf(buf + len, bufsz - len, "%u %u %s %d %d 0x%x %u %llu\n",
                         obj->id, hist[i].seq,
                         kobj_transfer_event_name(hist[i].event),
                         hist[i].from_pid, hist[i].to_pid, hist[i].rights,
                         hist[i].cpu, (unsigned long long)hist[i].ticks);
            if (n < 0 || (size_t)n >= bufsz - len) {
                len = bufsz;
                goto out;
            }
            len += (size_t)n;
        }
    }

    list_for_each_entry(ent, &ipc_port_registry, node) {
        struct kobj *obj = ent->obj;
        if (!obj)
            continue;
        size_t count =
            kobj_transfer_history_snapshot(obj, hist, KOBJ_TRANSFER_HISTORY_DEPTH);
        for (size_t i = 0; i < count; i++) {
            if (hist[i].seq == 0)
                continue;
            n = snprintf(buf + len, bufsz - len, "%u %u %s %d %d 0x%x %u %llu\n",
                         obj->id, hist[i].seq,
                         kobj_transfer_event_name(hist[i].event),
                         hist[i].from_pid, hist[i].to_pid, hist[i].rights,
                         hist[i].cpu, (unsigned long long)hist[i].ticks);
            if (n < 0 || (size_t)n >= bufsz - len) {
                len = bufsz;
                goto out;
            }
            len += (size_t)n;
        }
    }

out:
    mutex_unlock(&ipc_registry_lock);
    return (ssize_t)((len < bufsz) ? len : bufsz);
}

static const struct sysfs_attribute ipc_sysfs_attrs[] = {
    {.name = "objects", .mode = 0444, .show = ipc_sysfs_show_objects},
    {.name = "channels", .mode = 0444, .show = ipc_sysfs_show_channels},
    {.name = "ports", .mode = 0444, .show = ipc_sysfs_show_ports},
    {.name = "transfers", .mode = 0444, .show = ipc_sysfs_show_transfers},
};

static void ipc_sysfs_ensure_ready(void) {
    ipc_registry_ensure_lock();
    if (__atomic_load_n(&ipc_sysfs_ready, __ATOMIC_ACQUIRE))
        return;
    mutex_lock(&ipc_registry_lock);
    if (ipc_sysfs_ready) {
        mutex_unlock(&ipc_registry_lock);
        return;
    }

    struct sysfs_node *root = sysfs_root();
    if (!root) {
        mutex_unlock(&ipc_registry_lock);
        return;
    }

    ipc_sysfs_root = sysfs_mkdir(root, "ipc");
    if (!ipc_sysfs_root) {
        mutex_unlock(&ipc_registry_lock);
        return;
    }

    if (sysfs_create_files(ipc_sysfs_root, ipc_sysfs_attrs,
                           ARRAY_SIZE(ipc_sysfs_attrs)) < 0) {
        pr_warn("ipc: failed to create /sys/ipc attributes\n");
        mutex_unlock(&ipc_registry_lock);
        return;
    }

    __atomic_store_n(&ipc_sysfs_ready, true, __ATOMIC_RELEASE);
    mutex_unlock(&ipc_registry_lock);
}

static void ipc_registry_register_obj(struct kobj *obj) {
    if (!obj)
        return;
    struct list_head *list = ipc_registry_list_for_type(obj->type);
    if (!list)
        return;

    ipc_registry_ensure_lock();
    struct ipc_registry_entry *ent = kzalloc(sizeof(*ent));
    if (!ent)
        return;
    ent->obj = obj;
    INIT_LIST_HEAD(&ent->node);

    mutex_lock(&ipc_registry_lock);
    list_add_tail(&ent->node, list);
    mutex_unlock(&ipc_registry_lock);

    ipc_sysfs_ensure_ready();
}

static void ipc_registry_unregister_obj(struct kobj *obj) {
    if (!obj)
        return;
    struct list_head *list = ipc_registry_list_for_type(obj->type);
    if (!list)
        return;

    ipc_registry_ensure_lock();
    mutex_lock(&ipc_registry_lock);
    struct ipc_registry_entry *ent, *tmp;
    list_for_each_entry_safe(ent, tmp, list, node) {
        if (ent->obj != obj)
            continue;
        list_del(&ent->node);
        mutex_unlock(&ipc_registry_lock);
        kfree(ent);
        return;
    }
    mutex_unlock(&ipc_registry_lock);
}

static void kchannel_emit_locked(struct kchannel *ch, uint32_t signal);
static void kchannel_poll_wake_locked(struct kchannel *ch, uint32_t events);

static uint32_t kchannel_poll_revents_locked(struct kchannel *ch,
                                             uint32_t events) {
    uint32_t revents = 0;
    if (!ch)
        return 0;

    if (ch->rxq_len > 0)
        revents |= POLLIN;
    if (ch->peer_closed || !ch->peer)
        revents |= POLLHUP;

    if ((events & POLLOUT) && !ch->peer_closed && ch->peer) {
        if (!mutex_trylock(&ch->peer->lock)) {
            /*
             * Poll wake callbacks can observe channel state while send/recv
             * still holds endpoint locks. Report writable conservatively.
             */
            revents |= POLLOUT;
        } else {
            if (ch->peer->rxq_len < KCHANNEL_MAX_QUEUE)
                revents |= POLLOUT;
            mutex_unlock(&ch->peer->lock);
        }
    }

    return revents;
}

static void kchannel_on_last_handle_release(struct kchannel *ch) {
    if (!ch)
        return;

    struct kchannel *peer = NULL;
    struct kport *bound = NULL;

    mutex_lock(&ch->lock);
    if (ch->endpoint_closed) {
        mutex_unlock(&ch->lock);
        return;
    }
    ch->endpoint_closed = true;
    peer = ch->peer;
    ch->peer = NULL;

    bound = ch->bind.port;
    ch->bind.port = NULL;
    ch->bind.key = 0;
    ch->bind.signals = 0;
    mutex_unlock(&ch->lock);

    if (bound)
        kobj_put(&bound->obj);

    if (!peer)
        return;

    bool dropped_peer_ref_to_ch = false;
    mutex_lock(&peer->lock);
    if (peer->peer == ch) {
        peer->peer = NULL;
        dropped_peer_ref_to_ch = true;
    }
    peer->peer_closed = true;
    poll_wait_source_wake_all(&peer->rd_src, 0);
    poll_wait_source_wake_all(&peer->wr_src, 0);
    wait_queue_wakeup_all(&peer->obj.waitq);
    kchannel_poll_wake_locked(peer, POLLHUP);
    kchannel_emit_locked(peer, KPORT_BIND_PEER_CLOSED);
    mutex_unlock(&peer->lock);

    kobj_put(&peer->obj);
    if (dropped_peer_ref_to_ch)
        kobj_put(&ch->obj);
}

static void kobj_handle_ref_inc(struct kobj *obj) {
    struct kchannel *ch = kchannel_from_obj(obj);
    if (!ch)
        return;
    atomic_inc(&ch->handle_refs);
}

static void kobj_handle_ref_dec(struct kobj *obj) {
    struct kchannel *ch = kchannel_from_obj(obj);
    if (!ch)
        return;
    uint32_t left = atomic_dec_return(&ch->handle_refs);
    if (left == 0)
        kchannel_on_last_handle_release(ch);
}

static void kchannel_msg_reset(struct kchannel_msg *msg) {
    if (!msg)
        return;
    for (size_t i = 0; i < msg->num_handles; i++) {
        if (msg->handles[i].obj) {
            if (msg->owns_caps) {
                khandle_transfer_drop_cap(msg->handles[i].obj,
                                          msg->handles[i].rights,
                                          msg->handles[i].cap_id);
            } else {
                kobj_put(msg->handles[i].obj);
            }
            msg->handles[i].obj = NULL;
        }
    }
    if (msg->bytes && !msg->inline_bytes_used)
        kfree(msg->bytes);
    msg->num_bytes = 0;
    msg->bytes = NULL;
    msg->inline_bytes_used = false;
    msg->num_handles = 0;
    msg->owns_caps = false;
    INIT_LIST_HEAD(&msg->node);
}

static struct kchannel_msg *kchannel_msg_alloc_locked(struct kchannel *ch) {
    if (!ch || list_empty(&ch->rxq_free))
        return NULL;
    struct kchannel_msg *msg =
        list_first_entry(&ch->rxq_free, struct kchannel_msg, node);
    list_del(&msg->node);
    INIT_LIST_HEAD(&msg->node);
    return msg;
}

static void kchannel_msg_recycle_locked(struct kchannel *ch,
                                        struct kchannel_msg *msg) {
    if (!ch || !msg)
        return;
    kchannel_msg_reset(msg);
    list_add_tail(&msg->node, &ch->rxq_free);
}

static uint32_t kobj_refcount_record(struct kobj *obj,
                                     enum kobj_refcount_event event,
                                     uint32_t refcount) {
    if (!obj)
        return 0;
    uint32_t seq = atomic_add_return(&obj->refcount_hist_head, 1);
    uint32_t idx = (seq - 1) % KOBJ_REFCOUNT_HISTORY_DEPTH;
    struct process *curr = proc_current();
    struct kobj_refcount_history_entry *ent = &obj->refcount_hist[idx];
    ent->ticks = arch_timer_get_ticks();
    ent->pid = curr ? curr->pid : -1;
    ent->refcount = refcount;
    ent->event = (uint16_t)event;
    int cpu = arch_cpu_id();
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        cpu = 0;
    ent->cpu = (uint16_t)cpu;
    __atomic_store_n(&ent->seq, seq, __ATOMIC_RELEASE);
    return seq;
}

static uint32_t kobj_transfer_record_internal(struct kobj *obj,
                                              enum kobj_transfer_event event,
                                              int32_t from_pid, int32_t to_pid,
                                              uint32_t rights) {
    if (!obj)
        return 0;
    uint32_t seq = atomic_add_return(&obj->transfer_hist_head, 1);
    uint32_t idx = (seq - 1) % KOBJ_TRANSFER_HISTORY_DEPTH;
    struct kobj_transfer_history_entry *ent = &obj->transfer_hist[idx];
    ent->ticks = arch_timer_get_ticks();
    ent->from_pid = from_pid;
    ent->to_pid = to_pid;
    ent->rights = rights;
    ent->event = (uint16_t)event;
    int cpu = arch_cpu_id();
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        cpu = 0;
    ent->cpu = (uint16_t)cpu;
    __atomic_store_n(&ent->seq, seq, __ATOMIC_RELEASE);
    return seq;
}

void kobj_init(struct kobj *obj, uint32_t type, const struct kobj_ops *ops) {
    if (!obj)
        return;
    atomic_init(&obj->refcount, 1);
    atomic_init(&obj->refcount_hist_head, 0);
    atomic_init(&obj->transfer_hist_head, 0);
    memset(obj->refcount_hist, 0, sizeof(obj->refcount_hist));
    memset(obj->transfer_hist, 0, sizeof(obj->transfer_hist));
    obj->id = atomic_inc_return(&kobj_id_next);
    obj->type = type;
    obj->ops = ops;
    wait_queue_init(&obj->waitq);
    kobj_refcount_record(obj, KOBJ_REFCOUNT_INIT, 1);
    ipc_registry_register_obj(obj);
}

void kobj_get(struct kobj *obj) {
    if (!obj)
        return;
    uint32_t refcount = atomic_inc_return(&obj->refcount);
    kobj_refcount_record(obj, KOBJ_REFCOUNT_GET, refcount);
}

void kobj_put(struct kobj *obj) {
    if (!obj)
        return;
    uint32_t refcount = atomic_dec_return(&obj->refcount);
    if (refcount == 0)
        kobj_refcount_record(obj, KOBJ_REFCOUNT_LAST_PUT, 0);
    else
        kobj_refcount_record(obj, KOBJ_REFCOUNT_PUT, refcount);
    if (refcount == 0 && obj->ops && obj->ops->release)
        obj->ops->release(obj);
}

uint32_t kobj_id(const struct kobj *obj) {
    if (!obj)
        return 0;
    return obj->id;
}

int kobj_read(struct kobj *obj, void *buf, size_t len, size_t *out_len,
              uint32_t options) {
    if (!obj)
        return -EINVAL;
    if ((len > 0 && !buf) || !out_len)
        return -EINVAL;
    *out_len = 0;
    if (!obj->ops || !obj->ops->read)
        return -ENOTSUP;
    return obj->ops->read(obj, buf, len, out_len, options);
}

int kobj_write(struct kobj *obj, const void *buf, size_t len, size_t *out_len,
               uint32_t options) {
    if (!obj)
        return -EINVAL;
    if ((len > 0 && !buf) || !out_len)
        return -EINVAL;
    *out_len = 0;
    if (!obj->ops || !obj->ops->write)
        return -ENOTSUP;
    return obj->ops->write(obj, buf, len, out_len, options);
}

int kobj_wait(struct kobj *obj, void *out, uint64_t timeout_ns,
              uint32_t options) {
    if (!obj || !obj->ops || !obj->ops->wait)
        return -ENOTSUP;
    return obj->ops->wait(obj, out, timeout_ns, options);
}

int kobj_poll(struct kobj *obj, uint32_t events, uint32_t *out_revents) {
    if (!obj || !out_revents)
        return -EINVAL;
    if (!obj->ops || !obj->ops->poll)
        return -ENOTSUP;
    return obj->ops->poll(obj, events, out_revents);
}

int kobj_poll_revents(struct kobj *obj, uint32_t events,
                      uint32_t *out_revents) {
    return kobj_poll(obj, events, out_revents);
}

int kobj_signal(struct kobj *obj, uint32_t signal, uint32_t flags) {
    if (!obj)
        return -EINVAL;
    if (!obj->ops || !obj->ops->signal)
        return -ENOTSUP;
    return obj->ops->signal(obj, signal, flags);
}

int kobj_poll_attach_vnode(struct kobj *obj, struct vnode *vn) {
    if (!obj || !vn)
        return -EINVAL;
    if (!obj->ops || !obj->ops->poll_attach_vnode)
        return -ENOTSUP;
    return obj->ops->poll_attach_vnode(obj, vn);
}

int kobj_poll_detach_vnode(struct kobj *obj, struct vnode *vn) {
    if (!obj || !vn)
        return -EINVAL;
    if (!obj->ops || !obj->ops->poll_detach_vnode)
        return -ENOTSUP;
    return obj->ops->poll_detach_vnode(obj, vn);
}

size_t kobj_refcount_history_snapshot(struct kobj *obj,
                                      struct kobj_refcount_history_entry *out,
                                      size_t max_entries) {
    if (!obj || !out || max_entries == 0)
        return 0;

    uint32_t head = atomic_read(&obj->refcount_hist_head);
    size_t available = head < KOBJ_REFCOUNT_HISTORY_DEPTH ? (size_t)head
                                                          : KOBJ_REFCOUNT_HISTORY_DEPTH;
    if (available > max_entries)
        available = max_entries;
    if (available == 0)
        return 0;

    uint32_t start = (head >= available) ? (head - (uint32_t)available) : 0;
    for (size_t i = 0; i < available; i++) {
        uint32_t pos = (start + (uint32_t)i) % KOBJ_REFCOUNT_HISTORY_DEPTH;
        const struct kobj_refcount_history_entry *src = &obj->refcount_hist[pos];
        while (1) {
            uint32_t seq0 = __atomic_load_n(&src->seq, __ATOMIC_ACQUIRE);
            if (seq0 == 0) {
                memset(&out[i], 0, sizeof(out[i]));
                break;
            }
            out[i] = *src;
            uint32_t seq1 = __atomic_load_n(&src->seq, __ATOMIC_ACQUIRE);
            if (seq0 == seq1 && seq0 == out[i].seq)
                break;
        }
    }
    return available;
}

void kobj_transfer_record(struct kobj *obj, enum kobj_transfer_event event,
                          int32_t from_pid, int32_t to_pid, uint32_t rights) {
    if (!obj)
        return;
    kobj_transfer_record_internal(obj, event, from_pid, to_pid, rights);
}

size_t kobj_transfer_history_snapshot(struct kobj *obj,
                                      struct kobj_transfer_history_entry *out,
                                      size_t max_entries) {
    if (!obj || !out || max_entries == 0)
        return 0;

    uint32_t head = atomic_read(&obj->transfer_hist_head);
    size_t available = head < KOBJ_TRANSFER_HISTORY_DEPTH ? (size_t)head
                                                          : KOBJ_TRANSFER_HISTORY_DEPTH;
    if (available > max_entries)
        available = max_entries;
    if (available == 0)
        return 0;

    uint32_t start = (head >= available) ? (head - (uint32_t)available) : 0;
    for (size_t i = 0; i < available; i++) {
        uint32_t pos = (start + (uint32_t)i) % KOBJ_TRANSFER_HISTORY_DEPTH;
        const struct kobj_transfer_history_entry *src = &obj->transfer_hist[pos];
        while (1) {
            uint32_t seq0 = __atomic_load_n(&src->seq, __ATOMIC_ACQUIRE);
            if (seq0 == 0) {
                memset(&out[i], 0, sizeof(out[i]));
                break;
            }
            out[i] = *src;
            uint32_t seq1 = __atomic_load_n(&src->seq, __ATOMIC_ACQUIRE);
            if (seq0 == seq1 && seq0 == out[i].seq)
                break;
        }
    }
    return available;
}

#define KHANDLE_CACHE_SLOTS 16U
_Static_assert((KHANDLE_CACHE_SLOTS & (KHANDLE_CACHE_SLOTS - 1U)) == 0,
               "KHANDLE_CACHE_SLOTS must be power-of-two");

struct kcap_node {
    struct list_head all_node;
    struct list_head sibling_node;
    struct list_head children;
    struct kcap_node *parent;
    uint64_t id;
    struct handletable *owner_ht;
    int32_t owner_handle;
    bool live;
};

struct khandle_lookup_cache_entry {
    struct process *proc;
    struct handletable *ht;
    uint64_t cache_epoch;
    int32_t handle;
    uint32_t seq;
    enum kobj_access_op access;
    uint32_t rights;
    struct kobj *obj;
};

struct khandle_lookup_cache_cpu {
    struct khandle_lookup_cache_entry slots[KHANDLE_CACHE_SLOTS];
};

static LIST_HEAD(kcap_nodes);
static spinlock_t kcap_lock = SPINLOCK_INIT;
static uint64_t kcap_next_id = 1;
static uint64_t khandle_cache_epoch_next = 1;
static struct khandle_lookup_cache_cpu
    khandle_lookup_cache[CONFIG_MAX_CPUS];

static uint64_t kcap_alloc_id(void) {
    return __atomic_fetch_add(&kcap_next_id, 1, __ATOMIC_RELAXED);
}

static uint64_t khandle_alloc_cache_epoch(void) {
    return __atomic_fetch_add(&khandle_cache_epoch_next, 1,
                              __ATOMIC_RELAXED);
}

static struct kcap_node *kcap_find_locked(uint64_t cap_id) {
    struct list_head *pos = NULL;
    list_for_each(pos, &kcap_nodes) {
        struct kcap_node *node = list_entry(pos, struct kcap_node, all_node);
        if (node->id == cap_id)
            return node;
    }
    return NULL;
}

static void kcap_free_nodes(struct list_head *free_nodes) {
    struct list_head *pos = NULL;
    struct list_head *tmp = NULL;
    list_for_each_safe(pos, tmp, free_nodes) {
        struct kcap_node *node = list_entry(pos, struct kcap_node, all_node);
        list_del(&node->all_node);
        kfree(node);
    }
}

static void kcap_prune_locked(struct kcap_node *node,
                              struct list_head *free_nodes) {
    while (node && !node->live && list_empty(&node->children)) {
        struct kcap_node *parent = node->parent;
        if (parent)
            list_del(&node->sibling_node);
        list_del(&node->all_node);
        list_add(&node->all_node, free_nodes);
        node = parent;
    }
}

static uint64_t kcap_create(uint64_t parent_cap_id, struct handletable *owner_ht,
                            int32_t owner_handle) {
    struct kcap_node *node = kzalloc(sizeof(*node));
    if (!node)
        return KHANDLE_INVALID_CAP_ID;

    INIT_LIST_HEAD(&node->all_node);
    INIT_LIST_HEAD(&node->sibling_node);
    INIT_LIST_HEAD(&node->children);
    node->owner_ht = owner_ht;
    node->owner_handle = owner_handle;
    node->live = true;

    spin_lock(&kcap_lock);
    if (parent_cap_id != KHANDLE_INVALID_CAP_ID) {
        struct kcap_node *parent = kcap_find_locked(parent_cap_id);
        if (!parent) {
            spin_unlock(&kcap_lock);
            kfree(node);
            return KHANDLE_INVALID_CAP_ID;
        }
        node->parent = parent;
        list_add_tail(&node->sibling_node, &parent->children);
    }
    node->id = kcap_alloc_id();
    list_add_tail(&node->all_node, &kcap_nodes);
    spin_unlock(&kcap_lock);
    return node->id;
}

static int kcap_bind_existing(uint64_t cap_id, struct handletable *owner_ht,
                              int32_t owner_handle) {
    if (cap_id == KHANDLE_INVALID_CAP_ID)
        return -EINVAL;

    spin_lock(&kcap_lock);
    struct kcap_node *node = kcap_find_locked(cap_id);
    if (!node) {
        spin_unlock(&kcap_lock);
        return -ENOENT;
    }
    if (node->live) {
        spin_unlock(&kcap_lock);
        return -EBUSY;
    }
    node->owner_ht = owner_ht;
    node->owner_handle = owner_handle;
    node->live = true;
    spin_unlock(&kcap_lock);
    return 0;
}

static void kcap_detach_owner(uint64_t cap_id, struct handletable *owner_ht,
                              int32_t owner_handle, bool retain_node) {
    if (cap_id == KHANDLE_INVALID_CAP_ID)
        return;

    LIST_HEAD(free_nodes);
    spin_lock(&kcap_lock);
    struct kcap_node *node = kcap_find_locked(cap_id);
    if (node && node->live && node->owner_ht == owner_ht &&
        node->owner_handle == owner_handle) {
        node->owner_ht = NULL;
        node->owner_handle = -1;
        node->live = false;
        if (!retain_node)
            kcap_prune_locked(node, &free_nodes);
    }
    spin_unlock(&kcap_lock);
    kcap_free_nodes(&free_nodes);
}

static void kcap_drop_detached(uint64_t cap_id) {
    if (cap_id == KHANDLE_INVALID_CAP_ID)
        return;

    LIST_HEAD(free_nodes);
    spin_lock(&kcap_lock);
    struct kcap_node *node = kcap_find_locked(cap_id);
    if (node && !node->live)
        kcap_prune_locked(node, &free_nodes);
    spin_unlock(&kcap_lock);
    kcap_free_nodes(&free_nodes);
}

static struct kcap_node *kcap_find_live_descendant_locked(
    struct kcap_node *root) {
    if (!root)
        return NULL;

    struct list_head *pos = NULL;
    list_for_each(pos, &root->children) {
        struct kcap_node *child =
            list_entry(pos, struct kcap_node, sibling_node);
        if (child->live && child->owner_ht &&
            child->owner_handle >= 0 &&
            child->owner_handle < CONFIG_MAX_HANDLES_PER_PROC)
            return child;
        struct kcap_node *nested = kcap_find_live_descendant_locked(child);
        if (nested)
            return nested;
    }
    return NULL;
}

static int kcap_pick_live_descendant(uint64_t root_cap_id,
                                     struct handletable **out_ht,
                                     int32_t *out_handle,
                                     uint64_t *out_cap_id) {
    if (!out_ht || !out_handle || !out_cap_id)
        return -EINVAL;
    *out_ht = NULL;
    *out_handle = -1;
    *out_cap_id = KHANDLE_INVALID_CAP_ID;

    spin_lock(&kcap_lock);
    struct kcap_node *root = kcap_find_locked(root_cap_id);
    if (!root) {
        spin_unlock(&kcap_lock);
        return -ENOENT;
    }
    struct kcap_node *node = kcap_find_live_descendant_locked(root);
    if (!node || !node->owner_ht) {
        spin_unlock(&kcap_lock);
        return -ENOENT;
    }

    *out_ht = node->owner_ht;
    handletable_get(*out_ht);
    *out_handle = node->owner_handle;
    *out_cap_id = node->id;
    spin_unlock(&kcap_lock);
    return 0;
}

static bool krights_allow_access(uint32_t rights, enum kobj_access_op access) {
    switch (access) {
    case KOBJ_ACCESS_READ:
        return (rights & KRIGHT_READ) != 0;
    case KOBJ_ACCESS_WRITE:
        return (rights & KRIGHT_WRITE) != 0;
    case KOBJ_ACCESS_POLL:
        return (rights & (KRIGHT_READ | KRIGHT_WRITE | KRIGHT_WAIT)) != 0;
    case KOBJ_ACCESS_SIGNAL:
        return (rights & (KRIGHT_MANAGE | KRIGHT_READ)) != 0;
    case KOBJ_ACCESS_WAIT:
        return (rights & KRIGHT_WAIT) != 0;
    case KOBJ_ACCESS_MANAGE:
        return (rights & KRIGHT_MANAGE) != 0;
    case KOBJ_ACCESS_DUPLICATE:
        return (rights & KRIGHT_DUPLICATE) != 0;
    case KOBJ_ACCESS_TRANSFER:
        return (rights & KRIGHT_TRANSFER) != 0;
    default:
        return false;
    }
}

static bool khandle_rights_allow(uint32_t rights, uint32_t required_rights,
                                 enum kobj_access_op access, bool use_access) {
    if (use_access)
        return krights_allow_access(rights, access);
    return (rights & required_rights) == required_rights;
}

static int khandle_cache_cpu_index(void) {
    int cpu = arch_cpu_id_stable();
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        cpu = 0;
    return cpu;
}

static uint32_t khandle_cache_slot_index(int32_t handle,
                                         enum kobj_access_op access) {
    uint32_t key = (uint32_t)handle ^ ((uint32_t)access << 8);
    return key & (KHANDLE_CACHE_SLOTS - 1U);
}

static void khandle_cache_slot_invalidate(
    struct khandle_lookup_cache_entry *slot) {
    if (!slot)
        return;
    if (slot->obj)
        kobj_put(slot->obj);
    memset(slot, 0, sizeof(*slot));
}

static bool khandle_cache_lookup(struct process *p, struct handletable *ht,
                                 int32_t handle, enum kobj_access_op access,
                                 struct kobj **out_obj,
                                 uint32_t *out_rights) {
    if (!p || !ht || !out_obj)
        return false;

    int cpu = khandle_cache_cpu_index();
    struct khandle_lookup_cache_entry *slot =
        &khandle_lookup_cache[cpu]
             .slots[khandle_cache_slot_index(handle, access)];
    if (!slot->obj)
        return false;
    if (slot->proc != p || slot->ht != ht || slot->handle != handle ||
        slot->access != access) {
        return false;
    }

    if (slot->cache_epoch != ht->cache_epoch ||
        slot->seq != (uint32_t)atomic_read(&ht->seq) ||
        !khandle_rights_allow(slot->rights, 0, access, true)) {
        khandle_cache_slot_invalidate(slot);
        return false;
    }

    kobj_get(slot->obj);
    *out_obj = slot->obj;
    if (out_rights)
        *out_rights = slot->rights;
    return true;
}

static void khandle_cache_store(struct process *p, struct handletable *ht,
                                int32_t handle, enum kobj_access_op access,
                                uint32_t rights, struct kobj *obj) {
    if (!p || !ht || !obj)
        return;

    int cpu = khandle_cache_cpu_index();
    struct khandle_lookup_cache_entry *slot =
        &khandle_lookup_cache[cpu]
             .slots[khandle_cache_slot_index(handle, access)];
    khandle_cache_slot_invalidate(slot);
    slot->proc = p;
    slot->ht = ht;
    slot->cache_epoch = ht->cache_epoch;
    slot->handle = handle;
    slot->seq = (uint32_t)atomic_read(&ht->seq);
    slot->access = access;
    slot->rights = rights;
    slot->obj = obj;
    kobj_get(obj);
}

struct handletable *handletable_alloc(void) {
    struct handletable *ht = kzalloc(sizeof(*ht));
    if (!ht)
        return NULL;
    mutex_init(&ht->lock, "handletable");
    atomic_init(&ht->refcount, 1);
    atomic_init(&ht->seq, 1);
    ht->cache_epoch = khandle_alloc_cache_epoch();
    return ht;
}

struct handletable *handletable_copy(struct handletable *src) {
    if (!src)
        return handletable_alloc();

    struct handletable *dst = handletable_alloc();
    if (!dst)
        return NULL;

    int rc = 0;
    mutex_lock(&src->lock);
    for (int i = 0; i < CONFIG_MAX_HANDLES_PER_PROC; i++) {
        struct kobj *obj = src->entries[i].obj;
        if (!obj)
            continue;
        uint64_t parent_cap = src->entries[i].cap_id;
        uint64_t cap_id = kcap_create(parent_cap, dst, i);
        if (cap_id == KHANDLE_INVALID_CAP_ID) {
            rc = -ENOMEM;
            break;
        }
        kobj_get(obj);
        kobj_handle_ref_inc(obj);
        dst->entries[i].obj = obj;
        dst->entries[i].rights = src->entries[i].rights;
        dst->entries[i].cap_id = cap_id;
    }
    mutex_unlock(&src->lock);
    if (rc < 0) {
        handletable_put(dst);
        return NULL;
    }

    return dst;
}

void handletable_get(struct handletable *ht) {
    if (!ht)
        return;
    atomic_inc(&ht->refcount);
}

void handletable_put(struct handletable *ht) {
    if (!ht)
        return;
    if (atomic_dec_return(&ht->refcount) != 0)
        return;

    for (int i = 0; i < CONFIG_MAX_HANDLES_PER_PROC; i++) {
        struct kobj *obj = ht->entries[i].obj;
        uint64_t cap_id = ht->entries[i].cap_id;
        if (!obj)
            continue;
        ht->entries[i].obj = NULL;
        ht->entries[i].rights = 0;
        ht->entries[i].cap_id = KHANDLE_INVALID_CAP_ID;
        kcap_detach_owner(cap_id, ht, i, false);
        kobj_handle_ref_dec(obj);
        kobj_put(obj);
    }
    kfree(ht);
}

static int khandle_close_in_table(struct handletable *ht, int32_t handle,
                                  uint64_t expected_cap_id,
                                  bool enforce_cap_id) {
    if (!ht)
        return -EINVAL;
    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    struct kobj *obj = NULL;
    uint64_t cap_id = KHANDLE_INVALID_CAP_ID;
    mutex_lock(&ht->lock);
    obj = ht->entries[handle].obj;
    if (!obj) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    cap_id = ht->entries[handle].cap_id;
    if (enforce_cap_id && cap_id != expected_cap_id) {
        mutex_unlock(&ht->lock);
        return -EAGAIN;
    }
    ht->entries[handle].obj = NULL;
    ht->entries[handle].rights = 0;
    ht->entries[handle].cap_id = KHANDLE_INVALID_CAP_ID;
    atomic_inc(&ht->seq);
    mutex_unlock(&ht->lock);

    kcap_detach_owner(cap_id, ht, handle, false);
    kobj_handle_ref_dec(obj);
    kobj_put(obj);
    return 0;
}

static int khandle_install_locked(struct handletable *ht, int32_t handle,
                                  struct kobj *obj, uint32_t rights,
                                  uint64_t parent_cap_id,
                                  uint64_t existing_cap_id) {
    uint64_t cap_id = KHANDLE_INVALID_CAP_ID;
    if (existing_cap_id != KHANDLE_INVALID_CAP_ID) {
        int rc = kcap_bind_existing(existing_cap_id, ht, handle);
        if (rc < 0)
            return rc;
        cap_id = existing_cap_id;
    } else {
        cap_id = kcap_create(parent_cap_id, ht, handle);
        if (cap_id == KHANDLE_INVALID_CAP_ID)
            return -ENOMEM;
    }

    kobj_get(obj);
    kobj_handle_ref_inc(obj);
    ht->entries[handle].obj = obj;
    ht->entries[handle].rights = rights;
    ht->entries[handle].cap_id = cap_id;
    atomic_inc(&ht->seq);
    return 0;
}

int khandle_alloc(struct process *p, struct kobj *obj, uint32_t rights) {
    struct handletable *ht = proc_handletable(p);
    if (!ht || !obj || rights == 0)
        return -EINVAL;

    mutex_lock(&ht->lock);
    for (int h = 0; h < CONFIG_MAX_HANDLES_PER_PROC; h++) {
        if (ht->entries[h].obj)
            continue;
        int rc =
            khandle_install_locked(ht, h, obj, rights, KHANDLE_INVALID_CAP_ID,
                                   KHANDLE_INVALID_CAP_ID);
        mutex_unlock(&ht->lock);
        if (rc < 0)
            return rc;
        return h;
    }
    mutex_unlock(&ht->lock);
    return -EMFILE;
}

static int khandle_get_common(struct process *p, int32_t handle,
                              uint32_t required_rights,
                              enum kobj_access_op access, bool use_access,
                              struct kobj **out_obj, uint32_t *out_rights,
                              bool take, uint64_t *out_cap_id) {
    struct handletable *ht = proc_handletable(p);
    if (!ht || !out_obj)
        return -EINVAL;

    *out_obj = NULL;
    if (out_rights)
        *out_rights = 0;
    if (out_cap_id)
        *out_cap_id = KHANDLE_INVALID_CAP_ID;

    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    if (!take && use_access &&
        khandle_cache_lookup(p, ht, handle, access, out_obj, out_rights)) {
        return 0;
    }

    struct kobj *obj = NULL;
    uint32_t rights = 0;
    uint64_t cap_id = KHANDLE_INVALID_CAP_ID;
    mutex_lock(&ht->lock);
    obj = ht->entries[handle].obj;
    rights = ht->entries[handle].rights;
    cap_id = ht->entries[handle].cap_id;
    if (!obj) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    if (!khandle_rights_allow(rights, required_rights, access, use_access)) {
        mutex_unlock(&ht->lock);
        return -EACCES;
    }

    if (take) {
        ht->entries[handle].obj = NULL;
        ht->entries[handle].rights = 0;
        ht->entries[handle].cap_id = KHANDLE_INVALID_CAP_ID;
        atomic_inc(&ht->seq);
    } else {
        kobj_get(obj);
    }
    mutex_unlock(&ht->lock);

    if (take) {
        bool retain_cap_node =
            use_access && access == KOBJ_ACCESS_TRANSFER;
        kcap_detach_owner(cap_id, ht, handle, retain_cap_node);
        if (use_access && access == KOBJ_ACCESS_TRANSFER) {
            int32_t from_pid = p ? p->pid : -1;
            kobj_transfer_record(obj, KOBJ_TRANSFER_TAKE, from_pid, -1,
                                 rights);
        }
    } else if (use_access) {
        khandle_cache_store(p, ht, handle, access, rights, obj);
    }

    *out_obj = obj;
    if (out_rights)
        *out_rights = rights;
    if (out_cap_id)
        *out_cap_id = cap_id;
    return 0;
}

int khandle_get(struct process *p, int32_t handle, uint32_t required_rights,
                struct kobj **out_obj, uint32_t *out_rights) {
    return khandle_get_common(p, handle, required_rights, 0, false, out_obj,
                              out_rights, false, NULL);
}

int khandle_get_for_access(struct process *p, int32_t handle,
                           enum kobj_access_op access, struct kobj **out_obj,
                           uint32_t *out_rights) {
    return khandle_get_common(p, handle, 0, access, true, out_obj, out_rights,
                              false, NULL);
}

int khandle_take_with_cap(struct process *p, int32_t handle,
                          uint32_t required_rights, struct kobj **out_obj,
                          uint32_t *out_rights, uint64_t *out_cap_id) {
    return khandle_get_common(p, handle, required_rights, 0, false, out_obj,
                              out_rights, true, out_cap_id);
}

int khandle_take(struct process *p, int32_t handle, uint32_t required_rights,
                 struct kobj **out_obj, uint32_t *out_rights) {
    return khandle_take_with_cap(p, handle, required_rights, out_obj,
                                 out_rights, NULL);
}

int khandle_take_for_access_with_cap(struct process *p, int32_t handle,
                                     enum kobj_access_op access,
                                     struct kobj **out_obj,
                                     uint32_t *out_rights,
                                     uint64_t *out_cap_id) {
    return khandle_get_common(p, handle, 0, access, true, out_obj, out_rights,
                              true, out_cap_id);
}

int khandle_take_for_access(struct process *p, int32_t handle,
                            enum kobj_access_op access, struct kobj **out_obj,
                            uint32_t *out_rights) {
    return khandle_take_for_access_with_cap(p, handle, access, out_obj,
                                            out_rights, NULL);
}

int khandle_restore_cap(struct process *p, int32_t handle, struct kobj *obj,
                        uint32_t rights, uint64_t cap_id) {
    struct handletable *ht = proc_handletable(p);
    if (!ht || !obj || rights == 0)
        return -EINVAL;
    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    mutex_lock(&ht->lock);
    if (ht->entries[handle].obj) {
        mutex_unlock(&ht->lock);
        return -EBUSY;
    }

    int rc = 0;
    bool fallback_root = false;
    uint64_t install_cap = cap_id;
    if (install_cap != KHANDLE_INVALID_CAP_ID) {
        rc = kcap_bind_existing(install_cap, ht, handle);
        if (rc < 0) {
            install_cap = KHANDLE_INVALID_CAP_ID;
            fallback_root = true;
        }
    }
    if (install_cap == KHANDLE_INVALID_CAP_ID) {
        install_cap = kcap_create(KHANDLE_INVALID_CAP_ID, ht, handle);
        if (install_cap == KHANDLE_INVALID_CAP_ID)
            rc = -ENOMEM;
    }
    if (rc < 0) {
        mutex_unlock(&ht->lock);
        return rc;
    }

    ht->entries[handle].obj = obj;
    ht->entries[handle].rights = rights;
    ht->entries[handle].cap_id = install_cap;
    atomic_inc(&ht->seq);
    mutex_unlock(&ht->lock);
    if (fallback_root && cap_id != KHANDLE_INVALID_CAP_ID)
        kcap_drop_detached(cap_id);
    kobj_transfer_record(obj, KOBJ_TRANSFER_RESTORE, -1, p ? p->pid : -1,
                         rights);
    return 0;
}

int khandle_restore(struct process *p, int32_t handle, struct kobj *obj,
                    uint32_t rights) {
    return khandle_restore_cap(p, handle, obj, rights, KHANDLE_INVALID_CAP_ID);
}

int khandle_close(struct process *p, int32_t handle) {
    struct handletable *ht = proc_handletable(p);
    if (!ht)
        return -EINVAL;
    return khandle_close_in_table(ht, handle, KHANDLE_INVALID_CAP_ID, false);
}

int khandle_duplicate(struct process *p, int32_t handle, uint32_t rights_mask,
                      int32_t *out_new_handle) {
    struct handletable *ht = proc_handletable(p);
    if (!ht || !out_new_handle)
        return -EINVAL;
    *out_new_handle = -1;

    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    mutex_lock(&ht->lock);
    struct kobj *obj = ht->entries[handle].obj;
    uint32_t rights = ht->entries[handle].rights;
    uint64_t parent_cap_id = ht->entries[handle].cap_id;
    if (!obj) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    if ((rights & KRIGHT_DUPLICATE) == 0) {
        mutex_unlock(&ht->lock);
        return -EACCES;
    }

    uint32_t new_rights = rights_mask ? (rights & rights_mask) : rights;
    if (new_rights == 0) {
        mutex_unlock(&ht->lock);
        return -EACCES;
    }

    for (int h = 0; h < CONFIG_MAX_HANDLES_PER_PROC; h++) {
        if (ht->entries[h].obj)
            continue;
        int rc =
            khandle_install_locked(ht, h, obj, new_rights, parent_cap_id,
                                   KHANDLE_INVALID_CAP_ID);
        mutex_unlock(&ht->lock);
        if (rc < 0)
            return rc;
        *out_new_handle = h;
        return 0;
    }

    mutex_unlock(&ht->lock);
    return -EMFILE;
}

int khandle_revoke_descendants(struct process *p, int32_t handle) {
    struct handletable *ht = proc_handletable(p);
    if (!ht)
        return -EINVAL;
    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    uint64_t root_cap_id = KHANDLE_INVALID_CAP_ID;
    mutex_lock(&ht->lock);
    if (!ht->entries[handle].obj) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    root_cap_id = ht->entries[handle].cap_id;
    mutex_unlock(&ht->lock);
    if (root_cap_id == KHANDLE_INVALID_CAP_ID)
        return -EINVAL;

    while (1) {
        struct handletable *target_ht = NULL;
        int32_t target_handle = -1;
        uint64_t target_cap_id = KHANDLE_INVALID_CAP_ID;
        int rc = kcap_pick_live_descendant(root_cap_id, &target_ht,
                                           &target_handle, &target_cap_id);
        if (rc < 0)
            break;
        rc = khandle_close_in_table(target_ht, target_handle, target_cap_id,
                                    true);
        handletable_put(target_ht);
        (void)rc;
    }
    return 0;
}

void khandle_transfer_drop_cap(struct kobj *obj, uint32_t rights,
                               uint64_t cap_id) {
    if (!obj)
        return;
    kobj_transfer_record(obj, KOBJ_TRANSFER_DROP, -1, -1, rights);
    kcap_drop_detached(cap_id);
    kobj_handle_ref_dec(obj);
    kobj_put(obj);
}

void khandle_transfer_drop_with_rights(struct kobj *obj, uint32_t rights) {
    khandle_transfer_drop_cap(obj, rights, KHANDLE_INVALID_CAP_ID);
}

void khandle_transfer_drop(struct kobj *obj) {
    khandle_transfer_drop_cap(obj, 0, KHANDLE_INVALID_CAP_ID);
}

int khandle_install_transferred_cap(struct process *p, struct kobj *obj,
                                    uint32_t rights, uint64_t cap_id,
                                    int32_t *out_handle) {
    if (out_handle)
        *out_handle = -1;
    if (!out_handle)
        return -EINVAL;

    struct handletable *ht = proc_handletable(p);
    if (!ht || !obj || rights == 0)
        return -EINVAL;

    mutex_lock(&ht->lock);
    for (int h = 0; h < CONFIG_MAX_HANDLES_PER_PROC; h++) {
        if (ht->entries[h].obj)
            continue;
        bool fallback_root = false;
        int rc = khandle_install_locked(ht, h, obj, rights,
                                        KHANDLE_INVALID_CAP_ID, cap_id);
        if (rc < 0 && cap_id != KHANDLE_INVALID_CAP_ID) {
            fallback_root = true;
            rc = khandle_install_locked(ht, h, obj, rights,
                                        KHANDLE_INVALID_CAP_ID,
                                        KHANDLE_INVALID_CAP_ID);
        }
        mutex_unlock(&ht->lock);
        if (rc < 0)
            return rc;
        *out_handle = h;
        if (fallback_root)
            kcap_drop_detached(cap_id);
        kobj_transfer_record(obj, KOBJ_TRANSFER_INSTALL, -1, p ? p->pid : -1,
                             rights);
        return 0;
    }
    mutex_unlock(&ht->lock);
    return -EMFILE;
}

int khandle_install_transferred(struct process *p, struct kobj *obj,
                                uint32_t rights, int32_t *out_handle) {
    return khandle_install_transferred_cap(
        p, obj, rights, KHANDLE_INVALID_CAP_ID, out_handle);
}

static void kport_enqueue_locked(struct kport *port, uint64_t key,
                                 uint32_t observed) {
    if (!port || observed == 0)
        return;

    struct kport_packet *tail = NULL;
    if (!list_empty(&port->queue)) {
        tail = list_entry(port->queue.prev, struct kport_packet, node);
        if (tail && tail->key == key) {
            tail->observed |= observed;
            poll_wait_source_wake_one(&port->rd_src, 0);
            wait_queue_wakeup_one(&port->obj.waitq);
            return;
        }
    }

    if (port->queue_len >= KPORT_MAX_QUEUE && !list_empty(&port->queue)) {
        struct kport_packet *old =
            list_first_entry(&port->queue, struct kport_packet, node);
        list_del(&old->node);
        if (port->queue_len > 0)
            port->queue_len--;
        kfree(old);
    }

    struct kport_packet *pkt = kzalloc(sizeof(*pkt));
    if (!pkt)
        return;
    pkt->key = key;
    pkt->observed = observed;
    list_add_tail(&pkt->node, &port->queue);
    port->queue_len++;
    poll_wait_source_wake_one(&port->rd_src, 0);
    wait_queue_wakeup_one(&port->obj.waitq);
    struct kport_watch *watch;
    list_for_each_entry(watch, &port->poll_vnodes, node) {
        if (watch->vn)
            vfs_poll_wake(watch->vn, POLLIN);
    }
}

static void kchannel_emit_locked(struct kchannel *ch, uint32_t signal) {
    if (!ch || signal == 0)
        return;
    struct kport *port = ch->bind.port;
    if (!port)
        return;
    if ((ch->bind.signals & signal) == 0)
        return;

    mutex_lock(&port->lock);
    kport_enqueue_locked(port, ch->bind.key, signal);
    mutex_unlock(&port->lock);
}

static void kchannel_poll_wake_locked(struct kchannel *ch, uint32_t events) {
    if (!ch || events == 0)
        return;
    struct kchannel_watch *watch;
    list_for_each_entry(watch, &ch->poll_vnodes, node) {
        if (watch->vn)
            vfs_poll_wake(watch->vn, events);
    }
}

static struct kchannel *kchannel_alloc(void) {
    struct kchannel *ch = kzalloc(sizeof(*ch));
    if (!ch)
        return NULL;
    kobj_init(&ch->obj, KOBJ_TYPE_CHANNEL, &kchannel_ops);
    atomic_init(&ch->handle_refs, 0);
    mutex_init(&ch->lock, "kchannel");
    poll_wait_source_init(&ch->rd_src, NULL);
    poll_wait_source_init(&ch->wr_src, NULL);
    INIT_LIST_HEAD(&ch->rxq);
    INIT_LIST_HEAD(&ch->rxq_free);
    for (size_t i = 0; i < KCHANNEL_MAX_QUEUE; i++) {
        struct kchannel_msg *msg = &ch->rxq_slots[i];
        memset(msg, 0, sizeof(*msg));
        INIT_LIST_HEAD(&msg->node);
        list_add_tail(&msg->node, &ch->rxq_free);
    }
    INIT_LIST_HEAD(&ch->poll_vnodes);
    ch->rxq_len = 0;
    ch->peer = NULL;
    ch->peer_closed = false;
    ch->endpoint_closed = false;
    ch->recv_waiter = NULL;
    ch->bind.port = NULL;
    ch->bind.key = 0;
    ch->bind.signals = 0;
    return ch;
}

int kchannel_create_pair(struct kobj **out0, struct kobj **out1) {
    if (!out0 || !out1)
        return -EINVAL;
    *out0 = NULL;
    *out1 = NULL;

    struct kchannel *a = kchannel_alloc();
    if (!a)
        return -ENOMEM;
    struct kchannel *b = kchannel_alloc();
    if (!b) {
        kobj_put(&a->obj);
        return -ENOMEM;
    }

    mutex_lock(&a->lock);
    mutex_lock(&b->lock);
    a->peer = b;
    b->peer = a;
    kobj_get(&b->obj);
    kobj_get(&a->obj);
    mutex_unlock(&b->lock);
    mutex_unlock(&a->lock);

    *out0 = &a->obj;
    *out1 = &b->obj;
    return 0;
}

static bool kchannel_try_rendezvous_locked(struct kchannel *peer,
                                           struct kchannel_msg *msg) {
    if (!peer || !msg || peer->rxq_len != 0)
        return false;

    struct kchannel_rendezvous *rv = peer->recv_waiter;
    if (!rv || !rv->active || rv->completed)
        return false;

    if (rv->bytes_cap < msg->num_bytes || rv->handles_cap < msg->num_handles)
        return false;

    if (msg->num_bytes > 0 && msg->bytes)
        memcpy(rv->bytes, msg->bytes, msg->num_bytes);

    for (size_t i = 0; i < msg->num_handles; i++) {
        rv->handles[i] = msg->handles[i];
        msg->handles[i].obj = NULL;
    }

    rv->got_bytes = msg->num_bytes;
    rv->got_handles = msg->num_handles;
    rv->handles_truncated = false;
    rv->status = 0;
    rv->completed = true;

    poll_wait_source_wake_one(&peer->rd_src, 0);
    wait_queue_wakeup_one(&peer->obj.waitq);
    return true;
}

static bool kchannel_try_rendezvous_raw_locked(
    struct kchannel *peer, const void *bytes, size_t num_bytes,
    const struct khandle_transfer *handles, size_t num_handles) {
    if (!peer || peer->rxq_len != 0)
        return false;

    struct kchannel_rendezvous *rv = peer->recv_waiter;
    if (!rv || !rv->active || rv->completed)
        return false;

    if (rv->bytes_cap < num_bytes || rv->handles_cap < num_handles)
        return false;

    if (num_bytes > 0 && bytes)
        memcpy(rv->bytes, bytes, num_bytes);

    for (size_t i = 0; i < num_handles; i++) {
        if (!handles[i].obj)
            return false;
    }
    for (size_t i = 0; i < num_handles; i++) {
        rv->handles[i] = handles[i];
        kobj_get(rv->handles[i].obj);
    }

    rv->got_bytes = num_bytes;
    rv->got_handles = num_handles;
    rv->handles_truncated = false;
    rv->status = 0;
    rv->completed = true;

    poll_wait_source_wake_one(&peer->rd_src, 0);
    wait_queue_wakeup_one(&peer->obj.waitq);
    return true;
}

int kchannel_send(struct kobj *obj, const void *bytes, size_t num_bytes,
                  const struct khandle_transfer *handles, size_t num_handles,
                  uint32_t options) {
    struct kchannel *self = kchannel_from_obj(obj);
    if (!self)
        return -ENOTSUP;
    if (options & ~(KCHANNEL_OPT_NONBLOCK | KCHANNEL_OPT_RENDEZVOUS))
        return -EINVAL;
    if (num_bytes > KCHANNEL_MAX_MSG_BYTES || num_handles > KCHANNEL_MAX_MSG_HANDLES)
        return -EMSGSIZE;
    if (num_bytes > 0 && !bytes)
        return -EFAULT;
    if (num_handles > 0 && !handles)
        return -EINVAL;
    for (size_t i = 0; i < num_handles; i++) {
        if (!handles[i].obj)
            return -EINVAL;
    }

    struct kchannel *peer = NULL;
    mutex_lock(&self->lock);
    if (!self->peer || self->peer_closed) {
        mutex_unlock(&self->lock);
        return -EPIPE;
    }
    peer = self->peer;
    kobj_get(&peer->obj);
    mutex_unlock(&self->lock);

    bool rendezvous = (options & KCHANNEL_OPT_RENDEZVOUS) != 0;
    int32_t sender_pid = -1;
    struct process *curr = proc_current();
    if (curr)
        sender_pid = curr->pid;
    int ret = 0;
    struct kchannel_msg *msg = NULL;
    bool nonblock = (options & KCHANNEL_OPT_NONBLOCK) != 0;

    mutex_lock(&peer->lock);
    if (rendezvous &&
        kchannel_try_rendezvous_raw_locked(peer, bytes, num_bytes, handles,
                                           num_handles)) {
        for (size_t i = 0; i < num_handles; i++) {
            kobj_transfer_record(handles[i].obj, KOBJ_TRANSFER_ENQUEUE,
                                 sender_pid, -1, handles[i].rights);
        }
        goto out_unlock;
    }

    while (peer->rxq_len >= KCHANNEL_MAX_QUEUE || list_empty(&peer->rxq_free)) {
        if (nonblock) {
            ret = -EAGAIN;
            goto out_unlock;
        }
        int rc = poll_wait_source_block(&peer->wr_src, 0, &peer->wr_src,
                                        &peer->lock);
        if (rc < 0) {
            ret = rc;
            goto out_unlock;
        }
        if (peer->peer_closed || !peer->peer) {
            ret = -EPIPE;
            goto out_unlock;
        }
    }

    msg = kchannel_msg_alloc_locked(peer);
    if (!msg) {
        ret = -EAGAIN;
        goto out_unlock;
    }
    msg->num_bytes = num_bytes;
    msg->num_handles = num_handles;
    if (num_bytes > 0) {
        if (num_bytes <= KCHANNEL_INLINE_MSG_BYTES) {
            msg->bytes = msg->inline_bytes;
            msg->inline_bytes_used = true;
        } else {
            msg->bytes = kmalloc(num_bytes);
            if (!msg->bytes) {
                ret = -ENOMEM;
                goto out_unlock;
            }
        }
        memcpy(msg->bytes, bytes, num_bytes);
    }
    for (size_t i = 0; i < num_handles; i++) {
        msg->handles[i] = handles[i];
        if (msg->handles[i].obj)
            kobj_get(msg->handles[i].obj);
    }

    if (rendezvous && kchannel_try_rendezvous_locked(peer, msg))
        goto out_unlock;

    list_add_tail(&msg->node, &peer->rxq);
    peer->rxq_len++;
    msg->owns_caps = true;
    for (size_t i = 0; i < num_handles; i++) {
        kobj_transfer_record(handles[i].obj, KOBJ_TRANSFER_ENQUEUE, sender_pid,
                             -1, handles[i].rights);
    }
    msg = NULL;
    poll_wait_source_wake_one(&peer->rd_src, 0);
    wait_queue_wakeup_one(&peer->obj.waitq);
    kchannel_poll_wake_locked(peer, POLLIN);
    kchannel_emit_locked(peer, KPORT_BIND_READABLE);
    ret = 0;

out_unlock:
    if (msg)
        kchannel_msg_recycle_locked(peer, msg);
    mutex_unlock(&peer->lock);
    kobj_put(&peer->obj);
    return ret;
}

int kchannel_recv(struct kobj *obj, void *bytes, size_t bytes_cap,
                  size_t *out_bytes, struct khandle_transfer *handles,
                  size_t handles_cap, size_t *out_handles,
                  bool *out_handles_truncated, uint32_t options) {
    struct kchannel *ch = kchannel_from_obj(obj);
    if (!ch)
        return -ENOTSUP;
    if (options & ~(KCHANNEL_OPT_NONBLOCK | KCHANNEL_OPT_RENDEZVOUS))
        return -EINVAL;
    if (bytes_cap > 0 && !bytes)
        return -EFAULT;
    if ((handles_cap > 0 && !handles) || !out_bytes || !out_handles ||
        !out_handles_truncated)
        return -EINVAL;

    *out_bytes = 0;
    *out_handles = 0;
    *out_handles_truncated = false;

    bool nonblock = (options & KCHANNEL_OPT_NONBLOCK) != 0;
    bool rendezvous = (options & KCHANNEL_OPT_RENDEZVOUS) != 0;
    struct kchannel_msg *msg = NULL;
    struct kchannel *peer_for_write = NULL;
    struct kchannel_rendezvous rv = {0};

    mutex_lock(&ch->lock);
    while (ch->rxq_len == 0) {
        if (rv.completed)
            break;
        if (ch->peer_closed) {
            if (rv.active && ch->recv_waiter == &rv)
                ch->recv_waiter = NULL;
            mutex_unlock(&ch->lock);
            return 0;
        }
        if (nonblock) {
            if (rv.active && ch->recv_waiter == &rv)
                ch->recv_waiter = NULL;
            mutex_unlock(&ch->lock);
            return -EAGAIN;
        }
        if (rendezvous && !rv.active && ch->recv_waiter == NULL) {
            rv.active = true;
            rv.bytes = bytes;
            rv.bytes_cap = bytes_cap;
            rv.handles = handles;
            rv.handles_cap = handles_cap;
            ch->recv_waiter = &rv;
        }
        int rc =
            poll_wait_source_block(&ch->rd_src, 0, &ch->rd_src, &ch->lock);
        if (rc < 0) {
            if (rv.active && ch->recv_waiter == &rv)
                ch->recv_waiter = NULL;
            mutex_unlock(&ch->lock);
            return rc;
        }
    }

    if (rv.active && ch->recv_waiter == &rv)
        ch->recv_waiter = NULL;
    if (rv.completed) {
        int32_t to_pid = -1;
        struct process *curr = proc_current();
        if (curr)
            to_pid = curr->pid;
        for (size_t i = 0; i < rv.got_handles; i++) {
            if (!rv.handles[i].obj)
                continue;
            kobj_transfer_record(rv.handles[i].obj, KOBJ_TRANSFER_DELIVER, -1,
                                 to_pid, rv.handles[i].rights);
        }
        *out_bytes = rv.got_bytes;
        *out_handles = rv.got_handles;
        *out_handles_truncated = rv.handles_truncated;
        mutex_unlock(&ch->lock);
        return rv.status;
    }

    msg = list_first_entry(&ch->rxq, struct kchannel_msg, node);
    if (bytes_cap < msg->num_bytes || handles_cap < msg->num_handles) {
        *out_bytes = msg->num_bytes;
        *out_handles = msg->num_handles;
        *out_handles_truncated = (handles_cap < msg->num_handles);
        mutex_unlock(&ch->lock);
        return -EMSGSIZE;
    }

    list_del(&msg->node);
    INIT_LIST_HEAD(&msg->node);
    if (ch->rxq_len > 0)
        ch->rxq_len--;
    peer_for_write = ch->peer;
    if (peer_for_write)
        kobj_get(&peer_for_write->obj);
    if (ch->rxq_len > 0)
        kchannel_poll_wake_locked(ch, POLLIN);
    if (ch->rxq_len > 0)
        kchannel_emit_locked(ch, KPORT_BIND_READABLE);
    if (msg->num_bytes > 0)
        memcpy(bytes, msg->bytes, msg->num_bytes);

    size_t delivered_handles = msg->num_handles;
    for (size_t i = 0; i < delivered_handles; i++) {
        handles[i] = msg->handles[i];
        msg->handles[i].obj = NULL;
    }
    *out_bytes = msg->num_bytes;
    *out_handles = msg->num_handles;
    *out_handles_truncated = false;
    kchannel_msg_recycle_locked(ch, msg);
    msg = NULL;
    poll_wait_source_wake_one(&ch->wr_src, 0);
    mutex_unlock(&ch->lock);

    if (peer_for_write) {
        mutex_lock(&peer_for_write->lock);
        kchannel_poll_wake_locked(peer_for_write, POLLOUT);
        mutex_unlock(&peer_for_write->lock);
        kobj_put(&peer_for_write->obj);
    }

    int32_t to_pid = -1;
    struct process *curr = proc_current();
    if (curr)
        to_pid = curr->pid;
    for (size_t i = 0; i < delivered_handles; i++) {
        if (!handles[i].obj)
            continue;
        kobj_transfer_record(handles[i].obj, KOBJ_TRANSFER_DELIVER, -1, to_pid,
                             handles[i].rights);
    }

    return 0;
}

int kport_create(struct kobj **out) {
    if (!out)
        return -EINVAL;
    *out = NULL;

    struct kport *port = kzalloc(sizeof(*port));
    if (!port)
        return -ENOMEM;
    kobj_init(&port->obj, KOBJ_TYPE_PORT, &kport_ops);
    mutex_init(&port->lock, "kport");
    poll_wait_source_init(&port->rd_src, NULL);
    INIT_LIST_HEAD(&port->queue);
    INIT_LIST_HEAD(&port->poll_vnodes);
    port->queue_len = 0;

    *out = &port->obj;
    return 0;
}

int kchannel_poll_revents(struct kobj *channel_obj, uint32_t events,
                          uint32_t *out_revents) {
    struct kchannel *ch = kchannel_from_obj(channel_obj);
    if (!ch || !out_revents)
        return -EINVAL;

    if (!mutex_trylock(&ch->lock)) {
        /*
         * Poll wake callbacks can race with endpoint lock holders. Report
         * readiness conservatively to avoid lock inversion in callbacks.
         */
        *out_revents = events & (POLLIN | POLLOUT | POLLHUP);
        return 0;
    }

    *out_revents = kchannel_poll_revents_locked(ch, events) & events;
    mutex_unlock(&ch->lock);
    return 0;
}

int kchannel_poll_attach_vnode(struct kobj *channel_obj, struct vnode *vn) {
    struct kchannel *ch = kchannel_from_obj(channel_obj);
    if (!ch || !vn)
        return -EINVAL;

    struct kchannel_watch *watch = kzalloc(sizeof(*watch));
    if (!watch)
        return -ENOMEM;
    watch->vn = vn;
    INIT_LIST_HEAD(&watch->node);

    uint32_t wake_events = 0;
    mutex_lock(&ch->lock);
    struct kchannel_watch *iter;
    list_for_each_entry(iter, &ch->poll_vnodes, node) {
        if (iter->vn == vn) {
            wake_events =
                kchannel_poll_revents_locked(ch, POLLIN | POLLOUT | POLLHUP);
            mutex_unlock(&ch->lock);
            kfree(watch);
            if (wake_events)
                vfs_poll_wake(vn, wake_events);
            return 0;
        }
    }
    list_add_tail(&watch->node, &ch->poll_vnodes);
    wake_events = kchannel_poll_revents_locked(ch, POLLIN | POLLOUT | POLLHUP);
    mutex_unlock(&ch->lock);

    if (wake_events)
        vfs_poll_wake(vn, wake_events);
    return 0;
}

int kchannel_poll_detach_vnode(struct kobj *channel_obj, struct vnode *vn) {
    struct kchannel *ch = kchannel_from_obj(channel_obj);
    if (!ch || !vn)
        return -EINVAL;

    mutex_lock(&ch->lock);
    struct kchannel_watch *iter, *tmp;
    list_for_each_entry_safe(iter, tmp, &ch->poll_vnodes, node) {
        if (iter->vn != vn)
            continue;
        list_del(&iter->node);
        mutex_unlock(&ch->lock);
        kfree(iter);
        return 0;
    }
    mutex_unlock(&ch->lock);
    return -ENOENT;
}

int kport_bind_channel(struct kobj *port_obj, struct kobj *channel_obj,
                       uint64_t key, uint32_t signals) {
    struct kport *port = kport_from_obj(port_obj);
    struct kchannel *ch = kchannel_from_obj(channel_obj);
    if (!port || !ch)
        return -ENOTSUP;
    if ((signals & ~KPORT_BIND_ALL) != 0 || signals == 0)
        return -EINVAL;

    struct kport *old = NULL;

    mutex_lock(&ch->lock);
    old = ch->bind.port;
    kobj_get(&port->obj);
    ch->bind.port = port;
    ch->bind.key = key;
    ch->bind.signals = signals;

    if ((signals & KPORT_BIND_READABLE) && ch->rxq_len > 0)
        kchannel_emit_locked(ch, KPORT_BIND_READABLE);
    if ((signals & KPORT_BIND_PEER_CLOSED) && ch->peer_closed)
        kchannel_emit_locked(ch, KPORT_BIND_PEER_CLOSED);

    mutex_unlock(&ch->lock);

    if (old)
        kobj_put(&old->obj);
    return 0;
}

int kport_wait(struct kobj *port_obj, struct kairos_port_packet_user *out,
               uint64_t timeout_ns, uint32_t options) {
    struct kport *port = kport_from_obj(port_obj);
    if (!port || !out)
        return -ENOTSUP;
    if (options & ~KPORT_WAIT_NONBLOCK)
        return -EINVAL;

    bool nonblock = (options & KPORT_WAIT_NONBLOCK) != 0;
    bool infinite = (timeout_ns == UINT64_MAX);
    uint64_t deadline = 0;

    if (!infinite && timeout_ns > 0) {
        uint64_t delta = arch_timer_ns_to_ticks(timeout_ns);
        if (delta == 0)
            delta = 1;
        deadline = arch_timer_get_ticks() + delta;
    }

    mutex_lock(&port->lock);
    while (list_empty(&port->queue)) {
        if (nonblock) {
            mutex_unlock(&port->lock);
            return -EAGAIN;
        }
        if (!infinite && timeout_ns == 0) {
            mutex_unlock(&port->lock);
            return -ETIMEDOUT;
        }

        int rc = 0;
        if (infinite) {
            rc = poll_block_current_mutex(&port->obj.waitq, 0, &port->obj.waitq,
                                          &port->lock);
        } else {
            rc = poll_block_current_mutex(&port->obj.waitq, deadline,
                                          &port->obj.waitq, &port->lock);
            if (rc == -ETIMEDOUT) {
                mutex_unlock(&port->lock);
                return -ETIMEDOUT;
            }
        }
        if (rc < 0) {
            mutex_unlock(&port->lock);
            return rc;
        }
    }

    struct kport_packet *pkt =
        list_first_entry(&port->queue, struct kport_packet, node);
    list_del(&pkt->node);
    if (port->queue_len > 0)
        port->queue_len--;
    mutex_unlock(&port->lock);

    out->key = pkt->key;
    out->observed = pkt->observed;
    out->reserved = 0;
    kfree(pkt);
    return 0;
}

int kport_poll_ready(struct kobj *port_obj, bool *out_ready) {
    struct kport *port = kport_from_obj(port_obj);
    if (!port || !out_ready)
        return -EINVAL;

    if (!mutex_trylock(&port->lock)) {
        /*
         * Poll wake callbacks can race with enqueue while enqueue still holds
         * port->lock. Report readable conservatively to avoid lock inversion
         * in that callback path.
         */
        *out_ready = true;
        return 0;
    }

    *out_ready = !list_empty(&port->queue);
    mutex_unlock(&port->lock);
    return 0;
}

int kport_poll_attach_vnode(struct kobj *port_obj, struct vnode *vn) {
    struct kport *port = kport_from_obj(port_obj);
    if (!port || !vn)
        return -EINVAL;

    struct kport_watch *watch = kzalloc(sizeof(*watch));
    if (!watch)
        return -ENOMEM;
    watch->vn = vn;
    INIT_LIST_HEAD(&watch->node);

    bool ready = false;
    mutex_lock(&port->lock);
    struct kport_watch *iter;
    list_for_each_entry(iter, &port->poll_vnodes, node) {
        if (iter->vn == vn) {
            ready = !list_empty(&port->queue);
            mutex_unlock(&port->lock);
            kfree(watch);
            if (ready)
                vfs_poll_wake(vn, POLLIN);
            return 0;
        }
    }
    list_add_tail(&watch->node, &port->poll_vnodes);
    ready = !list_empty(&port->queue);
    mutex_unlock(&port->lock);

    if (ready)
        vfs_poll_wake(vn, POLLIN);
    return 0;
}

int kport_poll_detach_vnode(struct kobj *port_obj, struct vnode *vn) {
    struct kport *port = kport_from_obj(port_obj);
    if (!port || !vn)
        return -EINVAL;

    mutex_lock(&port->lock);
    struct kport_watch *iter, *tmp;
    list_for_each_entry_safe(iter, tmp, &port->poll_vnodes, node) {
        if (iter->vn != vn)
            continue;
        list_del(&iter->node);
        mutex_unlock(&port->lock);
        kfree(iter);
        return 0;
    }
    mutex_unlock(&port->lock);
    return -ENOENT;
}

static int kobj_options_to_channel(uint32_t options, uint32_t *out_opts) {
    if (!out_opts)
        return -EINVAL;
    if (options & ~(KOBJ_IO_NONBLOCK | KOBJ_IO_RENDEZVOUS))
        return -EINVAL;
    uint32_t kopts = 0;
    if (options & KOBJ_IO_NONBLOCK)
        kopts |= KCHANNEL_OPT_NONBLOCK;
    if (options & KOBJ_IO_RENDEZVOUS)
        kopts |= KCHANNEL_OPT_RENDEZVOUS;
    *out_opts = kopts;
    return 0;
}

static int kchannel_obj_read(struct kobj *obj, void *buf, size_t len,
                             size_t *out_len, uint32_t options) {
    if (!out_len)
        return -EINVAL;
    *out_len = 0;

    uint32_t kopts = 0;
    int rc = kobj_options_to_channel(options, &kopts);
    if (rc < 0)
        return rc;

    size_t got_handles = 0;
    bool handles_truncated = false;
    struct khandle_transfer dropped[KCHANNEL_MAX_MSG_HANDLES] = {0};
    rc = kchannel_recv(obj, buf, len, out_len, dropped, KCHANNEL_MAX_MSG_HANDLES,
                       &got_handles, &handles_truncated, kopts);
    if (rc < 0)
        return rc;
    (void)handles_truncated;

    for (size_t i = 0; i < got_handles; i++) {
        if (dropped[i].obj) {
            khandle_transfer_drop_cap(dropped[i].obj, dropped[i].rights,
                                      dropped[i].cap_id);
            dropped[i].obj = NULL;
        }
    }
    return 0;
}

static int kchannel_obj_write(struct kobj *obj, const void *buf, size_t len,
                              size_t *out_len, uint32_t options) {
    if (!out_len)
        return -EINVAL;
    *out_len = 0;

    uint32_t kopts = 0;
    int rc = kobj_options_to_channel(options, &kopts);
    if (rc < 0)
        return rc;

    rc = kchannel_send(obj, buf, len, NULL, 0, kopts);
    if (rc < 0)
        return rc;
    *out_len = len;
    return 0;
}

static int kchannel_obj_signal(struct kobj *obj, uint32_t signal,
                               uint32_t flags) {
    struct kchannel *ch = kchannel_from_obj(obj);
    if (!ch)
        return -ENOTSUP;
    if (flags != 0)
        return -EINVAL;
    if (signal == 0 || (signal & ~KPORT_BIND_ALL) != 0)
        return -EINVAL;

    mutex_lock(&ch->lock);
    kchannel_emit_locked(ch, signal);
    mutex_unlock(&ch->lock);
    return 0;
}

static int kport_obj_read(struct kobj *obj, void *buf, size_t len,
                          size_t *out_len, uint32_t options) {
    if (!buf || !out_len)
        return -EINVAL;
    *out_len = 0;
    if (len < sizeof(struct kairos_port_packet_user))
        return -EINVAL;
    if (options & ~KOBJ_IO_NONBLOCK)
        return -EINVAL;

    struct kairos_port_packet_user pkt = {0};
    uint32_t wait_opts = (options & KOBJ_IO_NONBLOCK) ? KPORT_WAIT_NONBLOCK : 0;
    int rc = kport_wait(obj, &pkt, UINT64_MAX, wait_opts);
    if (rc < 0)
        return rc;
    memcpy(buf, &pkt, sizeof(pkt));
    *out_len = sizeof(pkt);
    return 0;
}

static int kchannel_obj_poll_revents(struct kobj *obj, uint32_t events,
                                     uint32_t *out_revents) {
    return kchannel_poll_revents(obj, events, out_revents);
}

static int kchannel_obj_poll_attach(struct kobj *obj, struct vnode *vn) {
    return kchannel_poll_attach_vnode(obj, vn);
}

static int kchannel_obj_poll_detach(struct kobj *obj, struct vnode *vn) {
    return kchannel_poll_detach_vnode(obj, vn);
}

static int kport_obj_wait(struct kobj *obj, void *out, uint64_t timeout_ns,
                          uint32_t options) {
    if (!out)
        return -EFAULT;
    return kport_wait(obj, (struct kairos_port_packet_user *)out, timeout_ns,
                      options);
}

static int kport_obj_poll_revents(struct kobj *obj, uint32_t events,
                                  uint32_t *out_revents) {
    if (!out_revents)
        return -EINVAL;

    bool ready = false;
    int rc = kport_poll_ready(obj, &ready);
    if (rc < 0)
        return rc;

    *out_revents = ready ? (events & POLLIN) : 0;
    return 0;
}

static int kport_obj_poll_attach(struct kobj *obj, struct vnode *vn) {
    return kport_poll_attach_vnode(obj, vn);
}

static int kport_obj_poll_detach(struct kobj *obj, struct vnode *vn) {
    return kport_poll_detach_vnode(obj, vn);
}

int kfile_create(struct file *file, struct kobj **out) {
    if (!file || !out)
        return -EINVAL;
    *out = NULL;

    struct kfile *kfile = kzalloc(sizeof(*kfile));
    if (!kfile)
        return -ENOMEM;
    file_get(file);
    kobj_init(&kfile->obj, KOBJ_TYPE_FILE, &kfile_ops);
    kfile->file = file;
    *out = &kfile->obj;
    return 0;
}

int kfile_get_file(struct kobj *obj, struct file **out_file) {
    if (!out_file)
        return -EINVAL;
    *out_file = NULL;

    struct kfile *kfile = kfile_from_obj(obj);
    if (!kfile || !kfile->file)
        return -ENOTSUP;

    file_get(kfile->file);
    *out_file = kfile->file;
    return 0;
}

static void kchannel_release_obj(struct kobj *obj) {
    struct kchannel *ch = kchannel_from_obj(obj);
    if (!ch)
        return;
    ipc_registry_unregister_obj(obj);

    struct kchannel *peer = NULL;
    struct kport *bound = NULL;
    LIST_HEAD(reap);
    LIST_HEAD(poll_reap);

    mutex_lock(&ch->lock);
    peer = ch->peer;
    ch->peer = NULL;

    bound = ch->bind.port;
    ch->bind.port = NULL;
    ch->bind.signals = 0;
    ch->bind.key = 0;

    while (!list_empty(&ch->rxq)) {
        struct kchannel_msg *msg =
            list_first_entry(&ch->rxq, struct kchannel_msg, node);
        list_del(&msg->node);
        list_add_tail(&msg->node, &reap);
    }
    while (!list_empty(&ch->poll_vnodes)) {
        struct kchannel_watch *watch =
            list_first_entry(&ch->poll_vnodes, struct kchannel_watch, node);
        list_del(&watch->node);
        list_add_tail(&watch->node, &poll_reap);
    }
    ch->recv_waiter = NULL;
    ch->rxq_len = 0;
    wait_queue_wakeup_all(&ch->obj.waitq);
    mutex_unlock(&ch->lock);

    while (!list_empty(&reap)) {
        struct kchannel_msg *msg =
            list_first_entry(&reap, struct kchannel_msg, node);
        list_del(&msg->node);
        INIT_LIST_HEAD(&msg->node);
        kchannel_msg_reset(msg);
    }
    while (!list_empty(&poll_reap)) {
        struct kchannel_watch *watch =
            list_first_entry(&poll_reap, struct kchannel_watch, node);
        list_del(&watch->node);
        kfree(watch);
    }

    if (bound)
        kobj_put(&bound->obj);

    if (peer) {
        mutex_lock(&peer->lock);
        if (peer->peer == ch)
            peer->peer = NULL;
        peer->peer_closed = true;
        poll_wait_source_wake_all(&peer->rd_src, 0);
        poll_wait_source_wake_all(&peer->wr_src, 0);
        wait_queue_wakeup_all(&peer->obj.waitq);
        kchannel_poll_wake_locked(peer, POLLHUP);
        kchannel_emit_locked(peer, KPORT_BIND_PEER_CLOSED);
        mutex_unlock(&peer->lock);

        kobj_put(&peer->obj);
    }

    kfree(ch);
}

static void kport_release_obj(struct kobj *obj) {
    struct kport *port = kport_from_obj(obj);
    if (!port)
        return;
    ipc_registry_unregister_obj(obj);

    LIST_HEAD(reap);
    LIST_HEAD(poll_reap);

    mutex_lock(&port->lock);
    while (!list_empty(&port->queue)) {
        struct kport_packet *pkt =
            list_first_entry(&port->queue, struct kport_packet, node);
        list_del(&pkt->node);
        list_add_tail(&pkt->node, &reap);
    }
    while (!list_empty(&port->poll_vnodes)) {
        struct kport_watch *watch =
            list_first_entry(&port->poll_vnodes, struct kport_watch, node);
        list_del(&watch->node);
        list_add_tail(&watch->node, &poll_reap);
    }
    port->queue_len = 0;
    wait_queue_wakeup_all(&port->obj.waitq);
    mutex_unlock(&port->lock);

    while (!list_empty(&reap)) {
        struct kport_packet *pkt =
            list_first_entry(&reap, struct kport_packet, node);
        list_del(&pkt->node);
        kfree(pkt);
    }
    while (!list_empty(&poll_reap)) {
        struct kport_watch *watch =
            list_first_entry(&poll_reap, struct kport_watch, node);
        list_del(&watch->node);
        kfree(watch);
    }

    kfree(port);
}

static void kfile_release_obj(struct kobj *obj) {
    struct kfile *kfile = kfile_from_obj(obj);
    if (!kfile)
        return;
    if (kfile->file)
        file_put(kfile->file);
    kfree(kfile);
}
