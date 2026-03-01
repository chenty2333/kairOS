/**
 * kernel/core/ipc/handle.c - Capability handles + channel/port objects
 */

#include <kairos/arch.h>
#include <kairos/completion.h>
#include <kairos/dentry.h>
#if CONFIG_KERNEL_FAULT_INJECT
#include <kairos/fault_inject.h>
#endif
#include <kairos/handle.h>
#include <kairos/hashtable.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/pollwait.h>
#include <kairos/preempt.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/sched.h>
#include <kairos/string.h>
#include <kairos/sysfs.h>
#include <kairos/time.h>
#include <kairos/tracepoint.h>
#include <kairos/vfs.h>

struct kchannel;
struct kport;

enum kchannel_endpoint_state {
    KCHANNEL_ENDPOINT_OPEN = 0,
    KCHANNEL_ENDPOINT_CLOSING = 1,
    KCHANNEL_ENDPOINT_CLOSED = 2,
};

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
    /* Endpoint liveness refs: handle slots + bridged channel fds. */
    atomic_t handle_refs;
    atomic_t endpoint_ref_handle_count;
    atomic_t endpoint_ref_channelfd_count;
    atomic_t endpoint_ref_other_count;
    /* Lockless poll fallback hints to avoid fabricating readiness. */
    atomic_t pollin_hint;
    atomic_t pollout_hint;
    atomic_t pollhup_hint;
    struct mutex lock;
    struct poll_wait_source rd_src;
    struct poll_wait_source wr_src;
    struct list_head rxq;
    struct list_head rxq_free;
    size_t rxq_len;
    struct kchannel_msg rxq_slots[KCHANNEL_MAX_QUEUE];
    struct list_head poll_vnodes;
    /* Lock order: self->lock must be acquired before peer->lock. */
    struct kchannel *peer;
    bool peer_closed;
    enum kchannel_endpoint_state endpoint_state;
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
    atomic_t ready_hint;
    struct list_head queue;
    struct list_head poll_vnodes;
    size_t queue_len;
    uint64_t dropped_count;
};

struct kfile {
    struct kobj obj;
    struct file *file;
};

struct ipc_registry_entry {
    struct list_head type_node;
    struct list_head all_node;
    struct list_head hash_node;
    struct list_head project_node;
    struct kobj *obj;
    uint32_t generation;
    uint8_t lifecycle;
    uint8_t pending_proj_ops;
    bool project_queued;
    struct sysfs_node *sysfs_dir;
};

struct ipc_sysfs_object_state {
    atomic_t refs;
    uint32_t obj_id;
    uint32_t transfers_cursor;
    uint32_t transfers_page_size;
};

struct ipc_registry_obj_owner_pin {
    struct kobj *obj;
    struct vnode *vnode;
    struct dentry *dentry;
};

static LIST_HEAD(ipc_registry_all);
static LIST_HEAD(ipc_channel_registry);
static LIST_HEAD(ipc_port_registry);
static LIST_HEAD(ipc_file_registry);
static LIST_HEAD(ipc_vnode_registry);
static LIST_HEAD(ipc_dentry_registry);
static LIST_HEAD(ipc_buffer_registry);
static LIST_HEAD(ipc_sysfs_project_queue);
#define IPC_REGISTRY_ID_HASH_BITS 10U
KHASH_DECLARE(ipc_registry_id_hash, IPC_REGISTRY_ID_HASH_BITS);
static struct mutex ipc_registry_lock;
static bool ipc_registry_lock_ready;
static spinlock_t ipc_registry_init_lock = SPINLOCK_INIT;
static struct completion ipc_sysfs_project_completion;
static bool ipc_sysfs_project_completion_ready;
static bool ipc_sysfs_projector_started;
/* Suppress registry reentry while sysfs projection holds ipc_registry_lock. */
static struct process *ipc_registry_register_suppress_proc;
static int ipc_registry_register_suppress_cpu = -1;
static uint32_t ipc_registry_register_suppress_depth;
static struct sysfs_node *ipc_sysfs_root;
static struct sysfs_node *ipc_sysfs_objects_dir;
static bool ipc_sysfs_ready;
static atomic_t kobj_id_next = ATOMIC_INIT(0);
static atomic_t ipc_registry_generation_next = ATOMIC_INIT(0);
static uint64_t ipc_registry_register_oom_failures;
static uint64_t ipc_port_queue_drops_total;
static uint64_t ipc_channel_send_epipe_total;
static uint64_t ipc_channel_recv_eof_total;
static uint64_t ipc_channel_close_last_ref_total;
static uint64_t ipc_channel_close_release_total;
static uint64_t ipc_channel_close_wake_local_total;
static uint64_t ipc_channel_close_wake_peer_total;
static uint64_t ipc_channel_poll_hint_checks_total;
static uint64_t ipc_channel_poll_hint_mismatch_in_total;
static uint64_t ipc_channel_poll_hint_mismatch_out_total;
static uint64_t ipc_channel_poll_hint_mismatch_hup_total;
static uint64_t ipc_channel_ref_audit_checks_total;
static uint64_t ipc_channel_ref_audit_mismatch_total;
static uint64_t ipc_cap_revoke_marked_total;
static uint64_t ipc_cap_bind_rejected_revoked_total;
static uint64_t ipc_cap_commit_eagain_total;
static uint64_t ipc_cap_commit_epoch_mismatch_total;
static uint64_t ipc_cap_tryget_failed_total;
static uint64_t ipc_lock_probe_registry_after_channel_total;
static uint64_t ipc_lock_probe_registry_after_port_total;
static uint64_t ipc_lock_probe_registry_then_channel_total;
static uint64_t ipc_lock_probe_registry_then_port_total;
static uint64_t ipc_lock_probe_channel_then_port_total;
static uint64_t ipc_lock_probe_channel_after_port_total;
static uint64_t ipc_lock_probe_registry_contention_total;
static uint64_t ipc_lock_probe_channel_contention_total;
static uint64_t ipc_lock_probe_port_contention_total;
static uint64_t ipc_lock_probe_state_underflow_total;
static uint64_t kobj_lifecycle_transition_warn_total;
static uint64_t kobj_lifecycle_access_warn_total;
static atomic_t ipc_registry_register_oom_warn_count = ATOMIC_INIT(0);
static atomic_t ipc_port_queue_drop_warn_count = ATOMIC_INIT(0);
static atomic_t ipc_channel_ref_underflow_warn_count = ATOMIC_INIT(0);
static atomic_t ipc_channel_poll_hint_warn_count = ATOMIC_INIT(0);
static atomic_t ipc_channel_ref_audit_warn_count = ATOMIC_INIT(0);
static atomic_t ipc_lock_probe_warn_count = ATOMIC_INIT(0);
static atomic_t kobj_lifecycle_warn_count = ATOMIC_INIT(0);

#define IPC_SYSFS_PAGE_SIZE_DEFAULT 64U
#define IPC_SYSFS_PAGE_SIZE_MAX     512U
#define IPC_SYSFS_TRANSFER_V2_DEFAULT_PAGE 128U
#define IPC_SYSFS_TRANSFER_V2_MAX_PAGE     512U
#define IPC_REG_ENTRY_LIVE   1U
#define IPC_REG_ENTRY_DYING  2U
#define IPC_PROJ_OP_ADD      (1U << 0)
#define IPC_PROJ_OP_DEL      (1U << 1)

struct ipc_sysfs_page_state {
    uint32_t cursor;
    uint32_t page_size;
};

struct khandle_cache_stats_snapshot {
    uint64_t lookups_total;
    uint64_t hits_total;
    uint64_t misses_total;
    uint64_t stores_total;
    uint64_t slot_invalidate_calls_total;
    uint64_t invalidated_slots_total;
    uint64_t released_refs_total;
    uint64_t ht_sweeps_total;
    uint64_t active_refs;
};

struct ipc_lock_probe_cpu_state {
    uint32_t registry_depth;
    uint32_t channel_depth;
    uint32_t port_depth;
};

static struct ipc_sysfs_page_state ipc_sysfs_page = {
    .cursor = 0,
    .page_size = IPC_SYSFS_PAGE_SIZE_DEFAULT,
};
static struct ipc_lock_probe_cpu_state ipc_lock_probe_states[CONFIG_MAX_CPUS];

static bool ipc_warn_ratelimited(atomic_t *warn_counter) {
    if (!warn_counter)
        return false;
    uint32_t n = atomic_inc_return(warn_counter);
    return n <= 4 || (n & (n - 1U)) == 0;
}

static inline void ipc_stat_inc_u64(uint64_t *counter) {
    if (!counter)
        return;
    __atomic_fetch_add(counter, 1, __ATOMIC_RELAXED);
}

static inline struct ipc_lock_probe_cpu_state *ipc_lock_probe_cpu_state_get(void) {
    int cpu = arch_cpu_id_stable();
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        cpu = 0;
    return &ipc_lock_probe_states[cpu];
}

static inline void ipc_lock_probe_warn_once(const char *edge, const char *detail) {
    if (!ipc_warn_ratelimited(&ipc_lock_probe_warn_count))
        return;
    struct process *curr = proc_current();
    int32_t pid = curr ? curr->pid : -1;
    pr_warn("ipc_lock_probe: edge=%s pid=%d %s\n", edge ? edge : "?",
            (int)pid, detail ? detail : "");
}

static void ipc_registry_lock_enter(void) {
    struct ipc_lock_probe_cpu_state *st = ipc_lock_probe_cpu_state_get();
    if (st->channel_depth > 0) {
        ipc_stat_inc_u64(&ipc_lock_probe_registry_after_channel_total);
        ipc_lock_probe_warn_once("channel->registry",
                                 "registry lock acquired while channel lock held");
    }
    if (st->port_depth > 0) {
        ipc_stat_inc_u64(&ipc_lock_probe_registry_after_port_total);
        ipc_lock_probe_warn_once("port->registry",
                                 "registry lock acquired while port lock held");
    }
    if (!mutex_trylock(&ipc_registry_lock)) {
        ipc_stat_inc_u64(&ipc_lock_probe_registry_contention_total);
        mutex_lock(&ipc_registry_lock);
    }
    st->registry_depth++;
}

static void ipc_registry_lock_leave(void) {
    struct ipc_lock_probe_cpu_state *st = ipc_lock_probe_cpu_state_get();
    if (st->registry_depth == 0)
        ipc_stat_inc_u64(&ipc_lock_probe_state_underflow_total);
    else
        st->registry_depth--;
    mutex_unlock(&ipc_registry_lock);
}

static void ipc_channel_lock(struct kchannel *ch) {
    if (!ch)
        return;
    struct ipc_lock_probe_cpu_state *st = ipc_lock_probe_cpu_state_get();
    if (st->registry_depth > 0)
        ipc_stat_inc_u64(&ipc_lock_probe_registry_then_channel_total);
    if (st->port_depth > 0) {
        ipc_stat_inc_u64(&ipc_lock_probe_channel_after_port_total);
        ipc_lock_probe_warn_once("port->channel",
                                 "channel lock acquired while port lock held");
    }
    if (!mutex_trylock(&ch->lock)) {
        ipc_stat_inc_u64(&ipc_lock_probe_channel_contention_total);
        mutex_lock(&ch->lock);
    }
    st->channel_depth++;
}

static void ipc_channel_unlock(struct kchannel *ch) {
    if (!ch)
        return;
    struct ipc_lock_probe_cpu_state *st = ipc_lock_probe_cpu_state_get();
    if (st->channel_depth == 0)
        ipc_stat_inc_u64(&ipc_lock_probe_state_underflow_total);
    else
        st->channel_depth--;
    mutex_unlock(&ch->lock);
}

static void ipc_port_lock(struct kport *port) {
    if (!port)
        return;
    struct ipc_lock_probe_cpu_state *st = ipc_lock_probe_cpu_state_get();
    if (st->registry_depth > 0)
        ipc_stat_inc_u64(&ipc_lock_probe_registry_then_port_total);
    if (st->channel_depth > 0)
        ipc_stat_inc_u64(&ipc_lock_probe_channel_then_port_total);
    if (!mutex_trylock(&port->lock)) {
        ipc_stat_inc_u64(&ipc_lock_probe_port_contention_total);
        mutex_lock(&port->lock);
    }
    st->port_depth++;
}

static void ipc_port_unlock(struct kport *port) {
    if (!port)
        return;
    struct ipc_lock_probe_cpu_state *st = ipc_lock_probe_cpu_state_get();
    if (st->port_depth == 0)
        ipc_stat_inc_u64(&ipc_lock_probe_state_underflow_total);
    else
        st->port_depth--;
    mutex_unlock(&port->lock);
}

extern bool sysfs_is_vnode(const struct vnode *vn);

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
static const char *
kchannel_endpoint_state_name(enum kchannel_endpoint_state state);
static bool kchannel_try_rendezvous_locked(struct kchannel *peer,
                                           struct kchannel_msg *msg);
static bool kchannel_try_rendezvous_raw_locked(
    struct kchannel *peer, const void *bytes, size_t num_bytes,
    const struct khandle_transfer *handles, size_t num_handles);
static void ipc_registry_register_obj(struct kobj *obj);
static void ipc_registry_unregister_obj(struct kobj *obj);
static bool ipc_registry_register_suppressed_for_current(void);
static void ipc_registry_register_suppress_enter(void);
static void ipc_registry_register_suppress_exit(void);
static void ipc_sysfs_ensure_ready(void);
static void ipc_sysfs_create_object_dir_locked(struct ipc_registry_entry *ent);
static void ipc_sysfs_remove_object_dir_locked(struct ipc_registry_entry *ent);
static void ipc_sysfs_object_state_put(void *priv);
static bool ipc_sysfs_project_mark_locked(struct ipc_registry_entry *ent,
                                          uint8_t ops);
static bool ipc_sysfs_project_drain_once(void);
static int ipc_sysfs_projector_main(void *arg);
static void ipc_sysfs_projector_start(void);
static void kcap_hash_stats_snapshot(struct khash_stats *out_stats,
                                     bool *out_ready);
static void
khandle_cache_stats_snapshot(struct khandle_cache_stats_snapshot *out);
static void kchannel_endpoint_ref_inc_internal(
    struct kobj *obj, enum kchannel_endpoint_ref_owner owner);
static bool kchannel_endpoint_ref_dec_internal(
    struct kobj *obj, enum kchannel_endpoint_ref_owner owner);
static void kchannel_trace_event(enum trace_ipc_channel_op op,
                                 enum trace_ipc_channel_wake wake,
                                 const struct kchannel *self,
                                 const struct kchannel *peer);
static void kcap_trace_event(enum trace_ipc_cap_op op, uint64_t cap_id,
                             uint64_t arg1);

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

const char *kobj_type_name(uint32_t type) {
    switch (type) {
    case KOBJ_TYPE_CHANNEL:
        return "channel";
    case KOBJ_TYPE_PORT:
        return "port";
    case KOBJ_TYPE_FILE:
        return "file";
    case KOBJ_TYPE_BUFFER:
        return "buffer";
    case VFS_KOBJ_TYPE_VNODE:
        return "vnode";
    case VFS_KOBJ_TYPE_DENTRY:
        return "dentry";
    default:
        return "unknown";
    }
}

const char *kobj_lifecycle_state_name(enum kobj_lifecycle_state state) {
    switch (state) {
    case KOBJ_LIFECYCLE_INIT:
        return "init";
    case KOBJ_LIFECYCLE_LIVE:
        return "live";
    case KOBJ_LIFECYCLE_DETACHED:
        return "detached";
    case KOBJ_LIFECYCLE_DYING:
        return "dying";
    case KOBJ_LIFECYCLE_FREED:
        return "freed";
    default:
        return "unknown";
    }
}

static inline enum kobj_lifecycle_state
kobj_lifecycle_state_get(const struct kobj *obj) {
    if (!obj)
        return KOBJ_LIFECYCLE_FREED;
    return (enum kobj_lifecycle_state)atomic_read(&obj->lifecycle);
}

static void kobj_lifecycle_warn_transition(struct kobj *obj, const char *site,
                                           enum kobj_lifecycle_state prev,
                                           enum kobj_lifecycle_state next) {
    ipc_stat_inc_u64(&kobj_lifecycle_transition_warn_total);
    if (!ipc_warn_ratelimited(&kobj_lifecycle_warn_count))
        return;
    pr_warn("kobj_lifecycle: transition obj=%u type=%s %s->%s site=%s\n",
            obj ? obj->id : 0U, obj ? kobj_type_name(obj->type) : "unknown",
            kobj_lifecycle_state_name(prev), kobj_lifecycle_state_name(next),
            site ? site : "?");
}

static void kobj_lifecycle_warn_access(struct kobj *obj, const char *op,
                                       enum kobj_lifecycle_state state) {
    ipc_stat_inc_u64(&kobj_lifecycle_access_warn_total);
    if (!ipc_warn_ratelimited(&kobj_lifecycle_warn_count))
        return;
    pr_warn("kobj_lifecycle: access op=%s obj=%u type=%s state=%s\n",
            op ? op : "?", obj ? obj->id : 0U,
            obj ? kobj_type_name(obj->type) : "unknown",
            kobj_lifecycle_state_name(state));
}

static inline void kobj_lifecycle_check_access(struct kobj *obj, const char *op) {
    enum kobj_lifecycle_state state = kobj_lifecycle_state_get(obj);
    if (state == KOBJ_LIFECYCLE_LIVE)
        return;
    kobj_lifecycle_warn_access(obj, op, state);
}

static const char *vnode_type_name(enum vnode_type type) {
    switch (type) {
    case VNODE_FILE:
        return "file";
    case VNODE_DIR:
        return "dir";
    case VNODE_DEVICE:
        return "device";
    case VNODE_PIPE:
        return "pipe";
    case VNODE_SOCKET:
        return "socket";
    case VNODE_SYMLINK:
        return "symlink";
    case VNODE_EPOLL:
        return "epoll";
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
        KHASH_INIT(ipc_registry_id_hash);
        completion_init(&ipc_sysfs_project_completion);
        ipc_sysfs_project_completion_ready = true;
        __atomic_store_n(&ipc_registry_lock_ready, true, __ATOMIC_RELEASE);
    }
    spin_unlock_irqrestore(&ipc_registry_init_lock, irq_flags);
}

static void ipc_registry_id_hash_insert_locked(struct ipc_registry_entry *ent) {
    if (!ent || !ent->obj)
        return;
    khash_add(ipc_registry_id_hash, &ent->hash_node, ent->obj->id);
}

static void ipc_registry_id_hash_remove_locked(struct ipc_registry_entry *ent) {
    if (!ent || list_empty(&ent->hash_node))
        return;
    khash_del(&ent->hash_node);
}

static struct ipc_registry_entry *
ipc_registry_find_by_obj_id_locked(uint32_t obj_id) {
    if (obj_id == 0)
        return NULL;
    struct ipc_registry_entry *ent;
    khash_for_each_possible_u32(ipc_registry_id_hash, ent, hash_node, obj_id) {
        if (ent->obj && ent->obj->id == obj_id)
            return ent;
    }
    return NULL;
}

static struct list_head *ipc_registry_list_for_type(uint32_t type) {
    switch (type) {
    case KOBJ_TYPE_CHANNEL:
        return &ipc_channel_registry;
    case KOBJ_TYPE_PORT:
        return &ipc_port_registry;
    case KOBJ_TYPE_FILE:
        return &ipc_file_registry;
    case KOBJ_TYPE_BUFFER:
        return &ipc_buffer_registry;
    case VFS_KOBJ_TYPE_VNODE:
        return &ipc_vnode_registry;
    case VFS_KOBJ_TYPE_DENTRY:
        return &ipc_dentry_registry;
    default:
        return NULL;
    }
}

static bool ipc_registry_is_sysfs_mount(const struct mount *mnt) {
    if (!vfs_mount_is_live(mnt))
        return false;
    return mnt && mnt->ops && mnt->ops->name &&
           strcmp(mnt->ops->name, "sysfs") == 0;
}

static bool ipc_registry_track_object(struct kobj *obj) {
    if (!obj)
        return false;

    if (obj->type == VFS_KOBJ_TYPE_VNODE) {
        struct vnode *vn = vnode_from_kobj(obj);
        if (!vn)
            return false;
        return !sysfs_is_vnode(vn);
    }

    if (obj->type == VFS_KOBJ_TYPE_DENTRY) {
        struct dentry *d = dentry_from_kobj(obj);
        if (!d)
            return false;
        struct mount *mnt = d->mnt;
        if (mnt && !vfs_mount_is_live(mnt))
            mnt = NULL;
        if (ipc_registry_is_sysfs_mount(mnt))
            return false;
        if (d->vnode && sysfs_is_vnode(d->vnode))
            return false;
    }

    return true;
}

static bool ipc_registry_register_suppressed_for_current(void) {
    uint32_t depth = __atomic_load_n(&ipc_registry_register_suppress_depth,
                                     __ATOMIC_ACQUIRE);
    if (depth == 0)
        return false;

    struct process *owner = __atomic_load_n(
        &ipc_registry_register_suppress_proc, __ATOMIC_ACQUIRE);
    struct process *curr = proc_current();
    if (owner)
        return curr == owner;
    if (curr)
        return false;

    int owner_cpu = __atomic_load_n(&ipc_registry_register_suppress_cpu,
                                    __ATOMIC_ACQUIRE);
    return owner_cpu == arch_cpu_id();
}

static void ipc_registry_register_suppress_enter(void) {
    uint32_t depth = __atomic_load_n(&ipc_registry_register_suppress_depth,
                                     __ATOMIC_ACQUIRE);
    if (depth == 0) {
        struct process *curr = proc_current();
        __atomic_store_n(&ipc_registry_register_suppress_proc, curr,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&ipc_registry_register_suppress_cpu,
                         curr ? -1 : arch_cpu_id(), __ATOMIC_RELEASE);
    }
    __atomic_add_fetch(&ipc_registry_register_suppress_depth, 1,
                       __ATOMIC_ACQ_REL);
}

static void ipc_registry_register_suppress_exit(void) {
    uint32_t depth = __atomic_load_n(&ipc_registry_register_suppress_depth,
                                     __ATOMIC_ACQUIRE);
    if (depth == 0)
        return;

    depth = __atomic_sub_fetch(&ipc_registry_register_suppress_depth, 1,
                               __ATOMIC_ACQ_REL);
    if (depth == 0) {
        __atomic_store_n(&ipc_registry_register_suppress_proc, NULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&ipc_registry_register_suppress_cpu, -1,
                         __ATOMIC_RELEASE);
    }
}

static bool ipc_sysfs_project_mark_locked(struct ipc_registry_entry *ent,
                                          uint8_t ops) {
    if (!ent)
        return false;

    bool high_prio = false;
    if (ent->obj) {
        switch (ent->obj->type) {
        case KOBJ_TYPE_CHANNEL:
        case KOBJ_TYPE_PORT:
        case KOBJ_TYPE_FILE:
        case KOBJ_TYPE_BUFFER:
            high_prio = true;
            break;
        default:
            break;
        }
    }

    if (ops)
        ent->pending_proj_ops |= ops;
    if (!ent->project_queued) {
        if (high_prio)
            list_add(&ent->project_node, &ipc_sysfs_project_queue);
        else
            list_add_tail(&ent->project_node, &ipc_sysfs_project_queue);
        ent->project_queued = true;
    } else if (high_prio) {
        list_del(&ent->project_node);
        list_add(&ent->project_node, &ipc_sysfs_project_queue);
    }
    return ipc_sysfs_projector_started;
}

static bool ipc_sysfs_project_drain_once(void) {
    struct ipc_registry_entry *ent = NULL;
    uint8_t ops = 0;
    bool do_free = false;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    if (list_empty(&ipc_sysfs_project_queue)) {
        ipc_registry_lock_leave();
        return false;
    }

    ent = list_first_entry(&ipc_sysfs_project_queue, struct ipc_registry_entry,
                           project_node);
    list_del(&ent->project_node);
    INIT_LIST_HEAD(&ent->project_node);
    ent->project_queued = false;
    ops = ent->pending_proj_ops;
    ent->pending_proj_ops = 0;

    ipc_registry_register_suppress_enter();
    if (ipc_sysfs_ready) {
        if ((ops & IPC_PROJ_OP_ADD) && ent->lifecycle == IPC_REG_ENTRY_LIVE)
            ipc_sysfs_create_object_dir_locked(ent);
        if ((ops & IPC_PROJ_OP_DEL) || ent->lifecycle == IPC_REG_ENTRY_DYING)
            ipc_sysfs_remove_object_dir_locked(ent);
    }
    ipc_registry_register_suppress_exit();

    do_free = ent->lifecycle == IPC_REG_ENTRY_DYING && !ent->project_queued &&
              ent->pending_proj_ops == 0;
    ipc_registry_lock_leave();

    if (do_free)
        kfree(ent);
    return true;
}

static int ipc_sysfs_projector_main(void *arg __attribute__((unused))) {
    for (;;) {
        wait_for_completion(&ipc_sysfs_project_completion);
        while (ipc_sysfs_project_drain_once()) {
        }
    }
    return 0;
}

static void ipc_sysfs_projector_start(void) {
    bool do_start = false;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    if (!ipc_sysfs_projector_started && ipc_sysfs_project_completion_ready) {
        /*
         * Mark started before dropping the lock so concurrent bootstrap paths
         * cannot race and spawn duplicate projector workers.
         */
        ipc_sysfs_projector_started = true;
        do_start = true;
    }
    ipc_registry_lock_leave();
    if (!do_start)
        return;

    struct process *task =
        kthread_create(ipc_sysfs_projector_main, NULL, "ipcsysfs");
    if (!task) {
        ipc_registry_ensure_lock();
        ipc_registry_lock_enter();
        ipc_sysfs_projector_started = false;
        ipc_registry_lock_leave();
        pr_warn("ipc: failed to start sysfs projector thread\n");
        return;
    }
    sched_enqueue(task);
}

static bool ipc_char_is_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static int ipc_parse_u32(const char *buf, size_t len, uint32_t *out) {
    if (!buf || !out)
        return -EINVAL;

    size_t i = 0;
    while (i < len && ipc_char_is_space(buf[i]))
        i++;
    if (i >= len)
        return -EINVAL;

    bool seen_digit = false;
    uint64_t value = 0;
    for (; i < len; i++) {
        char c = buf[i];
        if (c >= '0' && c <= '9') {
            seen_digit = true;
            value = (value * 10ULL) + (uint64_t)(c - '0');
            if (value > 0xffffffffULL)
                return -ERANGE;
            continue;
        }
        if (!ipc_char_is_space(c))
            return -EINVAL;
        while (i < len && ipc_char_is_space(buf[i]))
            i++;
        if (i != len)
            return -EINVAL;
        break;
    }
    if (!seen_digit)
        return -EINVAL;

    *out = (uint32_t)value;
    return 0;
}

static bool ipc_registry_pin_obj_owner_by_id(
    uint32_t obj_id, struct ipc_registry_obj_owner_pin *pin) {
    if (!pin)
        return false;
    memset(pin, 0, sizeof(*pin));
    if (obj_id == 0)
        return false;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    struct ipc_registry_entry *ent = ipc_registry_find_by_obj_id_locked(obj_id);
    struct kobj *obj = NULL;
    if (ent && ent->obj && ent->lifecycle == IPC_REG_ENTRY_LIVE) {
        obj = ent->obj;
        kobj_get(obj);
    }
    ipc_registry_lock_leave();
    if (!obj)
        return false;

    pin->obj = obj;
    switch (obj->type) {
    case VFS_KOBJ_TYPE_VNODE: {
        struct vnode *vn = vnode_from_kobj(obj);
        if (vn) {
            vnode_get(vn);
            pin->vnode = vn;
        }
        break;
    }
    case VFS_KOBJ_TYPE_DENTRY: {
        struct dentry *d = dentry_from_kobj(obj);
        if (d) {
            dentry_get(d);
            pin->dentry = d;
        }
        break;
    }
    default:
        break;
    }

    return true;
}

/*
 * Compatibility helper for legacy call sites that only need a pinned kobj.
 * Keep this alongside owner-pin API so mixed integration states compile.
 */
static struct kobj *__attribute__((unused))
ipc_registry_pin_obj_by_id(uint32_t obj_id) {
    if (obj_id == 0)
        return NULL;
    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    struct ipc_registry_entry *ent = ipc_registry_find_by_obj_id_locked(obj_id);
    struct kobj *obj = NULL;
    if (ent && ent->obj && ent->lifecycle == IPC_REG_ENTRY_LIVE) {
        obj = ent->obj;
        kobj_get(obj);
    }
    ipc_registry_lock_leave();
    return obj;
}

static void ipc_registry_unpin_obj_owner(struct ipc_registry_obj_owner_pin *pin) {
    if (!pin || !pin->obj)
        return;
    if (pin->dentry)
        dentry_put(pin->dentry);
    if (pin->vnode)
        vnode_put(pin->vnode);
    kobj_put(pin->obj);
    pin->obj = NULL;
    pin->vnode = NULL;
    pin->dentry = NULL;
}

static struct ipc_sysfs_object_state *
ipc_sysfs_object_state_get(struct ipc_sysfs_object_state *state) {
    if (!state)
        return NULL;
    atomic_inc(&state->refs);
    return state;
}

static void ipc_sysfs_object_state_put(void *priv) {
    struct ipc_sysfs_object_state *state = priv;
    if (!state)
        return;
    if (atomic_dec_return(&state->refs) == 0)
        kfree(state);
}

static bool ipc_sysfs_create_or_get_file(struct sysfs_node *parent,
                                         const struct sysfs_attribute *attr) {
    if (!parent || !attr || !attr->name)
        return false;
    if (sysfs_create_file(parent, attr))
        return true;
    return sysfs_find_child(parent, attr->name) != NULL;
}

static int ipc_sysfs_append_object_row(struct kobj *obj, char *buf, size_t bufsz,
                                       size_t *out_len) {
    if (!obj || !buf || !out_len || *out_len >= bufsz)
        return -EINVAL;

    size_t len = *out_len;
    int n = 0;
    const char *lifecycle =
        kobj_lifecycle_state_name(kobj_lifecycle_state_get(obj));
    struct kchannel *ch = kchannel_from_obj(obj);
    if (ch) {
        size_t rxq_len = 0;
        bool peer_closed = false;
        bool endpoint_closed = false;
        enum kchannel_endpoint_state endpoint_state = KCHANNEL_ENDPOINT_CLOSED;
        uint32_t refs_handle = 0;
        uint32_t refs_fd = 0;
        uint32_t refs_other = 0;
        ipc_channel_lock(ch);
        rxq_len = ch->rxq_len;
        peer_closed = ch->peer_closed;
        endpoint_state = ch->endpoint_state;
        endpoint_closed = endpoint_state != KCHANNEL_ENDPOINT_OPEN;
        ipc_channel_unlock(ch);
        refs_handle = atomic_read(&ch->endpoint_ref_handle_count);
        refs_fd = atomic_read(&ch->endpoint_ref_channelfd_count);
        refs_other = atomic_read(&ch->endpoint_ref_other_count);

        n = snprintf(buf + len, bufsz - len,
                     "%u %s %u %s handle_refs=%u ref_handle=%u ref_fd=%u ref_other=%u "
                     "rxq_len=%zu peer_closed=%u endpoint_state=%s endpoint_closed=%u\n",
                     obj->id, kobj_type_name(obj->type),
                     atomic_read(&obj->refcount), lifecycle,
                     atomic_read(&ch->handle_refs),
                     refs_handle, refs_fd, refs_other, rxq_len,
                     peer_closed ? 1U : 0U,
                     kchannel_endpoint_state_name(endpoint_state),
                     endpoint_closed ? 1U : 0U);
    } else {
        struct kport *port = kport_from_obj(obj);
        if (port) {
            size_t queue_len = 0;
            uint64_t dropped_count = 0;
            ipc_port_lock(port);
            queue_len = port->queue_len;
            dropped_count = port->dropped_count;
            ipc_port_unlock(port);

            n = snprintf(buf + len, bufsz - len,
                         "%u %s %u %s queue_len=%zu dropped_count=%llu\n",
                         obj->id, kobj_type_name(obj->type),
                         atomic_read(&obj->refcount), lifecycle, queue_len,
                         (unsigned long long)dropped_count);
        } else {
            struct kfile *kfile = kfile_from_obj(obj);
            if (kfile && kfile->file && kfile->file->vnode) {
                const char *path = kfile->file->path[0] ? kfile->file->path : "-";
                n = snprintf(buf + len, bufsz - len,
                             "%u %s %u %s ino=%lu path=%s\n",
                             obj->id, kobj_type_name(obj->type),
                             atomic_read(&obj->refcount), lifecycle,
                             (unsigned long)kfile->file->vnode->ino, path);
            } else {
                struct vnode *vn = vnode_from_kobj(obj);
                if (vn) {
                    unsigned int mnt_present = vn->mount ? 1U : 0U;
                    const char *name = vn->name[0] ? vn->name : "-";
                    n = snprintf(buf + len, bufsz - len,
                                 "%u %s %u %s ino=%lu vnode_type=%s mode=0%o size=%llu name=%s mnt_present=%u\n",
                                 obj->id, kobj_type_name(obj->type),
                                 atomic_read(&obj->refcount), lifecycle,
                                 (unsigned long)vn->ino, vnode_type_name(vn->type),
                                 (unsigned int)vn->mode,
                                 (unsigned long long)vn->size, name, mnt_present);
                } else {
                    struct dentry *d = dentry_from_kobj(obj);
                    if (d) {
                        struct mount *mnt = d->mnt;
                        bool mnt_live = vfs_mount_is_live(mnt);
                        unsigned int mnt_present = mnt_live ? 1U : 0U;
                        char path[CONFIG_PATH_MAX];
                        const char *path_out = d->name[0] ? d->name : "/";
                        if (mnt_live &&
                            vfs_build_path_dentry(d, path, sizeof(path)) >= 0 &&
                            path[0]) {
                            path_out = path;
                        }
                        n = snprintf(buf + len, bufsz - len,
                                     "%u %s %u %s flags=0x%x path=%s mnt_present=%u\n",
                                     obj->id, kobj_type_name(obj->type),
                                     atomic_read(&obj->refcount), lifecycle,
                                     d->flags, path_out, mnt_present);
                    } else if (obj->type == VFS_KOBJ_TYPE_VNODE ||
                               obj->type == VFS_KOBJ_TYPE_DENTRY) {
                        n = snprintf(buf + len, bufsz - len,
                                     "%u %s %u %s owner=stale\n", obj->id,
                                     kobj_type_name(obj->type),
                                     atomic_read(&obj->refcount), lifecycle);
                    } else {
                        n = snprintf(buf + len, bufsz - len, "%u %s %u %s\n",
                                     obj->id, kobj_type_name(obj->type),
                                     atomic_read(&obj->refcount), lifecycle);
                    }
                }
            }
        }
    }
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz - len)
        return -ENOSPC;
    *out_len = len + (size_t)n;
    return 0;
}

static ssize_t ipc_sysfs_show_objects_page(void *priv __attribute__((unused)),
                                           char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    size_t len = 0;
    int n = 0;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();

    uint32_t cursor = ipc_sysfs_page.cursor;
    uint32_t page_size = ipc_sysfs_page.page_size;
    if (page_size == 0)
        page_size = IPC_SYSFS_PAGE_SIZE_DEFAULT;

    n = snprintf(buf + len, bufsz - len, "cursor=%u page_size=%u\n", cursor,
                 page_size);
    if (n < 0)
        goto out_err;
    if ((size_t)n >= bufsz - len)
        goto out_trunc;
    len += (size_t)n;

    n = snprintf(buf + len, bufsz - len, "id type refcount state\n");
    if (n < 0)
        goto out_err;
    if ((size_t)n >= bufsz - len)
        goto out_trunc;
    len += (size_t)n;

    size_t emitted = 0;
    uint32_t last_id = cursor;
    struct ipc_registry_entry *ent;
    while (emitted < page_size) {
        struct kobj *next_obj = NULL;
        uint32_t next_id = 0xFFFFFFFFU;
        list_for_each_entry(ent, &ipc_registry_all, all_node) {
            struct kobj *obj = ent->obj;
            if (!obj || obj->id <= last_id)
                continue;
            if (!next_obj || obj->id < next_id) {
                next_obj = obj;
                next_id = obj->id;
            }
        }
        if (!next_obj)
            break;
        if (ipc_sysfs_append_object_row(next_obj, buf, bufsz, &len) < 0)
            goto out_trunc;
        last_id = next_id;
        emitted++;
    }

    bool has_more = false;
    list_for_each_entry(ent, &ipc_registry_all, all_node) {
        struct kobj *obj = ent->obj;
        if (obj && obj->id > last_id) {
            has_more = true;
            break;
        }
    }

    uint32_t next_cursor = has_more ? last_id : 0U;
    n = snprintf(buf + len, bufsz - len, "next_cursor=%u has_more=%u\n",
                 next_cursor, has_more ? 1U : 0U);
    if (n < 0)
        goto out_err;
    if ((size_t)n >= bufsz - len)
        goto out_trunc;
    len += (size_t)n;

    ipc_registry_lock_leave();
    return (ssize_t)len;

out_trunc:
    ipc_registry_lock_leave();
    return (ssize_t)bufsz;
out_err:
    ipc_registry_lock_leave();
    return -EINVAL;
}

static ssize_t ipc_sysfs_show_objects_cursor(void *priv __attribute__((unused)),
                                             char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    uint32_t cursor = ipc_sysfs_page.cursor;
    ipc_registry_lock_leave();

    int n = snprintf(buf, bufsz, "%u\n", cursor);
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)bufsz;
    return (ssize_t)n;
}

static ssize_t ipc_sysfs_store_objects_cursor(
    void *priv __attribute__((unused)), const char *buf, size_t len) {
    uint32_t value = 0;
    int rc = ipc_parse_u32(buf, len, &value);
    if (rc < 0)
        return rc;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    ipc_sysfs_page.cursor = value;
    ipc_registry_lock_leave();
    return (ssize_t)len;
}

static ssize_t ipc_sysfs_show_objects_page_size(
    void *priv __attribute__((unused)), char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    uint32_t page_size = ipc_sysfs_page.page_size;
    ipc_registry_lock_leave();

    int n = snprintf(buf, bufsz, "%u\n", page_size);
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)bufsz;
    return (ssize_t)n;
}

static ssize_t ipc_sysfs_store_objects_page_size(
    void *priv __attribute__((unused)), const char *buf, size_t len) {
    uint32_t value = 0;
    int rc = ipc_parse_u32(buf, len, &value);
    if (rc < 0)
        return rc;
    if (value == 0 || value > IPC_SYSFS_PAGE_SIZE_MAX)
        return -EINVAL;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    ipc_sysfs_page.page_size = value;
    ipc_registry_lock_leave();
    return (ssize_t)len;
}

static ssize_t ipc_sysfs_show_object_summary(void *priv, char *buf, size_t bufsz) {
    if (!buf || bufsz == 0 || !priv)
        return -EINVAL;

    struct ipc_sysfs_object_state *state = priv;
    struct ipc_registry_obj_owner_pin pin = {0};
    if (!ipc_registry_pin_obj_owner_by_id(state->obj_id, &pin))
        return -ENODEV;
    struct kobj *obj = pin.obj;

    ssize_t ret = -EINVAL;
    size_t len = 0;
    int n = snprintf(buf + len, bufsz - len,
                     "id=%u\ntype=%s\nrefcount=%u\nlifecycle=%s\n",
                     obj->id, kobj_type_name(obj->type),
                     atomic_read(&obj->refcount),
                     kobj_lifecycle_state_name(kobj_lifecycle_state_get(obj)));
    if (n < 0)
        goto out_put;
    if ((size_t)n >= bufsz - len) {
        ret = (ssize_t)bufsz;
        goto out_put;
    }
    len += (size_t)n;

    struct kchannel *ch = kchannel_from_obj(obj);
    if (ch) {
        size_t rxq_len = 0;
        bool peer_closed = false;
        bool endpoint_closed = false;
        enum kchannel_endpoint_state endpoint_state = KCHANNEL_ENDPOINT_CLOSED;
        uint32_t refs_handle = 0;
        uint32_t refs_fd = 0;
        uint32_t refs_other = 0;
        ipc_channel_lock(ch);
        rxq_len = ch->rxq_len;
        peer_closed = ch->peer_closed;
        endpoint_state = ch->endpoint_state;
        endpoint_closed = endpoint_state != KCHANNEL_ENDPOINT_OPEN;
        ipc_channel_unlock(ch);
        refs_handle = atomic_read(&ch->endpoint_ref_handle_count);
        refs_fd = atomic_read(&ch->endpoint_ref_channelfd_count);
        refs_other = atomic_read(&ch->endpoint_ref_other_count);
        n = snprintf(buf + len, bufsz - len,
                     "handle_refs=%u\nref_handle=%u\nref_fd=%u\nref_other=%u\n"
                     "rxq_len=%zu\npeer_closed=%u\n"
                     "endpoint_state=%s\nendpoint_closed=%u\n",
                     atomic_read(&ch->handle_refs), refs_handle, refs_fd,
                     refs_other, rxq_len,
                     peer_closed ? 1U : 0U,
                     kchannel_endpoint_state_name(endpoint_state),
                     endpoint_closed ? 1U : 0U);
        if (n < 0)
            goto out_put;
        if ((size_t)n >= bufsz - len) {
            ret = (ssize_t)bufsz;
            goto out_put;
        }
        len += (size_t)n;
        ret = (ssize_t)len;
        goto out_put;
    }

    struct kport *port = kport_from_obj(obj);
    if (port) {
        size_t queue_len = 0;
        ipc_port_lock(port);
        queue_len = port->queue_len;
        ipc_port_unlock(port);
        n = snprintf(buf + len, bufsz - len, "queue_len=%zu\n", queue_len);
        if (n < 0)
            goto out_put;
        if ((size_t)n >= bufsz - len) {
            ret = (ssize_t)bufsz;
            goto out_put;
        }
        len += (size_t)n;
        ret = (ssize_t)len;
        goto out_put;
    }

    struct kfile *kfile = kfile_from_obj(obj);
    if (kfile) {
        const char *path = "-";
        unsigned long ino = 0;
        if (kfile->file) {
            if (kfile->file->path[0])
                path = kfile->file->path;
            if (kfile->file->vnode)
                ino = (unsigned long)kfile->file->vnode->ino;
        }
        n = snprintf(buf + len, bufsz - len, "ino=%lu\npath=%s\n", ino, path);
        if (n < 0)
            goto out_put;
        if ((size_t)n >= bufsz - len) {
            ret = (ssize_t)bufsz;
            goto out_put;
        }
        len += (size_t)n;
        ret = (ssize_t)len;
        goto out_put;
    }

    struct vnode *vn = pin.vnode;
    if (vn) {
        unsigned int mnt_present = vn->mount ? 1U : 0U;
        const char *name = vn->name[0] ? vn->name : "-";
        n = snprintf(buf + len, bufsz - len,
                     "ino=%lu\nvnode_type=%s\nmode=0%o\nsize=%llu\nname=%s\nmnt_present=%u\n",
                     (unsigned long)vn->ino, vnode_type_name(vn->type),
                     (unsigned int)vn->mode, (unsigned long long)vn->size, name,
                     mnt_present);
        if (n < 0)
            goto out_put;
        if ((size_t)n >= bufsz - len) {
            ret = (ssize_t)bufsz;
            goto out_put;
        }
        len += (size_t)n;
        ret = (ssize_t)len;
        goto out_put;
    }

    struct dentry *d = pin.dentry;
    if (d) {
        struct mount *mnt = d->mnt;
        bool mnt_live = vfs_mount_is_live(mnt);
        unsigned int mnt_present = mnt_live ? 1U : 0U;
        char path[CONFIG_PATH_MAX];
        const char *path_out = d->name[0] ? d->name : "/";
        if (mnt_live && vfs_build_path_dentry(d, path, sizeof(path)) >= 0 &&
            path[0])
            path_out = path;
        n = snprintf(buf + len, bufsz - len,
                     "flags=0x%x\npath=%s\nmnt_present=%u\n", d->flags, path_out,
                     mnt_present);
        if (n < 0)
            goto out_put;
        if ((size_t)n >= bufsz - len) {
            ret = (ssize_t)bufsz;
            goto out_put;
        }
        len += (size_t)n;
    } else if (obj->type == VFS_KOBJ_TYPE_VNODE ||
               obj->type == VFS_KOBJ_TYPE_DENTRY) {
        n = snprintf(buf + len, bufsz - len, "owner=stale\n");
        if (n < 0)
            goto out_put;
        if ((size_t)n >= bufsz - len) {
            ret = (ssize_t)bufsz;
            goto out_put;
        }
        len += (size_t)n;
    }

    ret = (ssize_t)len;
out_put:
    ipc_registry_unpin_obj_owner(&pin);
    return ret;
}

static ssize_t ipc_sysfs_show_object_transfers(void *priv, char *buf, size_t bufsz) {
    if (!buf || bufsz == 0 || !priv)
        return -EINVAL;

    struct ipc_sysfs_object_state *state = priv;
    struct ipc_registry_obj_owner_pin pin = {0};
    if (!ipc_registry_pin_obj_owner_by_id(state->obj_id, &pin))
        return -ENODEV;
    struct kobj *obj = pin.obj;

    ssize_t ret = -EINVAL;
    size_t len = 0;
    int n = snprintf(buf + len, bufsz - len,
                     "seq event from_pid to_pid rights cpu ticks\n");
    if (n < 0)
        goto out_put;
    if ((size_t)n >= bufsz - len) {
        ret = (ssize_t)bufsz;
        goto out_put;
    }
    len += (size_t)n;

    struct kobj_transfer_history_entry hist[KOBJ_TRANSFER_HISTORY_DEPTH] = {0};
    size_t count =
        kobj_transfer_history_snapshot(obj, hist, KOBJ_TRANSFER_HISTORY_DEPTH);
    for (size_t i = 0; i < count; i++) {
        if (hist[i].seq == 0)
            continue;
        n = snprintf(buf + len, bufsz - len, "%u %s %d %d 0x%x %u %llu\n",
                     hist[i].seq, kobj_transfer_event_name(hist[i].event),
                     hist[i].from_pid, hist[i].to_pid, hist[i].rights,
                     hist[i].cpu, (unsigned long long)hist[i].ticks);
        if (n < 0)
            goto out_put;
        if ((size_t)n >= bufsz - len) {
            ret = (ssize_t)bufsz;
            goto out_put;
        }
        len += (size_t)n;
    }

    ret = (ssize_t)len;
out_put:
    ipc_registry_unpin_obj_owner(&pin);
    return ret;
}

static ssize_t ipc_sysfs_show_object_transfers_v2(void *priv, char *buf,
                                                  size_t bufsz) {
    if (!buf || bufsz == 0 || !priv)
        return -EINVAL;

    struct ipc_sysfs_object_state *state = priv;
    struct ipc_registry_obj_owner_pin pin = {0};
    if (!ipc_registry_pin_obj_owner_by_id(state->obj_id, &pin))
        return -ENODEV;
    struct kobj *obj = pin.obj;

    ssize_t ret = -EINVAL;
    uint32_t cursor =
        __atomic_load_n(&state->transfers_cursor, __ATOMIC_ACQUIRE);
    uint32_t page_size =
        __atomic_load_n(&state->transfers_page_size, __ATOMIC_ACQUIRE);
    if (page_size == 0)
        page_size = IPC_SYSFS_TRANSFER_V2_DEFAULT_PAGE;

    size_t len = 0;
    int n = snprintf(buf + len, bufsz - len,
                     "schema=sysfs_ipc_object_transfers_v2\n"
                     "obj_id=%u\n"
                     "type=%s\n"
                     "cursor=%u\n"
                     "page_size=%u\n"
                     "columns=seq event from_pid to_pid rights cpu ticks\n",
                     obj->id, kobj_type_name(obj->type), cursor, page_size);
    if (n < 0)
        goto out_put;
    if ((size_t)n >= bufsz - len) {
        ret = (ssize_t)bufsz;
        goto out_put;
    }
    len += (size_t)n;

    struct kobj_transfer_history_entry hist[KOBJ_TRANSFER_HISTORY_DEPTH] = {0};
    size_t count =
        kobj_transfer_history_snapshot(obj, hist, KOBJ_TRANSFER_HISTORY_DEPTH);

    uint32_t scanned = 0;
    uint32_t emitted = 0;
    bool has_more = false;
    for (size_t i = 0; i < count; i++) {
        if (hist[i].seq == 0)
            continue;
        if (scanned < cursor) {
            scanned++;
            continue;
        }
        if (emitted >= page_size) {
            has_more = true;
            break;
        }

        n = snprintf(buf + len, bufsz - len, "%u %s %d %d 0x%x %u %llu\n",
                     hist[i].seq, kobj_transfer_event_name(hist[i].event),
                     hist[i].from_pid, hist[i].to_pid, hist[i].rights,
                     hist[i].cpu, (unsigned long long)hist[i].ticks);
        if (n < 0)
            goto out_put;
        if ((size_t)n >= bufsz - len) {
            ret = (ssize_t)bufsz;
            goto out_put;
        }
        len += (size_t)n;
        emitted++;
        scanned++;
    }

    uint64_t next_cursor64 = (uint64_t)cursor + (uint64_t)emitted;
    if (next_cursor64 > 0xFFFFFFFFULL)
        next_cursor64 = 0xFFFFFFFFULL;
    uint32_t next_cursor = (uint32_t)next_cursor64;

    n = snprintf(buf + len, bufsz - len,
                 "returned=%u\n"
                 "next_cursor=%u\n"
                 "end=%u\n",
                 emitted, next_cursor, has_more ? 0U : 1U);
    if (n < 0)
        goto out_put;
    if ((size_t)n >= bufsz - len) {
        ret = (ssize_t)bufsz;
        goto out_put;
    }
    len += (size_t)n;

    ret = (ssize_t)len;
out_put:
    ipc_registry_unpin_obj_owner(&pin);
    return ret;
}

static ssize_t ipc_sysfs_show_object_transfers_cursor(void *priv, char *buf,
                                                      size_t bufsz) {
    if (!buf || bufsz == 0 || !priv)
        return -EINVAL;
    struct ipc_sysfs_object_state *state = priv;
    uint32_t cursor =
        __atomic_load_n(&state->transfers_cursor, __ATOMIC_ACQUIRE);
    int n = snprintf(buf, bufsz, "%u\n", cursor);
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)bufsz;
    return (ssize_t)n;
}

static ssize_t ipc_sysfs_store_object_transfers_cursor(void *priv,
                                                       const char *buf,
                                                       size_t len) {
    if (!priv)
        return -EINVAL;
    uint32_t value = 0;
    int rc = ipc_parse_u32(buf, len, &value);
    if (rc < 0)
        return rc;
    struct ipc_sysfs_object_state *state = priv;
    __atomic_store_n(&state->transfers_cursor, value, __ATOMIC_RELEASE);
    return (ssize_t)len;
}

static ssize_t ipc_sysfs_show_object_transfers_page_size(void *priv, char *buf,
                                                         size_t bufsz) {
    if (!buf || bufsz == 0 || !priv)
        return -EINVAL;
    struct ipc_sysfs_object_state *state = priv;
    uint32_t page_size =
        __atomic_load_n(&state->transfers_page_size, __ATOMIC_ACQUIRE);
    if (page_size == 0)
        page_size = IPC_SYSFS_TRANSFER_V2_DEFAULT_PAGE;
    int n = snprintf(buf, bufsz, "%u\n", page_size);
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)bufsz;
    return (ssize_t)n;
}

static ssize_t ipc_sysfs_store_object_transfers_page_size(void *priv,
                                                          const char *buf,
                                                          size_t len) {
    if (!priv)
        return -EINVAL;
    uint32_t value = 0;
    int rc = ipc_parse_u32(buf, len, &value);
    if (rc < 0)
        return rc;
    if (value == 0 || value > IPC_SYSFS_TRANSFER_V2_MAX_PAGE)
        return -EINVAL;
    struct ipc_sysfs_object_state *state = priv;
    __atomic_store_n(&state->transfers_page_size, value, __ATOMIC_RELEASE);
    return (ssize_t)len;
}

static ssize_t ipc_sysfs_show_channels(void *priv __attribute__((unused)),
                                       char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    size_t len = 0;
    int n = snprintf(
        buf, bufsz,
        "id refcount handle_refs ref_handle ref_fd ref_other rxq_len peer_closed endpoint_state endpoint_closed\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)(bufsz - 1);
    len = (size_t)n;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();

    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_channel_registry, type_node) {
        struct kobj *obj = ent->obj;
        struct kchannel *ch = kchannel_from_obj(obj);
        if (!obj || !ch)
            continue;

        size_t rxq_len = 0;
        bool peer_closed = false;
        bool endpoint_closed = false;
        enum kchannel_endpoint_state endpoint_state = KCHANNEL_ENDPOINT_CLOSED;
        uint32_t refs_handle = 0;
        uint32_t refs_fd = 0;
        uint32_t refs_other = 0;
        ipc_channel_lock(ch);
        rxq_len = ch->rxq_len;
        peer_closed = ch->peer_closed;
        endpoint_state = ch->endpoint_state;
        endpoint_closed = endpoint_state != KCHANNEL_ENDPOINT_OPEN;
        ipc_channel_unlock(ch);
        refs_handle = atomic_read(&ch->endpoint_ref_handle_count);
        refs_fd = atomic_read(&ch->endpoint_ref_channelfd_count);
        refs_other = atomic_read(&ch->endpoint_ref_other_count);

        n = snprintf(buf + len, bufsz - len, "%u %u %u %u %u %u %zu %u %s %u\n",
                     obj->id,
                     atomic_read(&obj->refcount), atomic_read(&ch->handle_refs),
                     refs_handle, refs_fd, refs_other, rxq_len,
                     peer_closed ? 1U : 0U,
                     kchannel_endpoint_state_name(endpoint_state),
                     endpoint_closed ? 1U : 0U);
        if (n < 0 || (size_t)n >= bufsz - len) {
            len = bufsz;
            break;
        }
        len += (size_t)n;
    }

    ipc_registry_lock_leave();
    return (ssize_t)((len < bufsz) ? len : bufsz);
}

static ssize_t ipc_sysfs_show_ports(void *priv __attribute__((unused)), char *buf,
                                    size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    size_t len = 0;
    int n = snprintf(buf, bufsz, "id refcount queue_len dropped_count\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)(bufsz - 1);
    len = (size_t)n;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();

    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_port_registry, type_node) {
        struct kobj *obj = ent->obj;
        struct kport *port = kport_from_obj(obj);
        if (!obj || !port)
            continue;

        size_t queue_len = 0;
        uint64_t dropped_count = 0;
        ipc_port_lock(port);
        queue_len = port->queue_len;
        dropped_count = port->dropped_count;
        ipc_port_unlock(port);

        n = snprintf(buf + len, bufsz - len, "%u %u %zu %llu\n", obj->id,
                     atomic_read(&obj->refcount), queue_len,
                     (unsigned long long)dropped_count);
        if (n < 0 || (size_t)n >= bufsz - len) {
            len = bufsz;
            break;
        }
        len += (size_t)n;
    }

    ipc_registry_lock_leave();
    return (ssize_t)((len < bufsz) ? len : bufsz);
}

static ssize_t ipc_sysfs_show_stats(void *priv __attribute__((unused)), char *buf,
                                    size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    uint64_t reg_oom = __atomic_load_n(&ipc_registry_register_oom_failures,
                                       __ATOMIC_RELAXED);
    uint64_t port_drops =
        __atomic_load_n(&ipc_port_queue_drops_total, __ATOMIC_RELAXED);
    uint64_t send_epipe =
        __atomic_load_n(&ipc_channel_send_epipe_total, __ATOMIC_RELAXED);
    uint64_t recv_eof =
        __atomic_load_n(&ipc_channel_recv_eof_total, __ATOMIC_RELAXED);
    uint64_t close_last_ref =
        __atomic_load_n(&ipc_channel_close_last_ref_total, __ATOMIC_RELAXED);
    uint64_t close_release =
        __atomic_load_n(&ipc_channel_close_release_total, __ATOMIC_RELAXED);
    uint64_t wake_local =
        __atomic_load_n(&ipc_channel_close_wake_local_total, __ATOMIC_RELAXED);
    uint64_t wake_peer =
        __atomic_load_n(&ipc_channel_close_wake_peer_total, __ATOMIC_RELAXED);
    uint64_t hint_checks =
        __atomic_load_n(&ipc_channel_poll_hint_checks_total, __ATOMIC_RELAXED);
    uint64_t hint_mismatch_in = __atomic_load_n(
        &ipc_channel_poll_hint_mismatch_in_total, __ATOMIC_RELAXED);
    uint64_t hint_mismatch_out = __atomic_load_n(
        &ipc_channel_poll_hint_mismatch_out_total, __ATOMIC_RELAXED);
    uint64_t hint_mismatch_hup = __atomic_load_n(
        &ipc_channel_poll_hint_mismatch_hup_total, __ATOMIC_RELAXED);
    uint64_t ref_audit_checks =
        __atomic_load_n(&ipc_channel_ref_audit_checks_total, __ATOMIC_RELAXED);
    uint64_t ref_audit_mismatch = __atomic_load_n(
        &ipc_channel_ref_audit_mismatch_total, __ATOMIC_RELAXED);
    uint64_t cap_revoke_marked = __atomic_load_n(
        &ipc_cap_revoke_marked_total, __ATOMIC_RELAXED);
    uint64_t cap_bind_rejected_revoked = __atomic_load_n(
        &ipc_cap_bind_rejected_revoked_total, __ATOMIC_RELAXED);
    uint64_t cap_commit_eagain = __atomic_load_n(
        &ipc_cap_commit_eagain_total, __ATOMIC_RELAXED);
    uint64_t cap_commit_epoch_mismatch = __atomic_load_n(
        &ipc_cap_commit_epoch_mismatch_total, __ATOMIC_RELAXED);
    uint64_t cap_tryget_failed = __atomic_load_n(
        &ipc_cap_tryget_failed_total, __ATOMIC_RELAXED);
    uint32_t reg_oom_warns = atomic_read(&ipc_registry_register_oom_warn_count);
    uint32_t port_drop_warns = atomic_read(&ipc_port_queue_drop_warn_count);
    uint32_t ref_underflow_warns =
        atomic_read(&ipc_channel_ref_underflow_warn_count);
    uint32_t hint_warns = atomic_read(&ipc_channel_poll_hint_warn_count);
    uint32_t ref_audit_warns = atomic_read(&ipc_channel_ref_audit_warn_count);
    uint64_t lock_registry_after_channel = __atomic_load_n(
        &ipc_lock_probe_registry_after_channel_total, __ATOMIC_RELAXED);
    uint64_t lock_registry_after_port = __atomic_load_n(
        &ipc_lock_probe_registry_after_port_total, __ATOMIC_RELAXED);
    uint64_t lock_registry_then_channel = __atomic_load_n(
        &ipc_lock_probe_registry_then_channel_total, __ATOMIC_RELAXED);
    uint64_t lock_registry_then_port = __atomic_load_n(
        &ipc_lock_probe_registry_then_port_total, __ATOMIC_RELAXED);
    uint64_t lock_channel_then_port = __atomic_load_n(
        &ipc_lock_probe_channel_then_port_total, __ATOMIC_RELAXED);
    uint64_t lock_channel_after_port = __atomic_load_n(
        &ipc_lock_probe_channel_after_port_total, __ATOMIC_RELAXED);
    uint64_t lock_registry_contention = __atomic_load_n(
        &ipc_lock_probe_registry_contention_total, __ATOMIC_RELAXED);
    uint64_t lock_channel_contention = __atomic_load_n(
        &ipc_lock_probe_channel_contention_total, __ATOMIC_RELAXED);
    uint64_t lock_port_contention = __atomic_load_n(
        &ipc_lock_probe_port_contention_total, __ATOMIC_RELAXED);
    uint64_t lock_state_underflow = __atomic_load_n(
        &ipc_lock_probe_state_underflow_total, __ATOMIC_RELAXED);
    uint32_t lock_warns = atomic_read(&ipc_lock_probe_warn_count);
    uint64_t kobj_lifecycle_transition_warns = __atomic_load_n(
        &kobj_lifecycle_transition_warn_total, __ATOMIC_RELAXED);
    uint64_t kobj_lifecycle_access_warns = __atomic_load_n(
        &kobj_lifecycle_access_warn_total, __ATOMIC_RELAXED);
    uint32_t kobj_lifecycle_warns = atomic_read(&kobj_lifecycle_warn_count);
    struct khandle_cache_stats_snapshot cache_stats = {0};
    khandle_cache_stats_snapshot(&cache_stats);
    uint64_t cache_hit_per_mille =
        cache_stats.lookups_total
            ? ((cache_stats.hits_total * 1000ULL) / cache_stats.lookups_total)
            : 0;

    int n = snprintf(buf, bufsz,
                     "schema=sysfs_ipc_stats_v2\n"
                     "registry_register_oom_failures=%llu\n"
                     "registry_register_oom_warns=%u\n"
                     "port_queue_drops_total=%llu\n"
                     "port_queue_drop_warns=%u\n"
                     "channel_send_epipe_total=%llu\n"
                     "channel_recv_eof_total=%llu\n"
                     "channel_close_last_ref_total=%llu\n"
                     "channel_close_release_total=%llu\n"
                     "channel_close_wake_local_total=%llu\n"
                     "channel_close_wake_peer_total=%llu\n"
                     "channel_ref_underflow_warns=%u\n"
                     "channel_ref_audit_checks_total=%llu\n"
                     "channel_ref_audit_mismatch_total=%llu\n"
                     "channel_ref_audit_warns=%u\n"
                     "cap_revoke_marked_total=%llu\n"
                     "cap_bind_rejected_revoked_total=%llu\n"
                     "cap_commit_eagain_total=%llu\n"
                     "cap_commit_epoch_mismatch_total=%llu\n"
                     "cap_tryget_failed_total=%llu\n"
                     "channel_poll_hint_checks_total=%llu\n"
                     "channel_poll_hint_mismatch_in_total=%llu\n"
                     "channel_poll_hint_mismatch_out_total=%llu\n"
                     "channel_poll_hint_mismatch_hup_total=%llu\n"
                     "channel_poll_hint_warns=%u\n"
                     "khandle_cache_lookups_total=%llu\n"
                     "khandle_cache_hits_total=%llu\n"
                     "khandle_cache_misses_total=%llu\n"
                     "khandle_cache_hit_per_mille=%llu\n"
                     "khandle_cache_stores_total=%llu\n"
                     "khandle_cache_slot_invalidate_calls_total=%llu\n"
                     "khandle_cache_invalidated_slots_total=%llu\n"
                     "khandle_cache_released_refs_total=%llu\n"
                     "khandle_cache_ht_sweeps_total=%llu\n"
                     "khandle_cache_active_refs=%llu\n"
                     "ipc_lock_probe_registry_after_channel_total=%llu\n"
                     "ipc_lock_probe_registry_after_port_total=%llu\n"
                     "ipc_lock_probe_registry_then_channel_total=%llu\n"
                     "ipc_lock_probe_registry_then_port_total=%llu\n"
                     "ipc_lock_probe_channel_then_port_total=%llu\n"
                     "ipc_lock_probe_channel_after_port_total=%llu\n"
                     "ipc_lock_probe_registry_contention_total=%llu\n"
                     "ipc_lock_probe_channel_contention_total=%llu\n"
                     "ipc_lock_probe_port_contention_total=%llu\n"
                     "ipc_lock_probe_state_underflow_total=%llu\n"
                     "ipc_lock_probe_warns=%u\n"
                     "kobj_lifecycle_transition_warn_total=%llu\n"
                     "kobj_lifecycle_access_warn_total=%llu\n"
                     "kobj_lifecycle_warns=%u\n",
                     (unsigned long long)reg_oom, reg_oom_warns,
                     (unsigned long long)port_drops, port_drop_warns,
                     (unsigned long long)send_epipe,
                     (unsigned long long)recv_eof,
                     (unsigned long long)close_last_ref,
                     (unsigned long long)close_release,
                     (unsigned long long)wake_local, (unsigned long long)wake_peer,
                     ref_underflow_warns, (unsigned long long)ref_audit_checks,
                     (unsigned long long)ref_audit_mismatch, ref_audit_warns,
                     (unsigned long long)cap_revoke_marked,
                     (unsigned long long)cap_bind_rejected_revoked,
                     (unsigned long long)cap_commit_eagain,
                     (unsigned long long)cap_commit_epoch_mismatch,
                     (unsigned long long)cap_tryget_failed,
                     (unsigned long long)hint_checks,
                     (unsigned long long)hint_mismatch_in,
                     (unsigned long long)hint_mismatch_out,
                     (unsigned long long)hint_mismatch_hup, hint_warns,
                     (unsigned long long)cache_stats.lookups_total,
                     (unsigned long long)cache_stats.hits_total,
                     (unsigned long long)cache_stats.misses_total,
                     (unsigned long long)cache_hit_per_mille,
                     (unsigned long long)cache_stats.stores_total,
                     (unsigned long long)cache_stats.slot_invalidate_calls_total,
                     (unsigned long long)cache_stats.invalidated_slots_total,
                     (unsigned long long)cache_stats.released_refs_total,
                     (unsigned long long)cache_stats.ht_sweeps_total,
                     (unsigned long long)cache_stats.active_refs,
                     (unsigned long long)lock_registry_after_channel,
                     (unsigned long long)lock_registry_after_port,
                     (unsigned long long)lock_registry_then_channel,
                     (unsigned long long)lock_registry_then_port,
                     (unsigned long long)lock_channel_then_port,
                     (unsigned long long)lock_channel_after_port,
                     (unsigned long long)lock_registry_contention,
                     (unsigned long long)lock_channel_contention,
                     (unsigned long long)lock_port_contention,
                     (unsigned long long)lock_state_underflow, lock_warns,
                     (unsigned long long)kobj_lifecycle_transition_warns,
                     (unsigned long long)kobj_lifecycle_access_warns,
                     kobj_lifecycle_warns);
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)bufsz;
    return (ssize_t)n;
}

static ssize_t ipc_sysfs_show_hash_stats(void *priv __attribute__((unused)),
                                         char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    struct khash_stats registry_stats = {0};
    struct khash_stats kcap_stats = {0};
    bool kcap_ready = false;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    KHASH_STATS(ipc_registry_id_hash, &registry_stats);
    ipc_registry_lock_leave();

    kcap_hash_stats_snapshot(&kcap_stats, &kcap_ready);

    int n = snprintf(
        buf, bufsz,
        "schema=sysfs_ipc_hash_stats_v1\n"
        "table=ipc_registry_id buckets=%zu used_buckets=%zu entries=%zu "
        "load_per_mille=%u avg_chain_per_mille=%u collision_entries=%zu "
        "max_bucket_depth=%zu rehash_recommended=%u\n"
        "table=kcap_id ready=%u buckets=%zu used_buckets=%zu entries=%zu "
        "load_per_mille=%u avg_chain_per_mille=%u collision_entries=%zu "
        "max_bucket_depth=%zu rehash_recommended=%u\n",
        registry_stats.bucket_count, registry_stats.used_buckets,
        registry_stats.entries, khash_load_factor_per_mille(&registry_stats),
        khash_avg_chain_per_mille(&registry_stats),
        khash_collision_entries(&registry_stats), registry_stats.max_bucket_depth,
        khash_rehash_recommended_default(&registry_stats) ? 1U : 0U,
        kcap_ready ? 1U : 0U, kcap_stats.bucket_count, kcap_stats.used_buckets,
        kcap_stats.entries, khash_load_factor_per_mille(&kcap_stats),
        khash_avg_chain_per_mille(&kcap_stats),
        khash_collision_entries(&kcap_stats), kcap_stats.max_bucket_depth,
        khash_rehash_recommended_default(&kcap_stats) ? 1U : 0U);
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)bufsz;
    return (ssize_t)n;
}

static ssize_t ipc_sysfs_show_files(void *priv __attribute__((unused)), char *buf,
                                    size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    size_t len = 0;
    int n = snprintf(buf, bufsz, "id refcount ino path\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)(bufsz - 1);
    len = (size_t)n;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();

    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_file_registry, type_node) {
        struct kobj *obj = ent->obj;
        struct kfile *kfile = kfile_from_obj(obj);
        if (!obj || !kfile)
            continue;

        unsigned long ino = 0;
        const char *path = "-";
        if (kfile->file) {
            if (kfile->file->vnode)
                ino = (unsigned long)kfile->file->vnode->ino;
            if (kfile->file->path[0])
                path = kfile->file->path;
        }

        n = snprintf(buf + len, bufsz - len, "%u %u %lu %s\n", obj->id,
                     atomic_read(&obj->refcount), ino, path);
        if (n < 0 || (size_t)n >= bufsz - len) {
            len = bufsz;
            break;
        }
        len += (size_t)n;
    }

    ipc_registry_lock_leave();
    return (ssize_t)((len < bufsz) ? len : bufsz);
}

static ssize_t ipc_sysfs_show_vnodes(void *priv __attribute__((unused)), char *buf,
                                     size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    size_t len = 0;
    int n = snprintf(buf, bufsz,
                     "id refcount ino vnode_type mode size name mnt_present\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)(bufsz - 1);
    len = (size_t)n;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();

    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_vnode_registry, type_node) {
        struct kobj *obj = ent->obj;
        struct vnode *vn = vnode_from_kobj(obj);
        if (!obj)
            continue;
        if (!vn) {
            n = snprintf(buf + len, bufsz - len, "%u %u 0 - 0 0 - 0\n", obj->id,
                         atomic_read(&obj->refcount));
        } else {
            unsigned int mnt_present = vn->mount ? 1U : 0U;
            const char *name = vn->name[0] ? vn->name : "-";
            n = snprintf(buf + len, bufsz - len, "%u %u %lu %s 0%o %llu %s %u\n",
                         obj->id, atomic_read(&obj->refcount),
                         (unsigned long)vn->ino, vnode_type_name(vn->type),
                         (unsigned int)vn->mode, (unsigned long long)vn->size,
                         name, mnt_present);
        }
        if (n < 0 || (size_t)n >= bufsz - len) {
            len = bufsz;
            break;
        }
        len += (size_t)n;
    }

    ipc_registry_lock_leave();
    return (ssize_t)((len < bufsz) ? len : bufsz);
}

static ssize_t ipc_sysfs_show_dentries(void *priv __attribute__((unused)),
                                       char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return -EINVAL;

    size_t len = 0;
    int n = snprintf(buf, bufsz, "id refcount flags path mnt_present\n");
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= bufsz)
        return (ssize_t)(bufsz - 1);
    len = (size_t)n;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();

    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_dentry_registry, type_node) {
        struct kobj *obj = ent->obj;
        struct dentry *d = dentry_from_kobj(obj);
        if (!obj)
            continue;
        if (!d) {
            n = snprintf(buf + len, bufsz - len, "%u %u 0x0 - 0\n", obj->id,
                         atomic_read(&obj->refcount));
        } else {
            struct mount *mnt = d->mnt;
            bool mnt_live = vfs_mount_is_live(mnt);
            unsigned int mnt_present = mnt_live ? 1U : 0U;
            char path[CONFIG_PATH_MAX];
            const char *path_out = d->name[0] ? d->name : "/";
            if (mnt_live && vfs_build_path_dentry(d, path, sizeof(path)) >= 0 &&
                path[0])
                path_out = path;

            n = snprintf(buf + len, bufsz - len, "%u %u 0x%x %s %u\n", obj->id,
                         atomic_read(&obj->refcount), d->flags, path_out,
                         mnt_present);
        }
        if (n < 0 || (size_t)n >= bufsz - len) {
            len = bufsz;
            break;
        }
        len += (size_t)n;
    }

    ipc_registry_lock_leave();
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
    ipc_registry_lock_enter();

    struct kobj_transfer_history_entry hist[KOBJ_TRANSFER_HISTORY_DEPTH] = {0};
    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_registry_all, all_node) {
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
    ipc_registry_lock_leave();
    return (ssize_t)((len < bufsz) ? len : bufsz);
}

static const struct sysfs_attribute ipc_sysfs_attrs[] = {
    {.name = "channels", .mode = 0444, .show = ipc_sysfs_show_channels},
    {.name = "ports", .mode = 0444, .show = ipc_sysfs_show_ports},
    {.name = "files", .mode = 0444, .show = ipc_sysfs_show_files},
    {.name = "vnodes", .mode = 0444, .show = ipc_sysfs_show_vnodes},
    {.name = "dentries", .mode = 0444, .show = ipc_sysfs_show_dentries},
    {.name = "transfers", .mode = 0444, .show = ipc_sysfs_show_transfers},
    {.name = "stats", .mode = 0444, .show = ipc_sysfs_show_stats},
    {.name = "hash_stats", .mode = 0444, .show = ipc_sysfs_show_hash_stats},
};

static const struct sysfs_attribute ipc_sysfs_objects_attrs[] = {
    {.name = "page", .mode = 0444, .show = ipc_sysfs_show_objects_page},
    {
        .name = "cursor",
        .mode = 0644,
        .show = ipc_sysfs_show_objects_cursor,
        .store = ipc_sysfs_store_objects_cursor,
    },
    {
        .name = "page_size",
        .mode = 0644,
        .show = ipc_sysfs_show_objects_page_size,
        .store = ipc_sysfs_store_objects_page_size,
    },
};

static void ipc_sysfs_create_object_dir_locked(struct ipc_registry_entry *ent) {
    if (!ent || !ent->obj || !ipc_sysfs_objects_dir || ent->sysfs_dir)
        return;

    char name[16] = {0};
    int n = snprintf(name, sizeof(name), "%u", ent->obj->id);
    if (n < 0 || (size_t)n >= sizeof(name))
        return;

    struct sysfs_node *dir = sysfs_mkdir(ipc_sysfs_objects_dir, name);
    bool dir_created = dir != NULL;
    if (!dir) {
        dir = sysfs_find_child(ipc_sysfs_objects_dir, name);
        if (dir) {
            ent->sysfs_dir = dir;
            return;
        }
        return;
    }

    struct ipc_sysfs_object_state *state = kzalloc(sizeof(*state));
    if (!state) {
        if (dir_created)
            sysfs_rmdir(dir);
        return;
    }
    atomic_init(&state->refs, 1);
    state->obj_id = ent->obj->id;
    state->transfers_cursor = 0;
    state->transfers_page_size = IPC_SYSFS_TRANSFER_V2_DEFAULT_PAGE;

    struct sysfs_attribute attrs[] = {
        {
            .name = "summary",
            .mode = 0444,
            .show = ipc_sysfs_show_object_summary,
            .release_priv = ipc_sysfs_object_state_put,
        },
        {
            .name = "transfers",
            .mode = 0444,
            .show = ipc_sysfs_show_object_transfers,
            .release_priv = ipc_sysfs_object_state_put,
        },
        {
            .name = "transfers_v2",
            .mode = 0444,
            .show = ipc_sysfs_show_object_transfers_v2,
            .release_priv = ipc_sysfs_object_state_put,
        },
        {
            .name = "transfers_cursor",
            .mode = 0644,
            .show = ipc_sysfs_show_object_transfers_cursor,
            .store = ipc_sysfs_store_object_transfers_cursor,
            .release_priv = ipc_sysfs_object_state_put,
        },
        {
            .name = "transfers_page_size",
            .mode = 0644,
            .show = ipc_sysfs_show_object_transfers_page_size,
            .store = ipc_sysfs_store_object_transfers_page_size,
            .release_priv = ipc_sysfs_object_state_put,
        },
    };

    bool ok = true;
    for (size_t i = 0; i < ARRAY_SIZE(attrs); i++) {
        attrs[i].priv = ipc_sysfs_object_state_get(state);
        if (!attrs[i].priv || !sysfs_create_file(dir, &attrs[i])) {
            ipc_sysfs_object_state_put(attrs[i].priv);
            ok = false;
            break;
        }
    }

    ipc_sysfs_object_state_put(state);
    if (!ok) {
        if (dir_created)
            sysfs_rmdir(dir);
        return;
    }
    ent->sysfs_dir = dir;
}

static void ipc_sysfs_remove_object_dir_locked(struct ipc_registry_entry *ent) {
    if (!ent || !ent->sysfs_dir)
        return;
    sysfs_rmdir(ent->sysfs_dir);
    ent->sysfs_dir = NULL;
}

static void ipc_sysfs_ensure_ready(void) {
    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    ipc_registry_register_suppress_enter();

    if (!ipc_sysfs_ready) {
        struct sysfs_node *root = sysfs_root();
        if (!root)
            goto out_unlock;

        if (!ipc_sysfs_root) {
            ipc_sysfs_root = sysfs_mkdir(root, "ipc");
            if (!ipc_sysfs_root)
                ipc_sysfs_root = sysfs_find_child(root, "ipc");
        }
        if (!ipc_sysfs_root)
            goto out_unlock;

        for (size_t i = 0; i < ARRAY_SIZE(ipc_sysfs_attrs); i++) {
            if (!ipc_sysfs_create_or_get_file(ipc_sysfs_root,
                                              &ipc_sysfs_attrs[i])) {
                pr_warn("ipc: failed to ensure /sys/ipc/%s\n",
                        ipc_sysfs_attrs[i].name);
                goto out_unlock;
            }
        }

        if (!ipc_sysfs_objects_dir) {
            ipc_sysfs_objects_dir = sysfs_mkdir(ipc_sysfs_root, "objects");
            if (!ipc_sysfs_objects_dir)
                ipc_sysfs_objects_dir =
                    sysfs_find_child(ipc_sysfs_root, "objects");
        }
        if (!ipc_sysfs_objects_dir) {
            pr_warn("ipc: failed to create /sys/ipc/objects\n");
            goto out_unlock;
        }

        for (size_t i = 0; i < ARRAY_SIZE(ipc_sysfs_objects_attrs); i++) {
            if (!ipc_sysfs_create_or_get_file(ipc_sysfs_objects_dir,
                                              &ipc_sysfs_objects_attrs[i])) {
                pr_warn("ipc: failed to ensure /sys/ipc/objects/%s\n",
                        ipc_sysfs_objects_attrs[i].name);
                goto out_unlock;
            }
        }

        ipc_sysfs_page.cursor = 0;
        ipc_sysfs_page.page_size = IPC_SYSFS_PAGE_SIZE_DEFAULT;
        __atomic_store_n(&ipc_sysfs_ready, true, __ATOMIC_RELEASE);
    }

out_unlock:
    ipc_registry_register_suppress_exit();
    ipc_registry_lock_leave();
}

void ipc_registry_sysfs_bootstrap(void) {
    ipc_registry_ensure_lock();
    ipc_sysfs_ensure_ready();
    ipc_sysfs_projector_start();

    bool wake_projector = false;
    ipc_registry_lock_enter();
    if (!ipc_sysfs_ready) {
        ipc_registry_lock_leave();
        pr_warn("ipc: sysfs bootstrap deferred (sysfs root unavailable)\n");
        return;
    }
    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_registry_all, all_node) {
        if (ent->lifecycle != IPC_REG_ENTRY_LIVE)
            continue;
        wake_projector |= ipc_sysfs_project_mark_locked(ent, IPC_PROJ_OP_ADD);
    }
    if (!list_empty(&ipc_sysfs_project_queue))
        wake_projector = true;
    ipc_registry_lock_leave();

    if (wake_projector)
        complete_one(&ipc_sysfs_project_completion);
}

static void ipc_registry_register_obj(struct kobj *obj) {
    if (!ipc_registry_track_object(obj))
        return;
    if (ipc_registry_register_suppressed_for_current())
        return;
    struct list_head *list = ipc_registry_list_for_type(obj->type);
    if (!list)
        return;

    ipc_registry_ensure_lock();
    struct ipc_registry_entry *ent = kzalloc(sizeof(*ent));
    if (!ent) {
        uint64_t total = __atomic_add_fetch(&ipc_registry_register_oom_failures,
                                            1, __ATOMIC_RELAXED);
        if (ipc_warn_ratelimited(&ipc_registry_register_oom_warn_count)) {
            pr_warn("ipc: registry alloc failed obj_id=%u type=%s total=%llu\n",
                    obj->id, kobj_type_name(obj->type),
                    (unsigned long long)total);
        }
        return;
    }
    ent->obj = obj;
    ent->generation = atomic_inc_return(&ipc_registry_generation_next);
    ent->lifecycle = IPC_REG_ENTRY_LIVE;
    ent->pending_proj_ops = 0;
    ent->project_queued = false;
    ent->sysfs_dir = NULL;
    INIT_LIST_HEAD(&ent->type_node);
    INIT_LIST_HEAD(&ent->all_node);
    INIT_LIST_HEAD(&ent->hash_node);
    INIT_LIST_HEAD(&ent->project_node);

    bool wake_projector = false;
    ipc_registry_lock_enter();
    list_add_tail(&ent->type_node, list);
    list_add_tail(&ent->all_node, &ipc_registry_all);
    ipc_registry_id_hash_insert_locked(ent);
    wake_projector |= ipc_sysfs_project_mark_locked(ent, IPC_PROJ_OP_ADD);
    ipc_registry_lock_leave();

    if (wake_projector)
        complete_one(&ipc_sysfs_project_completion);
}

static void ipc_registry_unregister_obj(struct kobj *obj) {
    if (!obj)
        return;
    if (ipc_registry_register_suppressed_for_current())
        return;
    struct list_head *list = ipc_registry_list_for_type(obj->type);
    if (!list)
        return;

    ipc_registry_ensure_lock();
    bool wake_projector = false;
    ipc_registry_lock_enter();
    struct ipc_registry_entry *ent, *tmp;
    list_for_each_entry_safe(ent, tmp, list, type_node) {
        if (ent->obj != obj)
            continue;
        list_del(&ent->type_node);
        list_del(&ent->all_node);
        ipc_registry_id_hash_remove_locked(ent);
        ent->obj = NULL;
        ent->lifecycle = IPC_REG_ENTRY_DYING;
        wake_projector |= ipc_sysfs_project_mark_locked(ent, IPC_PROJ_OP_DEL);
        ipc_registry_lock_leave();
        if (wake_projector)
            complete_one(&ipc_sysfs_project_completion);
        return;
    }
    ipc_registry_lock_leave();
}

static void kchannel_emit_locked(struct kchannel *ch, uint32_t signal);
static void kchannel_poll_wake_locked(struct kchannel *ch, uint32_t events);
#if CONFIG_DEBUG
static inline bool
kchannel_endpoint_state_valid(enum kchannel_endpoint_state state);
#endif

static inline bool kchannel_endpoint_open_locked(const struct kchannel *ch) {
#if CONFIG_DEBUG
    if (ch)
        ASSERT(kchannel_endpoint_state_valid(ch->endpoint_state));
#endif
    return ch && ch->endpoint_state == KCHANNEL_ENDPOINT_OPEN;
}

static inline bool kchannel_endpoint_hup_locked(const struct kchannel *ch) {
    if (!ch)
        return true;
    return !kchannel_endpoint_open_locked(ch) || ch->peer_closed || !ch->peer;
}

static inline bool kchannel_send_open_locked(const struct kchannel *ch) {
    return ch && kchannel_endpoint_open_locked(ch) && !ch->peer_closed &&
           ch->peer != NULL;
}

static inline bool kchannel_peer_accepts_send_locked(const struct kchannel *peer) {
    return peer && kchannel_endpoint_open_locked(peer) && !peer->peer_closed &&
           peer->peer != NULL;
}

static inline const char *
kchannel_endpoint_state_name(enum kchannel_endpoint_state state) {
    switch (state) {
    case KCHANNEL_ENDPOINT_OPEN:
        return "OPEN";
    case KCHANNEL_ENDPOINT_CLOSING:
        return "CLOSING";
    case KCHANNEL_ENDPOINT_CLOSED:
        return "CLOSED";
    default:
        return "UNKNOWN";
    }
}

#if CONFIG_DEBUG
static inline bool
kchannel_endpoint_state_valid(enum kchannel_endpoint_state state) {
    return state == KCHANNEL_ENDPOINT_OPEN ||
           state == KCHANNEL_ENDPOINT_CLOSING ||
           state == KCHANNEL_ENDPOINT_CLOSED;
}

static inline bool kchannel_endpoint_transition_valid(
    enum kchannel_endpoint_state from, enum kchannel_endpoint_state to) {
    if (from == to)
        return true;
    if (from == KCHANNEL_ENDPOINT_OPEN && to == KCHANNEL_ENDPOINT_CLOSING)
        return true;
    if (from == KCHANNEL_ENDPOINT_CLOSING && to == KCHANNEL_ENDPOINT_CLOSED)
        return true;
    return false;
}
#endif

static inline void kchannel_endpoint_transition_locked(
    struct kchannel *ch, enum kchannel_endpoint_state to) {
    if (!ch)
        return;
#if CONFIG_DEBUG
    enum kchannel_endpoint_state from = ch->endpoint_state;
    ASSERT(kchannel_endpoint_state_valid(from));
    ASSERT(kchannel_endpoint_state_valid(to));
    ASSERT(kchannel_endpoint_transition_valid(from, to));
#endif
    ch->endpoint_state = to;
}

static inline const char *
kchannel_endpoint_ref_owner_name(enum kchannel_endpoint_ref_owner owner) {
    switch (owner) {
    case KCHANNEL_ENDPOINT_REF_OWNER_HANDLE:
        return "handle";
    case KCHANNEL_ENDPOINT_REF_OWNER_CHANNEL_FD:
        return "channel_fd";
    case KCHANNEL_ENDPOINT_REF_OWNER_OTHER:
        return "other";
    default:
        return "unknown";
    }
}

static inline atomic_t *
kchannel_owner_ref_counter(struct kchannel *ch,
                           enum kchannel_endpoint_ref_owner owner) {
    if (!ch)
        return NULL;
    switch (owner) {
    case KCHANNEL_ENDPOINT_REF_OWNER_HANDLE:
        return &ch->endpoint_ref_handle_count;
    case KCHANNEL_ENDPOINT_REF_OWNER_CHANNEL_FD:
        return &ch->endpoint_ref_channelfd_count;
    case KCHANNEL_ENDPOINT_REF_OWNER_OTHER:
        return &ch->endpoint_ref_other_count;
    default:
        return NULL;
    }
}

static bool kchannel_endpoint_ref_snapshot_consistent(
    struct kchannel *ch, uint32_t *out_total, uint32_t *out_handle,
    uint32_t *out_fd, uint32_t *out_other) {
    if (!ch || !out_total || !out_handle || !out_fd || !out_other)
        return false;

    uint32_t total = 0;
    uint32_t refs_handle = 0;
    uint32_t refs_fd = 0;
    uint32_t refs_other = 0;
    for (int attempt = 0; attempt < 8; attempt++) {
        uint32_t total_before = atomic_read(&ch->handle_refs);
        refs_handle = atomic_read(&ch->endpoint_ref_handle_count);
        refs_fd = atomic_read(&ch->endpoint_ref_channelfd_count);
        refs_other = atomic_read(&ch->endpoint_ref_other_count);
        uint32_t total_after = atomic_read(&ch->handle_refs);
        if (total_before != total_after) {
            arch_cpu_relax();
            continue;
        }
        total = total_after;
        uint64_t owner_sum = (uint64_t)refs_handle + (uint64_t)refs_fd +
                             (uint64_t)refs_other;
        if (owner_sum == (uint64_t)total) {
            *out_total = total;
            *out_handle = refs_handle;
            *out_fd = refs_fd;
            *out_other = refs_other;
            return true;
        }
        arch_cpu_relax();
    }

    *out_total = atomic_read(&ch->handle_refs);
    *out_handle = refs_handle;
    *out_fd = refs_fd;
    *out_other = refs_other;
    return false;
}

static void kchannel_endpoint_ref_audit_channel(struct kchannel *ch,
                                                const char *site, int32_t pid) {
    if (!ch)
        return;

    __atomic_add_fetch(&ipc_channel_ref_audit_checks_total, 1, __ATOMIC_RELAXED);

    uint32_t total = 0;
    uint32_t refs_handle = 0;
    uint32_t refs_fd = 0;
    uint32_t refs_other = 0;
    bool consistent = kchannel_endpoint_ref_snapshot_consistent(
        ch, &total, &refs_handle, &refs_fd, &refs_other);
    if (consistent)
        return;

    uint64_t owner_sum = (uint64_t)refs_handle + (uint64_t)refs_fd +
                         (uint64_t)refs_other;
    __atomic_add_fetch(&ipc_channel_ref_audit_mismatch_total, 1, __ATOMIC_RELAXED);
    if (ipc_warn_ratelimited(&ipc_channel_ref_audit_warn_count)) {
        const char *at = site ? site : "unknown";
        pr_warn("ipc: endpoint ref audit mismatch id=%u site=%s pid=%d total=%u "
                "ref_handle=%u ref_fd=%u ref_other=%u owner_sum=%llu\n",
                ch->obj.id, at, pid, total, refs_handle, refs_fd, refs_other,
                (unsigned long long)owner_sum);
    }
}

static inline void kchannel_hint_store(atomic_t *hint, bool ready) {
    if (!hint)
        return;
    __atomic_store_n(&hint->counter, ready ? 1U : 0U, __ATOMIC_RELEASE);
}

static inline bool kchannel_hint_load(const atomic_t *hint) {
    if (!hint)
        return false;
    return __atomic_load_n(&hint->counter, __ATOMIC_ACQUIRE) != 0;
}

static enum trace_ipc_channel_endpoint_state
kchannel_trace_state(const struct kchannel *ch) {
    if (!ch)
        return TRACE_IPC_CH_STATE_UNKNOWN;
    switch (ch->endpoint_state) {
    case KCHANNEL_ENDPOINT_OPEN:
        return TRACE_IPC_CH_STATE_OPEN;
    case KCHANNEL_ENDPOINT_CLOSING:
        return TRACE_IPC_CH_STATE_CLOSING;
    case KCHANNEL_ENDPOINT_CLOSED:
        return TRACE_IPC_CH_STATE_CLOSED;
    default:
        return TRACE_IPC_CH_STATE_UNKNOWN;
    }
}

static void kchannel_trace_event(enum trace_ipc_channel_op op,
                                 enum trace_ipc_channel_wake wake,
                                 const struct kchannel *self,
                                 const struct kchannel *peer) {
    uint32_t self_id = self ? self->obj.id : 0;
    uint32_t peer_id = peer ? peer->obj.id : 0;
    uint32_t flags = trace_ipc_channel_flags_build(
        op, wake, kchannel_trace_state(self), kchannel_trace_state(peer));
    uint64_t ids = ((uint64_t)self_id << 32) | (uint64_t)peer_id;
    tracepoint_emit(TRACE_IPC_CHANNEL, flags, ids, 0);
}

static void kcap_trace_event(enum trace_ipc_cap_op op, uint64_t cap_id,
                             uint64_t arg1) {
    uint32_t flags = trace_ipc_cap_flags_build(op);
    tracepoint_emit(TRACE_IPC_CAP, flags, cap_id, arg1);
}

static inline void kchannel_pollin_hup_hint_update_locked(struct kchannel *ch) {
    if (!ch)
        return;
    kchannel_hint_store(&ch->pollin_hint, (ch->rxq_len > 0));
    kchannel_hint_store(&ch->pollhup_hint, kchannel_endpoint_hup_locked(ch));
}

static inline void kchannel_pollout_hint_set(struct kchannel *ch, bool ready) {
    if (!ch)
        return;
    kchannel_hint_store(&ch->pollout_hint, ready);
}

static inline void kport_ready_hint_set_locked(struct kport *port) {
    if (!port)
        return;
    atomic_set(&port->ready_hint, list_empty(&port->queue) ? 0 : 1);
}

static uint32_t kchannel_poll_revents_locked(struct kchannel *ch,
                                             uint32_t events) {
    uint32_t revents = 0;
    if (!ch)
        return 0;

    if (ch->rxq_len > 0)
        revents |= POLLIN;
    if (kchannel_endpoint_hup_locked(ch))
        revents |= POLLHUP;

    if ((events & POLLOUT) && kchannel_send_open_locked(ch)) {
        if (!mutex_trylock(&ch->peer->lock)) {
            if (kchannel_hint_load(&ch->pollout_hint))
                revents |= POLLOUT;
        } else {
            if (ch->peer->rxq_len < KCHANNEL_MAX_QUEUE &&
                kchannel_peer_accepts_send_locked(ch->peer))
                revents |= POLLOUT;
            mutex_unlock(&ch->peer->lock);
        }
    }

    return revents;
}

static void kchannel_on_last_handle_release(struct kchannel *ch) {
    if (!ch)
        return;

    /* Keep channel lock ordering explicit: self->lock then peer->lock. */
    struct kchannel *peer = NULL;
    struct kport *bound = NULL;
    bool fi_close_extra_wake = false;
#if CONFIG_KERNEL_FAULT_INJECT
    fi_close_extra_wake =
        fault_inject_should_fail(FAULT_INJECT_POINT_IPC_CHANNEL_CLOSE);
#endif

    ipc_channel_lock(ch);
    if (ch->endpoint_state != KCHANNEL_ENDPOINT_OPEN) {
        ipc_channel_unlock(ch);
        return;
    }
    kchannel_endpoint_transition_locked(ch, KCHANNEL_ENDPOINT_CLOSING);
    peer = ch->peer;
    ch->peer = NULL;

    bound = ch->bind.port;
    ch->bind.port = NULL;
    ch->bind.key = 0;
    ch->bind.signals = 0;
    kchannel_endpoint_transition_locked(ch, KCHANNEL_ENDPOINT_CLOSED);
    __atomic_add_fetch(&ipc_channel_close_last_ref_total, 1, __ATOMIC_RELAXED);
    kchannel_trace_event(TRACE_IPC_CH_OP_CLOSE_LOCAL, TRACE_IPC_CH_WAKE_CLOSE, ch,
                         peer);
    kchannel_pollin_hup_hint_update_locked(ch);
    kchannel_pollout_hint_set(ch, false);
    __atomic_add_fetch(&ipc_channel_close_wake_local_total, 1, __ATOMIC_RELAXED);
    poll_wait_source_wake_all_reason(&ch->rd_src, 0, POLL_WAIT_WAKE_CLOSE);
    poll_wait_source_wake_all_reason(&ch->wr_src, 0, POLL_WAIT_WAKE_CLOSE);
    wait_queue_wakeup_all(&ch->obj.waitq);
    kchannel_poll_wake_locked(ch, POLLHUP);
    if (fi_close_extra_wake) {
        poll_wait_source_wake_all_reason(&ch->rd_src, 0, POLL_WAIT_WAKE_CLOSE);
        poll_wait_source_wake_all_reason(&ch->wr_src, 0, POLL_WAIT_WAKE_CLOSE);
        wait_queue_wakeup_all(&ch->obj.waitq);
    }
    ipc_channel_unlock(ch);

    if (bound)
        kobj_put(&bound->obj);

    if (!peer)
        return;

    bool dropped_peer_ref_to_ch = false;
    ipc_channel_lock(peer);
    if (peer->peer == ch) {
        peer->peer = NULL;
        dropped_peer_ref_to_ch = true;
    }
    peer->peer_closed = true;
    kchannel_trace_event(TRACE_IPC_CH_OP_CLOSE_PEER, TRACE_IPC_CH_WAKE_CLOSE,
                         peer, ch);
    kchannel_pollin_hup_hint_update_locked(peer);
    kchannel_pollout_hint_set(peer, false);
    __atomic_add_fetch(&ipc_channel_close_wake_peer_total, 1, __ATOMIC_RELAXED);
    poll_wait_source_wake_all_reason(&peer->rd_src, 0, POLL_WAIT_WAKE_CLOSE);
    poll_wait_source_wake_all_reason(&peer->wr_src, 0, POLL_WAIT_WAKE_CLOSE);
    wait_queue_wakeup_all(&peer->obj.waitq);
    kchannel_poll_wake_locked(peer, POLLHUP);
    if (fi_close_extra_wake) {
        poll_wait_source_wake_all_reason(&peer->rd_src, 0,
                                         POLL_WAIT_WAKE_CLOSE);
        poll_wait_source_wake_all_reason(&peer->wr_src, 0,
                                         POLL_WAIT_WAKE_CLOSE);
        wait_queue_wakeup_all(&peer->obj.waitq);
    }
    kchannel_emit_locked(peer, KPORT_BIND_PEER_CLOSED);
    ipc_channel_unlock(peer);

    kobj_put(&peer->obj);
    if (dropped_peer_ref_to_ch)
        kobj_put(&ch->obj);
}

static bool kchannel_atomic_dec_nonzero(atomic_t *counter, uint32_t *out_left) {
    if (!counter)
        return false;
    while (1) {
        uint32_t cur = atomic_read(counter);
        if (cur == 0)
            return false;
        uint32_t next = cur - 1U;
        if (atomic_cmpxchg(counter, &cur, next)) {
            if (out_left)
                *out_left = next;
            return true;
        }
    }
}

static void kchannel_endpoint_ref_inc_internal(
    struct kobj *obj, enum kchannel_endpoint_ref_owner owner) {
    struct kchannel *ch = kchannel_from_obj(obj);
    if (!ch)
        return;
    atomic_t *owner_refs = kchannel_owner_ref_counter(ch, owner);
    if (!owner_refs)
        owner_refs = &ch->endpoint_ref_other_count;
    atomic_inc(owner_refs);
    atomic_inc(&ch->handle_refs);
}

static bool kchannel_endpoint_ref_dec_internal(
    struct kobj *obj, enum kchannel_endpoint_ref_owner owner) {
    struct kchannel *ch = kchannel_from_obj(obj);
    if (!ch)
        return false;

    atomic_t *owner_refs = kchannel_owner_ref_counter(ch, owner);
    if (!owner_refs)
        owner_refs = &ch->endpoint_ref_other_count;

    uint32_t owner_left = 0;
    if (!kchannel_atomic_dec_nonzero(owner_refs, &owner_left)) {
        if (ipc_warn_ratelimited(&ipc_channel_ref_underflow_warn_count)) {
            pr_warn("ipc: endpoint ref underflow id=%u owner=%s\n", ch->obj.id,
                    kchannel_endpoint_ref_owner_name(owner));
        }
        return false;
    }

    uint32_t left = 0;
    if (!kchannel_atomic_dec_nonzero(&ch->handle_refs, &left)) {
        atomic_inc(owner_refs);
        if (ipc_warn_ratelimited(&ipc_channel_ref_underflow_warn_count)) {
            pr_warn("ipc: endpoint ref total underflow id=%u owner=%s owner_left=%u\n",
                    ch->obj.id, kchannel_endpoint_ref_owner_name(owner),
                    owner_left);
        }
        return false;
    }

    if (left == 0) {
        uint32_t owner_sum = atomic_read(&ch->endpoint_ref_handle_count) +
                             atomic_read(&ch->endpoint_ref_channelfd_count) +
                             atomic_read(&ch->endpoint_ref_other_count);
        if (owner_sum != 0 &&
            ipc_warn_ratelimited(&ipc_channel_ref_underflow_warn_count)) {
            pr_warn("ipc: endpoint ref accounting mismatch id=%u owner=%s owner_sum=%u\n",
                    ch->obj.id, kchannel_endpoint_ref_owner_name(owner),
                    owner_sum);
        }
        kchannel_on_last_handle_release(ch);
    }
    return true;
}

static void kobj_handle_ref_inc(struct kobj *obj) {
    kchannel_endpoint_ref_inc_internal(obj, KCHANNEL_ENDPOINT_REF_OWNER_HANDLE);
}

static void kobj_handle_ref_dec(struct kobj *obj) {
    (void)kchannel_endpoint_ref_dec_internal(obj,
                                             KCHANNEL_ENDPOINT_REF_OWNER_HANDLE);
}

void kchannel_endpoint_ref_inc_owner(struct kobj *obj,
                                     enum kchannel_endpoint_ref_owner owner) {
    kchannel_endpoint_ref_inc_internal(obj, owner);
}

void kchannel_endpoint_ref_dec_owner(struct kobj *obj,
                                     enum kchannel_endpoint_ref_owner owner) {
    (void)kchannel_endpoint_ref_dec_internal(obj, owner);
}

void kchannel_endpoint_ref_inc(struct kobj *obj) {
    /* Compatibility wrapper: prefer owner-explicit ref API. */
    kchannel_endpoint_ref_inc_owner(obj, KCHANNEL_ENDPOINT_REF_OWNER_OTHER);
}

void kchannel_endpoint_ref_dec(struct kobj *obj) {
    /* Compatibility wrapper: prefer owner-explicit ref API. */
    kchannel_endpoint_ref_dec_owner(obj, KCHANNEL_ENDPOINT_REF_OWNER_OTHER);
}

void kchannel_endpoint_ref_audit_obj(struct kobj *obj, const char *site,
                                     int32_t pid) {
    struct kchannel *ch = kchannel_from_obj(obj);
    if (!ch)
        return;
    kchannel_endpoint_ref_audit_channel(ch, site, pid);
}

void kchannel_endpoint_ref_audit_registry(const char *site, int32_t pid) {
    for (size_t i = 0;; i++) {
        uint32_t obj_id = 0;
        uint32_t type = 0;
        if (kobj_registry_get_nth(i, &obj_id, &type) < 0)
            break;
        if (type != KOBJ_TYPE_CHANNEL)
            continue;
        struct ipc_registry_obj_owner_pin pin = {0};
        if (!ipc_registry_pin_obj_owner_by_id(obj_id, &pin))
            continue;
        kchannel_endpoint_ref_audit_obj(pin.obj, site, pid);
        ipc_registry_unpin_obj_owner(&pin);
    }
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
    atomic_init(&obj->lifecycle, KOBJ_LIFECYCLE_INIT);
    memset(obj->refcount_hist, 0, sizeof(obj->refcount_hist));
    memset(obj->transfer_hist, 0, sizeof(obj->transfer_hist));
    obj->id = atomic_inc_return(&kobj_id_next);
    obj->type = type;
    obj->ops = ops;
    wait_queue_init(&obj->waitq);
    kobj_refcount_record(obj, KOBJ_REFCOUNT_INIT, 1);
}

void kobj_track_register(struct kobj *obj) {
    if (!obj)
        return;
    uint32_t expected = KOBJ_LIFECYCLE_INIT;
    if (!atomic_cmpxchg(&obj->lifecycle, &expected, KOBJ_LIFECYCLE_LIVE)) {
        kobj_lifecycle_warn_transition(
            obj, "kobj_track_register",
            (enum kobj_lifecycle_state)expected, KOBJ_LIFECYCLE_LIVE);
        return;
    }
    ipc_registry_register_obj(obj);
}

void kobj_get(struct kobj *obj) {
    if (!obj)
        return;
    enum kobj_lifecycle_state state = kobj_lifecycle_state_get(obj);
    if (state == KOBJ_LIFECYCLE_DYING || state == KOBJ_LIFECYCLE_FREED)
        kobj_lifecycle_warn_access(obj, "get", state);
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
    if (refcount == 0) {
        enum kobj_lifecycle_state state = kobj_lifecycle_state_get(obj);
        if (state == KOBJ_LIFECYCLE_LIVE) {
            atomic_set(&obj->lifecycle, KOBJ_LIFECYCLE_DETACHED);
            ipc_registry_unregister_obj(obj);
        } else if (state == KOBJ_LIFECYCLE_INIT) {
            atomic_set(&obj->lifecycle, KOBJ_LIFECYCLE_DETACHED);
        } else if (state != KOBJ_LIFECYCLE_DETACHED) {
            kobj_lifecycle_warn_transition(obj, "kobj_put:last_put", state,
                                           KOBJ_LIFECYCLE_DETACHED);
            atomic_set(&obj->lifecycle, KOBJ_LIFECYCLE_DETACHED);
        }
        atomic_set(&obj->lifecycle, KOBJ_LIFECYCLE_DYING);
        atomic_set(&obj->lifecycle, KOBJ_LIFECYCLE_FREED);
        if (obj->ops && obj->ops->release)
            obj->ops->release(obj);
    }
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
    kobj_lifecycle_check_access(obj, "read");
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
    kobj_lifecycle_check_access(obj, "write");
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
    kobj_lifecycle_check_access(obj, "wait");
    return obj->ops->wait(obj, out, timeout_ns, options);
}

int kobj_poll(struct kobj *obj, uint32_t events, uint32_t *out_revents) {
    if (!obj || !out_revents)
        return -EINVAL;
    kobj_lifecycle_check_access(obj, "poll");
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
    kobj_lifecycle_check_access(obj, "signal");
    if (!obj->ops || !obj->ops->signal)
        return -ENOTSUP;
    return obj->ops->signal(obj, signal, flags);
}

int kobj_poll_attach_vnode(struct kobj *obj, struct vnode *vn) {
    if (!obj || !vn)
        return -EINVAL;
    kobj_lifecycle_check_access(obj, "poll_attach_vnode");
    if (!obj->ops || !obj->ops->poll_attach_vnode)
        return -ENOTSUP;
    return obj->ops->poll_attach_vnode(obj, vn);
}

int kobj_poll_detach_vnode(struct kobj *obj, struct vnode *vn) {
    if (!obj || !vn)
        return -EINVAL;
    kobj_lifecycle_check_access(obj, "poll_detach_vnode");
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

int kobj_lookup_type_by_id(uint32_t obj_id, uint32_t *out_type) {
    if (!out_type || obj_id == 0)
        return -EINVAL;
    *out_type = 0;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    struct ipc_registry_entry *ent = ipc_registry_find_by_obj_id_locked(obj_id);
    if (ent && ent->obj)
        *out_type = ent->obj->type;
    ipc_registry_lock_leave();
    return *out_type ? 0 : -ENOENT;
}

int kobj_registry_get_nth(size_t index, uint32_t *out_id, uint32_t *out_type) {
    if (!out_id)
        return -EINVAL;
    *out_id = 0;
    if (out_type)
        *out_type = 0;

    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    size_t nth = 0;
    struct ipc_registry_entry *ent;
    list_for_each_entry(ent, &ipc_registry_all, all_node) {
        struct kobj *obj = ent->obj;
        if (!obj)
            continue;
        if (nth != index) {
            nth++;
            continue;
        }
        *out_id = obj->id;
        if (out_type)
            *out_type = obj->type;
        ipc_registry_lock_leave();
        return 0;
    }
    ipc_registry_lock_leave();
    return -ENOENT;
}

int kobj_transfer_history_page_by_id(
    uint32_t obj_id, uint32_t cursor, uint32_t page_size,
    struct kobj_transfer_history_entry *out, size_t out_cap,
    uint32_t *out_returned, uint32_t *out_next_cursor, bool *out_end,
    uint32_t *out_type) {
    if (!out_returned || !out_next_cursor || !out_end || !out_type ||
        page_size == 0 || obj_id == 0) {
        return -EINVAL;
    }

    *out_returned = 0;
    *out_next_cursor = cursor;
    *out_end = true;
    *out_type = 0;

    if (out_cap > 0 && !out)
        return -EINVAL;

    struct kobj *obj = NULL;
    ipc_registry_ensure_lock();
    ipc_registry_lock_enter();
    struct ipc_registry_entry *ent = ipc_registry_find_by_obj_id_locked(obj_id);
    if (ent && ent->obj) {
        obj = ent->obj;
        kobj_get(obj);
        *out_type = obj->type;
    }
    ipc_registry_lock_leave();

    if (!obj)
        return -ENOENT;

    struct kobj_transfer_history_entry hist[KOBJ_TRANSFER_HISTORY_DEPTH] = {0};
    size_t count =
        kobj_transfer_history_snapshot(obj, hist, KOBJ_TRANSFER_HISTORY_DEPTH);
    kobj_put(obj);

    uint32_t scanned = 0;
    uint32_t returned = 0;
    bool has_more = false;
    for (size_t i = 0; i < count; i++) {
        if (hist[i].seq == 0)
            continue;
        if (scanned < cursor) {
            scanned++;
            continue;
        }
        if (returned >= page_size) {
            has_more = true;
            break;
        }
        if (returned >= out_cap) {
            has_more = true;
            break;
        }
        out[returned++] = hist[i];
        scanned++;
    }

    uint64_t next_cursor64 = (uint64_t)cursor + (uint64_t)returned;
    if (next_cursor64 > 0xFFFFFFFFULL)
        next_cursor64 = 0xFFFFFFFFULL;

    *out_returned = returned;
    *out_next_cursor = (uint32_t)next_cursor64;
    *out_end = !has_more;
    return 0;
}

#define KHANDLE_CACHE_SLOTS 16U
_Static_assert((KHANDLE_CACHE_SLOTS & (KHANDLE_CACHE_SLOTS - 1U)) == 0,
               "KHANDLE_CACHE_SLOTS must be power-of-two");

struct kcap_node {
    struct list_head all_node;
    struct list_head hash_node;
    struct list_head sibling_node;
    struct list_head children;
    struct list_head retire_node;
    struct kcap_node *parent;
    uint32_t id;
    uint32_t generation;
    struct handletable *owner_ht;
    int32_t owner_handle;
    uint64_t revoke_epoch;
    uint64_t retire_after_ns;
    uint8_t state;
};

enum kcap_state {
    KCAP_STATE_LIVE = 1,
    KCAP_STATE_DETACHED = 2,
    KCAP_STATE_REVOKED = 3,
    KCAP_STATE_DEAD = 4,
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
    struct mutex lock;
    struct khandle_lookup_cache_entry slots[KHANDLE_CACHE_SLOTS];
};

#define KHANDLE_ENTRY_F_RESERVED_TRANSFER (1U << 0)
#define KHANDLE_RESERVED_TRANSFER_TIMEOUT_NS_DEFAULT (30ULL * 1000ULL * 1000ULL * 1000ULL)
#define KHANDLE_RESERVED_TRANSFER_TIMEOUT_NS_MIN     (10ULL * 1000ULL * 1000ULL)
#define KHANDLE_RESERVED_TRANSFER_SWEEP_INTERVAL_MIN_NS (50ULL * 1000ULL * 1000ULL)
#define KHANDLE_RESERVED_TRANSFER_SWEEP_INTERVAL_MAX_NS (1000ULL * 1000ULL * 1000ULL)
#define KHANDLE_RESERVED_TRANSFER_SWEEP_BUDGET_OPPORTUNISTIC 8U
#define KHANDLE_TABLE_LOCK_TIMEOUT_NS (2ULL * 1000ULL * 1000ULL * 1000ULL)
#define KHANDLE_TABLE_LOCK_TIMEOUT_FAST_NS (5ULL * 1000ULL * 1000ULL)
#define KHANDLE_RESERVED_TRANSFER_DEFERRED_DRAIN_BATCH 8U
#define KHANDLE_RESERVED_TRANSFER_DEFERRED_DRAIN_SAFEPOINT_BUDGET 16U
#define KHANDLE_DEFERRED_FREE_DELAY_NS (100ULL * 1000ULL * 1000ULL)

static LIST_HEAD(kcap_nodes);
#define KCAP_ID_HASH_BITS 10U
KHASH_DECLARE(kcap_id_hash, KCAP_ID_HASH_BITS);
static bool kcap_id_hash_ready;
static spinlock_t kcap_lock = SPINLOCK_INIT;
static uint32_t kcap_next_id = 1;
static uint32_t kcap_next_generation = 1;
static uint64_t kcap_revoke_epoch_next = 1;
static uint64_t khandle_cache_epoch_next = 1;
static uint64_t khandle_transfer_token_next = 1;
static uint64_t khandle_reserved_transfer_timeout_ns =
    KHANDLE_RESERVED_TRANSFER_TIMEOUT_NS_DEFAULT;
static bool khandle_cache_locks_ready;
static spinlock_t khandle_cache_init_lock = SPINLOCK_INIT;
static struct khandle_lookup_cache_cpu
    khandle_lookup_cache[CONFIG_MAX_CPUS];
static uint64_t khandle_cache_lookups_total;
static uint64_t khandle_cache_hits_total;
static uint64_t khandle_cache_misses_total;
static uint64_t khandle_cache_stores_total;
static uint64_t khandle_cache_slot_invalidate_calls_total;
static uint64_t khandle_cache_invalidated_slots_total;
static uint64_t khandle_cache_released_refs_total;
static uint64_t khandle_cache_ht_sweeps_total;
static LIST_HEAD(khandle_retired_tables);
static LIST_HEAD(kcap_retired_nodes);
static spinlock_t kcap_retire_lock = SPINLOCK_INIT;

static uint64_t kcap_make_cap_id(uint32_t id, uint32_t generation) {
    if (id == 0 || generation == 0)
        return KHANDLE_INVALID_CAP_ID;
    return ((uint64_t)generation << 32) | (uint64_t)id;
}

static uint32_t kcap_cap_id_id(uint64_t cap_id) {
    return (uint32_t)cap_id;
}

static uint32_t kcap_cap_id_generation(uint64_t cap_id) {
    return (uint32_t)(cap_id >> 32);
}

static uint64_t kcap_node_cap_id(const struct kcap_node *node) {
    if (!node)
        return KHANDLE_INVALID_CAP_ID;
    return kcap_make_cap_id(node->id, node->generation);
}

static uint32_t kcap_alloc_numeric_id(void) {
    uint32_t id = __atomic_fetch_add(&kcap_next_id, 1, __ATOMIC_RELAXED);
    if (id == 0)
        id = __atomic_fetch_add(&kcap_next_id, 1, __ATOMIC_RELAXED);
    if (id == 0)
        id = 1;
    return id;
}

static uint32_t kcap_alloc_generation(void) {
    uint32_t generation =
        __atomic_fetch_add(&kcap_next_generation, 1, __ATOMIC_RELAXED);
    if (generation == 0)
        generation =
            __atomic_fetch_add(&kcap_next_generation, 1, __ATOMIC_RELAXED);
    if (generation == 0)
        generation = 1;
    return generation;
}

static uint64_t kcap_alloc_revoke_epoch(void) {
    uint64_t epoch =
        __atomic_fetch_add(&kcap_revoke_epoch_next, 1, __ATOMIC_RELAXED);
    if (epoch == 0)
        epoch = __atomic_fetch_add(&kcap_revoke_epoch_next, 1, __ATOMIC_RELAXED);
    if (epoch == 0)
        epoch = 1;
    return epoch;
}

static uint64_t khandle_alloc_cache_epoch(void) {
    return __atomic_fetch_add(&khandle_cache_epoch_next, 1,
                              __ATOMIC_RELAXED);
}

static uint64_t khandle_alloc_transfer_token(void) {
    return __atomic_fetch_add(&khandle_transfer_token_next, 1,
                              __ATOMIC_RELAXED);
}

static const char *kcap_state_name(uint8_t state) {
    switch ((enum kcap_state)state) {
    case KCAP_STATE_LIVE:
        return "LIVE";
    case KCAP_STATE_DETACHED:
        return "DETACHED";
    case KCAP_STATE_REVOKED:
        return "REVOKED";
    case KCAP_STATE_DEAD:
        return "DEAD";
    default:
        return "UNKNOWN";
    }
}

static bool kcap_state_can_transition(uint8_t from, uint8_t to) {
    if (from == to)
        return true;
    switch ((enum kcap_state)from) {
    case KCAP_STATE_LIVE:
        return to == KCAP_STATE_DETACHED || to == KCAP_STATE_REVOKED;
    case KCAP_STATE_DETACHED:
        return to == KCAP_STATE_LIVE || to == KCAP_STATE_REVOKED ||
               to == KCAP_STATE_DEAD;
    case KCAP_STATE_REVOKED:
        return to == KCAP_STATE_DEAD;
    case KCAP_STATE_DEAD:
    default:
        return false;
    }
}

static void kcap_transition_locked(struct kcap_node *node, uint8_t to_state) {
    if (!node)
        return;
    uint8_t from_state = node->state;
    if (!kcap_state_can_transition(from_state, to_state)) {
        panic("kcap invalid state transition %s -> %s",
              kcap_state_name(from_state), kcap_state_name(to_state));
    }
    node->state = to_state;
}

static bool kcap_node_is_attached_locked(const struct kcap_node *node) {
    if (!node)
        return false;
    return node->owner_ht != NULL;
}

static void kcap_node_validate_locked(const struct kcap_node *node) {
    if (!node)
        return;
    ASSERT(node->id != 0);
    ASSERT(node->generation != 0);
    if (node->state == KCAP_STATE_LIVE) {
        ASSERT(node->owner_ht != NULL);
        ASSERT(node->owner_handle >= 0);
        ASSERT(node->owner_handle < CONFIG_MAX_HANDLES_PER_PROC);
        ASSERT(node->revoke_epoch == 0);
        return;
    }
    if (node->state == KCAP_STATE_DETACHED || node->state == KCAP_STATE_DEAD) {
        ASSERT(node->owner_ht == NULL);
        ASSERT(node->owner_handle == -1);
        ASSERT(node->revoke_epoch == 0 || node->state == KCAP_STATE_DEAD);
        return;
    }
    ASSERT(node->state == KCAP_STATE_REVOKED);
    ASSERT(node->revoke_epoch != 0);
    if (!node->owner_ht) {
        ASSERT(node->owner_handle == -1);
        return;
    }
    ASSERT(node->owner_handle >= 0);
    ASSERT(node->owner_handle < CONFIG_MAX_HANDLES_PER_PROC);
}

static uint32_t khandle_slot_generation_next(uint32_t generation) {
    generation++;
    if (generation == 0)
        generation = 1;
    return generation;
}

static void khandle_slot_generation_bump(struct khandle_entry *entry) {
    if (!entry)
        return;
    entry->slot_generation = khandle_slot_generation_next(entry->slot_generation);
}

static uint64_t khandle_u64_add_sat(uint64_t lhs, uint64_t rhs) {
    uint64_t out = 0;
    if (__builtin_add_overflow(lhs, rhs, &out))
        return UINT64_MAX;
    return out;
}

static uint64_t khandle_ns_to_sched_ticks(uint64_t ns) {
    const uint64_t ns_per_sec = 1000000000ULL;
    if (ns == 0)
        return 1;
    if (ns > UINT64_MAX / CONFIG_HZ)
        return UINT64_MAX;
    uint64_t scaled = ns * CONFIG_HZ;
    uint64_t rounded = khandle_u64_add_sat(scaled, ns_per_sec - 1ULL);
    uint64_t ticks = rounded / ns_per_sec;
    return ticks ? ticks : 1;
}

static int khandle_table_lock_bounded(struct handletable *ht,
                                      uint64_t timeout_ns) {
    if (!ht)
        return -EINVAL;
    uint64_t timeout_ticks = khandle_ns_to_sched_ticks(timeout_ns);
    int rc = -ETIMEDOUT;
    bool can_sleep = proc_current() && arch_irq_enabled() && !in_atomic();

    if (can_sleep) {
        rc = mutex_lock_timeout(&ht->lock, timeout_ticks);
        if (rc == 0)
            return 0;
    } else {
        uint64_t deadline_ns = khandle_u64_add_sat(time_now_ns(), timeout_ns);
        while (time_now_ns() < deadline_ns) {
            if (mutex_trylock(&ht->lock))
                return 0;
            arch_cpu_relax();
        }
    }
    struct process *curr = proc_current();
    struct process *holder = ht->lock.holder;
    pr_warn("ipc: handletable lock timeout ht=%p curr_pid=%d holder_pid=%d "
            "irq=%u atomic=%u\n",
            (void *)ht, curr ? curr->pid : -1, holder ? holder->pid : -1,
            arch_irq_enabled() ? 1U : 0U, in_atomic() ? 1U : 0U);
    return (rc < 0) ? rc : -ETIMEDOUT;
}

static bool khandle_table_lock_quiet(struct handletable *ht,
                                     uint64_t timeout_ns) {
    if (!ht)
        return false;
    uint64_t timeout_ticks = khandle_ns_to_sched_ticks(timeout_ns);
    bool can_sleep = proc_current() && arch_irq_enabled() && !in_atomic();

    if (can_sleep) {
        return mutex_lock_timeout(&ht->lock, timeout_ticks) == 0;
    }

    uint64_t deadline_ns = khandle_u64_add_sat(time_now_ns(), timeout_ns);
    while (time_now_ns() < deadline_ns) {
        if (mutex_trylock(&ht->lock))
            return true;
        arch_cpu_relax();
    }
    return false;
}

static uint64_t khandle_deferred_retire_after_ns(void) {
    return khandle_u64_add_sat(time_now_ns(), KHANDLE_DEFERRED_FREE_DELAY_NS);
}

static void khandle_reclaim_deferred(void) {
    LIST_HEAD(free_tables);
    LIST_HEAD(free_nodes);
    uint64_t now_ns = time_now_ns();
    bool irq_flags;
    spin_lock_irqsave(&kcap_retire_lock, &irq_flags);
    while (!list_empty(&khandle_retired_tables)) {
        struct handletable *ht = list_first_entry(
            &khandle_retired_tables, struct handletable, retire_node);
        if (ht->retire_after_ns > now_ns)
            break;
        list_del(&ht->retire_node);
        list_add_tail(&ht->retire_node, &free_tables);
    }
    while (!list_empty(&kcap_retired_nodes)) {
        struct kcap_node *node =
            list_first_entry(&kcap_retired_nodes, struct kcap_node, retire_node);
        if (node->retire_after_ns > now_ns)
            break;
        list_del(&node->retire_node);
        list_add_tail(&node->retire_node, &free_nodes);
    }
    spin_unlock_irqrestore(&kcap_retire_lock, irq_flags);

    struct list_head *pos = NULL;
    struct list_head *tmp = NULL;
    list_for_each_safe(pos, tmp, &free_tables) {
        struct handletable *ht = list_entry(pos, struct handletable, retire_node);
        list_del(&ht->retire_node);
        kfree(ht);
    }

    list_for_each_safe(pos, tmp, &free_nodes) {
        struct kcap_node *node = list_entry(pos, struct kcap_node, retire_node);
        list_del(&node->retire_node);
        kfree(node);
    }
}

static void khandle_retire_table_deferred(struct handletable *ht) {
    if (!ht)
        return;
    ht->retire_after_ns = khandle_deferred_retire_after_ns();
    bool irq_flags;
    spin_lock_irqsave(&kcap_retire_lock, &irq_flags);
    list_add_tail(&ht->retire_node, &khandle_retired_tables);
    spin_unlock_irqrestore(&kcap_retire_lock, irq_flags);
}

static void kcap_retire_node_deferred(struct kcap_node *node) {
    if (!node)
        return;
    node->retire_after_ns = khandle_deferred_retire_after_ns();
    bool irq_flags;
    spin_lock_irqsave(&kcap_retire_lock, &irq_flags);
    list_add_tail(&node->retire_node, &kcap_retired_nodes);
    spin_unlock_irqrestore(&kcap_retire_lock, irq_flags);
}

static uint64_t khandle_reserved_timeout_ns(void) {
    uint64_t timeout =
        __atomic_load_n(&khandle_reserved_transfer_timeout_ns, __ATOMIC_ACQUIRE);
    if (timeout < KHANDLE_RESERVED_TRANSFER_TIMEOUT_NS_MIN)
        timeout = KHANDLE_RESERVED_TRANSFER_TIMEOUT_NS_MIN;
    return timeout;
}

static uint64_t khandle_reserved_sweep_interval_ns(uint64_t timeout_ns) {
    uint64_t interval = timeout_ns / 4ULL;
    if (interval < KHANDLE_RESERVED_TRANSFER_SWEEP_INTERVAL_MIN_NS)
        interval = KHANDLE_RESERVED_TRANSFER_SWEEP_INTERVAL_MIN_NS;
    if (interval > KHANDLE_RESERVED_TRANSFER_SWEEP_INTERVAL_MAX_NS)
        interval = KHANDLE_RESERVED_TRANSFER_SWEEP_INTERVAL_MAX_NS;
    return interval;
}

static uint64_t khandle_reserved_deadline_ns(uint64_t now_ns) {
    return khandle_u64_add_sat(now_ns, khandle_reserved_timeout_ns());
}

static bool khandle_reserved_entry_expired(const struct khandle_entry *entry,
                                           uint64_t now_ns) {
    if (!entry || !entry->obj)
        return false;
    if ((entry->flags & KHANDLE_ENTRY_F_RESERVED_TRANSFER) == 0)
        return false;
    if (entry->reserved_deadline_ns == 0)
        return false;
    return now_ns >= entry->reserved_deadline_ns;
}

static uint32_t khandle_reserved_deferred_next_idx(uint32_t idx) {
    idx++;
    if (idx >= CONFIG_MAX_HANDLES_PER_PROC)
        idx = 0;
    return idx;
}

static bool khandle_reserved_deferred_enqueue_locked(
    struct handletable *ht, struct kobj *obj, uint32_t rights, uint64_t cap_id) {
    if (!ht || !obj)
        return false;
    if (ht->reserved_drop_count >= CONFIG_MAX_HANDLES_PER_PROC)
        return false;

    uint32_t tail = ht->reserved_drop_tail;
    ht->reserved_drop_q[tail].obj = obj;
    ht->reserved_drop_q[tail].rights = rights;
    ht->reserved_drop_q[tail].cap_id = cap_id;
    ht->reserved_drop_tail = khandle_reserved_deferred_next_idx(tail);
    ht->reserved_drop_count++;
    return true;
}

static bool khandle_reserved_deferred_dequeue_locked(
    struct handletable *ht, struct khandle_deferred_drop *out) {
    if (!ht || !out || ht->reserved_drop_count == 0)
        return false;

    uint32_t head = ht->reserved_drop_head;
    *out = ht->reserved_drop_q[head];
    ht->reserved_drop_q[head].obj = NULL;
    ht->reserved_drop_q[head].rights = 0;
    ht->reserved_drop_q[head].cap_id = KHANDLE_INVALID_CAP_ID;
    ht->reserved_drop_head = khandle_reserved_deferred_next_idx(head);
    ht->reserved_drop_count--;
    return true;
}

static uint32_t khandle_reserved_detach_expired_locked(struct handletable *ht,
                                                       uint64_t now_ns,
                                                       uint32_t budget) {
    if (!ht)
        return 0;
    if (budget == 0 || budget > CONFIG_MAX_HANDLES_PER_PROC)
        budget = CONFIG_MAX_HANDLES_PER_PROC;

    uint32_t detached = 0;
    for (int i = 0; i < CONFIG_MAX_HANDLES_PER_PROC; i++) {
        if (detached >= budget)
            break;

        struct khandle_entry *entry = &ht->entries[i];
        if (!khandle_reserved_entry_expired(entry, now_ns))
            continue;
        if (!khandle_reserved_deferred_enqueue_locked(ht, entry->obj,
                                                      entry->rights,
                                                      entry->cap_id)) {
            break;
        }

        entry->obj = NULL;
        entry->rights = 0;
        entry->cap_id = KHANDLE_INVALID_CAP_ID;
        entry->flags = 0;
        khandle_slot_generation_bump(entry);
        entry->transfer_token = KHANDLE_INVALID_CAP_ID;
        entry->cap_revoke_epoch = 0;
        entry->reserved_deadline_ns = 0;
        atomic_inc(&ht->seq);
        detached++;
    }
    return detached;
}

static void khandle_reserved_transfer_sweep(struct handletable *ht, bool force) {
    if (!ht)
        return;
    uint64_t now_ns = time_now_ns();
    uint64_t timeout_ns = khandle_reserved_timeout_ns();
    uint64_t sweep_interval_ns = khandle_reserved_sweep_interval_ns(timeout_ns);
    if (force) {
        if (khandle_table_lock_bounded(ht, KHANDLE_TABLE_LOCK_TIMEOUT_NS) < 0) {
            pr_warn("ipc: reserved sweep lock timeout ht=%p force=%u\n",
                    (void *)ht, force ? 1U : 0U);
            return;
        }
    } else {
        if (!khandle_table_lock_quiet(ht, KHANDLE_TABLE_LOCK_TIMEOUT_FAST_NS))
            return;
    }

    if (!force && ht->reserved_sweep_after_ns != 0 &&
        now_ns < ht->reserved_sweep_after_ns) {
        mutex_unlock(&ht->lock);
        return;
    }
    ht->reserved_sweep_after_ns = khandle_u64_add_sat(now_ns, sweep_interval_ns);
    uint32_t budget = force ? CONFIG_MAX_HANDLES_PER_PROC
                            : KHANDLE_RESERVED_TRANSFER_SWEEP_BUDGET_OPPORTUNISTIC;
    (void)khandle_reserved_detach_expired_locked(ht, now_ns, budget);
    mutex_unlock(&ht->lock);
}

static uint32_t khandle_reserved_transfer_drain_deferred(struct handletable *ht,
                                                         uint32_t budget,
                                                         bool force) {
    if (!ht || budget == 0)
        return 0;

    uint32_t drained = 0;
    while (drained < budget) {
        uint32_t batch_cap = KHANDLE_RESERVED_TRANSFER_DEFERRED_DRAIN_BATCH;
        uint32_t remain = budget - drained;
        if (remain < batch_cap)
            batch_cap = remain;

        bool locked = force ? (khandle_table_lock_bounded(
                                   ht, KHANDLE_TABLE_LOCK_TIMEOUT_NS) == 0)
                            : khandle_table_lock_quiet(
                                  ht, KHANDLE_TABLE_LOCK_TIMEOUT_FAST_NS);
        if (!locked)
            break;

        struct khandle_deferred_drop
            dropped[KHANDLE_RESERVED_TRANSFER_DEFERRED_DRAIN_BATCH];
        uint32_t popped = 0;
        while (popped < batch_cap &&
               khandle_reserved_deferred_dequeue_locked(ht, &dropped[popped])) {
            popped++;
        }
        bool empty = (ht->reserved_drop_count == 0);
        mutex_unlock(&ht->lock);

        if (popped == 0)
            break;

        for (uint32_t i = 0; i < popped; i++) {
            khandle_transfer_drop_cap(dropped[i].obj, dropped[i].rights,
                                      dropped[i].cap_id);
        }
        drained += popped;
        if (empty)
            break;
    }
    return drained;
}

static void khandle_reserved_transfer_drain_safepoint(struct handletable *ht) {
    (void)khandle_reserved_transfer_drain_deferred(
        ht, KHANDLE_RESERVED_TRANSFER_DEFERRED_DRAIN_SAFEPOINT_BUDGET, false);
}

#if CONFIG_KERNEL_TESTS
void khandle_test_set_reserved_transfer_timeout_ns(uint64_t timeout_ns) {
    if (timeout_ns < KHANDLE_RESERVED_TRANSFER_TIMEOUT_NS_MIN)
        timeout_ns = KHANDLE_RESERVED_TRANSFER_TIMEOUT_NS_MIN;
    __atomic_store_n(&khandle_reserved_transfer_timeout_ns, timeout_ns,
                     __ATOMIC_RELEASE);
}

void khandle_test_reset_reserved_transfer_timeout_ns(void) {
    __atomic_store_n(&khandle_reserved_transfer_timeout_ns,
                     KHANDLE_RESERVED_TRANSFER_TIMEOUT_NS_DEFAULT,
                     __ATOMIC_RELEASE);
}
#endif

static void kcap_hash_ensure_locked(void) {
    if (kcap_id_hash_ready)
        return;
    KHASH_INIT(kcap_id_hash);
    kcap_id_hash_ready = true;
}

static void kcap_hash_insert_locked(struct kcap_node *node) {
    if (!node || !kcap_id_hash_ready)
        return;
    khash_add(kcap_id_hash, &node->hash_node, kcap_node_cap_id(node));
}

static void kcap_hash_remove_locked(struct kcap_node *node) {
    if (!node || list_empty(&node->hash_node))
        return;
    khash_del(&node->hash_node);
}

static struct kcap_node *kcap_find_locked(uint64_t cap_id) {
    if (cap_id == KHANDLE_INVALID_CAP_ID || !kcap_id_hash_ready)
        return NULL;
    uint32_t want_id = kcap_cap_id_id(cap_id);
    uint32_t want_generation = kcap_cap_id_generation(cap_id);
    if (want_id == 0 || want_generation == 0)
        return NULL;
    struct kcap_node *node;
    khash_for_each_possible(kcap_id_hash, node, hash_node, cap_id) {
        if (node->id == want_id && node->generation == want_generation)
            return node;
    }
    return NULL;
}

static void kcap_hash_stats_snapshot(struct khash_stats *out_stats,
                                     bool *out_ready) {
    if (out_stats)
        memset(out_stats, 0, sizeof(*out_stats));
    if (out_ready)
        *out_ready = false;

    spin_lock(&kcap_lock);
    bool ready = kcap_id_hash_ready;
    if (out_ready)
        *out_ready = ready;
    if (ready && out_stats)
        KHASH_STATS(kcap_id_hash, out_stats);
    spin_unlock(&kcap_lock);
}

static void kcap_free_nodes(struct list_head *free_nodes) {
    struct list_head *pos = NULL;
    struct list_head *tmp = NULL;
    list_for_each_safe(pos, tmp, free_nodes) {
        struct kcap_node *node = list_entry(pos, struct kcap_node, all_node);
        list_del(&node->all_node);
        kcap_retire_node_deferred(node);
    }
    khandle_reclaim_deferred();
}

static void kcap_prune_locked(struct kcap_node *node,
                              struct list_head *free_nodes) {
    while (node && !kcap_node_is_attached_locked(node) &&
           list_empty(&node->children) &&
           (node->state == KCAP_STATE_DETACHED ||
            node->state == KCAP_STATE_REVOKED)) {
        struct kcap_node *parent = node->parent;
        if (parent)
            list_del(&node->sibling_node);
        kcap_transition_locked(node, KCAP_STATE_DEAD);
        kcap_hash_remove_locked(node);
        list_del(&node->all_node);
        list_add(&node->all_node, free_nodes);
        node = parent;
    }
}

static int kcap_create(uint64_t parent_cap_id, struct handletable *owner_ht,
                       int32_t owner_handle, uint64_t *out_cap_id) {
    if (!out_cap_id)
        return -EINVAL;
    *out_cap_id = KHANDLE_INVALID_CAP_ID;

    struct kcap_node *node = kzalloc(sizeof(*node));
    if (!node)
        return -ENOMEM;

    INIT_LIST_HEAD(&node->all_node);
    INIT_LIST_HEAD(&node->hash_node);
    INIT_LIST_HEAD(&node->sibling_node);
    INIT_LIST_HEAD(&node->children);
    INIT_LIST_HEAD(&node->retire_node);
    node->owner_ht = owner_ht;
    node->owner_handle = owner_handle;
    node->revoke_epoch = 0;
    node->state = KCAP_STATE_LIVE;
    kcap_node_validate_locked(node);

    spin_lock(&kcap_lock);
    kcap_hash_ensure_locked();
    if (parent_cap_id != KHANDLE_INVALID_CAP_ID) {
        struct kcap_node *parent = kcap_find_locked(parent_cap_id);
        if (!parent) {
            spin_unlock(&kcap_lock);
            kfree(node);
            return -ENOENT;
        }
        if (parent->state == KCAP_STATE_REVOKED) {
            spin_unlock(&kcap_lock);
            kfree(node);
            return -EACCES;
        }
        if (parent->revoke_epoch != 0) {
            spin_unlock(&kcap_lock);
            kfree(node);
            return -EACCES;
        }
        if (parent->state != KCAP_STATE_LIVE) {
            spin_unlock(&kcap_lock);
            kfree(node);
            return -EAGAIN;
        }
        node->parent = parent;
        node->revoke_epoch = parent->revoke_epoch;
        list_add_tail(&node->sibling_node, &parent->children);
    }
    node->id = kcap_alloc_numeric_id();
    node->generation = kcap_alloc_generation();
    list_add_tail(&node->all_node, &kcap_nodes);
    kcap_hash_insert_locked(node);
    spin_unlock(&kcap_lock);
    *out_cap_id = kcap_node_cap_id(node);
    return 0;
}

static int kcap_bind_existing(uint64_t cap_id, struct handletable *owner_ht,
                              int32_t owner_handle) {
    if (cap_id == KHANDLE_INVALID_CAP_ID)
        return -EINVAL;

    spin_lock(&kcap_lock);
    kcap_hash_ensure_locked();
    struct kcap_node *node = kcap_find_locked(cap_id);
    if (!node) {
        spin_unlock(&kcap_lock);
        return -ENOENT;
    }
    kcap_node_validate_locked(node);
    if (node->state == KCAP_STATE_LIVE) {
        spin_unlock(&kcap_lock);
        return -EBUSY;
    }
    if (node->state == KCAP_STATE_REVOKED) {
        ipc_stat_inc_u64(&ipc_cap_bind_rejected_revoked_total);
        kcap_trace_event(TRACE_IPC_CAP_OP_BIND_REJECTED_REVOKED, cap_id, 1);
        spin_unlock(&kcap_lock);
        return -EACCES;
    }
    if (node->revoke_epoch != 0) {
        ipc_stat_inc_u64(&ipc_cap_bind_rejected_revoked_total);
        kcap_trace_event(TRACE_IPC_CAP_OP_BIND_REJECTED_REVOKED, cap_id, 2);
        spin_unlock(&kcap_lock);
        return -EACCES;
    }
    if (node->state != KCAP_STATE_DETACHED) {
        spin_unlock(&kcap_lock);
        return -EAGAIN;
    }
    node->owner_ht = owner_ht;
    node->owner_handle = owner_handle;
    kcap_transition_locked(node, KCAP_STATE_LIVE);
    kcap_node_validate_locked(node);
    spin_unlock(&kcap_lock);
    return 0;
}

static void kcap_detach_owner(uint64_t cap_id, struct handletable *owner_ht,
                              int32_t owner_handle, bool retain_node) {
    if (cap_id == KHANDLE_INVALID_CAP_ID)
        return;

    LIST_HEAD(free_nodes);
    spin_lock(&kcap_lock);
    kcap_hash_ensure_locked();
    struct kcap_node *node = kcap_find_locked(cap_id);
    if (node && kcap_node_is_attached_locked(node) && node->owner_ht == owner_ht &&
        node->owner_handle == owner_handle) {
        kcap_node_validate_locked(node);
        node->owner_ht = NULL;
        node->owner_handle = -1;
        if (node->state == KCAP_STATE_LIVE)
            kcap_transition_locked(node, KCAP_STATE_DETACHED);
        kcap_node_validate_locked(node);
        if (!retain_node)
            kcap_prune_locked(node, &free_nodes);
    }
    spin_unlock(&kcap_lock);
    kcap_free_nodes(&free_nodes);
}

static void kcap_drop_detached(uint64_t cap_id) {
    if (cap_id == KHANDLE_INVALID_CAP_ID)
        return;

    const uint64_t spin_timeout_ns = 2ULL * 1000ULL * 1000ULL;
    uint64_t deadline_ns = khandle_u64_add_sat(time_now_ns(), spin_timeout_ns);
    LIST_HEAD(free_nodes);
    while (!spin_trylock(&kcap_lock)) {
        if (time_now_ns() >= deadline_ns) {
            pr_warn("ipc: kcap_drop_detached lock timeout cap=%llu\n",
                    (unsigned long long)cap_id);
            return;
        }
        arch_cpu_relax();
    }
    kcap_hash_ensure_locked();
    struct kcap_node *node = kcap_find_locked(cap_id);
    if (node && !kcap_node_is_attached_locked(node))
        kcap_prune_locked(node, &free_nodes);
    spin_unlock(&kcap_lock);
    kcap_free_nodes(&free_nodes);
}

static bool kcap_is_descendant_of_locked(const struct kcap_node *node,
                                         const struct kcap_node *ancestor) {
    if (!node || !ancestor)
        return false;
    const struct kcap_node *cursor = node->parent;
    while (cursor) {
        if (cursor == ancestor)
            return true;
        cursor = cursor->parent;
    }
    return false;
}

static void kcap_mark_subtree_revoked_locked(struct kcap_node *root,
                                             bool include_root,
                                             uint64_t revoke_epoch) {
    if (!root)
        return;

    uint64_t root_cap_id = kcap_node_cap_id(root);
    struct kcap_node *node = NULL;
    list_for_each_entry(node, &kcap_nodes, all_node) {
        if (node == root) {
            if (include_root) {
                bool changed =
                    node->state != KCAP_STATE_REVOKED ||
                    node->revoke_epoch != revoke_epoch;
                if (node->state != KCAP_STATE_REVOKED)
                    kcap_transition_locked(node, KCAP_STATE_REVOKED);
                node->revoke_epoch = revoke_epoch;
                kcap_node_validate_locked(node);
                if (changed) {
                    ipc_stat_inc_u64(&ipc_cap_revoke_marked_total);
                    kcap_trace_event(TRACE_IPC_CAP_OP_REVOKE_MARKED,
                                     kcap_node_cap_id(node), root_cap_id);
                }
            }
            continue;
        }
        if (kcap_is_descendant_of_locked(node, root)) {
            bool changed =
                node->state != KCAP_STATE_REVOKED ||
                node->revoke_epoch != revoke_epoch;
            if (node->state != KCAP_STATE_REVOKED)
                kcap_transition_locked(node, KCAP_STATE_REVOKED);
            node->revoke_epoch = revoke_epoch;
            kcap_node_validate_locked(node);
            if (changed) {
                ipc_stat_inc_u64(&ipc_cap_revoke_marked_total);
                kcap_trace_event(TRACE_IPC_CAP_OP_REVOKE_MARKED,
                                 kcap_node_cap_id(node), root_cap_id);
            }
        }
    }
}

static int kcap_mark_subtree_revoked(uint64_t root_cap_id, bool include_root) {
    spin_lock(&kcap_lock);
    kcap_hash_ensure_locked();
    struct kcap_node *root = kcap_find_locked(root_cap_id);
    if (!root) {
        spin_unlock(&kcap_lock);
        return -ENOENT;
    }
    uint64_t revoke_epoch = kcap_alloc_revoke_epoch();
    kcap_mark_subtree_revoked_locked(root, include_root, revoke_epoch);
    spin_unlock(&kcap_lock);
    return 0;
}

static uint64_t kcap_revoke_epoch_snapshot(uint64_t cap_id) {
    if (cap_id == KHANDLE_INVALID_CAP_ID)
        return 0;

    uint64_t epoch = 0;
    spin_lock(&kcap_lock);
    kcap_hash_ensure_locked();
    struct kcap_node *node = kcap_find_locked(cap_id);
    if (node)
        epoch = node->revoke_epoch;
    spin_unlock(&kcap_lock);
    return epoch;
}

static bool kcap_transfer_commit_epoch_matches(uint64_t cap_id,
                                               uint64_t expected_epoch) {
    if (cap_id == KHANDLE_INVALID_CAP_ID)
        return true;

    bool matched = false;
    spin_lock(&kcap_lock);
    kcap_hash_ensure_locked();
    struct kcap_node *node = kcap_find_locked(cap_id);
    if (node)
        matched = node->revoke_epoch == expected_epoch;
    spin_unlock(&kcap_lock);
    return matched;
}

static int kcap_pick_revoked_descendant(uint64_t root_cap_id,
                                        struct handletable **out_ht,
                                        int32_t *out_handle,
                                        uint64_t *out_cap_id) {
    if (!out_ht || !out_handle || !out_cap_id)
        return -EINVAL;
    *out_ht = NULL;
    *out_handle = -1;
    *out_cap_id = KHANDLE_INVALID_CAP_ID;

    spin_lock(&kcap_lock);
    kcap_hash_ensure_locked();
    struct kcap_node *root = kcap_find_locked(root_cap_id);
    if (!root) {
        spin_unlock(&kcap_lock);
        return -ENOENT;
    }
    struct kcap_node *node = NULL;
    list_for_each_entry(node, &kcap_nodes, all_node) {
        if (node->state != KCAP_STATE_REVOKED || !node->owner_ht)
            continue;
        if (node->owner_handle < 0 ||
            node->owner_handle >= CONFIG_MAX_HANDLES_PER_PROC) {
            continue;
        }
        if (!kcap_is_descendant_of_locked(node, root))
            continue;
        if (!handletable_tryget(node->owner_ht)) {
            ipc_stat_inc_u64(&ipc_cap_tryget_failed_total);
            kcap_trace_event(TRACE_IPC_CAP_OP_TRYGET_FAILED,
                             kcap_node_cap_id(node), root_cap_id);
            continue;
        }

        *out_ht = node->owner_ht;
        *out_handle = node->owner_handle;
        *out_cap_id = kcap_node_cap_id(node);
        spin_unlock(&kcap_lock);
        return 0;
    }
    spin_unlock(&kcap_lock);
    return -ENOENT;
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

static void khandle_cache_ensure_ready(void) {
    if (__atomic_load_n(&khandle_cache_locks_ready, __ATOMIC_ACQUIRE))
        return;

    bool irq_flags;
    spin_lock_irqsave(&khandle_cache_init_lock, &irq_flags);
    if (!khandle_cache_locks_ready) {
        for (int cpu = 0; cpu < CONFIG_MAX_CPUS; cpu++)
            mutex_init(&khandle_lookup_cache[cpu].lock, "khandle_cache");
        __atomic_store_n(&khandle_cache_locks_ready, true, __ATOMIC_RELEASE);
    }
    spin_unlock_irqrestore(&khandle_cache_init_lock, irq_flags);
}

static int khandle_cache_cpu_index(void) {
    int cpu = arch_cpu_id_stable();
    if (cpu < 0 || cpu >= CONFIG_MAX_CPUS)
        cpu = 0;
    return cpu;
}

static inline void khandle_cache_stat_inc(uint64_t *counter) {
    if (!counter)
        return;
    __atomic_fetch_add(counter, 1, __ATOMIC_RELAXED);
}

static inline uint64_t khandle_cache_stat_read(const uint64_t *counter) {
    if (!counter)
        return 0;
    return __atomic_load_n(counter, __ATOMIC_RELAXED);
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
    khandle_cache_stat_inc(&khandle_cache_slot_invalidate_calls_total);
    if (slot->obj) {
        kobj_put(slot->obj);
        khandle_cache_stat_inc(&khandle_cache_invalidated_slots_total);
        khandle_cache_stat_inc(&khandle_cache_released_refs_total);
    }
    memset(slot, 0, sizeof(*slot));
}

static uint64_t khandle_cache_active_refs_snapshot(void) {
    uint64_t active = 0;
    khandle_cache_ensure_ready();
    for (int cpu = 0; cpu < CONFIG_MAX_CPUS; cpu++) {
        struct khandle_lookup_cache_cpu *cpu_cache = &khandle_lookup_cache[cpu];
        mutex_lock(&cpu_cache->lock);
        for (size_t i = 0; i < KHANDLE_CACHE_SLOTS; i++) {
            if (cpu_cache->slots[i].obj)
                active++;
        }
        mutex_unlock(&cpu_cache->lock);
    }
    return active;
}

static void khandle_cache_stats_snapshot(struct khandle_cache_stats_snapshot *out) {
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->lookups_total = khandle_cache_stat_read(&khandle_cache_lookups_total);
    out->hits_total = khandle_cache_stat_read(&khandle_cache_hits_total);
    out->misses_total = khandle_cache_stat_read(&khandle_cache_misses_total);
    out->stores_total = khandle_cache_stat_read(&khandle_cache_stores_total);
    out->slot_invalidate_calls_total =
        khandle_cache_stat_read(&khandle_cache_slot_invalidate_calls_total);
    out->invalidated_slots_total =
        khandle_cache_stat_read(&khandle_cache_invalidated_slots_total);
    out->released_refs_total =
        khandle_cache_stat_read(&khandle_cache_released_refs_total);
    out->ht_sweeps_total = khandle_cache_stat_read(&khandle_cache_ht_sweeps_total);
    out->active_refs = khandle_cache_active_refs_snapshot();
}

static bool khandle_cache_lookup(struct process *p, struct handletable *ht,
                                 int32_t handle, enum kobj_access_op access,
                                 struct kobj **out_obj,
                                 uint32_t *out_rights) {
    if (!p || !ht || !out_obj)
        return false;

    khandle_cache_ensure_ready();
    khandle_cache_stat_inc(&khandle_cache_lookups_total);
    int cpu = khandle_cache_cpu_index();
    struct khandle_lookup_cache_cpu *cpu_cache = &khandle_lookup_cache[cpu];
    struct khandle_lookup_cache_entry *slot =
        &cpu_cache->slots[khandle_cache_slot_index(handle, access)];

    mutex_lock(&cpu_cache->lock);
    if (!slot->obj) {
        khandle_cache_stat_inc(&khandle_cache_misses_total);
        mutex_unlock(&cpu_cache->lock);
        return false;
    }
    if (slot->proc != p || slot->ht != ht || slot->handle != handle ||
        slot->access != access) {
        khandle_cache_slot_invalidate(slot);
        khandle_cache_stat_inc(&khandle_cache_misses_total);
        mutex_unlock(&cpu_cache->lock);
        return false;
    }

    if (slot->cache_epoch != ht->cache_epoch ||
        slot->seq != (uint32_t)atomic_read(&ht->seq) ||
        !khandle_rights_allow(slot->rights, 0, access, true)) {
        khandle_cache_slot_invalidate(slot);
        khandle_cache_stat_inc(&khandle_cache_misses_total);
        mutex_unlock(&cpu_cache->lock);
        return false;
    }

    kobj_get(slot->obj);
    khandle_cache_stat_inc(&khandle_cache_hits_total);
    *out_obj = slot->obj;
    if (out_rights)
        *out_rights = slot->rights;
    mutex_unlock(&cpu_cache->lock);
    return true;
}

static void khandle_cache_store(struct process *p, struct handletable *ht,
                                int32_t handle, enum kobj_access_op access,
                                uint32_t rights, struct kobj *obj) {
    if (!p || !ht || !obj)
        return;

    khandle_cache_ensure_ready();
    khandle_cache_stat_inc(&khandle_cache_stores_total);
    int cpu = khandle_cache_cpu_index();
    struct khandle_lookup_cache_cpu *cpu_cache = &khandle_lookup_cache[cpu];
    struct khandle_lookup_cache_entry *slot =
        &cpu_cache->slots[khandle_cache_slot_index(handle, access)];
    mutex_lock(&cpu_cache->lock);
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
    mutex_unlock(&cpu_cache->lock);
}

static void khandle_cache_invalidate_ht(struct handletable *ht) {
    if (!ht)
        return;

    khandle_cache_ensure_ready();
    khandle_cache_stat_inc(&khandle_cache_ht_sweeps_total);
    for (int cpu = 0; cpu < CONFIG_MAX_CPUS; cpu++) {
        struct khandle_lookup_cache_cpu *cpu_cache = &khandle_lookup_cache[cpu];
        mutex_lock(&cpu_cache->lock);
        for (size_t i = 0; i < KHANDLE_CACHE_SLOTS; i++) {
            struct khandle_lookup_cache_entry *slot = &cpu_cache->slots[i];
            if (slot->obj && slot->ht == ht)
                khandle_cache_slot_invalidate(slot);
        }
        mutex_unlock(&cpu_cache->lock);
    }
}

struct handletable *handletable_alloc(void) {
    khandle_reclaim_deferred();
    struct handletable *ht = kzalloc(sizeof(*ht));
    if (!ht)
        return NULL;
    mutex_init(&ht->lock, "handletable");
    atomic_init(&ht->refcount, 1);
    atomic_init(&ht->seq, 1);
    ht->cache_epoch = khandle_alloc_cache_epoch();
    INIT_LIST_HEAD(&ht->retire_node);
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
        if (src->entries[i].flags & KHANDLE_ENTRY_F_RESERVED_TRANSFER)
            continue;
        if (!obj)
            continue;
        uint64_t parent_cap = src->entries[i].cap_id;
        uint64_t cap_id = KHANDLE_INVALID_CAP_ID;
        rc = kcap_create(parent_cap, dst, i, &cap_id);
        if (rc < 0) {
            break;
        }
        kobj_get(obj);
        kobj_handle_ref_inc(obj);
        dst->entries[i].obj = obj;
        dst->entries[i].rights = src->entries[i].rights;
        dst->entries[i].cap_id = cap_id;
        dst->entries[i].flags = 0;
        dst->entries[i].slot_generation = src->entries[i].slot_generation;
        if (dst->entries[i].slot_generation == 0)
            dst->entries[i].slot_generation = 1;
        dst->entries[i].transfer_token = KHANDLE_INVALID_CAP_ID;
        dst->entries[i].cap_revoke_epoch = 0;
        dst->entries[i].reserved_deadline_ns = 0;
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

bool handletable_tryget(struct handletable *ht) {
    if (!ht)
        return false;
    uint32_t expect = atomic_read(&ht->refcount);
    while (expect != 0) {
        uint32_t want = expect + 1;
        if (atomic_cmpxchg(&ht->refcount, &expect, want))
            return true;
    }
    return false;
}

void handletable_put(struct handletable *ht) {
    if (!ht)
        return;
    if (atomic_dec_return(&ht->refcount) != 0)
        return;

    int32_t audit_pid = -1;
    struct process *curr = proc_current();
    if (curr)
        audit_pid = curr->pid;

    khandle_reserved_transfer_sweep(ht, true);
    (void)khandle_reserved_transfer_drain_deferred(ht, UINT32_MAX, true);
    khandle_cache_invalidate_ht(ht);
    for (int i = 0; i < CONFIG_MAX_HANDLES_PER_PROC; i++) {
        struct kobj *obj = ht->entries[i].obj;
        uint32_t rights = ht->entries[i].rights;
        uint64_t cap_id = ht->entries[i].cap_id;
        uint32_t flags = ht->entries[i].flags;
        if (!obj)
            continue;
        ht->entries[i].obj = NULL;
        ht->entries[i].rights = 0;
        ht->entries[i].cap_id = KHANDLE_INVALID_CAP_ID;
        ht->entries[i].flags = 0;
        ht->entries[i].slot_generation = 0;
        ht->entries[i].transfer_token = KHANDLE_INVALID_CAP_ID;
        ht->entries[i].cap_revoke_epoch = 0;
        ht->entries[i].reserved_deadline_ns = 0;
        if (flags & KHANDLE_ENTRY_F_RESERVED_TRANSFER) {
            khandle_transfer_drop_cap(obj, rights, cap_id);
            continue;
        }
        kcap_detach_owner(cap_id, ht, i, false);
        kobj_handle_ref_dec(obj);
        kchannel_endpoint_ref_audit_obj(obj, "handletable_put", audit_pid);
        kobj_put(obj);
    }
    khandle_retire_table_deferred(ht);
    khandle_reclaim_deferred();
}

static int khandle_close_in_table(struct handletable *ht, int32_t handle,
                                  uint64_t expected_cap_id,
                                  bool enforce_cap_id) {
    if (!ht)
        return -EINVAL;
    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    khandle_reserved_transfer_sweep(ht, false);
    khandle_reserved_transfer_drain_safepoint(ht);

    struct kobj *obj = NULL;
    uint64_t cap_id = KHANDLE_INVALID_CAP_ID;
    mutex_lock(&ht->lock);
    obj = ht->entries[handle].obj;
    if (!obj) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    if (ht->entries[handle].flags & KHANDLE_ENTRY_F_RESERVED_TRANSFER) {
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
    ht->entries[handle].flags = 0;
    khandle_slot_generation_bump(&ht->entries[handle]);
    ht->entries[handle].transfer_token = KHANDLE_INVALID_CAP_ID;
    ht->entries[handle].cap_revoke_epoch = 0;
    ht->entries[handle].reserved_deadline_ns = 0;
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
        int rc = kcap_create(parent_cap_id, ht, handle, &cap_id);
        if (rc < 0)
            return rc;
    }

    kobj_get(obj);
    kobj_handle_ref_inc(obj);
    ht->entries[handle].obj = obj;
    ht->entries[handle].rights = rights;
    ht->entries[handle].cap_id = cap_id;
    ht->entries[handle].flags = 0;
    khandle_slot_generation_bump(&ht->entries[handle]);
    ht->entries[handle].transfer_token = KHANDLE_INVALID_CAP_ID;
    ht->entries[handle].cap_revoke_epoch = 0;
    ht->entries[handle].reserved_deadline_ns = 0;
    atomic_inc(&ht->seq);
    return 0;
}

int khandle_alloc(struct process *p, struct kobj *obj, uint32_t rights) {
    struct handletable *ht = proc_handletable(p);
    struct process *curr = proc_current();
    if (!ht || !obj || rights == 0)
        return -EINVAL;

    khandle_reserved_transfer_sweep(ht, false);
    khandle_reserved_transfer_drain_safepoint(ht);

    int lock_rc = khandle_table_lock_bounded(ht, KHANDLE_TABLE_LOCK_TIMEOUT_NS);
    if (lock_rc < 0) {
        pr_warn("khandle_alloc: lock timeout pid=%d ht=%p\n",
                curr ? curr->pid : -1, (void *)ht);
        return -ETIMEDOUT;
    }
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

    khandle_reserved_transfer_sweep(ht, false);

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
    if (ht->entries[handle].flags & KHANDLE_ENTRY_F_RESERVED_TRANSFER) {
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
        ht->entries[handle].flags = 0;
        khandle_slot_generation_bump(&ht->entries[handle]);
        ht->entries[handle].transfer_token = KHANDLE_INVALID_CAP_ID;
        ht->entries[handle].cap_revoke_epoch = 0;
        ht->entries[handle].reserved_deadline_ns = 0;
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
    if (access == KOBJ_ACCESS_TRANSFER)
        return -EINVAL;
    return khandle_take_for_access_with_cap(p, handle, access, out_obj,
                                            out_rights, NULL);
}

int khandle_reserve_transfer(struct process *p, int32_t handle,
                             struct kobj **out_obj, uint32_t *out_rights,
                             uint64_t *out_cap_id, uint64_t *out_token,
                             uint32_t *out_slot_generation) {
    struct handletable *ht = proc_handletable(p);
    if (!ht || !out_obj || !out_slot_generation)
        return -EINVAL;
    *out_obj = NULL;
    if (out_rights)
        *out_rights = 0;
    if (out_cap_id)
        *out_cap_id = KHANDLE_INVALID_CAP_ID;
    if (out_token)
        *out_token = KHANDLE_INVALID_CAP_ID;
    *out_slot_generation = 0;
    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    khandle_reserved_transfer_sweep(ht, false);
    khandle_reserved_transfer_drain_safepoint(ht);

    uint64_t token = khandle_alloc_transfer_token();
    struct kobj *obj = NULL;
    uint32_t rights = 0;
    uint64_t cap_id = KHANDLE_INVALID_CAP_ID;
    uint32_t slot_generation = 0;

    mutex_lock(&ht->lock);
    struct khandle_entry *entry = &ht->entries[handle];
    obj = entry->obj;
    rights = entry->rights;
    cap_id = entry->cap_id;
    if (!obj) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    if (entry->flags & KHANDLE_ENTRY_F_RESERVED_TRANSFER) {
        mutex_unlock(&ht->lock);
        return -EBUSY;
    }
    if (!krights_allow_access(rights, KOBJ_ACCESS_TRANSFER)) {
        mutex_unlock(&ht->lock);
        return -EACCES;
    }
    entry->flags |= KHANDLE_ENTRY_F_RESERVED_TRANSFER;
    khandle_slot_generation_bump(entry);
    slot_generation = entry->slot_generation;
    entry->transfer_token = token;
    entry->cap_revoke_epoch = kcap_revoke_epoch_snapshot(cap_id);
    entry->reserved_deadline_ns = khandle_reserved_deadline_ns(time_now_ns());
    atomic_inc(&ht->seq);
    mutex_unlock(&ht->lock);

    kcap_detach_owner(cap_id, ht, handle, true);
    kobj_transfer_record(obj, KOBJ_TRANSFER_TAKE, p ? p->pid : -1, -1, rights);
    *out_obj = obj;
    if (out_rights)
        *out_rights = rights;
    if (out_cap_id)
        *out_cap_id = cap_id;
    if (out_token)
        *out_token = token;
    *out_slot_generation = slot_generation;
    return 0;
}

int khandle_commit_reserved_transfer(struct process *p, int32_t handle,
                                     uint64_t token,
                                     uint32_t slot_generation) {
    struct handletable *ht = proc_handletable(p);
    if (!ht)
        return -EINVAL;
    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;
    if (token == KHANDLE_INVALID_CAP_ID || slot_generation == 0)
        return -EINVAL;

    mutex_lock(&ht->lock);
    struct khandle_entry *entry = &ht->entries[handle];
    if (!entry->obj) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    if ((entry->flags & KHANDLE_ENTRY_F_RESERVED_TRANSFER) == 0 ||
        entry->transfer_token != token ||
        entry->slot_generation != slot_generation) {
        uint64_t cap_id = entry->cap_id;
        uint64_t mismatch = 0;
        if ((entry->flags & KHANDLE_ENTRY_F_RESERVED_TRANSFER) == 0)
            mismatch |= (1ULL << 0);
        if (entry->transfer_token != token)
            mismatch |= (1ULL << 1);
        if (entry->slot_generation != slot_generation)
            mismatch |= (1ULL << 2);
        mutex_unlock(&ht->lock);
        ipc_stat_inc_u64(&ipc_cap_commit_eagain_total);
        uint64_t arg1 = ((uint64_t)(uint32_t)handle << 32) |
                        (mismatch & 0xffffffffULL);
        kcap_trace_event(TRACE_IPC_CAP_OP_COMMIT_EAGAIN, cap_id, arg1);
        return -EAGAIN;
    }

    uint64_t cap_id = entry->cap_id;
    uint64_t reserved_epoch = entry->cap_revoke_epoch;
    bool epoch_match =
        kcap_transfer_commit_epoch_matches(cap_id, reserved_epoch);

    entry->obj = NULL;
    entry->rights = 0;
    entry->cap_id = KHANDLE_INVALID_CAP_ID;
    entry->flags = 0;
    khandle_slot_generation_bump(entry);
    entry->transfer_token = KHANDLE_INVALID_CAP_ID;
    entry->cap_revoke_epoch = 0;
    entry->reserved_deadline_ns = 0;
    atomic_inc(&ht->seq);
    mutex_unlock(&ht->lock);
    if (!epoch_match)
        ipc_stat_inc_u64(&ipc_cap_commit_epoch_mismatch_total);
    return 0;
}

int khandle_abort_reserved_transfer(struct process *p, int32_t handle,
                                    uint64_t token,
                                    uint32_t slot_generation) {
    struct handletable *ht = proc_handletable(p);
    if (!ht)
        return -EINVAL;
    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;
    if (token == KHANDLE_INVALID_CAP_ID || slot_generation == 0)
        return -EINVAL;

    struct kobj *obj = NULL;
    uint32_t rights = 0;
    uint64_t cap_id = KHANDLE_INVALID_CAP_ID;

    mutex_lock(&ht->lock);
    struct khandle_entry *entry = &ht->entries[handle];
    if (!entry->obj) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    if ((entry->flags & KHANDLE_ENTRY_F_RESERVED_TRANSFER) == 0 ||
        entry->transfer_token != token ||
        entry->slot_generation != slot_generation) {
        mutex_unlock(&ht->lock);
        return -EAGAIN;
    }

    obj = entry->obj;
    rights = entry->rights;
    cap_id = entry->cap_id;
    int rc = 0;
    if (cap_id != KHANDLE_INVALID_CAP_ID)
        rc = kcap_bind_existing(cap_id, ht, handle);
    if (rc < 0) {
        entry->obj = NULL;
        entry->rights = 0;
        entry->cap_id = KHANDLE_INVALID_CAP_ID;
        entry->flags = 0;
        khandle_slot_generation_bump(entry);
        entry->transfer_token = KHANDLE_INVALID_CAP_ID;
        entry->cap_revoke_epoch = 0;
        entry->reserved_deadline_ns = 0;
        atomic_inc(&ht->seq);
        mutex_unlock(&ht->lock);
        khandle_transfer_drop_cap(obj, rights, cap_id);
        return rc;
    }

    entry->flags &= ~KHANDLE_ENTRY_F_RESERVED_TRANSFER;
    khandle_slot_generation_bump(entry);
    entry->transfer_token = KHANDLE_INVALID_CAP_ID;
    entry->cap_revoke_epoch = 0;
    entry->reserved_deadline_ns = 0;
    atomic_inc(&ht->seq);
    mutex_unlock(&ht->lock);

    kobj_transfer_record(obj, KOBJ_TRANSFER_RESTORE, -1, p ? p->pid : -1,
                         rights);
    return 0;
}

int khandle_restore_cap(struct process *p, int32_t handle, struct kobj *obj,
                        uint32_t rights, uint64_t cap_id) {
    struct handletable *ht = proc_handletable(p);
    if (!ht || !obj || rights == 0)
        return -EINVAL;
    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    khandle_reserved_transfer_sweep(ht, false);
    khandle_reserved_transfer_drain_safepoint(ht);

    mutex_lock(&ht->lock);
    if (ht->entries[handle].obj) {
        mutex_unlock(&ht->lock);
        return -EBUSY;
    }

    int rc = 0;
    uint64_t install_cap = cap_id;
    if (install_cap != KHANDLE_INVALID_CAP_ID) {
        rc = kcap_bind_existing(install_cap, ht, handle);
        if (rc < 0) {
            mutex_unlock(&ht->lock);
            return rc;
        }
    }
    if (install_cap == KHANDLE_INVALID_CAP_ID) {
        rc = kcap_create(KHANDLE_INVALID_CAP_ID, ht, handle, &install_cap);
    }
    if (rc < 0) {
        mutex_unlock(&ht->lock);
        return rc;
    }

    ht->entries[handle].obj = obj;
    ht->entries[handle].rights = rights;
    ht->entries[handle].cap_id = install_cap;
    ht->entries[handle].flags = 0;
    ht->entries[handle].transfer_token = KHANDLE_INVALID_CAP_ID;
    ht->entries[handle].cap_revoke_epoch = 0;
    ht->entries[handle].reserved_deadline_ns = 0;
    atomic_inc(&ht->seq);
    mutex_unlock(&ht->lock);
    kobj_transfer_record(obj, KOBJ_TRANSFER_RESTORE, -1, p ? p->pid : -1,
                         rights);
    return 0;
}

int khandle_restore(struct process *p, int32_t handle, struct kobj *obj,
                    uint32_t rights) {
    return khandle_restore_cap(p, handle, obj, rights, KHANDLE_INVALID_CAP_ID);
}

int khandle_close(struct process *p, int32_t handle) {
    return khandle_close_with_flags(p, handle, 0);
}

static int khandle_revoke_descendants_by_root(uint64_t root_cap_id) {
    int first_error = 0;
    uint32_t retry_count = 0;

    while (1) {
        struct handletable *target_ht = NULL;
        int32_t target_handle = -1;
        uint64_t target_cap_id = KHANDLE_INVALID_CAP_ID;
        int rc = kcap_pick_revoked_descendant(root_cap_id, &target_ht,
                                              &target_handle, &target_cap_id);
        if (rc < 0)
            break;
        rc = khandle_close_in_table(target_ht, target_handle, target_cap_id,
                                    true);
        handletable_put(target_ht);

        if (rc == 0)
            continue;
        if (rc == -EAGAIN || rc == -EBADF) {
            retry_count++;
            continue;
        }
        if (first_error == 0)
            first_error = rc;
    }

    if (retry_count > 0) {
        pr_warn("ipc: revoke descendants had %u transient retries\n",
                retry_count);
    }
    return first_error;
}

static int khandle_resolve_root_cap_id(struct handletable *ht, int32_t handle,
                                       uint64_t *out_root_cap_id) {
    if (!ht || !out_root_cap_id)
        return -EINVAL;
    *out_root_cap_id = KHANDLE_INVALID_CAP_ID;
    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    mutex_lock(&ht->lock);
    if (!ht->entries[handle].obj ||
        (ht->entries[handle].flags & KHANDLE_ENTRY_F_RESERVED_TRANSFER)) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    *out_root_cap_id = ht->entries[handle].cap_id;
    mutex_unlock(&ht->lock);
    if (*out_root_cap_id == KHANDLE_INVALID_CAP_ID)
        return -EINVAL;
    return 0;
}

static int khandle_revoke_subtree_txn(struct handletable *ht, int32_t handle,
                                      bool close_root) {
    uint64_t root_cap_id = KHANDLE_INVALID_CAP_ID;
    int rc = khandle_resolve_root_cap_id(ht, handle, &root_cap_id);
    if (rc < 0)
        return rc;

    rc = kcap_mark_subtree_revoked(root_cap_id, close_root);
    if (rc < 0)
        return rc;

    rc = khandle_revoke_descendants_by_root(root_cap_id);
    if (rc < 0)
        return rc;

    if (!close_root)
        return 0;

    return khandle_close_in_table(ht, handle, root_cap_id, true);
}

int khandle_close_with_flags(struct process *p, int32_t handle, uint32_t flags) {
    struct handletable *ht = proc_handletable(p);
    if (!ht)
        return -EINVAL;
    if (flags & ~KHANDLE_CLOSE_F_REVOKE_DESCENDANTS)
        return -EINVAL;
    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    khandle_reserved_transfer_sweep(ht, false);
    khandle_reserved_transfer_drain_safepoint(ht);

    if ((flags & KHANDLE_CLOSE_F_REVOKE_DESCENDANTS) == 0)
        return khandle_close_in_table(ht, handle, KHANDLE_INVALID_CAP_ID, false);

    return khandle_revoke_subtree_txn(ht, handle, true);
}

int khandle_duplicate(struct process *p, int32_t handle, uint32_t rights_mask,
                      int32_t *out_new_handle) {
    struct handletable *ht = proc_handletable(p);
    if (!ht || !out_new_handle)
        return -EINVAL;
    *out_new_handle = -1;

    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    khandle_reserved_transfer_sweep(ht, false);
    khandle_reserved_transfer_drain_safepoint(ht);

    mutex_lock(&ht->lock);
    struct kobj *obj = ht->entries[handle].obj;
    uint32_t rights = ht->entries[handle].rights;
    uint64_t parent_cap_id = ht->entries[handle].cap_id;
    if (!obj || (ht->entries[handle].flags & KHANDLE_ENTRY_F_RESERVED_TRANSFER)) {
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

    khandle_reserved_transfer_sweep(ht, false);
    khandle_reserved_transfer_drain_safepoint(ht);

    return khandle_revoke_subtree_txn(ht, handle, false);
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

    khandle_reserved_transfer_sweep(ht, false);
    khandle_reserved_transfer_drain_safepoint(ht);

    mutex_lock(&ht->lock);
    for (int h = 0; h < CONFIG_MAX_HANDLES_PER_PROC; h++) {
        if (ht->entries[h].obj)
            continue;
        int rc = khandle_install_locked(ht, h, obj, rights,
                                        KHANDLE_INVALID_CAP_ID, cap_id);
        mutex_unlock(&ht->lock);
        if (rc < 0)
            return rc;
        *out_handle = h;
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
            kport_ready_hint_set_locked(port);
            poll_wait_source_wake_one_reason(&port->rd_src, 0,
                                             POLL_WAIT_WAKE_SIGNAL);
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
        port->dropped_count++;
        uint64_t total =
            __atomic_add_fetch(&ipc_port_queue_drops_total, 1, __ATOMIC_RELAXED);
        if (ipc_warn_ratelimited(&ipc_port_queue_drop_warn_count)) {
            pr_warn("ipc: port queue overflow id=%u port_drops=%llu total_drops=%llu\n",
                    port->obj.id, (unsigned long long)port->dropped_count,
                    (unsigned long long)total);
        }
        kfree(old);
    }

    struct kport_packet *pkt = kzalloc(sizeof(*pkt));
    if (!pkt)
        return;
    pkt->key = key;
    pkt->observed = observed;
    list_add_tail(&pkt->node, &port->queue);
    port->queue_len++;
    kport_ready_hint_set_locked(port);
    poll_wait_source_wake_one_reason(&port->rd_src, 0, POLL_WAIT_WAKE_SIGNAL);
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

    ipc_port_lock(port);
    kport_enqueue_locked(port, ch->bind.key, signal);
    ipc_port_unlock(port);
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
    atomic_init(&ch->endpoint_ref_handle_count, 0);
    atomic_init(&ch->endpoint_ref_channelfd_count, 0);
    atomic_init(&ch->endpoint_ref_other_count, 0);
    atomic_init(&ch->pollin_hint, 0);
    atomic_init(&ch->pollout_hint, 0);
    atomic_init(&ch->pollhup_hint, 0);
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
    ch->endpoint_state = KCHANNEL_ENDPOINT_OPEN;
    ch->recv_waiter = NULL;
    ch->bind.port = NULL;
    ch->bind.key = 0;
    ch->bind.signals = 0;
    kobj_track_register(&ch->obj);
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

    /* Pair initialization follows the canonical self->lock -> peer->lock order. */
    ipc_channel_lock(a);
    ipc_channel_lock(b);
    a->peer = b;
    b->peer = a;
    kchannel_pollin_hup_hint_update_locked(a);
    kchannel_pollin_hup_hint_update_locked(b);
    kchannel_pollout_hint_set(a, true);
    kchannel_pollout_hint_set(b, true);
    kobj_get(&b->obj);
    kobj_get(&a->obj);
    ipc_channel_unlock(b);
    ipc_channel_unlock(a);

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

    poll_wait_source_wake_one_reason(&peer->rd_src, 0, POLL_WAIT_WAKE_DATA);
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

    poll_wait_source_wake_one_reason(&peer->rd_src, 0, POLL_WAIT_WAKE_DATA);
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
#if CONFIG_KERNEL_FAULT_INJECT
    if (fault_inject_should_fail(FAULT_INJECT_POINT_IPC_CHANNEL_SEND))
        return -EINTR;
#endif

    struct kchannel *peer = NULL;
    ipc_channel_lock(self);
    if (!kchannel_send_open_locked(self)) {
        __atomic_add_fetch(&ipc_channel_send_epipe_total, 1, __ATOMIC_RELAXED);
        kchannel_trace_event(TRACE_IPC_CH_OP_SEND_EPIPE, TRACE_IPC_CH_WAKE_CLOSE,
                             self, self->peer);
        ipc_channel_unlock(self);
        return -EPIPE;
    }
    peer = self->peer;
    kobj_get(&peer->obj);
    ipc_channel_unlock(self);

    bool rendezvous = (options & KCHANNEL_OPT_RENDEZVOUS) != 0;
    int32_t sender_pid = -1;
    struct process *curr = proc_current();
    if (curr)
        sender_pid = curr->pid;
    int ret = 0;
    struct kchannel_msg *msg = NULL;
    bool nonblock = (options & KCHANNEL_OPT_NONBLOCK) != 0;

    ipc_channel_lock(peer);
    if (!kchannel_peer_accepts_send_locked(peer)) {
        __atomic_add_fetch(&ipc_channel_send_epipe_total, 1, __ATOMIC_RELAXED);
        kchannel_trace_event(TRACE_IPC_CH_OP_SEND_EPIPE, TRACE_IPC_CH_WAKE_CLOSE,
                             self, peer);
        kchannel_pollout_hint_set(self, false);
        ret = -EPIPE;
        goto out_unlock;
    }
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
        uint32_t wr_seq = poll_wait_source_seq_snapshot(&peer->wr_src);
        int rc = poll_wait_source_block_seq(&peer->wr_src, 0, &peer->wr_src,
                                            &peer->lock, wr_seq);
        if (rc < 0) {
            ret = rc;
            goto out_unlock;
        }
        if (!kchannel_peer_accepts_send_locked(peer)) {
            __atomic_add_fetch(&ipc_channel_send_epipe_total, 1,
                               __ATOMIC_RELAXED);
            kchannel_trace_event(TRACE_IPC_CH_OP_SEND_EPIPE,
                                 TRACE_IPC_CH_WAKE_CLOSE, self, peer);
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
    kchannel_pollin_hup_hint_update_locked(peer);
    msg->owns_caps = true;
    for (size_t i = 0; i < num_handles; i++) {
        kobj_transfer_record(handles[i].obj, KOBJ_TRANSFER_ENQUEUE, sender_pid,
                             -1, handles[i].rights);
    }
    msg = NULL;
    poll_wait_source_wake_one_reason(&peer->rd_src, 0, POLL_WAIT_WAKE_DATA);
    wait_queue_wakeup_one(&peer->obj.waitq);
    kchannel_poll_wake_locked(peer, POLLIN);
    kchannel_emit_locked(peer, KPORT_BIND_READABLE);
    ret = 0;

out_unlock:
    if (kchannel_peer_accepts_send_locked(peer) &&
        peer->rxq_len < KCHANNEL_MAX_QUEUE) {
        kchannel_pollout_hint_set(self, true);
    } else {
        kchannel_pollout_hint_set(self, false);
    }
    if (msg)
        kchannel_msg_recycle_locked(peer, msg);
    ipc_channel_unlock(peer);
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
#if CONFIG_KERNEL_FAULT_INJECT
    if (fault_inject_should_fail(FAULT_INJECT_POINT_IPC_CHANNEL_RECV))
        return -EINTR;
#endif

    bool nonblock = (options & KCHANNEL_OPT_NONBLOCK) != 0;
    bool rendezvous = (options & KCHANNEL_OPT_RENDEZVOUS) != 0;
    struct kchannel_msg *msg = NULL;
    struct kchannel *peer_for_write = NULL;
    struct kchannel_rendezvous rv = {0};

    ipc_channel_lock(ch);
    while (ch->rxq_len == 0) {
        if (rv.completed)
            break;
        if (kchannel_endpoint_hup_locked(ch)) {
            __atomic_add_fetch(&ipc_channel_recv_eof_total, 1, __ATOMIC_RELAXED);
            kchannel_trace_event(TRACE_IPC_CH_OP_RECV_EOF, TRACE_IPC_CH_WAKE_HUP,
                                 ch, ch->peer);
            if (rv.active && ch->recv_waiter == &rv)
                ch->recv_waiter = NULL;
            ipc_channel_unlock(ch);
            return 0;
        }
        if (nonblock) {
            if (rv.active && ch->recv_waiter == &rv)
                ch->recv_waiter = NULL;
            ipc_channel_unlock(ch);
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
        uint32_t rd_seq = poll_wait_source_seq_snapshot(&ch->rd_src);
        int rc = poll_wait_source_block_seq(&ch->rd_src, 0, &ch->rd_src,
                                            &ch->lock, rd_seq);
        if (rc < 0) {
            if (rv.active && ch->recv_waiter == &rv)
                ch->recv_waiter = NULL;
            ipc_channel_unlock(ch);
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
        ipc_channel_unlock(ch);
        return rv.status;
    }

    msg = list_first_entry(&ch->rxq, struct kchannel_msg, node);
    if (bytes_cap < msg->num_bytes || handles_cap < msg->num_handles) {
        *out_bytes = msg->num_bytes;
        *out_handles = msg->num_handles;
        *out_handles_truncated = (handles_cap < msg->num_handles);
        ipc_channel_unlock(ch);
        return -EMSGSIZE;
    }

    list_del(&msg->node);
    INIT_LIST_HEAD(&msg->node);
    if (ch->rxq_len > 0)
        ch->rxq_len--;
    kchannel_pollin_hup_hint_update_locked(ch);
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
    poll_wait_source_wake_one_reason(&ch->wr_src, 0, POLL_WAIT_WAKE_DATA);
    ipc_channel_unlock(ch);

    if (peer_for_write) {
        mutex_lock(&peer_for_write->lock);
        if (kchannel_peer_accepts_send_locked(peer_for_write) &&
            ch->rxq_len < KCHANNEL_MAX_QUEUE) {
            kchannel_pollout_hint_set(peer_for_write, true);
        } else {
            kchannel_pollout_hint_set(peer_for_write, false);
        }
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
    atomic_init(&port->ready_hint, 0);
    INIT_LIST_HEAD(&port->queue);
    INIT_LIST_HEAD(&port->poll_vnodes);
    port->queue_len = 0;
    port->dropped_count = 0;
    kobj_track_register(&port->obj);

    *out = &port->obj;
    return 0;
}

int kchannel_poll_revents(struct kobj *channel_obj, uint32_t events,
                          uint32_t *out_revents) {
    struct kchannel *ch = kchannel_from_obj(channel_obj);
    if (!ch || !out_revents)
        return -EINVAL;

    if (!mutex_trylock(&ch->lock)) {
        uint32_t revents = 0;
        if ((events & POLLIN) && kchannel_hint_load(&ch->pollin_hint))
            revents |= POLLIN;
        if ((events & POLLOUT) && kchannel_hint_load(&ch->pollout_hint))
            revents |= POLLOUT;
        if ((events & POLLHUP) && kchannel_hint_load(&ch->pollhup_hint))
            revents |= POLLHUP;
        *out_revents = revents;
        return 0;
    }

    uint32_t hinted = 0;
    if (events & POLLIN) {
        if (kchannel_hint_load(&ch->pollin_hint))
            hinted |= POLLIN;
    }
    if (events & POLLOUT) {
        if (kchannel_hint_load(&ch->pollout_hint))
            hinted |= POLLOUT;
    }
    if (events & POLLHUP) {
        if (kchannel_hint_load(&ch->pollhup_hint))
            hinted |= POLLHUP;
    }

    uint32_t actual = kchannel_poll_revents_locked(ch, events) & events;
    *out_revents = actual;
    ipc_channel_unlock(ch);

    uint32_t mismatch = (hinted ^ actual);
    __atomic_add_fetch(&ipc_channel_poll_hint_checks_total, 1, __ATOMIC_RELAXED);
    if ((mismatch & POLLIN) != 0) {
        __atomic_add_fetch(&ipc_channel_poll_hint_mismatch_in_total, 1,
                           __ATOMIC_RELAXED);
    }
    if ((mismatch & POLLOUT) != 0) {
        __atomic_add_fetch(&ipc_channel_poll_hint_mismatch_out_total, 1,
                           __ATOMIC_RELAXED);
    }
    if ((mismatch & POLLHUP) != 0) {
        __atomic_add_fetch(&ipc_channel_poll_hint_mismatch_hup_total, 1,
                           __ATOMIC_RELAXED);
    }
    if (mismatch != 0 && ipc_warn_ratelimited(&ipc_channel_poll_hint_warn_count)) {
        pr_warn("ipc: channel poll hint mismatch id=%u hinted=0x%x actual=0x%x events=0x%x\n",
                ch->obj.id, hinted, actual, events);
    }
#if CONFIG_IPC_POLL_HINT_STRICT
    if (mismatch != 0) {
        panic("ipc: strict poll hint mismatch id=%u hinted=0x%x actual=0x%x events=0x%x",
              ch->obj.id, hinted, actual, events);
    }
#endif
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
    ipc_channel_lock(ch);
    struct kchannel_watch *iter;
    list_for_each_entry(iter, &ch->poll_vnodes, node) {
        if (iter->vn == vn) {
            wake_events =
                kchannel_poll_revents_locked(ch, POLLIN | POLLOUT | POLLHUP);
            ipc_channel_unlock(ch);
            kfree(watch);
            if (wake_events)
                vfs_poll_wake(vn, wake_events);
            return 0;
        }
    }
    list_add_tail(&watch->node, &ch->poll_vnodes);
    vnode_get(vn);
    wake_events = kchannel_poll_revents_locked(ch, POLLIN | POLLOUT | POLLHUP);
    ipc_channel_unlock(ch);

    if (wake_events)
        vfs_poll_wake(vn, wake_events);
    return 0;
}

int kchannel_poll_detach_vnode(struct kobj *channel_obj, struct vnode *vn) {
    struct kchannel *ch = kchannel_from_obj(channel_obj);
    if (!ch || !vn)
        return -EINVAL;

    ipc_channel_lock(ch);
    struct kchannel_watch *iter, *tmp;
    list_for_each_entry_safe(iter, tmp, &ch->poll_vnodes, node) {
        if (iter->vn != vn)
            continue;
        list_del(&iter->node);
        ipc_channel_unlock(ch);
        vnode_put(iter->vn);
        kfree(iter);
        return 0;
    }
    ipc_channel_unlock(ch);
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

    ipc_channel_lock(ch);
    old = ch->bind.port;
    kobj_get(&port->obj);
    ch->bind.port = port;
    ch->bind.key = key;
    ch->bind.signals = signals;

    if ((signals & KPORT_BIND_READABLE) && ch->rxq_len > 0)
        kchannel_emit_locked(ch, KPORT_BIND_READABLE);
    if ((signals & KPORT_BIND_PEER_CLOSED) && ch->peer_closed)
        kchannel_emit_locked(ch, KPORT_BIND_PEER_CLOSED);

    ipc_channel_unlock(ch);

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

    ipc_port_lock(port);
    while (list_empty(&port->queue)) {
        kport_ready_hint_set_locked(port);
        if (nonblock) {
            ipc_port_unlock(port);
            return -EAGAIN;
        }
        if (!infinite && timeout_ns == 0) {
            ipc_port_unlock(port);
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
                ipc_port_unlock(port);
                return -ETIMEDOUT;
            }
        }
        if (rc < 0) {
            ipc_port_unlock(port);
            return rc;
        }
    }

    struct kport_packet *pkt =
        list_first_entry(&port->queue, struct kport_packet, node);
    list_del(&pkt->node);
    if (port->queue_len > 0)
        port->queue_len--;
    kport_ready_hint_set_locked(port);
    ipc_port_unlock(port);

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
        *out_ready = atomic_read(&port->ready_hint) != 0;
        return 0;
    }

    *out_ready = !list_empty(&port->queue);
    ipc_port_unlock(port);
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
    ipc_port_lock(port);
    struct kport_watch *iter;
    list_for_each_entry(iter, &port->poll_vnodes, node) {
        if (iter->vn == vn) {
            ready = !list_empty(&port->queue);
            ipc_port_unlock(port);
            kfree(watch);
            if (ready)
                vfs_poll_wake(vn, POLLIN);
            return 0;
        }
    }
    list_add_tail(&watch->node, &port->poll_vnodes);
    vnode_get(vn);
    ready = !list_empty(&port->queue);
    ipc_port_unlock(port);

    if (ready)
        vfs_poll_wake(vn, POLLIN);
    return 0;
}

int kport_poll_detach_vnode(struct kobj *port_obj, struct vnode *vn) {
    struct kport *port = kport_from_obj(port_obj);
    if (!port || !vn)
        return -EINVAL;

    ipc_port_lock(port);
    struct kport_watch *iter, *tmp;
    list_for_each_entry_safe(iter, tmp, &port->poll_vnodes, node) {
        if (iter->vn != vn)
            continue;
        list_del(&iter->node);
        ipc_port_unlock(port);
        vnode_put(iter->vn);
        kfree(iter);
        return 0;
    }
    ipc_port_unlock(port);
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

    ipc_channel_lock(ch);
    kchannel_emit_locked(ch, signal);
    ipc_channel_unlock(ch);
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
    kobj_track_register(&kfile->obj);
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

    struct kchannel *peer = NULL;
    struct kport *bound = NULL;
    LIST_HEAD(reap);
    LIST_HEAD(poll_reap);

    ipc_channel_lock(ch);
    if (ch->endpoint_state == KCHANNEL_ENDPOINT_OPEN)
        kchannel_endpoint_transition_locked(ch, KCHANNEL_ENDPOINT_CLOSING);
#if CONFIG_DEBUG
    else
        ASSERT(ch->endpoint_state == KCHANNEL_ENDPOINT_CLOSING ||
               ch->endpoint_state == KCHANNEL_ENDPOINT_CLOSED);
#endif
    peer = ch->peer;
    ch->peer = NULL;

    bound = ch->bind.port;
    ch->bind.port = NULL;
    ch->bind.signals = 0;
    ch->bind.key = 0;
    ch->peer_closed = true;
    if (ch->endpoint_state != KCHANNEL_ENDPOINT_CLOSED)
        kchannel_endpoint_transition_locked(ch, KCHANNEL_ENDPOINT_CLOSED);
    __atomic_add_fetch(&ipc_channel_close_release_total, 1, __ATOMIC_RELAXED);
    kchannel_trace_event(TRACE_IPC_CH_OP_CLOSE_LOCAL, TRACE_IPC_CH_WAKE_CLOSE, ch,
                         peer);

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
    kchannel_pollin_hup_hint_update_locked(ch);
    kchannel_pollout_hint_set(ch, false);
    __atomic_add_fetch(&ipc_channel_close_wake_local_total, 1, __ATOMIC_RELAXED);
    wait_queue_wakeup_all(&ch->obj.waitq);
    ipc_channel_unlock(ch);

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
        vnode_put(watch->vn);
        kfree(watch);
    }

    if (bound)
        kobj_put(&bound->obj);

    if (peer) {
        /* Release path also observes self->lock -> peer->lock order. */
        ipc_channel_lock(peer);
        if (peer->peer == ch)
            peer->peer = NULL;
        peer->peer_closed = true;
        kchannel_trace_event(TRACE_IPC_CH_OP_CLOSE_PEER,
                             TRACE_IPC_CH_WAKE_CLOSE, peer, ch);
        kchannel_pollin_hup_hint_update_locked(peer);
        kchannel_pollout_hint_set(peer, false);
        __atomic_add_fetch(&ipc_channel_close_wake_peer_total, 1,
                           __ATOMIC_RELAXED);
        poll_wait_source_wake_all_reason(&peer->rd_src, 0,
                                         POLL_WAIT_WAKE_CLOSE);
        poll_wait_source_wake_all_reason(&peer->wr_src, 0,
                                         POLL_WAIT_WAKE_CLOSE);
        wait_queue_wakeup_all(&peer->obj.waitq);
        kchannel_poll_wake_locked(peer, POLLHUP);
        kchannel_emit_locked(peer, KPORT_BIND_PEER_CLOSED);
        ipc_channel_unlock(peer);

        kobj_put(&peer->obj);
    }

    kfree(ch);
}

static void kport_release_obj(struct kobj *obj) {
    struct kport *port = kport_from_obj(obj);
    if (!port)
        return;

    LIST_HEAD(reap);
    LIST_HEAD(poll_reap);

    ipc_port_lock(port);
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
    kport_ready_hint_set_locked(port);
    wait_queue_wakeup_all(&port->obj.waitq);
    ipc_port_unlock(port);

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
        vnode_put(watch->vn);
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
