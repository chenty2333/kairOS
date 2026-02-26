/**
 * kernel/core/ipc/handle.c - Capability handles + channel/port objects
 */

#include <kairos/arch.h>
#include <kairos/handle.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/wait.h>

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
    size_t num_handles;
    bool owns_caps;
    struct khandle_transfer handles[KCHANNEL_MAX_MSG_HANDLES];
};

struct kchannel {
    struct kobj obj;
    atomic_t handle_refs;
    struct mutex lock;
    struct wait_queue read_wait;
    struct wait_queue write_wait;
    struct list_head rxq;
    size_t rxq_len;
    struct kchannel *peer;
    bool peer_closed;
    bool endpoint_closed;
    struct kchannel_binding bind;
};

struct kport_packet {
    struct list_head node;
    uint64_t key;
    uint32_t observed;
};

struct kport {
    struct kobj obj;
    struct mutex lock;
    struct wait_queue waitq;
    struct list_head queue;
    size_t queue_len;
};

static void kchannel_release_obj(struct kobj *obj);
static void kport_release_obj(struct kobj *obj);

static const struct kobj_ops kchannel_ops = {
    .release = kchannel_release_obj,
};

static const struct kobj_ops kport_ops = {
    .release = kport_release_obj,
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

static void kchannel_emit_locked(struct kchannel *ch, uint32_t signal);

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
    wait_queue_wakeup_all(&peer->read_wait);
    wait_queue_wakeup_all(&peer->write_wait);
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

static void kchannel_msg_free(struct kchannel_msg *msg) {
    if (!msg)
        return;
    for (size_t i = 0; i < msg->num_handles; i++) {
        if (msg->handles[i].obj) {
            if (msg->owns_caps)
                kobj_handle_ref_dec(msg->handles[i].obj);
            kobj_put(msg->handles[i].obj);
            msg->handles[i].obj = NULL;
        }
    }
    if (msg->bytes)
        kfree(msg->bytes);
    kfree(msg);
}

void kobj_init(struct kobj *obj, uint32_t type, const struct kobj_ops *ops) {
    if (!obj)
        return;
    atomic_init(&obj->refcount, 1);
    obj->type = type;
    obj->ops = ops;
}

void kobj_get(struct kobj *obj) {
    if (!obj)
        return;
    atomic_inc(&obj->refcount);
}

void kobj_put(struct kobj *obj) {
    if (!obj)
        return;
    if (atomic_dec_return(&obj->refcount) == 0 && obj->ops && obj->ops->release)
        obj->ops->release(obj);
}

struct handletable *handletable_alloc(void) {
    struct handletable *ht = kzalloc(sizeof(*ht));
    if (!ht)
        return NULL;
    mutex_init(&ht->lock, "handletable");
    atomic_init(&ht->refcount, 1);
    return ht;
}

struct handletable *handletable_copy(struct handletable *src) {
    if (!src)
        return handletable_alloc();

    struct handletable *dst = handletable_alloc();
    if (!dst)
        return NULL;

    mutex_lock(&src->lock);
    for (int i = 0; i < CONFIG_MAX_HANDLES_PER_PROC; i++) {
        struct kobj *obj = src->entries[i].obj;
        if (!obj)
            continue;
        kobj_get(obj);
        kobj_handle_ref_inc(obj);
        dst->entries[i].obj = obj;
        dst->entries[i].rights = src->entries[i].rights;
    }
    mutex_unlock(&src->lock);

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
        if (!obj)
            continue;
        ht->entries[i].obj = NULL;
        ht->entries[i].rights = 0;
        kobj_handle_ref_dec(obj);
        kobj_put(obj);
    }
    kfree(ht);
}

int khandle_alloc(struct process *p, struct kobj *obj, uint32_t rights) {
    struct handletable *ht = proc_handletable(p);
    if (!ht || !obj || rights == 0)
        return -EINVAL;

    mutex_lock(&ht->lock);
    for (int h = 0; h < CONFIG_MAX_HANDLES_PER_PROC; h++) {
        if (ht->entries[h].obj)
            continue;
        kobj_get(obj);
        kobj_handle_ref_inc(obj);
        ht->entries[h].obj = obj;
        ht->entries[h].rights = rights;
        mutex_unlock(&ht->lock);
        return h;
    }
    mutex_unlock(&ht->lock);
    return -EMFILE;
}

int khandle_get(struct process *p, int32_t handle, uint32_t required_rights,
                struct kobj **out_obj, uint32_t *out_rights) {
    struct handletable *ht = proc_handletable(p);
    if (!ht || !out_obj)
        return -EINVAL;

    *out_obj = NULL;
    if (out_rights)
        *out_rights = 0;

    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    mutex_lock(&ht->lock);
    struct kobj *obj = ht->entries[handle].obj;
    uint32_t rights = ht->entries[handle].rights;
    if (!obj) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    if ((rights & required_rights) != required_rights) {
        mutex_unlock(&ht->lock);
        return -EACCES;
    }
    kobj_get(obj);
    mutex_unlock(&ht->lock);

    *out_obj = obj;
    if (out_rights)
        *out_rights = rights;
    return 0;
}

int khandle_take(struct process *p, int32_t handle, uint32_t required_rights,
                 struct kobj **out_obj, uint32_t *out_rights) {
    struct handletable *ht = proc_handletable(p);
    if (!ht || !out_obj)
        return -EINVAL;

    *out_obj = NULL;
    if (out_rights)
        *out_rights = 0;

    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    mutex_lock(&ht->lock);
    struct kobj *obj = ht->entries[handle].obj;
    uint32_t rights = ht->entries[handle].rights;
    if (!obj) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    if ((rights & required_rights) != required_rights) {
        mutex_unlock(&ht->lock);
        return -EACCES;
    }

    ht->entries[handle].obj = NULL;
    ht->entries[handle].rights = 0;
    mutex_unlock(&ht->lock);

    *out_obj = obj;
    if (out_rights)
        *out_rights = rights;
    return 0;
}

int khandle_restore(struct process *p, int32_t handle, struct kobj *obj,
                    uint32_t rights) {
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
    ht->entries[handle].obj = obj;
    ht->entries[handle].rights = rights;
    mutex_unlock(&ht->lock);
    return 0;
}

int khandle_close(struct process *p, int32_t handle) {
    struct handletable *ht = proc_handletable(p);
    if (!ht)
        return -EINVAL;
    if (handle < 0 || handle >= CONFIG_MAX_HANDLES_PER_PROC)
        return -EBADF;

    mutex_lock(&ht->lock);
    struct kobj *obj = ht->entries[handle].obj;
    if (!obj) {
        mutex_unlock(&ht->lock);
        return -EBADF;
    }
    ht->entries[handle].obj = NULL;
    ht->entries[handle].rights = 0;
    kobj_handle_ref_dec(obj);
    mutex_unlock(&ht->lock);

    kobj_put(obj);
    return 0;
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
        kobj_get(obj);
        kobj_handle_ref_inc(obj);
        ht->entries[h].obj = obj;
        ht->entries[h].rights = new_rights;
        mutex_unlock(&ht->lock);
        *out_new_handle = h;
        return 0;
    }

    mutex_unlock(&ht->lock);
    return -EMFILE;
}

void khandle_transfer_drop(struct kobj *obj) {
    if (!obj)
        return;
    kobj_handle_ref_dec(obj);
    kobj_put(obj);
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
            wait_queue_wakeup_one(&port->waitq);
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
    wait_queue_wakeup_one(&port->waitq);
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

static struct kchannel *kchannel_alloc(void) {
    struct kchannel *ch = kzalloc(sizeof(*ch));
    if (!ch)
        return NULL;
    kobj_init(&ch->obj, KOBJ_TYPE_CHANNEL, &kchannel_ops);
    atomic_init(&ch->handle_refs, 0);
    mutex_init(&ch->lock, "kchannel");
    wait_queue_init(&ch->read_wait);
    wait_queue_init(&ch->write_wait);
    INIT_LIST_HEAD(&ch->rxq);
    ch->rxq_len = 0;
    ch->peer = NULL;
    ch->peer_closed = false;
    ch->endpoint_closed = false;
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

int kchannel_send(struct kobj *obj, const void *bytes, size_t num_bytes,
                  const struct khandle_transfer *handles, size_t num_handles,
                  uint32_t options) {
    struct kchannel *self = kchannel_from_obj(obj);
    if (!self)
        return -ENOTSUP;
    if (options & ~KCHANNEL_OPT_NONBLOCK)
        return -EINVAL;
    if (num_bytes > KCHANNEL_MAX_MSG_BYTES || num_handles > KCHANNEL_MAX_MSG_HANDLES)
        return -EMSGSIZE;
    if (num_bytes > 0 && !bytes)
        return -EFAULT;
    if (num_handles > 0 && !handles)
        return -EINVAL;

    struct kchannel *peer = NULL;
    mutex_lock(&self->lock);
    if (!self->peer || self->peer_closed) {
        mutex_unlock(&self->lock);
        return -EPIPE;
    }
    peer = self->peer;
    kobj_get(&peer->obj);
    mutex_unlock(&self->lock);

    struct kchannel_msg *msg = kzalloc(sizeof(*msg));
    if (!msg) {
        kobj_put(&peer->obj);
        return -ENOMEM;
    }
    INIT_LIST_HEAD(&msg->node);
    msg->num_bytes = num_bytes;
    msg->num_handles = num_handles;
    if (num_bytes) {
        msg->bytes = kmalloc(num_bytes);
        if (!msg->bytes) {
            kfree(msg);
            kobj_put(&peer->obj);
            return -ENOMEM;
        }
        memcpy(msg->bytes, bytes, num_bytes);
    }
    for (size_t i = 0; i < num_handles; i++) {
        if (!handles[i].obj) {
            kchannel_msg_free(msg);
            kobj_put(&peer->obj);
            return -EINVAL;
        }
        msg->handles[i] = handles[i];
        if (msg->handles[i].obj)
            kobj_get(msg->handles[i].obj);
    }

    int ret = 0;
    bool nonblock = (options & KCHANNEL_OPT_NONBLOCK) != 0;

    mutex_lock(&peer->lock);
    while (peer->rxq_len >= KCHANNEL_MAX_QUEUE) {
        if (nonblock) {
            ret = -EAGAIN;
            goto out_unlock;
        }
        int rc =
            proc_sleep_on_mutex(&peer->write_wait, &peer->write_wait, &peer->lock,
                                true);
        if (rc < 0) {
            ret = rc;
            goto out_unlock;
        }
        if (peer->peer_closed || !peer->peer) {
            ret = -EPIPE;
            goto out_unlock;
        }
    }

    list_add_tail(&msg->node, &peer->rxq);
    peer->rxq_len++;
    msg->owns_caps = true;
    wait_queue_wakeup_one(&peer->read_wait);
    kchannel_emit_locked(peer, KPORT_BIND_READABLE);
    ret = 0;

out_unlock:
    mutex_unlock(&peer->lock);
    kobj_put(&peer->obj);
    if (ret < 0)
        kchannel_msg_free(msg);
    return ret;
}

int kchannel_recv(struct kobj *obj, void *bytes, size_t bytes_cap,
                  size_t *out_bytes, struct khandle_transfer *handles,
                  size_t handles_cap, size_t *out_handles,
                  bool *out_handles_truncated, uint32_t options) {
    struct kchannel *ch = kchannel_from_obj(obj);
    if (!ch)
        return -ENOTSUP;
    if (options & ~KCHANNEL_OPT_NONBLOCK)
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
    struct kchannel_msg *msg = NULL;

    mutex_lock(&ch->lock);
    while (list_empty(&ch->rxq)) {
        if (ch->peer_closed) {
            mutex_unlock(&ch->lock);
            return 0;
        }
        if (nonblock) {
            mutex_unlock(&ch->lock);
            return -EAGAIN;
        }
        int rc = proc_sleep_on_mutex(&ch->read_wait, &ch->read_wait, &ch->lock,
                                     true);
        if (rc < 0) {
            mutex_unlock(&ch->lock);
            return rc;
        }
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
    if (ch->rxq_len > 0)
        ch->rxq_len--;
    if (!list_empty(&ch->rxq))
        kchannel_emit_locked(ch, KPORT_BIND_READABLE);
    wait_queue_wakeup_one(&ch->write_wait);
    mutex_unlock(&ch->lock);

    if (msg->num_bytes > 0)
        memcpy(bytes, msg->bytes, msg->num_bytes);

    for (size_t i = 0; i < msg->num_handles; i++) {
        handles[i] = msg->handles[i];
        msg->handles[i].obj = NULL;
    }

    *out_bytes = msg->num_bytes;
    *out_handles = msg->num_handles;
    *out_handles_truncated = false;
    kchannel_msg_free(msg);
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
    wait_queue_init(&port->waitq);
    INIT_LIST_HEAD(&port->queue);
    port->queue_len = 0;

    *out = &port->obj;
    return 0;
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

    if ((signals & KPORT_BIND_READABLE) && !list_empty(&ch->rxq))
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
            rc = proc_sleep_on_mutex(&port->waitq, &port->waitq, &port->lock,
                                     true);
        } else {
            rc = proc_sleep_on_mutex_timeout(&port->waitq, &port->waitq,
                                             &port->lock, true, deadline);
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

static void kchannel_release_obj(struct kobj *obj) {
    struct kchannel *ch = kchannel_from_obj(obj);
    if (!ch)
        return;

    struct kchannel *peer = NULL;
    struct kport *bound = NULL;
    LIST_HEAD(reap);

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
    ch->rxq_len = 0;
    mutex_unlock(&ch->lock);

    while (!list_empty(&reap)) {
        struct kchannel_msg *msg =
            list_first_entry(&reap, struct kchannel_msg, node);
        list_del(&msg->node);
        kchannel_msg_free(msg);
    }

    if (bound)
        kobj_put(&bound->obj);

    if (peer) {
        mutex_lock(&peer->lock);
        if (peer->peer == ch)
            peer->peer = NULL;
        peer->peer_closed = true;
        wait_queue_wakeup_all(&peer->read_wait);
        wait_queue_wakeup_all(&peer->write_wait);
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

    LIST_HEAD(reap);

    mutex_lock(&port->lock);
    while (!list_empty(&port->queue)) {
        struct kport_packet *pkt =
            list_first_entry(&port->queue, struct kport_packet, node);
        list_del(&pkt->node);
        list_add_tail(&pkt->node, &reap);
    }
    port->queue_len = 0;
    mutex_unlock(&port->lock);

    while (!list_empty(&reap)) {
        struct kport_packet *pkt =
            list_first_entry(&reap, struct kport_packet, node);
        list_del(&pkt->node);
        kfree(pkt);
    }

    kfree(port);
}
