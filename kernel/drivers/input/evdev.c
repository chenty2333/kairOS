/**
 * kernel/drivers/input/evdev.c - Event Device Interface
 *
 * Provides /dev/input/eventN character devices for input events.
 */

#include <kairos/devfs.h>
#include <kairos/input.h>
#include <kairos/ioctl.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/poll.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/spinlock.h>
#include <kairos/string.h>
#include <kairos/sync.h>
#include <kairos/types.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>
#include <kairos/wait.h>

#define EVDEV_BUFFER_SIZE 256

/* evdev ioctl commands */
#define EVIOCGNAME(len) _IOC(_IOC_READ, 'E', 0x06, len)
#define EVIOCGID _IOR('E', 0x02, struct input_id)

struct input_id {
    uint16_t bustype;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;
};

struct evdev_client {
    struct input_event buffer[EVDEV_BUFFER_SIZE];
    uint32_t head;
    uint32_t tail;
    spinlock_t lock;
    struct wait_queue wait;
    struct list_head node;
    struct vnode *vnode;
};

struct evdev {
    struct input_dev *input_dev;
    int index;
    struct list_head client_list;
    spinlock_t lock;
};

static struct evdev *evdev_devices[32];
static int evdev_count = 0;
static spinlock_t evdev_global_lock = SPINLOCK_INIT;
static bool devfs_input_dir_created = false;

static int evdev_open(struct file *file);
static void evdev_release(struct file *file);
static ssize_t evdev_fread(struct file *file, void *buf, size_t len);
static int evdev_poll(struct file *file, uint32_t events);
static int evdev_ioctl(struct file *file, uint64_t cmd, uint64_t arg);

static struct file_ops evdev_fops = {
    .open = evdev_open,
    .release = evdev_release,
    .fread = evdev_fread,
    .poll = evdev_poll,
    .ioctl = evdev_ioctl,
};

static uint32_t evdev_client_available(struct evdev_client *client) {
    if (client->head >= client->tail)
        return client->head - client->tail;
    return EVDEV_BUFFER_SIZE - client->tail + client->head;
}

static bool evdev_client_push(struct evdev_client *client,
                              struct input_event *event) {
    uint32_t next_head = (client->head + 1) % EVDEV_BUFFER_SIZE;
    if (next_head == client->tail)
        return false;

    client->buffer[client->head] = *event;
    client->head = next_head;
    return true;
}

static bool evdev_client_pop(struct evdev_client *client,
                             struct input_event *event) {
    if (client->head == client->tail)
        return false;

    *event = client->buffer[client->tail];
    client->tail = (client->tail + 1) % EVDEV_BUFFER_SIZE;
    return true;
}

void evdev_notify_event(struct input_dev *dev, struct input_event *event) {
    if (!dev || !event)
        return;

    bool irq_state = arch_irq_save();
    spin_lock(&dev->lock);

    struct evdev_client *client;
    list_for_each_entry(client, &dev->client_list, node) {
        spin_lock(&client->lock);
        bool pushed = evdev_client_push(client, event);
        spin_unlock(&client->lock);

        if (pushed) {
            wait_queue_wakeup_all(&client->wait);
            if (client->vnode)
                vfs_poll_wake(client->vnode, POLLIN);
        }
    }

    spin_unlock(&dev->lock);
    arch_irq_restore(irq_state);
}

static int evdev_open(struct file *file) {
    if (!file || !file->vnode)
        return -EINVAL;

    struct evdev *evdev = devfs_get_priv(file->vnode);
    if (!evdev)
        return -EINVAL;
    struct evdev_client *client = kzalloc(sizeof(*client));
    if (!client)
        return -ENOMEM;

    spin_init(&client->lock);
    wait_queue_init(&client->wait);
    client->head = 0;
    client->tail = 0;
    client->vnode = file->vnode;
    INIT_LIST_HEAD(&client->node);

    bool irq_state = arch_irq_save();
    spin_lock(&evdev->input_dev->lock);
    list_add_tail(&client->node, &evdev->input_dev->client_list);
    spin_unlock(&evdev->input_dev->lock);
    arch_irq_restore(irq_state);

    file->private_data = client;
    return 0;
}

static void evdev_release(struct file *file) {
    if (!file || !file->private_data)
        return;

    struct evdev_client *client = file->private_data;
    struct evdev *evdev = devfs_get_priv(file->vnode);

    bool irq_state = arch_irq_save();
    spin_lock(&evdev->input_dev->lock);
    list_del(&client->node);
    spin_unlock(&evdev->input_dev->lock);
    arch_irq_restore(irq_state);

    kfree(client);
    file->private_data = NULL;
}

static ssize_t evdev_fread(struct file *file, void *buf, size_t len) {
    if (!file || !file->private_data || !buf)
        return -EINVAL;

    struct evdev_client *client = file->private_data;
    size_t event_size = sizeof(struct input_event);

    if (len < event_size)
        return -EINVAL;

    size_t bytes_read = 0;
    bool nonblock = (file->flags & O_NONBLOCK) != 0;

    while (bytes_read < len) {
        struct input_event event;
        bool has_event = false;

        bool irq_state = arch_irq_save();
        spin_lock(&client->lock);
        has_event = evdev_client_pop(client, &event);
        spin_unlock(&client->lock);
        arch_irq_restore(irq_state);

        if (has_event) {
            if (copy_to_user((uint8_t *)buf + bytes_read, &event, event_size) != 0)
                return bytes_read > 0 ? (ssize_t)bytes_read : -EFAULT;
            bytes_read += event_size;
        } else {
            if (bytes_read > 0)
                break;

            if (nonblock)
                return -EAGAIN;

            int ret = proc_sleep_on(&client->wait, &client->wait, false);
            if (ret < 0)
                return ret;
        }
    }

    return (ssize_t)bytes_read;
}

static int evdev_poll(struct file *file, uint32_t events) {
    if (!file || !file->private_data)
        return 0;

    struct evdev_client *client = file->private_data;
    uint32_t revents = 0;

    if (events & POLLIN) {
        bool irq_state = arch_irq_save();
        spin_lock(&client->lock);
        if (evdev_client_available(client) > 0)
            revents |= POLLIN;
        spin_unlock(&client->lock);
        arch_irq_restore(irq_state);
    }

    return revents;
}

static int evdev_ioctl(struct file *file, uint64_t cmd, uint64_t arg) {
    if (!file || !file->vnode)
        return -EINVAL;

    struct evdev *evdev = devfs_get_priv(file->vnode);
    if (!evdev)
        return -EINVAL;
    struct input_dev *dev = evdev->input_dev;

    if (_IOC_TYPE(cmd) == 'E' && _IOC_NR(cmd) == 0x06) {
        size_t len = _IOC_SIZE(cmd);
        if (len > sizeof(dev->name))
            len = sizeof(dev->name);
        if (copy_to_user((void *)arg, dev->name, len) != 0)
            return -EFAULT;
        return 0;
    }

    if (cmd == EVIOCGID) {
        struct input_id id;
        id.bustype = dev->id_bus;
        id.vendor = dev->id_vendor;
        id.product = dev->id_product;
        id.version = dev->id_version;
        if (copy_to_user((void *)arg, &id, sizeof(id)) != 0)
            return -EFAULT;
        return 0;
    }

    return -EINVAL;
}

int evdev_register_device(struct input_dev *dev) {
    if (!dev)
        return -EINVAL;

    if (!devfs_input_dir_created) {
        devfs_register_dir("/dev/input");
        devfs_input_dir_created = true;
    }

    struct evdev *evdev = kzalloc(sizeof(*evdev));
    if (!evdev)
        return -ENOMEM;

    spin_init(&evdev->lock);
    INIT_LIST_HEAD(&evdev->client_list);
    evdev->input_dev = dev;

    bool irq_state = arch_irq_save();
    spin_lock(&evdev_global_lock);
    evdev->index = evdev_count;
    evdev_devices[evdev_count++] = evdev;
    spin_unlock(&evdev_global_lock);
    arch_irq_restore(irq_state);

    char name[32];
    snprintf(name, sizeof(name), "/dev/input/event%d", evdev->index);

    int ret = devfs_register_node(name, &evdev_fops, evdev);
    if (ret < 0) {
        pr_err("evdev: failed to register %s\n", name);
        kfree(evdev);
        return ret;
    }

    pr_info("evdev: registered %s for '%s'\n", name, dev->name);

    return 0;
}
