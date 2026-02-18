/**
 * kernel/drivers/gpu/drm_lite.c - Limine framebuffer DRM-lite device
 */

#include <boot/limine.h>
#include <kairos/atomic.h>
#include <kairos/boot.h>
#include <kairos/config.h>
#include <kairos/devfs.h>
#include <kairos/device.h>
#include <kairos/drm_lite.h>
#include <kairos/list.h>
#include <kairos/mm.h>
#include <kairos/platform.h>
#include <kairos/printk.h>
#include <kairos/process.h>
#include <kairos/string.h>
#include <kairos/uaccess.h>
#include <kairos/vfs.h>

/* Per-process mapping record, linked into drm_lite_buffer.mappings */
struct drm_lite_mapping {
    struct list_head list;
    pid_t pid;
    vaddr_t user_va;
    struct mm_struct *mm;
};

struct drm_lite_buffer {
    uint32_t handle;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t format;
    uint64_t size;
    size_t page_count;
    paddr_t *pages;

    atomic_t refcount;
    struct mutex lock;              /* protects mappings list */
    struct list_head mappings;

    struct list_head list;          /* link into drm_lite_device.buffers */
};

struct drm_lite_device {
    struct device *dev;
    struct boot_framebuffer fb;
    void *fb_kva;
    uint32_t card_id;
    uint32_t next_handle;
    uint32_t buffer_count;
    struct mutex lock;              /* protects buffers list */
    struct list_head buffers;
    struct drm_lite_fb_ops *ops;
};

static uint32_t drm_lite_next_card = 0;
static struct drm_lite_device *global_drm_device = NULL;

/* Forward declarations */
static void drm_lite_buffer_free(struct drm_lite_buffer *buf);
static void drm_lite_buffer_unmap_all(struct drm_lite_buffer *buf);

static inline void drm_lite_buffer_get(struct drm_lite_buffer *buf)
{
    atomic_inc(&buf->refcount);
}

/*
 * Drop one reference.  When the last reference is released the buffer
 * pages are freed.  Callers must have already removed the buffer from
 * the device list and unmapped it from every process before the final
 * put (or accept that drm_lite_buffer_free will do so).
 */
static void drm_lite_buffer_put(struct drm_lite_buffer *buf)
{
    if (atomic_dec_return(&buf->refcount) == 0) {
        drm_lite_buffer_free(buf);
    }
}

/* Release physical pages and metadata.  Called only when refcount == 0. */
static void drm_lite_buffer_free(struct drm_lite_buffer *buf)
{
    /* Safety: unmap any stale mappings that were not cleaned up */
    drm_lite_buffer_unmap_all(buf);

    for (size_t i = 0; i < buf->page_count; i++) {
        pmm_free_page(buf->pages[i]);
    }
    kfree(buf->pages);
    kfree(buf);
}

/* Record a new mapping and take a reference on the buffer. */
static int drm_lite_buffer_add_mapping(struct drm_lite_buffer *buf,
                                       pid_t pid, vaddr_t user_va,
                                       struct mm_struct *mm)
{
    struct drm_lite_mapping *mapping = kzalloc(sizeof(*mapping));
    if (!mapping) {
        return -ENOMEM;
    }

    mapping->pid = pid;
    mapping->user_va = user_va;
    mapping->mm = mm;

    mutex_lock(&buf->lock);
    list_add_tail(&mapping->list, &buf->mappings);
    mutex_unlock(&buf->lock);

    drm_lite_buffer_get(buf);
    return 0;
}

/*
 * Remove ALL mappings belonging to @pid from @buf, unmapping each one
 * from the process address space and dropping the corresponding
 * reference.  Safe to call even if @pid has no mappings on @buf.
 *
 * IMPORTANT: the caller must NOT hold ldev->lock while calling this,
 * because the final drm_lite_buffer_put may free the buffer.
 */
static void drm_lite_buffer_remove_mappings_for_pid(
    struct drm_lite_buffer *buf, pid_t pid)
{
    struct drm_lite_mapping *mapping, *tmp;
    struct list_head removed;

    INIT_LIST_HEAD(&removed);

    /* Collect matching entries under the lock */
    mutex_lock(&buf->lock);
    list_for_each_entry_safe(mapping, tmp, &buf->mappings, list) {
        if (mapping->pid == pid) {
            list_del(&mapping->list);
            list_add_tail(&mapping->list, &removed);
        }
    }
    mutex_unlock(&buf->lock);

    /* Unmap and release outside the lock */
    list_for_each_entry_safe(mapping, tmp, &removed, list) {
        list_del(&mapping->list);
        mm_munmap(mapping->mm, mapping->user_va, buf->size);
        kfree(mapping);
        drm_lite_buffer_put(buf);
    }
}

/*
 * Unmap every mapping and free the mapping records.
 * Does NOT touch the refcount — this is used during the final
 * destroy path where refcount is already zero.
 */
static void drm_lite_buffer_unmap_all(struct drm_lite_buffer *buf)
{
    struct drm_lite_mapping *mapping, *tmp;

    mutex_lock(&buf->lock);
    list_for_each_entry_safe(mapping, tmp, &buf->mappings, list) {
        list_del(&mapping->list);
        mm_munmap(mapping->mm, mapping->user_va, buf->size);
        kfree(mapping);
    }
    mutex_unlock(&buf->lock);
}

static struct drm_lite_buffer *drm_lite_find_buffer(struct drm_lite_device *ldev,
                                                    uint32_t handle)
{
    struct drm_lite_buffer *buf;

    list_for_each_entry(buf, &ldev->buffers, list) {
        if (buf->handle == handle) {
            return buf;
        }
    }
    return NULL;
}

static void drm_lite_copy_from_pages(uint8_t *dst,
                                     const struct drm_lite_buffer *buf,
                                     size_t src_off, size_t bytes)
{
    size_t remaining = bytes;

    while (remaining > 0) {
        size_t page_idx = src_off / CONFIG_PAGE_SIZE;
        size_t page_off = src_off % CONFIG_PAGE_SIZE;
        size_t chunk = MIN(remaining, CONFIG_PAGE_SIZE - page_off);

        if (page_idx >= buf->page_count) {
            break;
        }
        uint8_t *src =
            (uint8_t *)phys_to_virt(buf->pages[page_idx]) + page_off;
        memcpy(dst, src, chunk);
        dst += chunk;
        src_off += chunk;
        remaining -= chunk;
    }
}

/*
 * Present buffer contents (or a sub-rectangle) to the framebuffer.
 * When w==0 && h==0 the entire buffer is copied (backward compatible).
 */
static int drm_lite_present(struct drm_lite_device *ldev,
                            struct drm_lite_buffer *buf,
                            uint32_t x, uint32_t y,
                            uint32_t w, uint32_t h)
{
    if (!ldev || !buf) {
        return -EINVAL;
    }

    /* Default: full buffer */
    if (w == 0) {
        w = MIN(buf->width, ldev->fb.width) - x;
    }
    if (h == 0) {
        h = MIN(buf->height, ldev->fb.height) - y;
    }

    /* Clamp to both buffer and framebuffer bounds */
    if (x >= buf->width || y >= buf->height) {
        return -EINVAL;
    }
    if (x + w > buf->width) {
        w = buf->width - x;
    }
    if (y + h > buf->height) {
        h = buf->height - y;
    }
    if (x + w > ldev->fb.width) {
        w = ldev->fb.width - x;
    }
    if (y + h > ldev->fb.height) {
        h = ldev->fb.height - y;
    }

    uint8_t *dst = (uint8_t *)ldev->fb_kva;
    uint32_t bpp_bytes = 4; /* XRGB8888 */

    /* Check whether the buffer pages are physically contiguous */
    bool contiguous = true;
    for (size_t i = 1; i < buf->page_count; i++) {
        if (buf->pages[i] != buf->pages[i - 1] + CONFIG_PAGE_SIZE) {
            contiguous = false;
            break;
        }
    }

    if (contiguous && x == 0 && w == buf->width &&
        buf->pitch == ldev->fb.pitch) {
        /*
         * Fast path: contiguous pages, full-width, matching pitch.
         * Single memcpy for the entire dirty region.
         */
        uint8_t *src = (uint8_t *)phys_to_virt(buf->pages[0]);
        size_t src_off = (size_t)y * buf->pitch;
        size_t dst_off = (size_t)y * ldev->fb.pitch;
        size_t copy_size = (size_t)h * buf->pitch;

        memcpy(dst + dst_off, src + src_off, copy_size);
    } else {
        /* Slow path: per-row copy through page helper */
        for (uint32_t row = 0; row < h; row++) {
            size_t src_off = (size_t)(y + row) * buf->pitch +
                             (size_t)x * bpp_bytes;
            size_t dst_off = (size_t)(y + row) * ldev->fb.pitch +
                             (size_t)x * bpp_bytes;
            size_t copy_bytes = (size_t)w * bpp_bytes;

            drm_lite_copy_from_pages(dst + dst_off, buf,
                                     src_off, copy_bytes);
        }
    }

    return 0;
}

static int drm_lite_ioctl(struct vnode *vn, uint64_t cmd, uint64_t arg) {
    struct drm_lite_device *ldev =
        (struct drm_lite_device *)devfs_get_priv(vn);
    if (!ldev)
        return -ENODEV;

    switch (cmd) {
    case DRM_LITE_IOC_GET_INFO: {
        if (!arg) {
            return -EFAULT;
        }
        struct drm_lite_info info = {
            .width = ldev->fb.width,
            .height = ldev->fb.height,
            .pitch = ldev->fb.pitch,
            .bpp = ldev->fb.bpp,
            .format = DRM_LITE_FORMAT_XRGB8888,
            .max_buffers = DRM_LITE_MAX_BUFFERS,
        };
        if (copy_to_user((void *)arg, &info, sizeof(info)) < 0) {
            return -EFAULT;
        }
        return 0;
    }
    case DRM_LITE_IOC_CREATE_BUFFER: {
        if (!arg) {
            return -EFAULT;
        }
        struct drm_lite_create req;
        if (copy_from_user(&req, (void *)arg, sizeof(req)) < 0) {
            return -EFAULT;
        }
        if (req.format != DRM_LITE_FORMAT_XRGB8888) {
            return -EINVAL;
        }
        if (req.width == 0) {
            req.width = ldev->fb.width;
        }
        if (req.height == 0) {
            req.height = ldev->fb.height;
        }
        if (req.width > ldev->fb.width || req.height > ldev->fb.height) {
            return -EINVAL;
        }

        uint64_t pitch = (uint64_t)req.width * 4;
        uint64_t size = pitch * (uint64_t)req.height;
        size_t aligned = ALIGN_UP(size, CONFIG_PAGE_SIZE);
        size_t page_count = aligned / CONFIG_PAGE_SIZE;

        struct drm_lite_buffer *buf = kzalloc(sizeof(*buf));
        if (!buf) {
            return -ENOMEM;
        }
        paddr_t *pages = kzalloc(sizeof(*pages) * page_count);
        if (!pages) {
            kfree(buf);
            return -ENOMEM;
        }

        for (size_t i = 0; i < page_count; i++) {
            paddr_t pa = pmm_alloc_page();
            if (!pa) {
                for (size_t j = 0; j < i; j++) {
                    pmm_free_page(pages[j]);
                }
                kfree(pages);
                kfree(buf);
                return -ENOMEM;
            }
            pages[i] = pa;
        }

        mutex_lock(&ldev->lock);
        if (ldev->buffer_count >= DRM_LITE_MAX_BUFFERS) {
            mutex_unlock(&ldev->lock);
            for (size_t i = 0; i < page_count; i++) {
                pmm_free_page(pages[i]);
            }
            kfree(pages);
            kfree(buf);
            return -ENOSPC;
        }
        if (ldev->next_handle == 0) {
            ldev->next_handle = 1;
        }
        buf->handle = ldev->next_handle++;
        buf->width = req.width;
        buf->height = req.height;
        buf->pitch = (uint32_t)pitch;
        buf->format = req.format;
        buf->size = size;
        buf->page_count = page_count;
        buf->pages = pages;
        atomic_init(&buf->refcount, 1);
        mutex_init(&buf->lock, "drm_buffer_lock");
        INIT_LIST_HEAD(&buf->mappings);
        list_add_tail(&buf->list, &ldev->buffers);
        ldev->buffer_count++;
        mutex_unlock(&ldev->lock);

        req.handle = buf->handle;
        req.pitch = buf->pitch;
        req.size = buf->size;
        if (copy_to_user((void *)arg, &req, sizeof(req)) < 0) {
            mutex_lock(&ldev->lock);
            list_del(&buf->list);
            ldev->buffer_count--;
            mutex_unlock(&ldev->lock);
            for (size_t i = 0; i < page_count; i++) {
                pmm_free_page(pages[i]);
            }
            kfree(pages);
            kfree(buf);
            return -EFAULT;
        }
        return 0;
    }
    case DRM_LITE_IOC_MAP_BUFFER: {
        struct drm_lite_map req;
        struct drm_lite_buffer *buf = NULL;
        vaddr_t user_va = 0;
        int ret = 0;

        if (!arg) {
            return -EFAULT;
        }
        if (copy_from_user(&req, (void *)arg, sizeof(req)) < 0) {
            return -EFAULT;
        }

        mutex_lock(&ldev->lock);
        buf = drm_lite_find_buffer(ldev, req.handle);
        if (!buf) {
            ret = -ENOENT;
            goto err_unlock;
        }

        struct process *p = proc_current();
        if (!p || !p->mm) {
            ret = -EINVAL;
            goto err_unlock;
        }

        ret = mm_map_user_pages(p->mm, (size_t)buf->size,
                                VM_READ | VM_WRITE, VM_SHARED,
                                buf->pages, buf->page_count, &user_va);
        if (ret < 0) {
            goto err_unlock;
        }

        ret = drm_lite_buffer_add_mapping(buf, p->pid, user_va, p->mm);
        if (ret < 0) {
            goto err_unmap;
        }

        mutex_unlock(&ldev->lock);

        req.user_va = (uint64_t)user_va;
        if (copy_to_user((void *)arg, &req, sizeof(req)) < 0) {
            drm_lite_buffer_remove_mappings_for_pid(buf, p->pid);
            return -EFAULT;
        }
        return 0;

    err_unmap:
        mm_munmap(p->mm, user_va, (size_t)buf->size);
    err_unlock:
        mutex_unlock(&ldev->lock);
        return ret;
    }
    case DRM_LITE_IOC_PRESENT: {
        if (!arg) {
            return -EFAULT;
        }
        struct drm_lite_present req;
        if (copy_from_user(&req, (void *)arg, sizeof(req)) < 0) {
            return -EFAULT;
        }

        mutex_lock(&ldev->lock);
        struct drm_lite_buffer *buf = drm_lite_find_buffer(ldev, req.handle);
        if (!buf) {
            mutex_unlock(&ldev->lock);
            return -ENOENT;
        }

        int ret = drm_lite_present(ldev, buf,
                                   req.x, req.y, req.width, req.height);
        mutex_unlock(&ldev->lock);
        return ret;
    }
    case DRM_LITE_IOC_DESTROY_BUFFER: {
        if (!arg) {
            return -EFAULT;
        }
        struct drm_lite_destroy req;
        if (copy_from_user(&req, (void *)arg, sizeof(req)) < 0) {
            return -EFAULT;
        }

        struct drm_lite_buffer *buf = NULL;
        mutex_lock(&ldev->lock);
        buf = drm_lite_find_buffer(ldev, req.handle);
        if (buf) {
            list_del(&buf->list);
            ldev->buffer_count--;
        }
        mutex_unlock(&ldev->lock);

        if (!buf) {
            return -ENOENT;
        }

        drm_lite_buffer_put(buf);
        return 0;
    }
    case DRM_LITE_IOC_LIST_BUFFERS: {
        if (!arg) {
            return -EFAULT;
        }
        struct drm_lite_buffer_list blist;
        struct drm_lite_buffer *buf;

        memset(&blist, 0, sizeof(blist));

        mutex_lock(&ldev->lock);
        list_for_each_entry(buf, &ldev->buffers, list) {
            if (blist.count >= DRM_LITE_MAX_BUFFERS) {
                break;
            }
            blist.handles[blist.count++] = buf->handle;
        }
        mutex_unlock(&ldev->lock);

        if (copy_to_user((void *)arg, &blist, sizeof(blist)) < 0) {
            return -EFAULT;
        }
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

static struct file_ops drm_lite_ops = {
    .ioctl = drm_lite_ioctl,
};

/*
 * Process-exit cleanup callback.
 *
 * We must not hold ldev->lock while calling remove_mappings_for_pid
 * because the final buffer_put may free the buffer.  Instead we take
 * a snapshot of buffer pointers (with an extra ref each) under the
 * device lock, then process them without the device lock held.
 */
static void drm_lite_exit_callback(struct process *p)
{
    struct drm_lite_device *ldev = global_drm_device;
    struct drm_lite_buffer *buf;
    struct drm_lite_buffer *snapshot[DRM_LITE_MAX_BUFFERS];
    int count = 0;

    if (!ldev) {
        return;
    }

    /* Snapshot buffer pointers under device lock */
    mutex_lock(&ldev->lock);
    list_for_each_entry(buf, &ldev->buffers, list) {
        drm_lite_buffer_get(buf);
        snapshot[count++] = buf;
    }
    mutex_unlock(&ldev->lock);

    /* Remove mappings without holding device lock */
    for (int i = 0; i < count; i++) {
        drm_lite_buffer_remove_mappings_for_pid(snapshot[i], p->pid);
        drm_lite_buffer_put(snapshot[i]);
    }
}

static int drm_lite_probe(struct device *dev) {
    if (!dev || !dev->platform_data)
        return -EINVAL;
    struct boot_framebuffer *fb = (struct boot_framebuffer *)dev->platform_data;
    if (!fb->phys || !fb->size)
        return -EINVAL;
    if (fb->memory_model != LIMINE_FRAMEBUFFER_RGB)
        return -ENODEV;
    if (fb->bpp != 32 || fb->red_mask_size != 8 ||
        fb->green_mask_size != 8 || fb->blue_mask_size != 8 ||
        fb->red_mask_shift != 16 || fb->green_mask_shift != 8 ||
        fb->blue_mask_shift != 0)
        return -ENODEV;

    struct drm_lite_device *ldev = kzalloc(sizeof(*ldev));
    if (!ldev)
        return -ENOMEM;
    ldev->dev = dev;
    ldev->fb = *fb;
    ldev->fb_kva = phys_to_virt(fb->phys);
    ldev->card_id = drm_lite_next_card++;
    ldev->next_handle = 1;
    mutex_init(&ldev->lock, "drm_lite_lock");
    INIT_LIST_HEAD(&ldev->buffers);

    dev_set_drvdata(dev, ldev);

    if (!global_drm_device) {
        global_drm_device = ldev;
    }

    /* Register process-exit callback once across all devices */
    static bool callback_registered = false;
    if (!callback_registered) {
        proc_register_exit_callback(drm_lite_exit_callback);
        callback_registered = true;
    }

    char path[64];
    snprintf(path, sizeof(path), "/dev/fb%u", ldev->card_id);
    devfs_register_node(path, &drm_lite_ops, ldev);

    pr_info("drm-lite: registered %s (%ux%u@%u)\n", path, ldev->fb.width,
            ldev->fb.height, ldev->fb.bpp);
    return 0;
}

static void drm_lite_remove(struct device *dev) {
    (void)dev;
}

struct driver drm_lite_driver = {
    .name = "limine-fb",
    .compatible = "limine,framebuffer",
    .bus = &platform_bus_type,
    .probe = drm_lite_probe,
    .remove = drm_lite_remove,
};
