/**
 * kernel/drivers/gpu/drm_lite.c - Limine framebuffer DRM-lite device
 */

#include <boot/limine.h>
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

#define DRM_LITE_MAX_BUFFERS 16

struct drm_lite_buffer {
    uint32_t handle;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t format;
    uint64_t size;
    size_t page_count;
    paddr_t *pages;
    bool mapped;
    struct list_head list;
};

struct drm_lite_device {
    struct device *dev;
    struct boot_framebuffer fb;
    void *fb_kva;
    uint32_t card_id;
    uint32_t next_handle;
    uint32_t buffer_count;
    struct mutex lock;
    struct list_head buffers;
};

static uint32_t drm_lite_next_card = 0;

static struct drm_lite_buffer *drm_lite_find_buffer(struct drm_lite_device *ldev,
                                                    uint32_t handle) {
    struct drm_lite_buffer *buf;
    list_for_each_entry(buf, &ldev->buffers, list) {
        if (buf->handle == handle)
            return buf;
    }
    return NULL;
}

static void drm_lite_copy_from_pages(uint8_t *dst,
                                     const struct drm_lite_buffer *buf,
                                     size_t src_off, size_t bytes) {
    size_t remaining = bytes;
    while (remaining > 0) {
        size_t page_idx = src_off / CONFIG_PAGE_SIZE;
        size_t page_off = src_off % CONFIG_PAGE_SIZE;
        size_t chunk = MIN(remaining, CONFIG_PAGE_SIZE - page_off);
        if (page_idx >= buf->page_count)
            break;
        uint8_t *src =
            (uint8_t *)phys_to_virt(buf->pages[page_idx]) + page_off;
        memcpy(dst, src, chunk);
        dst += chunk;
        src_off += chunk;
        remaining -= chunk;
    }
}

static int drm_lite_present(struct drm_lite_device *ldev,
                            struct drm_lite_buffer *buf) {
    if (!ldev || !buf)
        return -EINVAL;
    size_t height = MIN((size_t)buf->height, (size_t)ldev->fb.height);
    size_t copy_bytes = MIN((size_t)buf->pitch, (size_t)ldev->fb.pitch);
    uint8_t *dst = (uint8_t *)ldev->fb_kva;
    for (size_t y = 0; y < height; y++) {
        size_t src_off = y * (size_t)buf->pitch;
        drm_lite_copy_from_pages(dst + y * (size_t)ldev->fb.pitch, buf,
                                 src_off, copy_bytes);
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
        if (!arg)
            return -EFAULT;
        struct drm_lite_info info = {
            .width = ldev->fb.width,
            .height = ldev->fb.height,
            .pitch = ldev->fb.pitch,
            .bpp = ldev->fb.bpp,
            .format = DRM_LITE_FORMAT_XRGB8888,
            .max_buffers = DRM_LITE_MAX_BUFFERS,
        };
        if (copy_to_user((void *)arg, &info, sizeof(info)) < 0)
            return -EFAULT;
        return 0;
    }
    case DRM_LITE_IOC_CREATE_BUFFER: {
        if (!arg)
            return -EFAULT;
        struct drm_lite_create req;
        if (copy_from_user(&req, (void *)arg, sizeof(req)) < 0)
            return -EFAULT;
        if (req.format != DRM_LITE_FORMAT_XRGB8888)
            return -EINVAL;
        if (req.width == 0)
            req.width = ldev->fb.width;
        if (req.height == 0)
            req.height = ldev->fb.height;
        if (req.width > ldev->fb.width || req.height > ldev->fb.height)
            return -EINVAL;

        uint64_t pitch = (uint64_t)req.width * 4;
        uint64_t size = pitch * (uint64_t)req.height;
        size_t aligned = ALIGN_UP(size, CONFIG_PAGE_SIZE);
        size_t page_count = aligned / CONFIG_PAGE_SIZE;

        struct drm_lite_buffer *buf = kzalloc(sizeof(*buf));
        if (!buf)
            return -ENOMEM;
        paddr_t *pages = kzalloc(sizeof(*pages) * page_count);
        if (!pages) {
            kfree(buf);
            return -ENOMEM;
        }

        for (size_t i = 0; i < page_count; i++) {
            paddr_t pa = pmm_alloc_page();
            if (!pa) {
                for (size_t j = 0; j < i; j++)
                    pmm_free_page(pages[j]);
                kfree(pages);
                kfree(buf);
                return -ENOMEM;
            }
            pages[i] = pa;
        }

        mutex_lock(&ldev->lock);
        if (ldev->buffer_count >= DRM_LITE_MAX_BUFFERS) {
            mutex_unlock(&ldev->lock);
            for (size_t i = 0; i < page_count; i++)
                pmm_free_page(pages[i]);
            kfree(pages);
            kfree(buf);
            return -ENOSPC;
        }
        if (ldev->next_handle == 0)
            ldev->next_handle = 1;
        buf->handle = ldev->next_handle++;
        buf->width = req.width;
        buf->height = req.height;
        buf->pitch = (uint32_t)pitch;
        buf->format = req.format;
        buf->size = size;
        buf->page_count = page_count;
        buf->pages = pages;
        buf->mapped = false;
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
            for (size_t i = 0; i < page_count; i++)
                pmm_free_page(pages[i]);
            kfree(pages);
            kfree(buf);
            return -EFAULT;
        }
        return 0;
    }
    case DRM_LITE_IOC_MAP_BUFFER: {
        if (!arg)
            return -EFAULT;
        struct drm_lite_map req;
        if (copy_from_user(&req, (void *)arg, sizeof(req)) < 0)
            return -EFAULT;

        mutex_lock(&ldev->lock);
        struct drm_lite_buffer *buf = drm_lite_find_buffer(ldev, req.handle);
        if (!buf) {
            mutex_unlock(&ldev->lock);
            return -ENOENT;
        }
        if (buf->mapped) {
            mutex_unlock(&ldev->lock);
            return -EBUSY;
        }
        struct process *p = proc_current();
        if (!p || !p->mm) {
            mutex_unlock(&ldev->lock);
            return -EINVAL;
        }

        vaddr_t user_va = 0;
        int ret = mm_map_user_pages(p->mm, (size_t)buf->size,
                                    VM_READ | VM_WRITE, VM_SHARED,
                                    buf->pages, buf->page_count, &user_va);
        if (ret < 0) {
            mutex_unlock(&ldev->lock);
            return ret;
        }
        buf->mapped = true;
        mutex_unlock(&ldev->lock);

        req.user_va = (uint64_t)user_va;
        if (copy_to_user((void *)arg, &req, sizeof(req)) < 0) {
            mm_munmap(p->mm, user_va, (size_t)buf->size);
            mutex_lock(&ldev->lock);
            buf->mapped = false;
            mutex_unlock(&ldev->lock);
            return -EFAULT;
        }
        return 0;
    }
    case DRM_LITE_IOC_PRESENT: {
        if (!arg)
            return -EFAULT;
        struct drm_lite_present req;
        if (copy_from_user(&req, (void *)arg, sizeof(req)) < 0)
            return -EFAULT;
        mutex_lock(&ldev->lock);
        struct drm_lite_buffer *buf = drm_lite_find_buffer(ldev, req.handle);
        if (!buf) {
            mutex_unlock(&ldev->lock);
            return -ENOENT;
        }
        int ret = drm_lite_present(ldev, buf);
        mutex_unlock(&ldev->lock);
        return ret;
    }
    case DRM_LITE_IOC_DESTROY_BUFFER: {
        if (!arg)
            return -EFAULT;
        struct drm_lite_destroy req;
        if (copy_from_user(&req, (void *)arg, sizeof(req)) < 0)
            return -EFAULT;

        struct drm_lite_buffer *buf = NULL;
        mutex_lock(&ldev->lock);
        buf = drm_lite_find_buffer(ldev, req.handle);
        if (buf)
            list_del(&buf->list);
        if (buf)
            ldev->buffer_count--;
        mutex_unlock(&ldev->lock);
        if (!buf)
            return -ENOENT;

        for (size_t i = 0; i < buf->page_count; i++)
            pmm_put_page(buf->pages[i]);
        kfree(buf->pages);
        kfree(buf);
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

static struct file_ops drm_lite_ops = {
    .ioctl = drm_lite_ioctl,
};

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
