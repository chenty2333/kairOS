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

#define DRM_LITE_MAX_BUFFERS 16

struct drm_lite_mapping {
    struct list_head list;      // 链接到 drm_lite_buffer->mappings
    pid_t pid;                   // 拥有此映射的进程 PID
    vaddr_t user_va;            // 用户空间虚拟地址
    struct mm_struct *mm;       // 进程的 mm_struct（用于 cleanup）
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

    // 新增字段
    atomic_t refcount;              // 引用计数
    struct mutex lock;              // 保护 mappings 列表
    struct list_head mappings;      // drm_lite_mapping 列表

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
static struct drm_lite_device *global_drm_device = NULL;  // 全局设备指针

// Forward declarations
static void drm_lite_buffer_destroy(struct drm_lite_buffer *buf);
static void drm_lite_buffer_unmap_all(struct drm_lite_buffer *buf);

// 增加引用计数
static inline void drm_lite_buffer_get(struct drm_lite_buffer *buf)
{
    atomic_inc(&buf->refcount);
}

// 减少引用计数，为 0 时销毁
static void drm_lite_buffer_put(struct drm_lite_buffer *buf)
{
    if (atomic_dec_return(&buf->refcount) == 0) {
        drm_lite_buffer_destroy(buf);
    }
}

// 实际销毁函数（从所有进程 unmap，释放页面）
static void drm_lite_buffer_destroy(struct drm_lite_buffer *buf)
{
    // 1. Unmap from all processes
    drm_lite_buffer_unmap_all(buf);

    // 2. Free physical pages
    for (size_t i = 0; i < buf->page_count; i++) {
        pmm_free_page(buf->pages[i]);
    }

    // 3. Free metadata
    kfree(buf->pages);
    kfree(buf);
}

// 添加映射记录
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

    drm_lite_buffer_get(buf);  // 增加引用计数
    return 0;
}

// 移除指定进程的映射
static void drm_lite_buffer_remove_mapping(struct drm_lite_buffer *buf, pid_t pid)
{
    struct drm_lite_mapping *mapping, *tmp;

    mutex_lock(&buf->lock);
    list_for_each_entry_safe(mapping, tmp, &buf->mappings, list) {
        if (mapping->pid == pid) {
            list_del(&mapping->list);
            mutex_unlock(&buf->lock);

            // Unmap from process address space
            mm_munmap(mapping->mm, mapping->user_va, buf->size);
            kfree(mapping);
            drm_lite_buffer_put(buf);  // 减少引用计数
            return;
        }
    }
    mutex_unlock(&buf->lock);
}

// 从所有进程 unmap（销毁前调用）
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
            drm_lite_buffer_remove_mapping(buf, p->pid);
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

        int ret = drm_lite_present(ldev, buf);
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

        drm_lite_buffer_put(buf);  // 减少引用计数，可能触发销毁
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

static struct file_ops drm_lite_ops = {
    .ioctl = drm_lite_ioctl,
};

// 进程退出清理回调
static void drm_lite_exit_callback(struct process *p)
{
    struct drm_lite_device *ldev = global_drm_device;

    if (!ldev) {
        return;
    }

    struct drm_lite_buffer *buf;
    mutex_lock(&ldev->lock);
    list_for_each_entry(buf, &ldev->buffers, list) {
        drm_lite_buffer_remove_mapping(buf, p->pid);
    }
    mutex_unlock(&ldev->lock);
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

    // 保存全局设备指针
    if (!global_drm_device) {
        global_drm_device = ldev;
    }

    // 注册进程退出回调（只注册一次）
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
