/**
 * kernel/include/kairos/drm_lite.h - Minimal DRM-lite uAPI
 */

#ifndef _KAIROS_DRM_LITE_H
#define _KAIROS_DRM_LITE_H

#include <kairos/types.h>

#define DRM_LITE_IOC_GET_INFO       0xF001
#define DRM_LITE_IOC_CREATE_BUFFER  0xF002
#define DRM_LITE_IOC_MAP_BUFFER     0xF003
#define DRM_LITE_IOC_PRESENT        0xF004
#define DRM_LITE_IOC_DESTROY_BUFFER 0xF005
#define DRM_LITE_IOC_LIST_BUFFERS   0xF006

#define DRM_LITE_MAX_BUFFERS        16

enum drm_lite_format {
    DRM_LITE_FORMAT_XRGB8888 = 1,
};

struct drm_lite_info {
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint32_t format;
    uint32_t max_buffers;
};

struct drm_lite_create {
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint32_t handle;
    uint32_t pitch;
    uint64_t size;
};

struct drm_lite_map {
    uint32_t handle;
    uint64_t user_va;
};

struct drm_lite_present {
    uint32_t handle;
    uint32_t flags;
    uint32_t x, y;              /* dirty rect origin (0,0 = top-left) */
    uint32_t width, height;     /* dirty rect size (0 = full extent) */
};

struct drm_lite_destroy {
    uint32_t handle;
};

struct drm_lite_buffer_list {
    uint32_t count;
    uint32_t handles[DRM_LITE_MAX_BUFFERS];
};

#endif /* _KAIROS_DRM_LITE_H */
