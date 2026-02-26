# 51 — DRM-Lite Display Subsystem

## Overview

drm_lite is a lightweight display driver framework. It exposes `/dev/fb<N>` via devfs with ioctl-based buffer create/map/destroy/present. The core layer handles buffer lifecycle and userspace mappings; backend-specific operations dispatch through `struct drm_lite_ops`.

Current backend: Limine framebuffer (direct writes to boot-provided linear framebuffer).

## Backend Interface (struct drm_lite_ops)

- `present`: blit buffer region to display target. Called with `ldev->lock` held.
- `get_info`: populate `drm_lite_info`. Called without locks.
- `cleanup`: optional. Called from `drm_lite_remove()` to free backend-private resources.

Backend-private data goes in `ldev->backend_data`. Limine backend uses `ldev->fb` / `ldev->fb_kva` directly.

## Core Layer

- Buffer create (page alloc), map (`mm_map_user_pages`), destroy (refcount → free)
- ioctl parsing and uAPI copy (`copy_from_user` / `copy_to_user`)
- Process-exit mapping cleanup (`proc_register_exit_callback`)
- `drm_lite_copy_from_pages()`: page-scatter → linear copy utility, reusable by backends

## Limine Backend

- `limine_fb_present()`: copy buffer pages to `fb_kva`. Contiguous fast path (single memcpy) or scatter slow path (per-row).
- `limine_fb_get_info()`: fills from `ldev->fb`, format fixed to `DRM_LITE_FORMAT_XRGB8888`.

## Adding a New Backend

1. Implement `struct drm_lite_ops` callbacks
2. Set `ldev->ops` (and optionally `ldev->backend_data`) in probe
3. Implement `cleanup` if backend allocates private resources

## uAPI (include/kairos/drm_lite.h)

`DRM_LITE_IOC_GET_INFO`, `CREATE_BUFFER`, `MAP_BUFFER`, `PRESENT`, `DESTROY_BUFFER`, `LIST_BUFFERS`.

Shared buffer transfer (compositor support):
- `EXPORT_HANDLE`: wraps device-local buffer handle in kobj (type `KOBJ_TYPE_BUFFER`), returns process handle (khandle). Each export creates new kobj with independent damage state.
- `IMPORT_HANDLE`: accepts khandle (from IPC transfer), validates same-device, returns device-local handle. Reuses existing handle if buffer already in device list.
- `DAMAGE`: marks rect dirty, merges into bounding box, wakes pollers (POLLIN) and waiters.

Buffer kobj ops: poll (POLLIN when damage pending, POLLOUT always), read (returns damage rect, clears pending), poll_attach/detach (epoll).

Flow: app CREATE_BUFFER → EXPORT_HANDLE → kchannel_send → compositor kchannel_recv → IMPORT_HANDLE → app DAMAGE → compositor poll/read → PRESENT.

## Current Limitations

- XRGB8888 only, 32bpp
- Single `global_drm_device`; process-exit cleanup only covers first device
- Synchronous memcpy present, no vsync / page-flip

Related references:
- references/50_DRIVERS_BUS_DISCOVERY.md
