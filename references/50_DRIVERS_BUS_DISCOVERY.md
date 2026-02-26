# 50 — Drivers / Bus / Device Discovery + Network Overview

## Device Model (core/dev/device.c)

Three core abstractions (include/kairos/device.h):
- bus_type: bus type, provides match() method to match devices and drivers
- device: device instance, contains name, compatible, bus, driver, resources (MMIO/IRQ), platform_data, sysfs_node
- driver: driver, contains name, compatible, bus, probe(), remove()

Global linked lists: bus_list, device_list, driver_list, protected by device_model_lock.

Matching flow:
- device_register(): after registering a device, immediately iterates driver_list to attempt matching
- driver_register(): after registering a driver, immediately iterates device_list to attempt matching
- bus_match_probe_locked(): calls bus->match() first (if available), otherwise matches by exact name; on match, releases lock and calls drv->probe()

Device registration automatically creates a sysfs node under /sys/devices/.

## Bus Implementations

Platform bus (bus/platform.c):
- For MMIO devices (virtio-mmio, framebuffer, etc.)
- Match strategy: exact name match first, then compatible string match
- platform_bus_enumerate(): iterates firmware descriptor table (fw_for_each_desc), creates a platform device for each descriptor and registers it
- Driver-facing IRQ helpers are available for platform devices:
  `platform_device_get_irq()`, `platform_device_request_irq()`,
  `platform_device_free_irq()`, `platform_device_free_irq_sync()`

PCI bus (bus/pci.c):
- ECAM config space access (pci_read/write_config_8/16/32)
- BAR decoding: supports 32-bit and 64-bit Memory BARs, I/O BARs
- Common PCI capability traversal APIs: `pci_find_capability()` / `pci_find_next_capability()`
- MSI/MSI-X APIs:
  - `pci_enable_msi()` / `pci_disable_msi()`
  - `pci_enable_msix()` / `pci_enable_msix_nvec()` / `pci_enable_msix_range()` / `pci_disable_msix()`
  - MSI-X helpers: `pci_msix_vector_irq()`, `pci_msix_set_vector_mask()`, `pci_msix_vector_pending()`, `pci_msix_pending_bitmap()`, `pci_msix_set_affinity()`, `pci_msix_set_affinity_spread()`
  - Message routing uses arch hook `arch_pci_msi_setup()`
  - MSI-X affinity reprogram path uses arch hook `arch_pci_msi_affinity_msg()`; when supported, `pci_msix_set_affinity()` rewrites MSI-X table entry `{addr,data}` and then updates irq-domain affinity
- Match strategy: by vendor_id/device_id (supports PCI_ANY_ID wildcard)
- pci_enumerate(): calls arch_pci_host_init() (weak symbol, arch-overridable) to get ECAM base, then scans bus
- pci_set_master(): enables bus-master and memory-space

VirtIO bus:
- Registered as a separate bus_type (virtio_bus_type)
- virtio_mmio.c: VirtIO MMIO transport layer, probed as a platform driver, discovers VirtIO devices and registers them on the virtio bus
- virtio_mmio now takes IRQ from platform resource helpers and registers/free IRQ through `platform_device_request_irq()` / `platform_device_free_irq()`
- virtio_pci.c: VirtIO PCI transport layer, probed as a PCI driver, parses VirtIO vendor capabilities (common/notify/isr/device config) and registers child virtio devices on the virtio bus
  - probe path attempts MSI-X first (`min=1, max=requested`), then MSI, then falls back to INTx
  - when MSI-X is active, common config and queue vector bindings are explicitly programmed
- virtio_mmio probe stores transport state in `dev->driver_data`; remove path unregisters the child virtio device and frees transport resources

## Device Discovery Flow (core/init/devices.c)

init_devices() execution order:
1. Register buses: platform_bus_init(), pci_bus_init(), bus_register(&virtio_bus_type)
2. Register drivers: virtio_mmio_driver, virtio_pci_driver, virtio_blk_driver, virtio_net_driver, virtio_iommu_driver, drm_lite_driver (optional)
3. Firmware descriptors: fw_init(), register_limine_framebuffers(), acpi_init()
4. Device tree scan: fdt_scan_devices() (if DTB present)
5. Enumerate devices: platform_bus_enumerate(), pci_enumerate()

FDT scanning and Limine framebuffer registration call fw_register_desc(); ACPI probes RSDP, and aarch64 PCI host init additionally parses ACPI MCFG to discover ECAM for pci_enumerate().

Full chain: firmware (FDT/Limine) → fw_register_desc() → platform_bus_enumerate() creates device → device_register() triggers matching → driver.probe()

## Block Device Layer (drivers/block/blkdev.c)

- blkdev_list: global block device linked list
- blkdev_register(): registers block device, validates sector_size/sector_count/ops
- blkdev partition probing registers child block devices for valid MBR/GPT entries (child I/O is translated to parent LBA range)
- blkdev_read() / blkdev_write(): dispatched through blkdev_ops to specific driver
- Current implementation: virtio_blk (drivers/block/virtio_blk.c)
- DMA mapping path is device-aware (`dma_map_single(dev, ...)/dma_unmap_single(dev, ...)`) and dispatched through `dma_ops`; default direct backend keeps current behavior, and aarch64 still performs cache clean/invalidate for non-coherent DMA directions (TO/FROM/BIDIRECTIONAL)
- Virtqueue ring memory now uses `dma_alloc_coherent(dev, ...)` with persistent DMA handles (`desc/avail/used`), and both virtio-mmio + virtio-pci program queue base registers from those DMA addresses instead of raw `virt_to_phys()`
- DMA constraints now support per-device mask/aperture policy (`dma_set_mask()`, `dma_set_aperture()`); map/alloc paths reject DMA addresses outside mask/aperture windows
- IOMMU core now provides `iommu_domain` + basic IOVA allocation and an IOMMU DMA backend (`iommu_get_dma_ops()`); PCI enumeration uses `iommu_attach_default_domain()`, which currently falls back to a global passthrough domain and can later be redirected by registering `iommu_hw_ops`
- IOMMU hardware provider registration supports multiple backends with `priority` + optional `match(dev, priv)` selection; default-domain attach walks providers in priority order, then falls back to passthrough
- IOMMU DMA domains now expose configurable mapping granularity (`iommu_domain_set_granule()`), so backend-required page size (for example 64K) can be enforced in IOVA allocation/map size alignment
- IOMMU domain ops now include an optional `release()` lifecycle callback so hardware backends can tear down per-domain resources (for example endpoint detach) at `iommu_domain_destroy()` time
- IOMMU IOVA allocation also honors the same per-device DMA mask/aperture checks, so translated DMA addresses stay inside the declared device-visible window
- Re-attaching a device to another IOMMU domain now auto-detaches the previous domain attachment and reclaims any per-device DMA mappings from the old domain before switching
- Device init now runs `iommu_init()` before PCI enumeration; architecture code can provide `arch_iommu_init()` to register hardware-backed domain allocation
- A `virtio-iommu` backend driver is wired as an `iommu_hw_ops` provider: it matches PCI endpoints, allocates per-device IOMMU domains (using device `input_range` when advertised), and issues ATTACH/MAP/UNMAP/DETACH requests through virtqueue 0
- When `virtio-iommu` comes online, it sweeps already-registered PCI devices and re-attaches passthrough-attached endpoints to backend-managed default domains, avoiding boot-order loss of IOMMU coverage

## Driver Overview

- drivers/virtio/: VirtIO transport layer (virtio_mmio, virtio_ring)
- drivers/iommu/: IOMMU backend drivers (virtio_iommu)
- drivers/block/: block device framework + virtio_blk
- drivers/net/: virtio_net
- drivers/tty/: terminal subsystem (tty_core, console_tty, n_tty line discipline, pty)
  - PTY slave->master output path now uses bounded buffering with backpressure (no overwrite-on-full); nonblocking writes return `EAGAIN`, and writable readiness is reflected by `POLLOUT`
  - n_tty/pty blocking read-write waits now use wait-queue sleep/wakeup paths (no poll-wait + yield spin loops)
  - PTY poll readiness now reports peer hangup via `POLLHUP`; slave-side `POLLOUT` follows master input buffer room (and is woken when master drains data)
- drivers/char/: character devices (console)
  - console input is IRQ-driven on supported arches (`arch_console_input_init()`), with tick-time polling retained as fallback
  - UART RX MMIO base/IRQ are resolved from FDT (`/chosen/stdout-path` + `/aliases` + `interrupts{,-extended}`) and fall back to arch defaults when firmware data is absent
- drivers/gpu/: drm_lite (optional, CONFIG_DRM_LITE)
- drivers/fb/: framebuffer (directory exists, currently empty)
- drivers/pci/: PCI drivers (directory exists, currently empty)
- drivers/usb/: USB drivers (directory exists, currently empty)

## Network Path Overview

Socket layer (net/socket.c):
- Protocol family table (families[], up to MAX_AF=4), dispatches by domain to stream_ops/dgram_ops
- Socket vnodes bridge to VFS through file_ops (read→recvfrom, write→sendto)

AF_UNIX (net/af_unix.c):
- Supports SOCK_STREAM (bidirectional ring buffer, 16KB) and SOCK_DGRAM (message queue)
- Connection mode: bind/listen/accept/connect
- Stream/Dgram peer and bind-table object lifetime is refcounted internally to avoid close/connect/send race UAFs
- Listener close now propagates connect errors to pending clients instead of leaving blocked connectors indefinitely
- Stream connect/accept support non-blocking mode (`MSG_DONTWAIT`), including connect-in-progress state and `SO_ERROR` readout
  - Nonblocking connect failure keeps `poll(POLLOUT|POLLERR)` visible until userspace consumes/clears it via `getsockopt(SO_ERROR)`

AF_INET (net/af_inet.c):
- Based on lwIP raw/callback API
- Each socket maps to a tcp_pcb or udp_pcb
- Receive buffer 64KB; listen() backlog is clamped to `[1, INET_ACCEPT_BACKLOG]` and enforced as accept queue upper bound
  - lwIP internal listen backlog is kept at `INET_ACCEPT_BACKLOG`; user-provided backlog is enforced by AF_INET accept queue policy to avoid small-backlog SYN stall behavior
- Stream connect/accept/recv and UDP recv honor non-blocking behavior (`EINPROGRESS`/`EALREADY`/`EAGAIN`), with connect readiness surfaced via poll + `SO_ERROR`
  - TCP connect completion races are stabilized: repeated connect returns `EALREADY` while in progress and `EISCONN` after completion

lwIP integration:
- net/lwip_netif.c: network interface adapter; virtio-net RX completion forwards ethernet payloads into `lwip_netif_input()`
- net/lwip_port/: lwIP system adaptation layer (threads, semaphores, timers)
- net/net_ioctl.c: network ioctl
- LWIP_TCPIP_CORE_LOCKING is enabled; AF_INET raw API paths and net_ioctl netif mutations are serialized with LWIP core lock

## Current Limitations

- ACPI platform-device discovery is still scaffolding (does not register fw descriptors); currently only PCI ECAM discovery via MCFG is wired for aarch64
- MSI routing backends:
  - x86_64: LAPIC MSI route (`0xFEE...`) with CPU-targeted message composition for affinity updates (`arch_pci_msi_affinity_msg`)
  - aarch64: baseline MSI/MSI-X route via GICD `SETSPI_NSR` doorbell path (QEMU virt)
    - MSI-X affinity updates are supported by reprogramming message while keeping SPI identity
  - riscv64:
    - default build remains PLIC/INTx-first
    - when built with `RISCV_AIA=1`, IRQ root backend attempts IMSIC and PCI MSI/MSI-X message composition (`arch_pci_msi_setup()` + `arch_pci_msi_affinity_msg()`)
    - if IMSIC CSR access is unavailable at runtime, backend falls back to a no-op external IRQ mode (no unsafe PLIC MMIO access on AIA machine)
    - current IMSIC backend still treats cross-hart MSI affinity migration as unsupported and returns `-EOPNOTSUPP` for remote-target reprogram attempts

Related references:
- references/00_REPO_MAP.md
- references/10_BOOT_FIRMWARE_TRAP_SYSCALL_TIME.md
- references/40_VFS_BLOCK_FS.md
- references/51_DRM_LITE_DISPLAY.md
