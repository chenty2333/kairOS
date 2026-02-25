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

PCI bus (bus/pci.c):
- ECAM config space access (pci_read/write_config_8/16/32)
- BAR decoding: supports 32-bit and 64-bit Memory BARs, I/O BARs
- Match strategy: by vendor_id/device_id (supports PCI_ANY_ID wildcard)
- pci_enumerate(): calls arch_pci_host_init() (weak symbol, arch-overridable) to get ECAM base, then scans bus
- pci_set_master(): enables bus-master and memory-space

VirtIO bus:
- Registered as a separate bus_type (virtio_bus_type)
- virtio_mmio.c: VirtIO MMIO transport layer, probed as a platform driver, discovers VirtIO devices and registers them on the virtio bus
- virtio_pci.c: VirtIO PCI transport layer, probed as a PCI driver, parses VirtIO vendor capabilities (common/notify/isr/device config) and registers child virtio devices on the virtio bus
- virtio_mmio probe stores transport state in `dev->driver_data`; remove path unregisters the child virtio device and frees transport resources

## Device Discovery Flow (core/init/devices.c)

init_devices() execution order:
1. Register buses: platform_bus_init(), pci_bus_init(), bus_register(&virtio_bus_type)
2. Register drivers: virtio_mmio_driver, virtio_pci_driver, virtio_blk_driver, virtio_net_driver, drm_lite_driver (optional)
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
- DMA mapping path uses `dma_map_single()/dma_unmap_single()`; on aarch64 this now performs cache clean/invalidate for non-coherent DMA directions (TO/FROM/BIDIRECTIONAL)

## Driver Overview

- drivers/virtio/: VirtIO transport layer (virtio_mmio, virtio_ring)
- drivers/block/: block device framework + virtio_blk
- drivers/net/: virtio_net
- drivers/tty/: terminal subsystem (tty_core, console_tty, n_tty line discipline, pty)
  - PTY slave->master output path now uses bounded buffering with backpressure (no overwrite-on-full); nonblocking writes return `EAGAIN`, and writable readiness is reflected by `POLLOUT`
  - n_tty/pty blocking read-write waits now use wait-queue sleep/wakeup paths (no poll-wait + yield spin loops)
- drivers/char/: character devices (console)
  - console input is IRQ-driven on supported arches (`arch_console_input_init()`), with tick-time polling retained as fallback; current wiring uses ns16550 IRQ10 on riscv64 QEMU virt and PL011 SPI 33 on aarch64 QEMU virt
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
- Stream connect/accept/recv and UDP recv honor non-blocking behavior (`EINPROGRESS`/`EALREADY`/`EAGAIN`), with connect readiness surfaced via poll + `SO_ERROR`
  - TCP connect completion races are stabilized: repeated connect returns `EALREADY` while in progress and `EISCONN` after completion

lwIP integration:
- net/lwip_netif.c: network interface adapter; virtio-net RX completion forwards ethernet payloads into `lwip_netif_input()`
- net/lwip_port/: lwIP system adaptation layer (threads, semaphores, timers)
- net/net_ioctl.c: network ioctl
- LWIP_TCPIP_CORE_LOCKING is enabled; AF_INET raw API paths and net_ioctl netif mutations are serialized with LWIP core lock

## Current Limitations

- ACPI platform-device discovery is still scaffolding (does not register fw descriptors); currently only PCI ECAM discovery via MCFG is wired for aarch64
- virtio-pci currently uses common INTx path; MSI-X and advanced PCI features are not wired yet

Related references:
- references/00_REPO_MAP.md
- references/10_BOOT_FIRMWARE_TRAP_SYSCALL_TIME.md
- references/40_VFS_BLOCK_FS.md
- references/51_DRM_LITE_DISPLAY.md
