# Third-Party Dependencies

This document lists all third-party libraries used by Kairos, their versions, and licenses.

## Fetching Dependencies

```bash
# Fetch all dependencies
./scripts/fetch-deps.sh all

# Or fetch individually
./scripts/fetch-deps.sh limine
./scripts/fetch-deps.sh lwip
./scripts/fetch-deps.sh tinyusb
./scripts/fetch-deps.sh fatfs
./scripts/fetch-deps.sh musl
```

## Library Versions

| Library | Version | License | Purpose |
|---------|---------|---------|---------|
| **Limine** | v10.x (latest stable) | BSD-2-Clause | Bootloader |
| **lwIP** | 2.2.1 (STABLE) | BSD-3-Clause | TCP/IP stack |
| **TinyUSB** | 0.20.0 | MIT | USB host/device stack |
| **FatFs** | R0.16 | BSD-1-Clause | FAT32 filesystem |
| **musl** | 1.2.5 | MIT | C library (for user space) |

## License Compatibility

All libraries use permissive licenses (MIT, BSD) compatible with Kairos's MIT license.

| License | Commercial Use | Modification | Distribution | Private Use |
|---------|---------------|--------------|--------------|-------------|
| MIT | Yes | Yes | Yes | Yes |
| BSD-2-Clause | Yes | Yes | Yes | Yes |
| BSD-3-Clause | Yes | Yes | Yes | Yes |

## Library Details

### Limine Bootloader

- **URL**: https://github.com/limine-bootloader/limine
- **Version**: v10.x-binary branch (prebuilt binaries)
- **Use**: Boot kernel on x86_64, AArch64, RISC-V
- **Integration**: Provides memory map, framebuffer, kernel modules

Key files:
- `limine.h` - Protocol header (copied to kernel/include/boot/)
- `limine-bios.sys` - BIOS bootloader
- `BOOTX64.EFI` - UEFI bootloader

### lwIP (Lightweight IP)

- **URL**: https://savannah.nongnu.org/projects/lwip/
- **Version**: STABLE-2_2_1_RELEASE
- **Use**: TCP/IP networking
- **Integration**: Kernel or user-space network stack

Features used:
- TCP/UDP sockets
- DHCP client
- DNS resolver
- IPv4 (IPv6 optional)

Configuration:
- Create `lwipopts.h` for Kairos-specific settings
- Implement `sys_arch.c` for OS integration

### TinyUSB

- **URL**: https://github.com/hathach/tinyusb
- **Version**: 0.20.0
- **Use**: USB host controller and HID devices
- **Integration**: Kernel driver

Features used:
- XHCI host controller (modern PCs)
- HID class (keyboard, mouse)
- Mass storage class (optional)

Configuration:
- Create `tusb_config.h`
- Implement platform-specific HAL

### FatFs

- **URL**: http://elm-chan.org/fsw/ff/
- **Version**: R0.16
- **Use**: FAT12/16/32 filesystem (boot partition, USB drives)
- **Integration**: VFS layer

Configuration:
- Create `ffconf.h` with Kairos settings
- Implement `diskio.c` for block device access

### musl libc

- **URL**: https://musl.libc.org/
- **Version**: 1.2.5
- **Use**: C library for user-space programs
- **Integration**: User-space library

Porting steps:
1. Create arch-specific `syscall_arch.h`
2. Implement `__syscall()` in assembly
3. Configure with Kairos-specific options
4. Build as static library

## Directory Structure

After running `fetch-deps.sh all`:

```
third_party/
├── limine/          # Bootloader binaries and tools
├── lwip/            # Network stack source
│   └── src/
├── tinyusb/         # USB stack source
│   └── src/
├── fatfs/           # FAT filesystem source
│   └── source/
└── musl/            # C library source
    ├── src/
    └── include/
```

## Version Selection Rationale

- **Limine v10.x**: Latest stable with full RISC-V support
- **lwIP 2.2.1**: Latest stable release, well-tested
- **TinyUSB 0.20.0**: Latest stable, good XHCI support
- **FatFs R0.16**: Latest, minimal changes needed
- **musl 1.2.5**: Latest stable, cleanest implementation

## Updating Dependencies

To update to newer versions:

1. Edit version tags in `scripts/fetch-deps.sh`
2. Remove old `third_party/<lib>` directory
3. Re-run fetch script
4. Test thoroughly before committing
