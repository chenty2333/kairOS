# Third-Party Dependencies

Kairos uses external libraries to handle common protocols and formats.

## 1. Core Libraries
| Library | Version | License | Use Case |
|---------|---------|---------|----------|
| **Limine** | v10.x | BSD-2-Clause | Bootloader & Protocol |
| **lwIP** | 2.2.1 | BSD-3-Clause | TCP/IP Stack |
| **TinyUSB** | 0.20.0 | MIT | USB Host (XHCI) & HID |
| **FatFs** | R0.16 | BSD-1-Clause | FAT32 FS Support |
| **musl** | 1.2.5 | MIT | User-space C Library |
| **BusyBox** | 1.36.1 | GPL-2.0 | User-space utilities & shell |

## 2. Management
- **Fetch**: Run `./scripts/fetch-deps.sh all` to download sources.
- **Location**: All external sources reside in `third_party/`.
- **Config**: Each library uses custom headers (e.g., `lwipopts.h`, `ffconf.h`) located within their respective module directories or the kernel include path.

## 3. Integration Status
- **Limine**: Integrated for all supported architectures.
- **musl**: Ported via arch-specific syscall implementation.
- **Others**: Integrated via HAL/VFS layer implementations (`sys_arch.c`, `diskio.c`, etc.).

## 4. Build Tools
- **xorriso**: ISO creation (`make iso`).
- **dosfstools**: UEFI FAT boot image (`make uefi`).
- **edk2** (RISC-V firmware): UEFI boot under QEMU (`make ARCH=riscv64 run`).
