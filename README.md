# Kairos

A modern, multi-architecture operating system kernel written in C.

## Goals

- **Multi-architecture**: RISC-V 64, AArch64, x86_64
- **Real hardware**: USB keyboard, NVMe storage, framebuffer display
- **POSIX-like**: Run busybox, TCC, and eventually GCC
- **Clean design**: Modular, well-documented, maintainable

## Architecture Support

| Architecture | Status | Bootloader |
|-------------|--------|------------|
| RISC-V 64   | Primary development | Limine |
| AArch64     | Planned | Limine |
| x86_64      | Planned | Limine |

## Building

```bash
make ARCH=riscv64    # Build for RISC-V
make ARCH=x86_64     # Build for x86_64
make run             # Run in QEMU
```

## Documentation

- [Architecture Design](docs/architecture.md)
- [Implementation Roadmap](docs/roadmap.md)
- [System Calls](docs/syscalls.md)
- [Coding Style](docs/coding-style.md)

## Directory Structure

```
kairos/
├── docs/           # Design documents
├── kernel/         # Kernel source
│   ├── arch/       # Architecture-specific code
│   ├── core/       # Core subsystems (scheduler, memory, process)
│   ├── fs/         # File systems
│   ├── drivers/    # Device drivers
│   ├── ipc/        # Inter-process communication
│   └── lib/        # Kernel libraries (rbtree, string, etc.)
├── user/           # User space
│   ├── libc/       # C library port (musl)
│   ├── init/       # Init process
│   └── shell/      # Basic shell
├── tools/          # Build tools and utilities
└── scripts/        # Build scripts
```

## License

MIT License

## Acknowledgments

- [Limine](https://limine-bootloader.org/) - Bootloader
- [musl](https://musl.libc.org/) - C library
- [lwIP](https://savannah.nongnu.org/projects/lwip/) - TCP/IP stack
- [tinyusb](https://github.com/hathach/tinyusb) - USB stack
