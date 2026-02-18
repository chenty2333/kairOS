 # Build & Run Guide

这份文档把 Kairos 的构建流程梳理成“从 busybox 到 UEFI，再到运行”的一条直线，
同时解释 `make run` / `make clean` 的实际逻辑与可用选项。

## 1) 一键运行（riscv64 默认）

```
make run
```

现在的默认行为（ARCH=riscv64）会自动完成：
1. 编译内核
2. 构建 musl + user
3. 构建 busybox
4. 生成 rootfs 并打包 ext2 `disk.img`
5. 准备 UEFI 固件并生成 FAT 启动盘 `boot.img`
6. 启动 QEMU（UEFI + virtio disk）

## 2) 目标与脚本对应关系

| Make 目标 | 做什么 | 关键脚本/产物 |
|---|---|---|
| `make` | 仅编译内核 | `build/<arch>/kairos.elf` |
| `make user` | 构建 musl + userland | `scripts/kairos.sh toolchain musl` → `make -C user` |
| `make busybox` | 构建 busybox | `scripts/kairos.sh toolchain busybox` |
| `make rootfs-base` | 生成 rootfs 基础目录 | `scripts/kairos.sh image rootfs-base` |
| `make rootfs-busybox` | 安装 busybox + applets | `scripts/kairos.sh image rootfs-busybox` |
| `make rootfs-init` | 安装 init | `scripts/kairos.sh image rootfs-init` |
| `make rootfs` | 生成完整 rootfs | `scripts/kairos.sh image rootfs` |
| `make initramfs` | 生成 initramfs 镜像 | `scripts/kairos.sh image initramfs` |
| `make disk` | 生成 ext2 `disk.img`（无 sudo） | `scripts/kairos.sh image disk` |
| `make uefi` | 准备 UEFI 固件 + FAT 启动盘 | `scripts/kairos.sh image uefi` |
| `make run` | 启动 QEMU | 统一依赖 `check-tools + kernel + uefi + disk` |
| `make check-tools` | 检查工具链 | QEMU / mke2fs / mkfs.fat / xorriso 等 |
| `make clean` | 清理构建产物 | `rm -rf build/` |

脚本职责与分层可参考：`scripts/README.md`。

## 3) `make run` / `make clean` 具体逻辑

### `make run`
- 三种架构（`riscv64` / `x86_64` / `aarch64`）统一依赖：
  - `check-tools + kernel + uefi + disk`
- 即都会先生成 UEFI 启动盘 `boot.img` 与 ext2 `disk.img`，再启动 QEMU。

### `make clean`
- 仅删除 `build/` 目录。
- 不会删除 `third_party/` 源码，也不会清除系统工具。
- `build/<arch>/stamps/` 用于缓存构建步骤；删除 `build/` 会强制全量重建。

## 4) 常用选项（环境变量 / Make 变量）

### 通用
- `ARCH`：目标架构（`riscv64` / `x86_64` / `aarch64`）
- `USE_GCC=1`：使用 GCC 交叉编译器（默认用 clang + lld）
- `EMBEDDED_INIT=1`：riscv64 内置 init（可选）
- `HOSTFWD_PORT=8080`：QEMU 端口转发（host→guest 80）

### UEFI 相关（全部架构）
- `UEFI_CODE_SRC` / `UEFI_VARS_SRC`：UEFI 固件来源（默认系统路径）
- `LIMINE_EFI`：手动指定 Limine UEFI 入口文件
- `IMG_SIZE_MB`：UEFI FAT 镜像大小（`scripts/kairos.sh image uefi-disk`）

### Rootfs / Disk 相关（`scripts/kairos.sh image disk`）
- `DISK_IMG`：输出镜像位置（默认 `build/<arch>/disk.img`）
- `ROOTFS_DIR`：rootfs 目录（默认 `build/<arch>/rootfs`）
- `BUSYBOX_BIN`：busybox 路径
- `INIT_BIN`：init 路径
- `ROOTFS_ONLY=1`：只生成 rootfs，不打包 `disk.img`
- `ROOTFS_STAGE`：分阶段生成（`base` / `busybox` / `init` / `all`）
### Initramfs 相关（`scripts/kairos.sh image initramfs`）
- `INITRAMFS_DIR`：initramfs 临时目录
- `INITRAMFS_CPIO`：输出 cpio 路径
- `INITRAMFS_BUSYBOX=1`：在 initramfs 内带 busybox

### Clang compiler-rt（可选）
如果使用 clang（`USE_GCC=0`），需要为目标架构准备 compiler-rt：
```
scripts/kairos.sh --arch riscv64 toolchain compiler-rt
```
会生成并放到 `build/<arch>/compiler-rt/lib`，供 clang 链接使用。

### Musl 交叉工具链（可选）
如果需要 `riscv64-linux-musl-gcc`，可以使用：
```
scripts/kairos.sh --arch riscv64 toolchain musl-cross
```
完成后把 `toolchains/bin` 加入 PATH。

## 5) 依赖工具（Fedora 43 参考）

必需（riscv64 run）：
- `clang`, `lld`, `llvm` 或 `riscv64-unknown-elf-gcc`
- `qemu-system-riscv64`
- `edk2-ovmf`（提供 RISC-V UEFI 固件）
- `dosfstools`（`mkfs.fat`）
- `e2fsprogs`（`mkfs.ext2`）
- `python3`

可选：
- `xorriso`（`make iso` for x86_64）

## 6) 推荐工作流

1. 一次性：`scripts/kairos.sh deps all`
2. 默认运行：`make run`
3. 仅编译内核：`make`
4. 强制重建 rootfs：`make disk`
