# Scripts Map

`scripts/` 现在采用“单入口 + 模块化”结构。  
**官方入口是 `scripts/kairos.sh`**，Makefile 主路径统一通过它调度。

## 主入口

- `scripts/kairos.sh`
  - 全局参数：`--arch` `--quiet` `--verbose` `--jobs` `--build-root`
  - 顶层命令：`toolchain` `image` `run` `deps` `doctor`

## 模块层（由 kairos.sh 调用）

- `scripts/modules/toolchain.sh`
  - `compiler-rt` `musl` `busybox` `tcc` `musl-cross` `all`
- `scripts/modules/image.sh`
  - `initramfs` `rootfs-*` `rootfs` `disk` `uefi` `iso` `all`
- `scripts/modules/run.sh`
  - `test` `test-soak` `test-debug` `test-matrix`
  - `doctor`（host 环境检查）
- `scripts/modules/deps.sh`
  - `fetch [component]` `freedoom` `all`

## 公共库

- `scripts/lib/common.sh`：架构映射、BusyBox applet 链接等共享逻辑
- `scripts/lib/log.sh`：统一日志输出
- `scripts/lib/env.sh`：架构与默认 UEFI 路径解析
- `scripts/lib/cmd.sh`：统一命令执行与日志归档（`build/<arch>/logs/*.log`）
- `scripts/lib/lock.sh`：全局锁与 BUILD_ROOT 局部锁

## 实现层

- 实现层（模块直接调用）：
  - `scripts/impl/build-*.sh`
  - `scripts/impl/make-*.sh`
  - `scripts/impl/fetch-*.sh`
- 仍保留独立脚本：
  - `run-qemu-test.sh` `run-qemu-session.sh` `test-matrix.sh` `gen-user-init.sh` `patch-elf-phdrs.py`
  - `run-qemu-test.sh` / `run-qemu-session.sh` 会在运行目录输出 `manifest.json` 和 `result.json`

## 推荐调用方式

优先使用 Make 目标或 `scripts/kairos.sh`，避免直接拼接多个底层脚本。
