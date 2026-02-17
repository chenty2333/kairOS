#!/bin/bash
#
# make-initramfs.sh - Build initramfs cpio image
#
# Usage: ./scripts/make-initramfs.sh <arch>

set -euo pipefail

ARCH="${1:-riscv64}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/$ARCH"
QUIET="${QUIET:-0}"
ROOTFS_DIR="${INITRAMFS_DIR:-$BUILD_DIR/initramfs-root}"
INIT_BIN="${INITRAMFS_INIT:-$BUILD_DIR/user/initramfs/init}"
BUSYBOX_BIN="${BUSYBOX_BIN:-$BUILD_DIR/busybox/busybox}"
OUT_CPIO="${INITRAMFS_CPIO:-$BUILD_DIR/initramfs.cpio}"
INCLUDE_BUSYBOX="${INITRAMFS_BUSYBOX:-0}"
CPIO_BIN="${CPIO_BIN:-$(command -v cpio || true)}"

rm -rf "$ROOTFS_DIR"
mkdir -p "$ROOTFS_DIR"/bin "$ROOTFS_DIR"/sbin "$ROOTFS_DIR"/etc
mkdir -p "$ROOTFS_DIR"/dev "$ROOTFS_DIR"/proc "$ROOTFS_DIR"/newroot

if [[ -z "$CPIO_BIN" ]]; then
  echo "Error: cpio not found (install cpio on host)" >&2
  exit 1
fi

if [[ ! -x "$INIT_BIN" ]]; then
  echo "Error: initramfs init not found: $INIT_BIN" >&2
  exit 1
fi

cp -f "$INIT_BIN" "$ROOTFS_DIR/init"
chmod 0755 "$ROOTFS_DIR/init"

if [[ "$INCLUDE_BUSYBOX" == "1" ]]; then
  if [[ -x "$BUSYBOX_BIN" ]]; then
    mkdir -p "$ROOTFS_DIR/bin"
    cp -f "$BUSYBOX_BIN" "$ROOTFS_DIR/bin/busybox"
    chmod 0755 "$ROOTFS_DIR/bin/busybox"

    # Install a minimal but useful set of BusyBox applet links.
    applets=(
      sh ls cat echo pwd mkdir rmdir rm mv cp ln touch
      readlink realpath stat head tail wc grep sed awk cut tr sort uniq tee printf
      sleep date time uptime uname dmesg kill nice id whoami env
      basename dirname which true false yes
      chmod chown chgrp chroot mknod mkfifo mktemp sync mount umount
      df du free ps pidof pgrep pkill killall
      xargs find expr test seq
      dd hexdump od strings
      comm cmp diff paste fold nl
    )
    for app in "${applets[@]}"; do
      ln -sf /bin/busybox "$ROOTFS_DIR/bin/$app"
    done
  else
    echo "WARN: busybox not found ($BUSYBOX_BIN)" >&2
  fi
fi

mkdir -p "$(dirname "$OUT_CPIO")"
(
  cd "$ROOTFS_DIR"
  find . | "$CPIO_BIN" -o -H newc >"$OUT_CPIO"
)

if [[ "$QUIET" == "1" ]]; then
  SIZE=$(stat -c%s "$OUT_CPIO" 2>/dev/null || stat -f%z "$OUT_CPIO" 2>/dev/null || echo "?")
  echo "  CPIO    $OUT_CPIO (${SIZE} bytes)"
else
  echo "initramfs image created: $OUT_CPIO"
fi
