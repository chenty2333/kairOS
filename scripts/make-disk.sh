#!/bin/bash
#
# make-disk.sh - Create an ext2 disk image for testing
#
# Usage: ./scripts/make-disk.sh <arch>

set -euo pipefail

ARCH="${1:-riscv64}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

DISK_IMG="${DISK_IMG:-${ROOT_DIR}/build/${ARCH}/disk.img}"
ROOTFS_DIR="${ROOTFS_DIR:-${ROOT_DIR}/build/${ARCH}/rootfs}"
BUSYBOX_BIN="${BUSYBOX_BIN:-${ROOT_DIR}/build/${ARCH}/busybox/busybox}"
INIT_BIN="${INIT_BIN:-${ROOT_DIR}/build/${ARCH}/user/init}"
ROOTFS_ONLY="${ROOTFS_ONLY:-0}"

DISK_SIZE=64  # MB
MOUNT_POINT="/tmp/kairos-disk-$$"

stage_rootfs() {
  echo "Staging rootfs: $ROOTFS_DIR"
  mkdir -p "$ROOTFS_DIR"/{bin,sbin,etc,home,dev}

  echo "Hello from Kairos filesystem!" >"$ROOTFS_DIR/test.txt"
  echo "This is another test file" >"$ROOTFS_DIR/test2.txt"
  echo "root:x:0:0:root:/root:/bin/sh" >"$ROOTFS_DIR/etc/passwd"
  echo "127.0.0.1 localhost" >"$ROOTFS_DIR/etc/hosts"

  if [[ -x "$INIT_BIN" ]]; then
    cp -f "$INIT_BIN" "$ROOTFS_DIR/init"
    chmod 0755 "$ROOTFS_DIR/init"
  else
    echo "WARN: init not found ($INIT_BIN)"
  fi

  if [[ -x "$BUSYBOX_BIN" ]]; then
    cp -f "$BUSYBOX_BIN" "$ROOTFS_DIR/bin/busybox"
    chmod 0755 "$ROOTFS_DIR/bin/busybox"
  else
    echo "WARN: busybox not found ($BUSYBOX_BIN)"
  fi

  ln -sf /bin/busybox "$ROOTFS_DIR/bin/sh"
  ln -sf /init "$ROOTFS_DIR/sbin/init"
  ln -sf /init "$ROOTFS_DIR/bin/init"
}

stage_rootfs

if [[ "$ROOTFS_ONLY" == "1" ]]; then
  echo "Rootfs staged only; skipping disk image."
  exit 0
fi

echo "Creating ext2 disk image: $DISK_IMG"
mkdir -p "$(dirname "$DISK_IMG")"

dd if=/dev/zero of="$DISK_IMG" bs=1M count=$DISK_SIZE 2>/dev/null
mkfs.ext2 -F "$DISK_IMG" >/dev/null 2>&1

echo "Created $DISK_SIZE MB ext2 filesystem"

mkdir -p "$MOUNT_POINT"
sudo mount -o loop "$DISK_IMG" "$MOUNT_POINT"

sudo cp -a "$ROOTFS_DIR"/. "$MOUNT_POINT"/

echo ""
echo "Disk contents:"
sudo ls -lR "$MOUNT_POINT"

sudo umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"

echo ""
echo "Disk image created successfully: $DISK_IMG"
