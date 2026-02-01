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
DOOM_BIN="${DOOM_BIN:-${ROOT_DIR}/build/${ARCH}/user/doom}"
DOOM_WAD="${DOOM_WAD:-}"
ROOTFS_ONLY="${ROOTFS_ONLY:-0}"
ROOTFS_STAGE="${ROOTFS_STAGE:-all}"

if [[ -z "$DOOM_WAD" ]]; then
  if [[ -f "${ROOT_DIR}/third_party/freedoom/doom1.wad" ]]; then
    DOOM_WAD="${ROOT_DIR}/third_party/freedoom/doom1.wad"
  elif [[ -f "${ROOT_DIR}/third_party/freedoom/freedoom1.wad" ]]; then
    DOOM_WAD="${ROOT_DIR}/third_party/freedoom/freedoom1.wad"
  fi
fi

DISK_SIZE=64  # MB

stage_base() {
  echo "Staging rootfs base: $ROOTFS_DIR"
  mkdir -p "$ROOTFS_DIR"/{bin,sbin,etc,home,dev}

  echo "Hello from Kairos filesystem!" >"$ROOTFS_DIR/test.txt"
  echo "This is another test file" >"$ROOTFS_DIR/test2.txt"
  echo "root:x:0:0:root:/root:/bin/sh" >"$ROOTFS_DIR/etc/passwd"
  echo "127.0.0.1 localhost" >"$ROOTFS_DIR/etc/hosts"
}

stage_init() {
  echo "Staging rootfs init: $ROOTFS_DIR"
  mkdir -p "$ROOTFS_DIR"/{bin,sbin}
  if [[ -x "$INIT_BIN" ]]; then
    cp -f "$INIT_BIN" "$ROOTFS_DIR/init"
    chmod 0755 "$ROOTFS_DIR/init"
  else
    echo "WARN: init not found ($INIT_BIN)"
  fi

  ln -sf /init "$ROOTFS_DIR/sbin/init"
  ln -sf /init "$ROOTFS_DIR/bin/init"
}

stage_busybox() {
  echo "Staging rootfs busybox: $ROOTFS_DIR"
  mkdir -p "$ROOTFS_DIR/bin"
  if [[ -x "$BUSYBOX_BIN" ]]; then
    cp -f "$BUSYBOX_BIN" "$ROOTFS_DIR/bin/busybox"
    chmod 0755 "$ROOTFS_DIR/bin/busybox"

    # Install a minimal set of BusyBox applet links.
    local applets=(
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
    echo "WARN: busybox not found ($BUSYBOX_BIN)"
  fi
}

stage_doom() {
  echo "Staging rootfs doom: $ROOTFS_DIR"
  mkdir -p "$ROOTFS_DIR"/{bin,doom}
  if [[ -x "$DOOM_BIN" ]]; then
    cp -f "$DOOM_BIN" "$ROOTFS_DIR/bin/doom"
    chmod 0755 "$ROOTFS_DIR/bin/doom"
  else
    echo "WARN: doom not found ($DOOM_BIN)"
  fi

  if [[ -n "$DOOM_WAD" && -f "$DOOM_WAD" ]]; then
    cp -f "$DOOM_WAD" "$ROOTFS_DIR/doom/doom1.wad"
    chmod 0644 "$ROOTFS_DIR/doom/doom1.wad"
  fi
}

case "$ROOTFS_STAGE" in
  all)
    stage_base
    stage_init
    stage_busybox
    stage_doom
    ;;
  base)
    stage_base
    ;;
  init)
    stage_init
    ;;
  busybox)
    stage_busybox
    ;;
  *)
    echo "Error: unknown ROOTFS_STAGE=$ROOTFS_STAGE"
    exit 1
    ;;
esac

if [[ "$ROOTFS_ONLY" == "1" ]]; then
  echo "Rootfs staged only; skipping disk image."
  exit 0
fi

echo "Creating ext2 disk image: $DISK_IMG"
mkdir -p "$(dirname "$DISK_IMG")"

dd if=/dev/zero of="$DISK_IMG" bs=1M count=$DISK_SIZE 2>/dev/null
mke2fs -t ext2 -F -d "$ROOTFS_DIR" "$DISK_IMG" >/dev/null 2>&1

echo "Created $DISK_SIZE MB ext2 filesystem"
echo "Disk image created successfully: $DISK_IMG"
