#!/bin/bash
#
# Prepare UEFI boot media with Limine + kernel.
#
# Usage: scripts/kairos.sh --arch <arch> image uefi-disk
#

set -euo pipefail

ARCH="${1:-riscv64}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "${ROOT_DIR}/scripts/lib/common.sh"
BUILD_ROOT="${BUILD_ROOT:-$ROOT_DIR/build}"
BUILD_DIR="$BUILD_ROOT/$ARCH"
QUIET="${QUIET:-0}"
KERNEL="$BUILD_DIR/kairos.elf"
BOOT_IMG="$BUILD_DIR/boot.img"
BOOT_FS="$BUILD_DIR/bootfs"
LIMINE_DIR="$ROOT_DIR/third_party/limine"
INITRAMFS="$BUILD_DIR/initramfs.cpio"
LIMINE_CFG="$ROOT_DIR/limine.cfg"
UEFI_BOOT_MODE="${UEFI_BOOT_MODE:-dir}" # dir|img|both
QEMU_UEFI_BOOT_MODE="${QEMU_UEFI_BOOT_MODE:-}" # optional dir|img

BOOT_EFI="$(kairos_arch_to_boot_efi "$ARCH")" || {
    echo "Error: Unsupported ARCH for UEFI boot image: $ARCH"
    exit 1
}

case "$ARCH" in
    riscv64) LIMINE_DEFAULT_ENTRY=1 ;;
    x86_64) LIMINE_DEFAULT_ENTRY=2 ;;
    aarch64) LIMINE_DEFAULT_ENTRY=3 ;;
esac

case "$QEMU_UEFI_BOOT_MODE" in
    "" | dir | img) ;;
    *)
        echo "Error: invalid QEMU_UEFI_BOOT_MODE='$QEMU_UEFI_BOOT_MODE' (expected dir|img)" >&2
        exit 1
        ;;
esac

if [ -n "$QEMU_UEFI_BOOT_MODE" ] &&
    [ "$UEFI_BOOT_MODE" != "both" ] &&
    [ "$QEMU_UEFI_BOOT_MODE" != "$UEFI_BOOT_MODE" ]; then
    echo "Error: UEFI_BOOT_MODE='$UEFI_BOOT_MODE' mismatches QEMU_UEFI_BOOT_MODE='$QEMU_UEFI_BOOT_MODE'" >&2
    exit 1
fi

if [ ! -f "$KERNEL" ]; then
    echo "Error: Kernel not found at $KERNEL"
    echo "Run 'make ARCH=$ARCH' first"
    exit 1
fi

BOOT_EFI_SRC="${LIMINE_EFI:-$LIMINE_DIR/$BOOT_EFI}"
BOOT_EFI_DST="$BUILD_DIR/$BOOT_EFI"

if [ ! -f "$BOOT_EFI_SRC" ]; then
    echo "Error: Limine UEFI bootloader not found: $BOOT_EFI_SRC"
    echo "Run 'scripts/kairos.sh deps fetch limine' first"
    exit 1
fi

IMG_SIZE_MB="${IMG_SIZE_MB:-64}"
CFG_TMP="$(mktemp "${TMPDIR:-/tmp}/kairos-limine-XXXXXX.cfg")"

cleanup() {
    rm -f "$CFG_TMP"
}
trap cleanup EXIT

awk -v def_entry="$LIMINE_DEFAULT_ENTRY" '
BEGIN {
    print "default_entry: " def_entry;
    print "";
}
tolower($0) ~ /^default_entry[[:space:]]*:/ { next }
{ print }
' "$LIMINE_CFG" > "$CFG_TMP"

mkdir -p "$BUILD_DIR"
cp "$BOOT_EFI_SRC" "$BOOT_EFI_DST"
if [ -x "$LIMINE_DIR/limine" ]; then
    CFG_HASH="$(b2sum "$CFG_TMP" | awk '{print $1}')"
    "$LIMINE_DIR/limine" enroll-config "$BOOT_EFI_DST" "$CFG_HASH" >/dev/null 2>&1 || true
fi

rm -rf "$BOOT_FS"
mkdir -p "$BOOT_FS/EFI/BOOT" "$BOOT_FS/boot/limine" "$BOOT_FS/boot"
cp "$BOOT_EFI_DST" "$BOOT_FS/EFI/BOOT/$BOOT_EFI"
cp "$CFG_TMP" "$BOOT_FS/limine.cfg"
cp "$CFG_TMP" "$BOOT_FS/boot/limine/limine.cfg"
cp "$CFG_TMP" "$BOOT_FS/boot/limine/limine.conf"
cp "$KERNEL" "$BOOT_FS/kairos.elf"
cp "$KERNEL" "$BOOT_FS/boot/kairos.elf"
if [ "$ARCH" = "riscv64" ] && [ -f "qemu-virt.dtb" ]; then
    cp qemu-virt.dtb "$BOOT_FS/qemu-virt.dtb"
    cp qemu-virt.dtb "$BOOT_FS/boot/qemu-virt.dtb"
fi
if [ -f "$INITRAMFS" ]; then
    cp "$INITRAMFS" "$BOOT_FS/initramfs.cpio"
    cp "$INITRAMFS" "$BOOT_FS/boot/initramfs.cpio"
else
    echo "WARN: initramfs not found at $INITRAMFS" >&2
fi

make_boot_img_mtools() {
    local mkfs_fat
    mkfs_fat="$(command -v mkfs.fat || command -v mkfs.vfat || true)"
    if [ -z "$mkfs_fat" ]; then
        return 1
    fi
    if ! command -v mcopy >/dev/null 2>&1 || ! command -v mmd >/dev/null 2>&1; then
        return 1
    fi

    rm -f "$BOOT_IMG"
    if ! truncate -s "${IMG_SIZE_MB}M" "$BOOT_IMG" 2>/dev/null; then
        dd if=/dev/zero of="$BOOT_IMG" bs=1M count="$IMG_SIZE_MB" status=none
    fi
    "$mkfs_fat" -F 32 "$BOOT_IMG" >/dev/null
    mmd -i "$BOOT_IMG" ::/EFI ::/EFI/BOOT ::/boot ::/boot/limine >/dev/null
    mcopy -i "$BOOT_IMG" -s "$BOOT_FS"/* ::/ >/dev/null
}

case "$UEFI_BOOT_MODE" in
    dir) ;;
    img)
        if ! make_boot_img_mtools; then
            echo "Error: UEFI_BOOT_MODE=img requires mkfs.fat + mtools (mcopy/mmd)" >&2
            exit 1
        fi
        ;;
    both)
        if ! make_boot_img_mtools; then
            if [ "$QEMU_UEFI_BOOT_MODE" = "img" ]; then
                echo "Error: QEMU_UEFI_BOOT_MODE=img requires boot.img, but mkfs.fat + mtools are missing" >&2
                exit 1
            fi
            echo "WARN: boot.img skipped (missing mkfs.fat + mtools)" >&2
        fi
        ;;
    *)
        echo "Error: invalid UEFI_BOOT_MODE='$UEFI_BOOT_MODE' (expected dir|img|both)" >&2
        exit 1
        ;;
esac

if [ "$QUIET" = "1" ]; then
    if [ "$UEFI_BOOT_MODE" = "img" ]; then
        echo "  BOOT    $BOOT_IMG (${IMG_SIZE_MB}M FAT32)"
    else
        echo "  BOOT    $BOOT_FS (UEFI FAT dir)"
    fi
else
    echo "UEFI boot media prepared:"
    echo "  $BOOT_FS"
    if [ -f "$BOOT_IMG" ]; then
        echo "  $BOOT_IMG"
    fi
fi
