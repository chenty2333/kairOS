#!/bin/bash
#
# Create a UEFI bootable FAT image with Limine + kernel.
#
# Usage: ./scripts/make-uefi-disk.sh [ARCH]
#

set -e

ARCH="${1:-riscv64}"
BUILD_DIR="build/$ARCH"
QUIET="${QUIET:-0}"
KERNEL="$BUILD_DIR/kairos.elf"
BOOT_IMG="$BUILD_DIR/boot.img"
LIMINE_DIR="third_party/limine"
INITRAMFS="$BUILD_DIR/initramfs.cpio"

case "$ARCH" in
    x86_64) BOOT_EFI="BOOTX64.EFI" ;;
    aarch64) BOOT_EFI="BOOTAA64.EFI" ;;
    riscv64) BOOT_EFI="BOOTRISCV64.EFI" ;;
    *)
        echo "Error: Unsupported ARCH for UEFI boot image: $ARCH"
        exit 1
        ;;
esac

case "$ARCH" in
    riscv64) LIMINE_DEFAULT_ENTRY=1 ;;
    x86_64) LIMINE_DEFAULT_ENTRY=2 ;;
    aarch64) LIMINE_DEFAULT_ENTRY=3 ;;
esac

if [ ! -f "$KERNEL" ]; then
    echo "Error: Kernel not found at $KERNEL"
    echo "Run 'make ARCH=$ARCH' first"
    exit 1
fi

BOOT_EFI_SRC="${LIMINE_EFI:-$LIMINE_DIR/$BOOT_EFI}"
BOOT_EFI_DST="$BUILD_DIR/$BOOT_EFI"

if [ ! -f "$BOOT_EFI_SRC" ]; then
    echo "Error: Limine UEFI bootloader not found: $BOOT_EFI_SRC"
    echo "Run './scripts/fetch-deps.sh limine' first"
    exit 1
fi

MKFS_FAT="$(command -v mkfs.fat || command -v mkfs.vfat || true)"
if [ -z "$MKFS_FAT" ]; then
    echo "Error: mkfs.fat not found"
    echo "Install with: sudo dnf install dosfstools"
    exit 1
fi

IMG_SIZE_MB="${IMG_SIZE_MB:-64}"

rm -f "$BOOT_IMG"
dd if=/dev/zero of="$BOOT_IMG" bs=1M count="$IMG_SIZE_MB" status=none
"$MKFS_FAT" -F 32 "$BOOT_IMG" >/dev/null

MNT_DIR="$(mktemp -d /tmp/kairos-uefi-XXXXXX)"
CFG_TMP="$(mktemp /tmp/kairos-limine-XXXXXX.cfg)"

cleanup() {
    if mountpoint -q "$MNT_DIR"; then
        sudo umount "$MNT_DIR" || true
    fi
    rm -f "$CFG_TMP"
    rmdir "$MNT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

awk -v def_entry="$LIMINE_DEFAULT_ENTRY" '
BEGIN {
    print "default_entry: " def_entry;
    print "";
}
tolower($0) ~ /^default_entry[[:space:]]*:/ { next }
{ print }
' limine.cfg > "$CFG_TMP"

sudo mount -o loop "$BOOT_IMG" "$MNT_DIR"
mkdir -p "$BUILD_DIR"
cp "$BOOT_EFI_SRC" "$BOOT_EFI_DST"
if [ -x "$LIMINE_DIR/limine" ]; then
    CFG_HASH="$(b2sum "$CFG_TMP" | awk '{print $1}')"
    "$LIMINE_DIR/limine" enroll-config "$BOOT_EFI_DST" "$CFG_HASH" >/dev/null 2>&1 || true
fi

sudo mkdir -p "$MNT_DIR/EFI/BOOT" "$MNT_DIR/boot/limine"
sudo cp "$BOOT_EFI_DST" "$MNT_DIR/EFI/BOOT/$BOOT_EFI"
sudo cp "$CFG_TMP" "$MNT_DIR/limine.cfg"
sudo cp "$CFG_TMP" "$MNT_DIR/boot/limine/limine.cfg"
sudo cp "$CFG_TMP" "$MNT_DIR/boot/limine/limine.conf"
sudo cp "$KERNEL" "$MNT_DIR/kairos.elf"
sudo cp "$KERNEL" "$MNT_DIR/boot/kairos.elf"
if [ "$ARCH" = "riscv64" ] && [ -f "qemu-virt.dtb" ]; then
    sudo cp qemu-virt.dtb "$MNT_DIR/qemu-virt.dtb"
    sudo cp qemu-virt.dtb "$MNT_DIR/boot/qemu-virt.dtb"
fi
if [ -f "$INITRAMFS" ]; then
    sudo cp "$INITRAMFS" "$MNT_DIR/initramfs.cpio"
    sudo cp "$INITRAMFS" "$MNT_DIR/boot/initramfs.cpio"
else
    echo "WARN: initramfs not found at $INITRAMFS" >&2
fi
sync
sudo umount "$MNT_DIR"

if [ "$QUIET" = "1" ]; then
    echo "  BOOT    $BOOT_IMG (${IMG_SIZE_MB}M FAT32)"
else
    echo "UEFI boot image created: $BOOT_IMG"
fi
