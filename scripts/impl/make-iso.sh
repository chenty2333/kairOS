#!/bin/bash
#
# Create bootable ISO image for Kairos
#
# Prerequisites:
#   - xorriso (dnf install xorriso)
#   - Limine (run scripts/kairos.sh deps fetch limine first)
#
# Usage: scripts/kairos.sh --arch <arch> image iso

set -euo pipefail

ARCH="${1:-x86_64}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "${ROOT_DIR}/scripts/lib/common.sh"
BUILD_ROOT="${BUILD_ROOT:-$ROOT_DIR/build}"
BUILD_DIR="$BUILD_ROOT/$ARCH"
KERNEL="$BUILD_DIR/kairos.elf"
ISO_DIR="$BUILD_DIR/iso_root"
ISO_FILE="$BUILD_DIR/kairos.iso"
LIMINE_DIR="$ROOT_DIR/third_party/limine"
INITRAMFS="$BUILD_DIR/initramfs.cpio"
LIMINE_CFG_SRC="$ROOT_DIR/limine.cfg"
QEMU_MEM="${QEMU_MEM:-384M}"

if [ "$ARCH" = "x86_64" ]; then
    LIMINE_CFG_SRC="$BUILD_DIR/limine.x86_64.cfg"
    cat > "$LIMINE_CFG_SRC" <<'EOF'
# Limine bootloader configuration for Kairos (x86_64 ISO)

timeout: 3

/Kairos (x86_64)
	protocol: limine
	path: boot():/kairos.elf
	module_path: boot():/initramfs.cpio
	module_string: initramfs
EOF
fi

# Check prerequisites
if [ ! -f "$KERNEL" ]; then
    echo "Error: Kernel not found at $KERNEL"
    echo "Run 'make ARCH=$ARCH' first"
    exit 1
fi

if [ ! -d "$LIMINE_DIR" ]; then
    echo "Error: Limine not found"
    echo "Run 'scripts/kairos.sh deps fetch limine' first"
    exit 1
fi

if ! command -v xorriso &> /dev/null; then
    echo "Error: xorriso not found"
    echo "Install with: sudo dnf install xorriso"
    exit 1
fi

echo "=== Creating ISO for $ARCH ==="

# Create ISO directory structure
rm -rf "$ISO_DIR"
mkdir -p "$ISO_DIR/boot/limine"
mkdir -p "$ISO_DIR/EFI/BOOT"
mkdir -p "$ISO_DIR/EFI/limine"

# Copy kernel
cp "$KERNEL" "$ISO_DIR/boot/"
cp "$KERNEL" "$ISO_DIR/kairos.elf"

# Copy initramfs
if [ -f "$INITRAMFS" ]; then
    cp "$INITRAMFS" "$ISO_DIR/initramfs.cpio"
    mkdir -p "$ISO_DIR/boot"
    cp "$INITRAMFS" "$ISO_DIR/boot/initramfs.cpio"
else
    echo "WARN: initramfs not found at $INITRAMFS" >&2
fi

# Copy Limine files
cp "$LIMINE_CFG_SRC" "$ISO_DIR/boot/limine/limine.conf"
cp "$LIMINE_CFG_SRC" "$ISO_DIR/EFI/limine/limine.conf"
cp "$LIMINE_DIR/limine-bios.sys" "$ISO_DIR/boot/limine/"
cp "$LIMINE_DIR/limine-bios-cd.bin" "$ISO_DIR/boot/limine/"
cp "$LIMINE_DIR/limine-uefi-cd.bin" "$ISO_DIR/boot/limine/"

# Copy UEFI bootloader
BOOT_EFI="$(kairos_arch_to_boot_efi "$ARCH")" || {
    echo "Error: Unsupported ARCH for ISO image: $ARCH" >&2
    exit 1
}
cp "$LIMINE_DIR/$BOOT_EFI" "$ISO_DIR/EFI/BOOT/"

# Create ISO
echo "Creating ISO..."
xorriso -as mkisofs \
    -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part \
    --efi-boot-image \
    --protective-msdos-label \
    "$ISO_DIR" -o "$ISO_FILE" 2>/dev/null

# Install Limine for legacy BIOS boot
echo "Installing Limine..."
"$LIMINE_DIR/limine" bios-install "$ISO_FILE" 2>/dev/null

echo ""
echo "=== ISO created: $ISO_FILE ==="
echo ""
echo "To test:"
echo "  QEMU (BIOS):  qemu-system-$ARCH -cdrom $ISO_FILE -m $QEMU_MEM"
if [ "$ARCH" = "riscv64" ]; then
    echo "  QEMU (UEFI):  make ARCH=riscv64 run"
else
    echo "  QEMU (UEFI):  qemu-system-$ARCH -cdrom $ISO_FILE -m $QEMU_MEM -bios /usr/share/ovmf/OVMF.fd"
fi
echo "  Real hardware: Write to USB with 'dd if=$ISO_FILE of=/dev/sdX bs=4M'"
