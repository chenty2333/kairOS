#!/bin/bash
#
# Prepare padded UEFI firmware images for QEMU.
#
# Usage: scripts/kairos.sh --arch <arch> image prepare-uefi
#
# Environment variables:
#   UEFI_CODE_SRC  - Path to UEFI CODE firmware (auto-detected per arch)
#   UEFI_VARS_SRC  - Path to UEFI VARS firmware (auto-detected per arch)
#

set -euo pipefail

ARCH="${1:-riscv64}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "${ROOT_DIR}/scripts/lib/common.sh"
BUILD_DIR="$ROOT_DIR/build/$ARCH"
QUIET="${QUIET:-0}"

case "$ARCH" in
    riscv64)
        CODE_SRC="${UEFI_CODE_SRC:-/usr/share/edk2/riscv/RISCV_VIRT_CODE.fd}"
        VARS_SRC="${UEFI_VARS_SRC:-/usr/share/edk2/riscv/RISCV_VIRT_VARS.fd}"
        PFLASH_SIZE="32M"
        PKG_HINT="sudo dnf install edk2-ovmf"
        ;;
    x86_64)
        CODE_SRC="${UEFI_CODE_SRC:-/usr/share/edk2/ovmf/OVMF_CODE.fd}"
        VARS_SRC="${UEFI_VARS_SRC:-/usr/share/edk2/ovmf/OVMF_VARS.fd}"
        PFLASH_SIZE=""
        PKG_HINT="sudo dnf install edk2-ovmf"
        ;;
    aarch64)
        CODE_SRC_DEFAULT="/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw"
        if [ -f "/usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw" ]; then
            CODE_SRC_DEFAULT="/usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw"
        fi
        CODE_SRC="${UEFI_CODE_SRC:-$CODE_SRC_DEFAULT}"
        VARS_SRC="${UEFI_VARS_SRC:-/usr/share/edk2/aarch64/vars-template-pflash.raw}"
        PFLASH_SIZE="64M"
        PKG_HINT="sudo dnf install edk2-aarch64"
        ;;
    *)
        echo "Error: Unsupported ARCH for UEFI firmware: $ARCH"
        exit 1
        ;;
esac

CODE_DST="$BUILD_DIR/uefi-code.fd"
VARS_DST="$BUILD_DIR/uefi-vars.fd"

if [ ! -f "$CODE_SRC" ] || [ ! -f "$VARS_SRC" ]; then
    echo "Error: UEFI firmware not found for $ARCH."
    echo "Expected:"
    echo "  $CODE_SRC"
    echo "  $VARS_SRC"
    echo "Install with: $PKG_HINT"
    exit 1
fi

mkdir -p "$BUILD_DIR"
cp "$CODE_SRC" "$CODE_DST"
cp "$VARS_SRC" "$VARS_DST"

# Pad pflash images to required size (QEMU expects exact sizes for some archs)
if [ -n "$PFLASH_SIZE" ]; then
    truncate -s "$PFLASH_SIZE" "$CODE_DST"
    truncate -s "$PFLASH_SIZE" "$VARS_DST"
fi

if [ "$QUIET" = "1" ]; then
    if [ -n "$PFLASH_SIZE" ]; then
        echo "  UEFI    $CODE_DST ($PFLASH_SIZE pflash)"
    else
        echo "  UEFI    $CODE_DST (pflash)"
    fi
else
    echo "UEFI firmware prepared:"
    echo "  $CODE_DST"
    echo "  $VARS_DST"
fi
