#!/bin/bash
#
# Prepare padded UEFI firmware images for QEMU (RISC-V).
#
# Usage: ./scripts/prepare-uefi.sh [ARCH]
#

set -e

ARCH="${1:-riscv64}"
BUILD_DIR="build/$ARCH"
QUIET="${QUIET:-0}"

if [ "$ARCH" != "riscv64" ]; then
    echo "Error: UEFI firmware prep only supported for riscv64"
    exit 1
fi

CODE_SRC="${UEFI_CODE_SRC:-/usr/share/edk2/riscv/RISCV_VIRT_CODE.fd}"
VARS_SRC="${UEFI_VARS_SRC:-/usr/share/edk2/riscv/RISCV_VIRT_VARS.fd}"
CODE_DST="$BUILD_DIR/uefi-code.fd"
VARS_DST="$BUILD_DIR/uefi-vars.fd"

if [ ! -f "$CODE_SRC" ] || [ ! -f "$VARS_SRC" ]; then
    echo "Error: RISC-V UEFI firmware not found."
    echo "Expected:"
    echo "  $CODE_SRC"
    echo "  $VARS_SRC"
    echo "Install edk2 (Fedora: sudo dnf install edk2-ovmf)"
    exit 1
fi

mkdir -p "$BUILD_DIR"
cp "$CODE_SRC" "$CODE_DST"
cp "$VARS_SRC" "$VARS_DST"

# QEMU expects 32MB pflash images for RISCV_VIRT
truncate -s 32M "$CODE_DST"
truncate -s 32M "$VARS_DST"

if [ "$QUIET" = "1" ]; then
    echo "  UEFI    $CODE_DST (32M pflash)"
else
    echo "UEFI firmware prepared:"
    echo "  $CODE_DST"
    echo "  $VARS_DST"
fi
