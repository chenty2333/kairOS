#!/usr/bin/env bash
#
# build-musl-cross.sh - Build musl cross toolchain via musl-cross-make
#
# Usage: ./scripts/build-musl-cross.sh <arch>

set -euo pipefail

ARCH="${1:-riscv64}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MCM_DIR="$ROOT_DIR/third_party/musl-cross-make"
JOBS="${JOBS:-$(nproc)}"
OUTPUT="${OUTPUT:-$ROOT_DIR/toolchains}"

if [[ ! -d "$MCM_DIR" ]]; then
  echo "Error: musl-cross-make not found at $MCM_DIR" >&2
  exit 1
fi

case "$ARCH" in
  riscv64)
    TARGET="riscv64-linux-musl"
    GCC_CONFIG="--with-arch=rv64gc --with-abi=lp64"
    ;;
  x86_64)
    TARGET="x86_64-linux-musl"
    GCC_CONFIG=""
    ;;
  aarch64)
    TARGET="aarch64-linux-musl"
    GCC_CONFIG=""
    ;;
  *)
    echo "Unsupported ARCH: $ARCH" >&2
    exit 1
    ;;
 esac

echo "Building musl toolchain: TARGET=$TARGET"
echo "Output prefix: $OUTPUT"

make -C "$MCM_DIR" -j"$JOBS" \
  TARGET="$TARGET" \
  OUTPUT="$OUTPUT" \
  GCC_CONFIG="$GCC_CONFIG"

make -C "$MCM_DIR" install \
  TARGET="$TARGET" \
  OUTPUT="$OUTPUT" \
  GCC_CONFIG="$GCC_CONFIG"

echo "Toolchain installed to: $OUTPUT"
echo "Add to PATH: export PATH=$OUTPUT/bin:$PATH"
