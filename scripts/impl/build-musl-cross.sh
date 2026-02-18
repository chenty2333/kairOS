#!/usr/bin/env bash
#
# build-musl-cross.sh - Build musl cross toolchain via musl-cross-make
#
# Usage: scripts/kairos.sh --arch <arch> toolchain musl-cross

set -euo pipefail

ARCH="${1:-riscv64}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "${ROOT_DIR}/scripts/lib/common.sh"
MCM_DIR="$ROOT_DIR/third_party/musl-cross-make"
JOBS="${JOBS:-$(nproc)}"
OUTPUT="${OUTPUT:-$ROOT_DIR/toolchains}"

make_jobs=()
if [[ "${MAKEFLAGS:-}" != *"--jobserver-auth="* ]] &&
   [[ "${MAKEFLAGS:-}" != *"--jobserver-fds="* ]]; then
  make_jobs=(-j"$JOBS")
fi

if [[ ! -d "$MCM_DIR" ]]; then
  echo "Error: musl-cross-make not found at $MCM_DIR" >&2
  exit 1
fi

TARGET="$(kairos_arch_to_musl_target "$ARCH")" || {
  echo "Unsupported ARCH: $ARCH" >&2
  exit 1
}

if [[ "$ARCH" == "riscv64" ]]; then
  GCC_CONFIG="--with-arch=rv64gc --with-abi=lp64"
else
  GCC_CONFIG=""
fi

echo "Building musl toolchain: TARGET=$TARGET"
echo "Output prefix: $OUTPUT"

make -C "$MCM_DIR" "${make_jobs[@]}" \
  TARGET="$TARGET" \
  OUTPUT="$OUTPUT" \
  GCC_CONFIG="$GCC_CONFIG"

make -C "$MCM_DIR" install \
  TARGET="$TARGET" \
  OUTPUT="$OUTPUT" \
  GCC_CONFIG="$GCC_CONFIG"

echo "Toolchain installed to: $OUTPUT"
echo "Add to PATH: export PATH=$OUTPUT/bin:$PATH"
