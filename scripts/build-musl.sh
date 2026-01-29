#!/usr/bin/env bash
#
# build-musl.sh - Build musl libc for a target architecture
#
# Usage: ./scripts/build-musl.sh <arch>

set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
  echo "Usage: $0 <arch>" >&2
  exit 1
fi

MUSL_SRC="${MUSL_SRC:-third_party/musl}"
SYSROOT="${SYSROOT:-build/${ARCH}/sysroot}"
BUILD_DIR="${BUILD_DIR:-build/${ARCH}/musl}"
JOBS="${JOBS:-$(nproc)}"

case "$ARCH" in
  riscv64) TARGET="riscv64-linux-musl"; ARCH_CFLAGS="-march=rv64gc -mabi=lp64";;
  x86_64) TARGET="x86_64-linux-musl";;
  aarch64) TARGET="aarch64-linux-musl";;
  *) echo "Unsupported ARCH: $ARCH" >&2; exit 1;;
esac

CROSS_COMPILE="${CROSS_COMPILE:-${TARGET}-}"
CC=""
AR=""
RANLIB=""
STRIP=""
CFLAGS="${CFLAGS:-} ${ARCH_CFLAGS:-}"
LDFLAGS="${LDFLAGS:-} ${ARCH_CFLAGS:-}"

MUSL_SRC="$(realpath -m "$MUSL_SRC")"
SYSROOT="$(realpath -m "$SYSROOT")"
BUILD_DIR="$(realpath -m "$BUILD_DIR")"

if [[ ! -d "$MUSL_SRC" ]]; then
  echo "musl source not found: $MUSL_SRC (run ./scripts/fetch-deps.sh musl)" >&2
  exit 1
fi

if command -v "${CROSS_COMPILE}gcc" >/dev/null 2>&1; then
  CC="${CROSS_COMPILE}gcc"
  AR="${CROSS_COMPILE}ar"
  RANLIB="${CROSS_COMPILE}ranlib"
  STRIP="${CROSS_COMPILE}strip"
else
  GNU_CROSS="${TARGET/-musl/-gnu}-"
  if command -v "${GNU_CROSS}gcc" >/dev/null 2>&1; then
    CROSS_COMPILE="${GNU_CROSS}"
    CC="${CROSS_COMPILE}gcc"
    AR="${CROSS_COMPILE}ar"
    RANLIB="${CROSS_COMPILE}ranlib"
    STRIP="${CROSS_COMPILE}strip"
  else
  if ! command -v clang >/dev/null 2>&1; then
    echo "Toolchain not found: ${CROSS_COMPILE}gcc or clang" >&2
    exit 1
  fi
  for tool in llvm-ar llvm-ranlib llvm-strip; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "Toolchain not found: $tool" >&2
      exit 1
    fi
  done
  CC="clang --target=${TARGET} -fuse-ld=lld"
  AR="llvm-ar"
  RANLIB="llvm-ranlib"
  STRIP="llvm-strip"
  CFLAGS="--target=${TARGET} ${CFLAGS}"
  LDFLAGS="--target=${TARGET} -fuse-ld=lld ${LDFLAGS}"
  CROSS_COMPILE=""
  fi
fi

if [[ -f "$SYSROOT/lib/libc.a" ]]; then
  echo "musl already installed: $SYSROOT"
  exit 0
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$SYSROOT"
cp -a "$MUSL_SRC"/. "$BUILD_DIR"/

pushd "$BUILD_DIR" >/dev/null
  CC="$CC" AR="$AR" RANLIB="$RANLIB" STRIP="$STRIP" CFLAGS="$CFLAGS" \
  LDFLAGS="$LDFLAGS" CROSS_COMPILE="$CROSS_COMPILE" \
  ./configure --prefix=/ --target="$TARGET"
  make -j"$JOBS"
  DESTDIR="$SYSROOT" make install
popd >/dev/null

echo "musl installed to $SYSROOT"
