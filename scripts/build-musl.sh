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

QUIET="${QUIET:-0}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

MUSL_SRC="${MUSL_SRC:-$ROOT_DIR/third_party/musl}"
SYSROOT="${SYSROOT:-$ROOT_DIR/build/${ARCH}/sysroot}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build/${ARCH}/musl}"
JOBS="${JOBS:-$(nproc)}"

case "$ARCH" in
  riscv64) TARGET="riscv64-linux-musl"; ARCH_CFLAGS="-march=rv64gc -mabi=lp64";;
  x86_64) TARGET="x86_64-linux-musl";;
  aarch64) TARGET="aarch64-linux-musl";;
  *) echo "Unsupported ARCH: $ARCH" >&2; exit 1;;
esac

# Ignore any CROSS_COMPILE/CFLAGS/LDFLAGS from the environment (e.g. from
# the kernel Makefile) — we determine the correct toolchain ourselves.
unset CROSS_COMPILE CFLAGS LDFLAGS 2>/dev/null || true
CROSS_COMPILE="${TARGET}-"
CC=""
AR=""
RANLIB=""
STRIP=""
CFLAGS="${ARCH_CFLAGS:-}"
LDFLAGS="${ARCH_CFLAGS:-}"

MUSL_SRC="$(realpath -m "$MUSL_SRC")"
SYSROOT="$(realpath -m "$SYSROOT")"
BUILD_DIR="$(realpath -m "$BUILD_DIR"))"

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

# If compiler-rt builtins are available, tell clang where to find them.
# This is needed for the full build (libc.so) on aarch64 where 128-bit
# float operations require __subtf3 etc. from compiler-rt.
RT_RESOURCE_DIR="$(realpath -m "$ROOT_DIR/build/${ARCH}/compiler-rt/resource")"
if [[ -d "$RT_RESOURCE_DIR" ]]; then
  CFLAGS="${CFLAGS} -resource-dir $RT_RESOURCE_DIR"
  LDFLAGS="${LDFLAGS} -resource-dir $RT_RESOURCE_DIR"
fi

# MUSL_STATIC_ONLY=1: build only libc.a + headers (no libc.so).
# Used by compiler-rt bootstrap to break the circular dependency:
#   musl libc.so needs compiler-rt builtins (128-bit float on aarch64)
#   compiler-rt needs musl headers + libc.a
MUSL_STATIC_ONLY="${MUSL_STATIC_ONLY:-0}"

if [[ "$MUSL_STATIC_ONLY" == "1" ]]; then
  # For static-only, check if headers + libc.a already exist
  if [[ -f "$SYSROOT/lib/libc.a" ]] && [[ -f "$SYSROOT/include/stdlib.h" ]]; then
    [[ "$QUIET" != "1" ]] && echo "musl static already installed: $SYSROOT"
    exit 0
  fi
else
  # For full build, check if libc.so exists (libc.a alone means static-only was done)
  if [[ -f "$SYSROOT/lib/libc.so" ]]; then
    [[ "$QUIET" != "1" ]] && echo "musl already installed: $SYSROOT"
    exit 0
  fi
fi

# Clean build dir only if starting fresh (not resuming after static-only)
if [[ ! -d "$BUILD_DIR/obj" ]]; then
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR" "$SYSROOT"
  rsync -a "$MUSL_SRC"/ "$BUILD_DIR"/
  # Nuke any build artifacts that may have leaked into the source tree
  make -C "$BUILD_DIR" distclean >/dev/null 2>&1 || true
fi

if [[ "$QUIET" == "1" ]]; then
  _out=/dev/null
else
  _out=/dev/stdout
fi

pushd "$BUILD_DIR" >/dev/null
  if [[ ! -f config.mak ]]; then
    CC="$CC" AR="$AR" RANLIB="$RANLIB" STRIP="$STRIP" CFLAGS="$CFLAGS" \
    LDFLAGS="$LDFLAGS" CROSS_COMPILE="$CROSS_COMPILE" \
    ./configure --prefix=/ --target="$TARGET" >"$_out"
  fi

  if [[ "$MUSL_STATIC_ONLY" == "1" ]]; then
    make -j"$JOBS" lib/libc.a >"$_out"
    DESTDIR="$SYSROOT" make install-headers >"$_out"
    mkdir -p "$SYSROOT/lib"
    cp -f lib/libc.a "$SYSROOT/lib/libc.a"
    # Install crt files needed by compiler-rt
    for f in crt1.o crti.o crtn.o rcrt1.o Scrt1.o; do
      [[ -f "lib/$f" ]] && cp -f "lib/$f" "$SYSROOT/lib/$f"
    done
  else
    make -j"$JOBS" >"$_out"
    DESTDIR="$SYSROOT" make install >"$_out"
  fi
popd >/dev/null

if [[ "$QUIET" == "1" ]]; then
  if [[ "$MUSL_STATIC_ONLY" == "1" ]]; then
    echo "  MUSL    $SYSROOT (static only)"
  else
    echo "  MUSL    $SYSROOT"
  fi
else
  if [[ "$MUSL_STATIC_ONLY" == "1" ]]; then
    echo "musl static installed to $SYSROOT"
  else
    echo "musl installed to $SYSROOT"
  fi
fi
