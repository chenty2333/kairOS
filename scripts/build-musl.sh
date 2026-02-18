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
source "${ROOT_DIR}/scripts/lib/common.sh"

MUSL_SRC="${MUSL_SRC:-$ROOT_DIR/third_party/musl}"
SYSROOT="${SYSROOT:-$ROOT_DIR/build/${ARCH}/sysroot}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build/${ARCH}/musl}"
JOBS="${JOBS:-$(nproc)}"
USE_GCC="${USE_GCC:-0}"

TARGET="$(kairos_arch_to_musl_target "$ARCH")" || {
  echo "Unsupported ARCH: $ARCH" >&2
  exit 1
}
ARCH_CFLAGS="$(kairos_arch_cflags "$ARCH")"

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
BUILD_DIR="$(realpath -m "$BUILD_DIR")"

if [[ ! -d "$MUSL_SRC" ]]; then
  echo "musl source not found: $MUSL_SRC (run ./scripts/fetch-deps.sh musl)" >&2
  exit 1
fi

select_clang() {
  if ! command -v clang >/dev/null 2>&1; then
    return 1
  fi
  for tool in llvm-ar llvm-ranlib llvm-strip; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      return 1
    fi
  done
  CC="clang --target=${TARGET} -fuse-ld=lld"
  AR="llvm-ar"
  RANLIB="llvm-ranlib"
  STRIP="llvm-strip"
  CFLAGS="--target=${TARGET} ${CFLAGS}"
  LDFLAGS="--target=${TARGET} -fuse-ld=lld ${LDFLAGS}"
  CROSS_COMPILE=""
  return 0
}

select_gcc() {
  local prefix="$1"
  if ! command -v "${prefix}gcc" >/dev/null 2>&1; then
    return 1
  fi
  CC="${prefix}gcc"
  AR="${prefix}ar"
  RANLIB="${prefix}ranlib"
  STRIP="${prefix}strip"
  CROSS_COMPILE="${prefix}"
  return 0
}

if [[ "$USE_GCC" == "1" ]]; then
  if ! select_gcc "${TARGET}-"; then
    GNU_CROSS="${TARGET/-musl/-gnu}-"
    if ! select_gcc "$GNU_CROSS"; then
      if ! select_clang; then
        echo "Toolchain not found: ${TARGET}-gcc, ${GNU_CROSS}gcc, or clang/llvm-* tools" >&2
        exit 1
      fi
    fi
  fi
else
  if ! select_clang; then
    if ! select_gcc "${TARGET}-"; then
      GNU_CROSS="${TARGET/-musl/-gnu}-"
      if ! select_gcc "$GNU_CROSS"; then
        echo "Toolchain not found: clang/llvm-* tools, ${TARGET}-gcc, or ${GNU_CROSS}gcc" >&2
        exit 1
      fi
    fi
  fi
fi

# If using clang and compiler-rt builtins are available, tell clang where to
# find them.  This is needed for the full build (libc.so) on aarch64 where
# 128-bit float operations require __subtf3 etc. from compiler-rt.
# GCC ships its own libgcc so none of this applies.
RT_RESOURCE_DIR="$(realpath -m "$ROOT_DIR/build/${ARCH}/compiler-rt/resource")"
if [[ "$CC" == clang* ]] && [[ -d "$RT_RESOURCE_DIR" ]]; then
  CFLAGS="${CFLAGS} -resource-dir $RT_RESOURCE_DIR"
  LDFLAGS="${LDFLAGS} -resource-dir $RT_RESOURCE_DIR"
  # Find the builtins library so we can pass it as LIBCC to musl's configure.
  # musl's configure uses `$CC -print-libgcc-file-name` which doesn't honor
  # -resource-dir, so we must pass LIBCC explicitly.
  _builtins="$(find "$RT_RESOURCE_DIR" -name 'libclang_rt.builtins*.a' | head -n1)"
  if [[ -n "$_builtins" ]]; then
    LIBCC="$_builtins"
  fi
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

# Prepare build directory.
# - Fresh start: rsync source tree, clean any leaked artifacts.
# - Resuming after static-only: keep obj/ but force re-configure
#   (full build needs -resource-dir for compiler-rt builtins).
if [[ ! -f "$BUILD_DIR/Makefile" ]]; then
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR" "$SYSROOT"
  rsync -a "$MUSL_SRC"/ "$BUILD_DIR"/
  # Nuke any build artifacts that may have leaked into the source tree
  make -C "$BUILD_DIR" distclean >/dev/null 2>&1 || true
elif [[ "$MUSL_STATIC_ONLY" != "1" ]]; then
  # Force re-configure so LIBCC picks up compiler-rt via -resource-dir
  rm -f "$BUILD_DIR/config.mak"
fi

# Keep local build warning-free in quiet mode by avoiding pointer-to-local
# comparison in musl's getcwd implementation.
if [[ -f "$BUILD_DIR/src/unistd/getcwd.c" ]]; then
  cat > "$BUILD_DIR/src/unistd/getcwd.c" <<'EOF'
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include "syscall.h"

char *getcwd(char *buf, size_t size)
{
	char tmp[PATH_MAX];
	char *out = buf;

	if (!out) {
		out = tmp;
		size = sizeof(tmp);
	} else if (!size) {
		errno = EINVAL;
		return 0;
	}

	long ret = syscall(SYS_getcwd, out, size);
	if (ret < 0)
		return 0;
	if (ret == 0 || out[0] != '/') {
		errno = ENOENT;
		return 0;
	}

	return buf ? out : strdup(out);
}
EOF
fi

if [[ "$QUIET" == "1" ]]; then
  _out=/dev/null
else
  _out=/dev/stdout
fi

make_jobs=()
if [[ "${MAKEFLAGS:-}" != *"--jobserver-auth="* ]] &&
   [[ "${MAKEFLAGS:-}" != *"--jobserver-fds="* ]]; then
  make_jobs=(-j"$JOBS")
fi

pushd "$BUILD_DIR" >/dev/null
  if [[ ! -f config.mak ]]; then
    CONFIGURE_ARGS="--prefix=/ --target=$TARGET"
    if [[ -n "${LIBCC:-}" ]]; then
      CONFIGURE_ARGS="$CONFIGURE_ARGS LIBCC=$LIBCC"
    fi
    CC="$CC" AR="$AR" RANLIB="$RANLIB" STRIP="$STRIP" CFLAGS="$CFLAGS" \
    LDFLAGS="$LDFLAGS" CROSS_COMPILE="$CROSS_COMPILE" \
    ./configure $CONFIGURE_ARGS >"$_out"
  fi

  if [[ "$MUSL_STATIC_ONLY" == "1" ]]; then
    make "${make_jobs[@]}" lib/libc.a >"$_out"
    DESTDIR="$SYSROOT" make install-headers >"$_out"
    mkdir -p "$SYSROOT/lib"
    cp -f lib/libc.a "$SYSROOT/lib/libc.a"
    # Install crt files needed by compiler-rt
    for f in crt1.o crti.o crtn.o rcrt1.o Scrt1.o; do
      [[ -f "lib/$f" ]] && cp -f "lib/$f" "$SYSROOT/lib/$f"
    done
  else
    make "${make_jobs[@]}" >"$_out"
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
