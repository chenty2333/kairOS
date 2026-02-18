#!/usr/bin/env bash
#
# build-musl.sh - Build musl libc for a target architecture
#
# Usage: scripts/kairos.sh --arch <arch> toolchain musl

set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
  echo "Usage: $0 <arch>" >&2
  exit 1
fi

QUIET="${QUIET:-0}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "${ROOT_DIR}/scripts/lib/common.sh"
source "${ROOT_DIR}/scripts/lib/toolchain.sh"

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

MUSL_SRC="$(realpath -m "$MUSL_SRC")"
SYSROOT="$(realpath -m "$SYSROOT")"
BUILD_DIR="$(realpath -m "$BUILD_DIR")"

if [[ ! -d "$MUSL_SRC" ]]; then
  echo "musl source not found: $MUSL_SRC (run scripts/kairos.sh deps fetch musl)" >&2
  exit 1
fi

kairos_tc_select "$TARGET" "" "$ARCH_CFLAGS" 0
CC="$KAIROS_TC_CC"
AR="$KAIROS_TC_AR"
RANLIB="$KAIROS_TC_RANLIB"
STRIP="$KAIROS_TC_STRIP"
CROSS_COMPILE="$KAIROS_TC_CROSS_PREFIX"
CFLAGS="$KAIROS_TC_CFLAGS"
LDFLAGS="$KAIROS_TC_LDFLAGS"

if [[ -n "${KAIROS_TC_NOTE:-}" && "$QUIET" != "1" ]]; then
  echo "$KAIROS_TC_NOTE"
fi
if [[ "$QUIET" != "1" ]]; then
  echo "toolchain selected: ${KAIROS_TC_KIND}"
fi

# For full musl builds with clang, ensure compiler-rt builtins exist.
# This keeps TOOLCHAIN_MODE=auto usable when clang is selected.
if [[ "${MUSL_STATIC_ONLY:-0}" != "1" && "$KAIROS_TC_KIND" == "clang" ]]; then
  RT_RESOURCE_DIR="$(realpath -m "$ROOT_DIR/build/${ARCH}/compiler-rt/resource")"
  _rt_builtins="$(find "$RT_RESOURCE_DIR" -name 'libclang_rt.builtins*.a' | head -n1 || true)"
  if [[ -z "$_rt_builtins" ]]; then
    [[ "$QUIET" != "1" ]] && echo "compiler-rt builtins missing; building compiler-rt..."
    env TOOLCHAIN_MODE=clang QUIET="$QUIET" SYSROOT="$SYSROOT" \
      "$ROOT_DIR/scripts/impl/build-compiler-rt.sh" "$ARCH"
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

# Keep local build warning-free by replacing musl's getcwd implementation
# only when the expected upstream hash matches.
MUSL_GETCWD_FILE="$BUILD_DIR/src/unistd/getcwd.c"
MUSL_GETCWD_PATCHED_TEMPLATE="$ROOT_DIR/scripts/patches/musl/getcwd.c"
MUSL_GETCWD_ORIG_SHA256="7101e9ce4e6f16a313deab6196ce8f04ca70a0a060d40a7c5b79733e03c2bf23"
MUSL_GETCWD_PATCHED_SHA256="2ad7a5a4c4d50554ee34fba9516e6fd7acd574f42dcb269e989113b584ab52f0"
if [[ -f "$MUSL_GETCWD_FILE" && -f "$MUSL_GETCWD_PATCHED_TEMPLATE" ]]; then
  getcwd_sha="$(sha256sum "$MUSL_GETCWD_FILE" | awk '{print $1}')"
  if [[ "$getcwd_sha" == "$MUSL_GETCWD_ORIG_SHA256" ]]; then
    cp -f "$MUSL_GETCWD_PATCHED_TEMPLATE" "$MUSL_GETCWD_FILE"
  elif [[ "$getcwd_sha" != "$MUSL_GETCWD_PATCHED_SHA256" ]]; then
    kairos_warn "musl getcwd.c hash mismatch ($getcwd_sha); skip local patch"
  fi
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
