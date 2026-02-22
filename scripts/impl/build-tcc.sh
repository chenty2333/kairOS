#!/usr/bin/env bash
#
# build-tcc.sh - Build TCC (Tiny C Compiler) for a target architecture
#
# Usage: scripts/kairos.sh --arch <arch> toolchain tcc
#
# Produces a statically-linked tcc binary plus its runtime (libtcc1.a and
# built-in headers) suitable for inclusion in a KairOS disk image.

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

TCC_SRC="${TCC_SRC:-$ROOT_DIR/third_party/tinycc}"
BUILD_ROOT="${BUILD_ROOT:-$ROOT_DIR/build}"
OUT_DIR="${OUT_DIR:-$BUILD_ROOT/${ARCH}/tcc}"
SYSROOT="${SYSROOT:-$BUILD_ROOT/${ARCH}/sysroot}"
JOBS="${JOBS:-$(nproc)}"

TARGET="$(kairos_arch_to_musl_target "$ARCH")" || {
  echo "Unsupported ARCH: $ARCH" >&2
  exit 1
}
ARCH_CFLAGS="$(kairos_arch_cflags "$ARCH")"
if [[ "$ARCH" == "aarch64" ]]; then
  ARCH_CFLAGS="${ARCH_CFLAGS} -D__arm64_clear_cache=__builtin___clear_cache"
fi

TCC_SRC="$(realpath -m "$TCC_SRC")"
OUT_DIR="$(realpath -m "$OUT_DIR")"
SYSROOT="$(realpath -m "$SYSROOT")"

if [[ ! -d "$TCC_SRC" ]]; then
  echo "TCC source not found: $TCC_SRC (run scripts/kairos.sh deps fetch tcc)" >&2
  exit 1
fi

if [[ ! -f "$SYSROOT/lib/libc.a" ]]; then
  echo "musl sysroot not found: $SYSROOT (run scripts/kairos.sh --arch $ARCH toolchain musl)" >&2
  exit 1
fi

# --- Determine the TCC cpu name ---
case "$ARCH" in
  riscv64)
    TCC_CPU="riscv64"
    TCC_LIBTCC1_TARGET="riscv64"
    ;;
  x86_64)
    TCC_CPU="x86_64"
    TCC_LIBTCC1_TARGET="x86_64"
    ;;
  aarch64)
    # TinyCC uses arm64 as the backend target key in lib/Makefile.
    TCC_CPU="aarch64"
    TCC_LIBTCC1_TARGET="arm64"
    ;;
  *) echo "Unsupported ARCH for TCC: $ARCH" >&2; exit 1 ;;
esac

unset CROSS_COMPILE CFLAGS LDFLAGS 2>/dev/null || true
kairos_tc_prepare_libgcc_compat "$ARCH" "$SYSROOT"
kairos_tc_select "$TARGET" "$SYSROOT" "$ARCH_CFLAGS" 1
CC="$KAIROS_TC_CC"
CROSS_PREFIX="$KAIROS_TC_CROSS_PREFIX"
CFLAGS="$KAIROS_TC_CFLAGS"
LDFLAGS="$KAIROS_TC_LDFLAGS"

if [[ -n "${KAIROS_TC_NOTE:-}" && "$QUIET" != "1" ]]; then
  echo "$KAIROS_TC_NOTE"
fi

# --- Build in a temporary directory to avoid polluting the source tree ---
BUILD_DIR="$(realpath -m "$BUILD_ROOT/${ARCH}/tcc-build")"
mkdir -p "$BUILD_DIR"

if [[ "$QUIET" == "1" ]]; then
  _out=/dev/null
else
  _out=/dev/stdout
fi

[[ "$QUIET" != "1" ]] && echo "Configuring TCC for $ARCH (cpu=$TCC_CPU)..."

# TCC's configure is not autoconf — it has its own option set.
# --tccdir sets the runtime search path on the *target* system.
# --sysincludepaths / --crtprefix / --libpaths control where tcc looks
# for headers, CRT objects, and libraries when compiling on the target.
CONFIGURE_ARGS=(
  --cpu="$TCC_CPU"
  --targetos=Linux
  --config-bcheck=no
  --extra-cflags="-static ${CFLAGS}"
  --extra-ldflags="-static ${LDFLAGS}"
  --prefix=/usr
  --tccdir=/usr/lib/tcc
  --sysincludepaths="/usr/include:/usr/lib/tcc/include"
  --crtprefix="/usr/lib"
  --libpaths="/usr/lib"
  --config-musl
)

if [[ -n "$CROSS_PREFIX" ]]; then
  CONFIGURE_ARGS+=(--cross-prefix="$CROSS_PREFIX")
fi
if [[ -n "$CC" ]]; then
  CONFIGURE_ARGS+=(--cc="$CC")
fi

cd "$BUILD_DIR"
"$TCC_SRC/configure" "${CONFIGURE_ARGS[@]}" >"$_out" 2>&1

# c2str.exe is a host build tool that TCC's Makefile compiles with $(CC).
# When cross-compiling, $(CC) is the cross-compiler which cannot produce
# host executables.  Pre-build it with the native compiler so make skips it.
HOST_CC="${HOST_CC:-$(command -v cc || command -v gcc || command -v clang)}"
"$HOST_CC" -DC2STR "$TCC_SRC/conftest.c" -o "$BUILD_DIR/c2str.exe"

[[ "$QUIET" != "1" ]] && echo "Building TCC..."

make_jobs=()
if [[ "${MAKEFLAGS:-}" != *"--jobserver-auth="* ]] &&
   [[ "${MAKEFLAGS:-}" != *"--jobserver-fds="* ]]; then
  make_jobs=(-j"$JOBS")
fi

# libtcc1.a is normally built by running the just-compiled tcc, which is
# impossible when cross-compiling (riscv64 binary on x86_64 host).
# Setting <target>-libtcc1-usegcc=yes tells TCC's lib/Makefile to use
# the cross-GCC ($(CC)) and $(AR) instead.
#
# IMPORTANT: clear MAKEFLAGS/MAKEOVERRIDES from the outer KairOS build.
# Top-level `make ARCH=aarch64 ...` exports `ARCH` as a command-line override;
# if that leaks into TinyCC's Makefile it overrides config.mak's `ARCH=arm64`,
# resulting in empty libtcc object lists and link failures.
env -u MAKEFLAGS -u MAKEOVERRIDES -u MFLAGS \
make -C "$BUILD_DIR" "${make_jobs[@]}" \
  "${TCC_LIBTCC1_TARGET}-libtcc1-usegcc=yes" \
  tcc libtcc1.a >"$_out" 2>&1

# --- Install to staging directory (clean first for idempotency) ---
[[ "$QUIET" != "1" ]] && echo "Installing TCC to $OUT_DIR..."
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"/{bin,lib/tcc/include}

cp -f "$BUILD_DIR/tcc" "$OUT_DIR/bin/tcc"
chmod 0755 "$OUT_DIR/bin/tcc"

# Strip the binary — saves ~50% size on the disk image.
STRIP_TOOL=""
if [[ -n "$CROSS_PREFIX" ]] && command -v "${CROSS_PREFIX}strip" >/dev/null 2>&1; then
  STRIP_TOOL="${CROSS_PREFIX}strip"
elif command -v llvm-strip >/dev/null 2>&1; then
  STRIP_TOOL="llvm-strip"
fi
if [[ -n "$STRIP_TOOL" ]]; then
  "$STRIP_TOOL" "$OUT_DIR/bin/tcc"
fi

if [[ -f "$BUILD_DIR/libtcc1.a" ]]; then
  cp -f "$BUILD_DIR/libtcc1.a" "$OUT_DIR/lib/tcc/libtcc1.a"
else
  echo "WARN: libtcc1.a not found — tcc will not be able to link programs" >&2
fi

# Copy TCC's built-in headers (stdarg.h, stddef.h, etc.)
if [[ -d "$TCC_SRC/include" ]]; then
  cp -rf "$TCC_SRC/include"/* "$OUT_DIR/lib/tcc/include/"
fi

if [[ "$QUIET" == "1" ]]; then
  echo "  TCC     $OUT_DIR/bin/tcc"
else
  echo "TCC built: $OUT_DIR/bin/tcc"
  echo "Runtime:   $OUT_DIR/lib/tcc/"
fi
