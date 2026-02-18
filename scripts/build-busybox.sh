#!/usr/bin/env bash
#
# build-busybox.sh - Build BusyBox for a target architecture
#
# Usage: ./scripts/build-busybox.sh <arch>

set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
  echo "Usage: $0 <arch>" >&2
  exit 1
fi

QUIET="${QUIET:-0}"

BUSYBOX_SRC="${BUSYBOX_SRC:-third_party/busybox}"
OUT_DIR="${OUT_DIR:-build/${ARCH}/busybox}"
DEFCONFIG="${DEFCONFIG:-tools/busybox/kairos_defconfig}"
SYSROOT="${SYSROOT:-build/${ARCH}/sysroot}"
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

BUSYBOX_SRC="$(realpath -m "$BUSYBOX_SRC")"
OUT_DIR="$(realpath -m "$OUT_DIR")"
SYSROOT="$(realpath -m "$SYSROOT")"
DEFCONFIG="$(realpath -m "$DEFCONFIG")"

if [[ ! -d "$BUSYBOX_SRC" ]]; then
  echo "BusyBox source not found: $BUSYBOX_SRC (run ./scripts/fetch-deps.sh busybox)" >&2
  exit 1
fi

if [[ ! -f "$SYSROOT/lib/libc.a" ]]; then
  echo "musl sysroot not found: $SYSROOT (run ./scripts/build-musl.sh $ARCH)" >&2
  exit 1
fi

# Create libgcc.a / libgcc_eh.a compatibility symlinks for BusyBox.
# BusyBox's build system hardcodes -lgcc -lgcc_eh; when using clang +
# compiler-rt we satisfy those with symlinks to the builtins library.
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RT_RESOURCE_DIR="$(realpath -m "$ROOT_DIR/build/${ARCH}/compiler-rt/resource")"
_builtins="$(find "$RT_RESOURCE_DIR" -name 'libclang_rt.builtins*.a' 2>/dev/null | head -n1)"
if [[ -n "$_builtins" ]]; then
  ln -sf "$_builtins" "$SYSROOT/lib/libgcc.a"
  # libgcc_eh.a can be empty — BusyBox doesn't actually need unwind symbols
  if [[ ! -f "$SYSROOT/lib/libgcc_eh.a" ]]; then
    llvm-ar cr "$SYSROOT/lib/libgcc_eh.a"
  fi
fi

if command -v "${CROSS_COMPILE}gcc" >/dev/null 2>&1; then
  CC="${CROSS_COMPILE}gcc"
  AR="${CROSS_COMPILE}ar"
  RANLIB="${CROSS_COMPILE}ranlib"
  STRIP="${CROSS_COMPILE}strip"
  CFLAGS="--sysroot=${SYSROOT} -isystem ${SYSROOT}/include ${CFLAGS}"
  LDFLAGS="--sysroot=${SYSROOT} -L${SYSROOT}/lib ${LDFLAGS}"
else
  GNU_CROSS="${TARGET/-musl/-gnu}-"
  if command -v "${GNU_CROSS}gcc" >/dev/null 2>&1; then
    CROSS_COMPILE="${GNU_CROSS}"
    CC="${CROSS_COMPILE}gcc"
    AR="${CROSS_COMPILE}ar"
    RANLIB="${CROSS_COMPILE}ranlib"
    STRIP="${CROSS_COMPILE}strip"
    CFLAGS="--sysroot=${SYSROOT} -isystem ${SYSROOT}/include ${CFLAGS}"
    LDFLAGS="--sysroot=${SYSROOT} -L${SYSROOT}/lib ${LDFLAGS}"
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
  CC="clang --target=${TARGET} --sysroot=${SYSROOT} -fuse-ld=lld"
  AR="llvm-ar"
  RANLIB="llvm-ranlib"
  STRIP="llvm-strip"
  CFLAGS="--target=${TARGET} --sysroot=${SYSROOT} -isystem ${SYSROOT}/include ${CFLAGS}"
  LDFLAGS="--target=${TARGET} --sysroot=${SYSROOT} -fuse-ld=lld -L${SYSROOT}/lib ${LDFLAGS}"
  CROSS_COMPILE=""
  fi
fi

if [[ ! -f "$DEFCONFIG" ]]; then
  echo "BusyBox defconfig not found: $DEFCONFIG" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

if [[ "$QUIET" == "1" ]]; then
  _out=/dev/null
else
  _out=/dev/stdout
fi

make -C "$BUSYBOX_SRC" mrproper >"$_out" 2>&1

for shipped in zconf.tab.c_shipped lex.zconf.c_shipped zconf.hash.c_shipped; do
  src="${BUSYBOX_SRC}/scripts/kconfig/${shipped}"
  dst="${BUSYBOX_SRC}/scripts/kconfig/${shipped%_shipped}"
  if [[ -f "$src" && ! -f "$dst" ]]; then
    cp -f "$src" "$dst"
  fi
done

make -C "$BUSYBOX_SRC" O="$OUT_DIR" allnoconfig >"$_out" 2>&1

CONFIG_FILE="${OUT_DIR}/.config"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if [[ "$line" =~ ^#\ CONFIG_([A-Za-z0-9_]+)\ is\ not\ set$ ]]; then
    opt="CONFIG_${BASH_REMATCH[1]}"
    sed -i "/^${opt}=.*$/d;/^# ${opt} is not set$/d" "$CONFIG_FILE"
    echo "# ${opt} is not set" >> "$CONFIG_FILE"
  elif [[ "$line" =~ ^CONFIG_[A-Za-z0-9_]+= ]]; then
    opt="${line%%=*}"
    sed -i "/^${opt}=.*$/d;/^# ${opt} is not set$/d" "$CONFIG_FILE"
    echo "$line" >> "$CONFIG_FILE"
  fi
done < "$DEFCONFIG"

# Ensure new Kconfig symbols take defaults without prompting
make -C "$BUSYBOX_SRC" O="$OUT_DIR" silentoldconfig >"$_out" 2>&1

[[ "$QUIET" != "1" ]] && echo "Using CC=$CC CROSS_COMPILE=$CROSS_COMPILE"
make -C "$BUSYBOX_SRC" O="$OUT_DIR" ARCH="$ARCH" CROSS_COMPILE="$CROSS_COMPILE" \
  CC="$CC" AR="$AR" RANLIB="$RANLIB" STRIP="$STRIP" \
  CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" -j"$JOBS" >"$_out" 2>&1

if [[ "$QUIET" == "1" ]]; then
  echo "  BBOX    $OUT_DIR/busybox"
else
  echo "BusyBox built: $OUT_DIR/busybox"
fi
