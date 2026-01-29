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

CROSS_COMPILE="${CROSS_COMPILE:-${TARGET}-}"
CC=""
AR=""
RANLIB=""
STRIP=""
CFLAGS="${CFLAGS:-} ${ARCH_CFLAGS:-}"
LDFLAGS="${LDFLAGS:-} ${ARCH_CFLAGS:-}"

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

make -C "$BUSYBOX_SRC" mrproper

for shipped in zconf.tab.c_shipped lex.zconf.c_shipped zconf.hash.c_shipped; do
  src="${BUSYBOX_SRC}/scripts/kconfig/${shipped}"
  dst="${BUSYBOX_SRC}/scripts/kconfig/${shipped%_shipped}"
  if [[ -f "$src" && ! -f "$dst" ]]; then
    cp -f "$src" "$dst"
  fi
done

make -C "$BUSYBOX_SRC" O="$OUT_DIR" allnoconfig

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

echo "Using CC=$CC CROSS_COMPILE=$CROSS_COMPILE"
make -C "$BUSYBOX_SRC" O="$OUT_DIR" ARCH="$ARCH" CROSS_COMPILE="$CROSS_COMPILE" \
  CC="$CC" AR="$AR" RANLIB="$RANLIB" STRIP="$STRIP" \
  CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" -j"$JOBS"

echo "BusyBox built: $OUT_DIR/busybox"
