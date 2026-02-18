#!/usr/bin/env bash
#
# build-busybox.sh - Build BusyBox for a target architecture
#
# Usage: scripts/kairos.sh --arch <arch> toolchain busybox

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

BUSYBOX_SRC="${BUSYBOX_SRC:-$ROOT_DIR/third_party/busybox}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/build/${ARCH}/busybox}"
DEFCONFIG="${DEFCONFIG:-$ROOT_DIR/tools/busybox/kairos_defconfig}"
SYSROOT="${SYSROOT:-$ROOT_DIR/build/${ARCH}/sysroot}"
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

BUSYBOX_SRC="$(realpath -m "$BUSYBOX_SRC")"
OUT_DIR="$(realpath -m "$OUT_DIR")"
SYSROOT="$(realpath -m "$SYSROOT")"
DEFCONFIG="$(realpath -m "$DEFCONFIG")"

if [[ ! -d "$BUSYBOX_SRC" ]]; then
  echo "BusyBox source not found: $BUSYBOX_SRC (run scripts/kairos.sh deps fetch busybox)" >&2
  exit 1
fi

if [[ ! -f "$SYSROOT/lib/libc.a" ]]; then
  echo "musl sysroot not found: $SYSROOT (run scripts/kairos.sh --arch $ARCH toolchain musl)" >&2
  exit 1
fi

# BusyBox's link rules hardcode -lgcc/-lgcc_eh. Pre-populate compatibility
# archives before static probe so clang toolchain detection can succeed.
kairos_tc_prepare_libgcc_compat "$ARCH" "$SYSROOT"

kairos_tc_select "$TARGET" "$SYSROOT" "$ARCH_CFLAGS" 1
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

make_jobs=()
if [[ "${MAKEFLAGS:-}" != *"--jobserver-auth="* ]] &&
   [[ "${MAKEFLAGS:-}" != *"--jobserver-fds="* ]]; then
  make_jobs=(-j"$JOBS")
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

# Ensure new Kconfig symbols resolve non-interactively.
# BusyBox may introduce symbols without defaults; feeding empty answers to
# oldconfig reliably accepts each prompt's default choice.
set +o pipefail
yes "" | make -C "$BUSYBOX_SRC" O="$OUT_DIR" oldconfig >"$_out" 2>&1
set -o pipefail

[[ "$QUIET" != "1" ]] && echo "Using CC=$CC CROSS_COMPILE=$CROSS_COMPILE"
make -C "$BUSYBOX_SRC" O="$OUT_DIR" ARCH="$ARCH" CROSS_COMPILE="$CROSS_COMPILE" \
  CC="$CC" AR="$AR" RANLIB="$RANLIB" STRIP="$STRIP" \
  CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" "${make_jobs[@]}" >"$_out" 2>&1

if [[ "$QUIET" == "1" ]]; then
  echo "  BBOX    $OUT_DIR/busybox"
else
  echo "BusyBox built: $OUT_DIR/busybox"
fi
