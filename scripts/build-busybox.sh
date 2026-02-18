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
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${ROOT_DIR}/scripts/lib/common.sh"

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
CROSS_COMPILE="${TARGET}-"
CC=""
AR=""
RANLIB=""
STRIP=""
BASE_CFLAGS="${ARCH_CFLAGS:-}"
BASE_LDFLAGS="${ARCH_CFLAGS:-}"
CFLAGS="${BASE_CFLAGS}"
LDFLAGS="${BASE_LDFLAGS}"
GNU_CROSS="${TARGET/-musl/-gnu}-"

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
RT_RESOURCE_DIR="$(realpath -m "$ROOT_DIR/build/${ARCH}/compiler-rt/resource")"
_builtins="$(find "$RT_RESOURCE_DIR" -name 'libclang_rt.builtins*.a' 2>/dev/null | head -n1)"
if [[ -n "$_builtins" ]]; then
  ln -sf "$_builtins" "$SYSROOT/lib/libgcc.a"
  # libgcc_eh.a can be empty — BusyBox doesn't actually need unwind symbols
  if [[ ! -f "$SYSROOT/lib/libgcc_eh.a" ]]; then
    llvm-ar cr "$SYSROOT/lib/libgcc_eh.a"
  fi
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
  CC="clang --target=${TARGET} --sysroot=${SYSROOT}"
  AR="llvm-ar"
  RANLIB="llvm-ranlib"
  STRIP="llvm-strip"
  CFLAGS="--target=${TARGET} --sysroot=${SYSROOT} -isystem ${SYSROOT}/include ${BASE_CFLAGS}"
  LDFLAGS="--target=${TARGET} --sysroot=${SYSROOT} -fuse-ld=lld -L${SYSROOT}/lib ${BASE_LDFLAGS}"
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
  CFLAGS="--sysroot=${SYSROOT} -isystem ${SYSROOT}/include ${BASE_CFLAGS}"
  LDFLAGS="--sysroot=${SYSROOT} -L${SYSROOT}/lib ${BASE_LDFLAGS}"
  return 0
}

clang_can_link_static() {
  local src out
  src="$(mktemp /tmp/kairos-busybox-link-XXXXXX.c)"
  out="${src%.c}.bin"
  cat > "$src" <<'EOF'
int main(void) { return 0; }
EOF
  if clang --target="${TARGET}" --sysroot="${SYSROOT}" -fuse-ld=lld \
      -isystem "${SYSROOT}/include" -L"${SYSROOT}/lib" ${ARCH_CFLAGS} \
      -static "$src" -o "$out" >/dev/null 2>&1; then
    rm -f "$src" "$out"
    return 0
  fi
  rm -f "$src" "$out"
  return 1
}

if [[ "$USE_GCC" == "1" ]]; then
  if ! select_gcc "${TARGET}-"; then
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
      if ! select_gcc "$GNU_CROSS"; then
        echo "Toolchain not found: clang/llvm-* tools, ${TARGET}-gcc, or ${GNU_CROSS}gcc" >&2
        exit 1
      fi
    fi
  fi
fi

if [[ "$CC" == clang* ]] && ! clang_can_link_static; then
  if select_gcc "${TARGET}-" || select_gcc "$GNU_CROSS"; then
    [[ "$QUIET" != "1" ]] && echo "clang static link probe failed, falling back to GCC toolchain"
  else
    echo "clang cannot link static target binaries (missing crtbegin/crtend), and no GCC fallback was found" >&2
    exit 1
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
