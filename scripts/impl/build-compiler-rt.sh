#!/usr/bin/env bash
#
# build-compiler-rt.sh - Build compiler-rt builtins for clang
#
# Usage: scripts/kairos.sh --arch <arch> toolchain compiler-rt

set -euo pipefail

ARCH="${1:-riscv64}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "${ROOT_DIR}/scripts/lib/common.sh"
source "${ROOT_DIR}/scripts/lib/toolchain.sh"
QUIET="${QUIET:-0}"
LLVM_SRC="${LLVM_SRC:-$ROOT_DIR/third_party/llvm-project}"
LLVM_TAG="${LLVM_TAG:-llvmorg-21.1.8}"
SYSROOT="${SYSROOT:-$ROOT_DIR/build/${ARCH}/sysroot}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build/${ARCH}/compiler-rt}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/build/${ARCH}/compiler-rt/lib}"
JOBS="${JOBS:-$(nproc)}"
LOG_DIR="${ROOT_DIR}/build/${ARCH}/logs"
LOG_FILE="${LOG_DIR}/compiler-rt.log"

ensure_log_file() {
  mkdir -p "$LOG_DIR"
  : >>"$LOG_FILE"
}
ensure_log_file
: > "$LOG_FILE"

on_error() {
  local rc=$?
  echo "Error: compiler-rt build failed for ${ARCH}" >&2
  if [[ "$QUIET" == "1" ]]; then
    echo "See full log: $LOG_FILE" >&2
    echo "--- compiler-rt log (tail) ---" >&2
    tail -n 120 "$LOG_FILE" >&2 || true
    echo "-------------------------------" >&2
  fi
  exit "$rc"
}
trap on_error ERR

run_cmd() {
  if [[ "$QUIET" == "1" ]]; then
    ensure_log_file
    "$@" >>"$LOG_FILE" 2>&1
  else
    "$@"
  fi
}

ARCH_FLAGS=""
TARGET="$(kairos_arch_to_musl_target "$ARCH")" || {
  echo "Unsupported ARCH: $ARCH" >&2
  exit 1
}
ARCH_FLAGS="$(kairos_arch_cflags "$ARCH")"
if ! command -v llvm-config >/dev/null 2>&1; then
  echo "Error: llvm-config not found" >&2
  exit 1
fi
if ! command -v cmake >/dev/null 2>&1; then
  echo "Error: cmake not found" >&2
  exit 1
fi
if ! command -v ninja >/dev/null 2>&1; then
  echo "Error: ninja not found" >&2
  exit 1
fi

SYSROOT="$(realpath -m "$SYSROOT")"

kairos_tc_select "$TARGET" "$SYSROOT" "$ARCH_FLAGS" 0
if [[ "$KAIROS_TC_KIND" != "clang" ]]; then
  if [[ -n "${KAIROS_TC_NOTE:-}" ]]; then
    kairos_die "compiler-rt requires clang toolchain: ${KAIROS_TC_NOTE}"
  fi
  kairos_die "compiler-rt requires clang toolchain (selected ${KAIROS_TC_KIND})"
fi
if [[ -n "${KAIROS_TC_NOTE:-}" && "$QUIET" != "1" ]]; then
  echo "$KAIROS_TC_NOTE"
fi

if ! command -v clang >/dev/null 2>&1; then
  kairos_die "compiler-rt requires clang, but clang is not available"
fi
if ! clang --target="$TARGET" --sysroot="$SYSROOT" -c -x c /dev/null -o /dev/null >/dev/null 2>&1; then
  kairos_die "clang target probe failed for ${TARGET} (sysroot=${SYSROOT})"
fi

if [[ ! -f "$SYSROOT/lib/libc.a" ]] || [[ ! -f "$SYSROOT/include/stdlib.h" ]]; then
  [[ "$QUIET" != "1" ]] && echo "musl sysroot not found: $SYSROOT (building static-only via scripts/kairos.sh --arch $ARCH toolchain musl)"
  run_cmd env MUSL_STATIC_ONLY=1 QUIET=0 SYSROOT="$SYSROOT" \
    "$ROOT_DIR/scripts/impl/build-musl.sh" "$ARCH"
fi

if [[ ! -d "$LLVM_SRC" ]]; then
  [[ "$QUIET" != "1" ]] && echo "=== Fetching llvm-project ($LLVM_TAG) ==="
  run_cmd git clone --depth=1 --filter=blob:none --sparse \
    https://github.com/llvm/llvm-project.git \
    --branch="$LLVM_TAG" "$LLVM_SRC"
fi

if [[ -d "$LLVM_SRC/.git" ]]; then
  run_cmd git -C "$LLVM_SRC" sparse-checkout init --cone
  run_cmd git -C "$LLVM_SRC" sparse-checkout set llvm compiler-rt cmake third-party
fi

if [[ ! -f "$LLVM_SRC/llvm/CMakeLists.txt" ]]; then
  echo "Error: missing llvm source tree at $LLVM_SRC/llvm" >&2
  echo "Hint: refresh llvm-project checkout with llvm subtree" >&2
  exit 1
fi

mkdir -p "$BUILD_DIR" "$OUT_DIR"

copy_if_different() {
  local src="$1"
  local dst="$2"
  if [[ -e "$src" && -e "$dst" ]]; then
    local src_real
    local dst_real
    src_real="$(realpath -m "$src")"
    dst_real="$(realpath -m "$dst")"
    if [[ "$src_real" == "$dst_real" ]]; then
      return 0
    fi
  fi
  cp -f "$src" "$dst"
}

LINUX_HEADERS_DIR="$BUILD_DIR/linux-headers"
if [[ "$ARCH" == "riscv64" ]]; then
  mkdir -p "$LINUX_HEADERS_DIR/linux"
  cat > "$LINUX_HEADERS_DIR/linux/unistd.h" <<'EOF'
#ifndef _LINUX_UNISTD_H
#define _LINUX_UNISTD_H
#define __NR_riscv_flush_icache 259
#endif
EOF
fi

INCLUDE_FLAGS="-isystem $SYSROOT/include"
if [[ -d "$SYSROOT/usr/include" ]]; then
  INCLUDE_FLAGS="$INCLUDE_FLAGS -isystem $SYSROOT/usr/include"
fi
if [[ -d "$LINUX_HEADERS_DIR" ]]; then
  INCLUDE_FLAGS="-isystem $LINUX_HEADERS_DIR $INCLUDE_FLAGS"
fi

CFLAGS_COMMON="--target=$TARGET --sysroot=$SYSROOT $INCLUDE_FLAGS $ARCH_FLAGS"

run_cmd cmake -G Ninja -S "$LLVM_SRC/compiler-rt" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_COMPILER_TARGET="$TARGET" \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_SYSROOT="$SYSROOT" \
  -DCMAKE_C_FLAGS="$CFLAGS_COMMON -fuse-ld=lld" \
  -DCMAKE_CXX_FLAGS="$CFLAGS_COMMON -fuse-ld=lld" \
  -DCMAKE_ASM_FLAGS="$CFLAGS_COMMON" \
  -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld" \
  -DLLVM_MAIN_SRC_DIR="$LLVM_SRC/llvm" \
  -DLLVM_CONFIG_PATH="$(command -v llvm-config)" \
  -DCOMPILER_RT_BUILD_BUILTINS=ON \
  -DCOMPILER_RT_BUILD_SANITIZERS=OFF \
  -DCOMPILER_RT_BUILD_XRAY=OFF \
  -DCOMPILER_RT_BUILD_PROFILE=OFF \
  -DCOMPILER_RT_BUILD_CTX_PROFILE=OFF \
  -DCOMPILER_RT_BUILD_LIBFUZZER=OFF \
  -DCOMPILER_RT_BUILD_MEMPROF=OFF \
  -DCOMPILER_RT_BUILD_ORC=OFF \
  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON

run_cmd cmake --build "$BUILD_DIR" -j"$JOBS"

BUILTINS=$(find "$BUILD_DIR" -name "libclang_rt.builtins-*.a" | head -n1 || true)
if [[ -z "$BUILTINS" ]]; then
  echo "Error: compiler-rt builtins not found in $BUILD_DIR" >&2
  exit 1
fi

copy_if_different "$BUILTINS" "$OUT_DIR/$(basename "$BUILTINS")"

RESOURCE_DIR="$BUILD_DIR/resource"
TRIPLE="$(clang --target="$TARGET" -print-target-triple)"
RESOURCE_LIB_DIR="$RESOURCE_DIR/lib/$TRIPLE"
mkdir -p "$RESOURCE_LIB_DIR"
copy_if_different "$BUILTINS" "$RESOURCE_LIB_DIR/libclang_rt.builtins.a"

CRTBEGIN="$(find "$BUILD_DIR" -name "clang_rt.crtbegin-*.o" | head -n1 || true)"
CRTEND="$(find "$BUILD_DIR" -name "clang_rt.crtend-*.o" | head -n1 || true)"
if [[ -n "$CRTBEGIN" ]]; then
  copy_if_different "$CRTBEGIN" "$SYSROOT/lib/crtbeginT.o"
  copy_if_different "$CRTBEGIN" "$SYSROOT/lib/crtbegin.o"
  copy_if_different "$CRTBEGIN" "$SYSROOT/lib/crtbeginS.o"
fi
if [[ -n "$CRTEND" ]]; then
  copy_if_different "$CRTEND" "$SYSROOT/lib/crtend.o"
  copy_if_different "$CRTEND" "$SYSROOT/lib/crtendS.o"
fi

if [[ "$QUIET" == "1" ]]; then
  echo "  RT      $OUT_DIR/$(basename "$BUILTINS")"
else
  echo "compiler-rt builtins installed: $OUT_DIR/$(basename "$BUILTINS")"
  echo "compiler-rt resource dir: $RESOURCE_DIR"
fi
