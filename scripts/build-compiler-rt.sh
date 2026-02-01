#!/usr/bin/env bash
#
# build-compiler-rt.sh - Build compiler-rt builtins for clang
#
# Usage: ./scripts/build-compiler-rt.sh <arch>

set -euo pipefail

ARCH="${1:-riscv64}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LLVM_SRC="${LLVM_SRC:-$ROOT_DIR/third_party/llvm-project}"
LLVM_TAG="${LLVM_TAG:-llvmorg-21.1.8}"
SYSROOT="${SYSROOT:-$ROOT_DIR/build/${ARCH}/sysroot}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build/${ARCH}/compiler-rt}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/build/${ARCH}/compiler-rt/lib}"
JOBS="${JOBS:-$(nproc)}"

ARCH_FLAGS=""
case "$ARCH" in
  riscv64) TARGET="riscv64-linux-musl"; ARCH_FLAGS="-march=rv64gc -mabi=lp64" ;;
  x86_64) TARGET="x86_64-linux-musl" ;;
  aarch64) TARGET="aarch64-linux-musl" ;;
  *) echo "Unsupported ARCH: $ARCH" >&2; exit 1;;
 esac

if ! command -v clang >/dev/null 2>&1; then
  echo "Error: clang not found" >&2
  exit 1
fi
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

if [[ ! -f "$SYSROOT/lib/libc.a" ]] || [[ ! -f "$SYSROOT/include/stdlib.h" ]]; then
  echo "musl sysroot not found: $SYSROOT (building via ./scripts/build-musl.sh $ARCH)"
  SYSROOT="$SYSROOT" "$ROOT_DIR/scripts/build-musl.sh" "$ARCH"
fi

if [[ ! -d "$LLVM_SRC" ]]; then
  echo "=== Fetching llvm-project ($LLVM_TAG) ==="
  git clone --depth=1 --filter=blob:none --sparse \
    https://github.com/llvm/llvm-project.git \
    --branch="$LLVM_TAG" "$LLVM_SRC"
  git -C "$LLVM_SRC" sparse-checkout set compiler-rt cmake
else
  if [[ -d "$LLVM_SRC/.git" ]] && [[ -f "$LLVM_SRC/.git/info/sparse-checkout" ]]; then
    git -C "$LLVM_SRC" sparse-checkout set compiler-rt cmake
  fi
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

cmake -G Ninja -S "$LLVM_SRC/compiler-rt" -B "$BUILD_DIR" \
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
  -DLLVM_CONFIG_PATH="$(command -v llvm-config)" \
  -DCOMPILER_RT_BUILD_BUILTINS=ON \
  -DCOMPILER_RT_BUILD_SANITIZERS=OFF \
  -DCOMPILER_RT_BUILD_XRAY=OFF \
  -DCOMPILER_RT_BUILD_PROFILE=OFF \
  -DCOMPILER_RT_BUILD_CTX_PROFILE=OFF \
  -DCOMPILER_RT_BUILD_LIBFUZZER=OFF \
  -DCOMPILER_RT_BUILD_MEMPROF=OFF \
  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON

cmake --build "$BUILD_DIR" -j"$JOBS"

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

echo "compiler-rt builtins installed: $OUT_DIR/$(basename "$BUILTINS")"
echo "compiler-rt resource dir: $RESOURCE_DIR"
