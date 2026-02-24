#!/bin/bash
#
# make-disk.sh - Create an ext2 disk image for testing
#
# Usage: scripts/kairos.sh --arch <arch> image disk

set -euo pipefail

ARCH="${1:-riscv64}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
QUIET="${QUIET:-0}"
source "${ROOT_DIR}/scripts/lib/common.sh"
BUILD_ROOT="${BUILD_ROOT:-${ROOT_DIR}/build}"
BUILD_DIR="${BUILD_ROOT}/${ARCH}"

DISK_IMG="${DISK_IMG:-${BUILD_DIR}/disk.img}"
ROOTFS_DIR="${ROOTFS_DIR:-${BUILD_DIR}/rootfs}"
BUSYBOX_BIN="${BUSYBOX_BIN:-${BUILD_DIR}/busybox/busybox}"
INIT_BIN="${INIT_BIN:-${BUILD_DIR}/user/init}"
DOOM_BIN="${DOOM_BIN:-${BUILD_DIR}/user/doom}"
DOOM_WAD="${DOOM_WAD:-}"
TCC_BIN="${TCC_BIN:-${BUILD_DIR}/tcc/bin/tcc}"
TCC_LIB="${TCC_LIB:-${BUILD_DIR}/tcc/lib/tcc}"
SYSROOT_DIR="${SYSROOT_DIR:-${BUILD_DIR}/sysroot}"
ROOTFS_ONLY="${ROOTFS_ONLY:-0}"
ROOTFS_STAGE="${ROOTFS_STAGE:-all}"

if [[ -z "$DOOM_WAD" ]]; then
  if [[ -f "${ROOT_DIR}/third_party/freedoom/doom1.wad" ]]; then
    DOOM_WAD="${ROOT_DIR}/third_party/freedoom/doom1.wad"
  elif [[ -f "${ROOT_DIR}/third_party/freedoom/freedoom1.wad" ]]; then
    DOOM_WAD="${ROOT_DIR}/third_party/freedoom/freedoom1.wad"
  fi
fi

DISK_SIZE=64  # MB

stage_base() {
  [[ "$QUIET" != "1" ]] && echo "Staging rootfs base: $ROOTFS_DIR"
  mkdir -p "$ROOTFS_DIR"/{bin,sbin,etc,home,root,dev}

  echo "Hello from Kairos filesystem!" >"$ROOTFS_DIR/test.txt"
  echo "This is another test file" >"$ROOTFS_DIR/test2.txt"
  echo "root:x:0:0:root:/root:/bin/sh" >"$ROOTFS_DIR/etc/passwd"
  echo "127.0.0.1 localhost" >"$ROOTFS_DIR/etc/hosts"
  cat >"$ROOTFS_DIR/etc/profile" <<'EOF'
# Kairos shell profile
case "$-" in
  *i*) ;;
  *) return ;;
esac

export PATH="/bin:/sbin:/usr/bin:/usr/sbin"
export HISTFILE="/root/.ash_history"
export HISTSIZE=200

if test "${TERM:-dumb}" = "dumb"; then
  PS1='[\w] $ '
else
  PS1='\[\033[1;36m\][\w]\[\033[0m\] \$ '
fi
export PS1

if ls --color=auto / >/dev/null 2>&1; then
  if command -v alias >/dev/null 2>&1; then
    alias ls='ls --color=auto'
  fi
fi
if command -v alias >/dev/null 2>&1; then
  alias ll='ls -alF'
  alias la='ls -A'
fi
EOF
}

stage_init() {
  [[ "$QUIET" != "1" ]] && echo "Staging rootfs init: $ROOTFS_DIR"
  mkdir -p "$ROOTFS_DIR"/{bin,sbin}
  if [[ -x "$INIT_BIN" ]]; then
    cp -f "$INIT_BIN" "$ROOTFS_DIR/init"
    chmod 0755 "$ROOTFS_DIR/init"
  else
    echo "WARN: init not found ($INIT_BIN)"
  fi

  ln -sf /init "$ROOTFS_DIR/sbin/init"
  ln -sf /init "$ROOTFS_DIR/bin/init"
}

stage_busybox() {
  [[ "$QUIET" != "1" ]] && echo "Staging rootfs busybox: $ROOTFS_DIR"
  mkdir -p "$ROOTFS_DIR/bin"
  if [[ -x "$BUSYBOX_BIN" ]]; then
    cp -f "$BUSYBOX_BIN" "$ROOTFS_DIR/bin/busybox"
    chmod 0755 "$ROOTFS_DIR/bin/busybox"
    kairos_install_busybox_applet_links "$ROOTFS_DIR/bin" "/bin/busybox"
  else
    echo "WARN: busybox not found ($BUSYBOX_BIN)"
  fi
}

stage_doom() {
  [[ "$QUIET" != "1" ]] && echo "Staging rootfs doom: $ROOTFS_DIR"
  mkdir -p "$ROOTFS_DIR"/{bin,doom}
  if [[ -x "$DOOM_BIN" ]]; then
    cp -f "$DOOM_BIN" "$ROOTFS_DIR/bin/doom"
    chmod 0755 "$ROOTFS_DIR/bin/doom"
  else
    echo "WARN: doom not found ($DOOM_BIN)"
  fi

  if [[ -n "$DOOM_WAD" && -f "$DOOM_WAD" ]]; then
    cp -f "$DOOM_WAD" "$ROOTFS_DIR/doom/doom1.wad"
    chmod 0644 "$ROOTFS_DIR/doom/doom1.wad"
  fi
}

stage_tcc() {
  [[ "$QUIET" != "1" ]] && echo "Staging rootfs tcc: $ROOTFS_DIR"
  mkdir -p "$ROOTFS_DIR"/{usr/bin,usr/lib/tcc,usr/include,lib,tmp}

  # tcc binary
  if [[ -x "$TCC_BIN" ]]; then
    cp -f "$TCC_BIN" "$ROOTFS_DIR/usr/bin/tcc"
    chmod 0755 "$ROOTFS_DIR/usr/bin/tcc"
  else
    echo "WARN: tcc not found ($TCC_BIN)"
  fi

  # libtcc1.a + tcc built-in headers (stdarg.h, stddef.h, etc.)
  if [[ -d "$TCC_LIB" ]]; then
    cp -rf "$TCC_LIB"/* "$ROOTFS_DIR/usr/lib/tcc/"
    if [[ -f "$TCC_LIB/libtcc1.a" ]]; then
      cp -f "$TCC_LIB/libtcc1.a" "$ROOTFS_DIR/usr/lib/libtcc1.a"
    fi
  fi

  # musl sysroot: headers + static lib + CRT objects
  if [[ -d "$SYSROOT_DIR/include" ]]; then
    cp -rf "$SYSROOT_DIR/include"/* "$ROOTFS_DIR/usr/include/"
  fi
  for f in libc.a libgcc.a crt1.o crti.o crtn.o; do
    if [[ -f "$SYSROOT_DIR/lib/$f" ]]; then
      cp -f "$SYSROOT_DIR/lib/$f" "$ROOTFS_DIR/usr/lib/$f"
    fi
  done

  # Dynamic loader/runtime for dynamically-linked ELF binaries.
  if [[ -e "$SYSROOT_DIR/lib/libc.so" || -L "$SYSROOT_DIR/lib/libc.so" ]]; then
    rm -f "$ROOTFS_DIR/lib/libc.so"
    cp -a "$SYSROOT_DIR/lib/libc.so" "$ROOTFS_DIR/lib/libc.so"
  fi
  local -a ldso_candidates=()
  local -a rootfs_ldso=()
  shopt -s nullglob
  ldso_candidates=("$SYSROOT_DIR"/lib/ld-musl-*.so.1)
  shopt -u nullglob
  for ldso in "${ldso_candidates[@]}"; do
    local ldso_name
    ldso_name="$(basename "$ldso")"
    rm -f "$ROOTFS_DIR/lib/$ldso_name"
    if [[ -e "$ldso" || -L "$ldso" ]]; then
      cp -a "$ldso" "$ROOTFS_DIR/lib/$ldso_name"
    fi
  done
  if [[ "$ARCH" == "riscv64" && -e "$ROOTFS_DIR/lib/libc.so" &&
        ! -e "$ROOTFS_DIR/lib/ld-musl-riscv64.so.1" ]]; then
    ln -sf libc.so "$ROOTFS_DIR/lib/ld-musl-riscv64.so.1"
  fi

  if [[ ! -e "$ROOTFS_DIR/lib/libc.so" ]]; then
    kairos_warn "dynamic runtime missing: /lib/libc.so (dynamic binaries may fail)"
  fi
  shopt -s nullglob
  rootfs_ldso=("$ROOTFS_DIR"/lib/ld-musl-*.so.1)
  shopt -u nullglob
  if [[ ${#rootfs_ldso[@]} -eq 0 ]]; then
    kairos_warn "dynamic runtime missing: /lib/ld-musl-*.so.1 (PT_INTERP resolution may fail)"
  fi
}

case "$ROOTFS_STAGE" in
  all)
    stage_base
    stage_init
    stage_busybox
    stage_doom
    stage_tcc
    ;;
  base)
    stage_base
    ;;
  init)
    stage_init
    ;;
  busybox)
    stage_busybox
    ;;
  tcc)
    stage_tcc
    ;;
  *)
    echo "Error: unknown ROOTFS_STAGE=$ROOTFS_STAGE"
    exit 1
    ;;
esac

if [[ "$ROOTFS_ONLY" == "1" ]]; then
  [[ "$QUIET" != "1" ]] && echo "Rootfs staged only; skipping disk image."
  exit 0
fi

[[ "$QUIET" != "1" ]] && echo "Creating ext2 disk image: $DISK_IMG"
mkdir -p "$(dirname "$DISK_IMG")"

if ! truncate -s "${DISK_SIZE}M" "$DISK_IMG" 2>/dev/null; then
  dd if=/dev/zero of="$DISK_IMG" bs=1M count=$DISK_SIZE 2>/dev/null
fi
mke2fs -t ext2 -F -d "$ROOTFS_DIR" "$DISK_IMG" >/dev/null 2>&1

if [[ "$QUIET" == "1" ]]; then
  echo "  DISK    $DISK_IMG (${DISK_SIZE}M ext2)"
else
  echo "Created $DISK_SIZE MB ext2 filesystem"
  echo "Disk image created successfully: $DISK_IMG"
fi
